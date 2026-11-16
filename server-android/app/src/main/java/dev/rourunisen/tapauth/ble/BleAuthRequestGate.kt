package dev.rourunisen.tapauth.ble

import java.util.concurrent.ConcurrentHashMap

/**
 * Decides what happens to an already signature-verified BLE AuthenticationRequest.
 *
 * A Client that has not seen our response yet keeps retransmitting the same request, and the first
 * transmission can arrive twice at once: a `CLIENT_COMMAND` notification racing the initial
 * characteristic read, or a re-notification of the same in-flight challenge. Both copies carry the
 * same challenge nonce, so the replay cache classifies the second one as a replay and
 * [BleGattService] tears the GATT link down — killing the authentication the user is approving.
 *
 * This gate therefore tracks which `(challenge, peer)` pairs are in flight and answers a repeat
 * from the same peer as [Verdict.DUPLICATE_IN_FLIGHT] *before* the replay cache is consulted. A
 * different peer presenting the same captured bytes is not a duplicate: it falls through to the
 * replay check and is rejected there exactly as before.
 *
 * "In flight" means: the challenge was accepted for processing from that peer and no repeat of it
 * has to be re-examined yet. An entry is released when the Client abandons the challenge
 * ([conclude] — a verified `AuthenticationCancel` from the peer, or the daemon's own cancel of that
 * challenge), when its GATT link has stayed away past the reconnection grace ([concludePeer],
 * driven by the grace timer `BleGattService` starts on `STATE_DISCONNECTED` — deliberately *not* by
 * the disconnect itself), when the service stops ([clear]), and — for a link that never reports its
 * teardown — once it is older than [IN_FLIGHT_MAX_AGE_MS].
 *
 * A disconnect is therefore not a release: the Client reconnects to deliver the request it is still
 * retransmitting, and that reconnect presents the same challenge from the same peer on a new GATT
 * handle. With the claim held that arrival is a silent [Verdict.DUPLICATE_IN_FLIGHT] and the prompt
 * the user is answering survives; releasing it on the disconnect would send the arrival to the
 * replay cache, which reports the retransmitted challenge as a replay and tears the new link down.
 *
 * A concluded challenge is deliberately *not* released at the moment the grant, denial or timeout
 * is sent, and [BleGattService]'s `releaseLock` call sites say so. The Client keeps retransmitting
 * the same request until it has the answer, and those retransmissions arrive while the link is
 * still up; if the claim were dropped there, they would fall through to the replay cache, which has
 * already recorded this challenge and answers "replay", and the link would be torn down — exactly
 * the symptom this gate exists to remove. Holding the claim instead makes such a retransmission a
 * silent [Decision.Duplicate]. Nothing legitimate is swallowed by that: a new authentication always
 * carries a new challenge, and a different peer replaying the captured bytes still falls through to
 * the replay check.
 *
 * ### The ladder
 *
 * [decide] is the one call that answers this question, so the ordering is a property of this file
 * and not of the service that reacts to it. First match wins:
 *
 * 1. [Decision.Claimed] — the transport lock refused the challenge, so another transport (usually
 *    UDP) already owns it. The claim is consulted first, through the injected [claimTransport],
 *    because that is the order the service ran the two in; nothing is admitted to [inFlight] and
 *    the replay cache is never asked.
 * 2. [Decision.Duplicate] — same peer, same challenge, still in flight. Answered *before* the
 *    replay cache, which is the whole point: its answer for those bytes is "replay".
 * 3. [Decision.Replay] — the cache rejected the request. A different peer holding the same bytes
 *    lands here, which is what keeps a captured request from being replayed from another phone.
 * 4. [Decision.Process] — fresh; the caller raises the prompt.
 *
 * [BleGattService] performs one effect per outcome and decides nothing itself.
 */
internal class BleAuthRequestGate(
    private val isReplay: (challenge: ByteArray, timestampUnixSeconds: Long) -> Boolean,
    private val elapsedMillis: () -> Long,
) {

    /**
     * What [decide] answered for one arrival. Exactly one of these is returned, and the caller does
     * nothing else than perform its effect.
     */
    sealed class Decision {
        /** Another transport owns this challenge: drop the link without touching anything here. */
        data object Claimed : Decision()

        /** Same peer, same challenge, still in flight: ignore without touching the replay cache. */
        data object Duplicate : Decision()

        /** The replay cache rejected the request: reject and disconnect exactly as before. */
        data object Replay : Decision()

        /** First arrival for this challenge from this peer: process it. */
        data object Process : Decision()
    }

    private class InFlight(val peerAddress: String, val startedAtMillis: Long)

    private val inFlight = ConcurrentHashMap<String, InFlight>()

    /** Number of challenges currently held as in flight (tests and diagnostics). */
    val inFlightCount: Int
        get() = inFlight.size

    /**
     * Decide what this arrival is: [Decision.Claimed], [Decision.Duplicate], [Decision.Replay] or
     * [Decision.Process], in that order (see the class documentation).
     *
     * [claimTransport] is the transport lock (`TransportLockManager.tryClaimTransport`): it is
     * consulted first and its `false` ends the decision, so a challenge another transport already
     * owns never installs a claim here and never reaches the replay cache.
     */
    fun decide(
        challenge: ByteArray,
        timestampUnixSeconds: Long,
        peerAddress: String,
        claimTransport: () -> Boolean,
    ): Decision {
        if (!claimTransport()) return Decision.Claimed

        val challengeKey = challenge.toHex()
        pruneExpired()

        // Claim the challenge BEFORE the replay check so two arrivals that race each other cannot
        // both pass it: exactly one wins putIfAbsent and the other is a duplicate. A different
        // peer leaves the owner's entry untouched and falls through to the replay check below.
        val claim = InFlight(peerAddress, elapsedMillis())
        val existing = inFlight.putIfAbsent(challengeKey, claim)
        if (existing != null && existing.peerAddress == peerAddress) {
            return Decision.Duplicate
        }

        if (isReplay(challenge, timestampUnixSeconds)) {
            // Nothing is in flight for this arrival, so drop the claim we just installed (if it was
            // ours) and let a later legitimate request be treated as a first arrival again.
            if (existing == null) {
                inFlight.remove(challengeKey, claim)
            }
            return Decision.Replay
        }

        return Decision.Process
    }

    /**
     * Forget [challenge] because the Client abandoned it: a verified `AuthenticationCancel` from
     * the peer, or the daemon's cancel of that challenge.
     *
     * Only the abandonment paths call this. A grant, denial or timeout leaves the claim in place on
     * purpose (see the class documentation): the Client's retransmissions of the concluded request
     * must stay silent duplicates instead of tripping the replay cache.
     */
    fun conclude(challenge: ByteArray) {
        inFlight.remove(challenge.toHex())
    }

    /**
     * Forget everything in flight for [peerAddress], whose link is gone for good.
     *
     * Called at the end of the reconnection grace that `BleGattService` starts when a link drops,
     * and only if the device did not come back: until then the claim has to survive, because the
     * reconnect that carries the Client's retransmission of the same request arrives as a duplicate
     * from the same peer. Once the grace has passed the request is treated as concluded — the same
     * destination a grant, denial or timeout eventually reaches — so no claim outlives its link.
     */
    fun concludePeer(peerAddress: String) {
        inFlight.entries.removeIf { it.value.peerAddress == peerAddress }
    }

    /** Forget every entry; the service is going away. */
    fun clear() {
        inFlight.clear()
    }

    /**
     * Drop entries that outlived any plausible prompt.
     *
     * A link that never reports its disconnect leaves its entry behind; the TTL bounds that leak
     * and is far longer than the longest session timeout, so a live prompt is never pruned.
     */
    private fun pruneExpired() {
        val cutoff = elapsedMillis() - IN_FLIGHT_MAX_AGE_MS
        inFlight.entries.removeIf { it.value.startedAtMillis < cutoff }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        /** Longer than any prompt lifetime (default session timeout is 120 s). */
        private const val IN_FLIGHT_MAX_AGE_MS = 600_000L
    }
}
