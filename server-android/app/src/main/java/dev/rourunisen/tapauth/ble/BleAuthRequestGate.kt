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
 * challenge), when its GATT link goes away ([concludePeer], driven by `STATE_DISCONNECTED`), when
 * the service stops ([clear]), and — for a link that never reports its teardown — once it is older
 * than [IN_FLIGHT_MAX_AGE_MS].
 *
 * A concluded challenge is deliberately *not* released at the moment the grant, denial or timeout
 * is sent, and [BleGattService]'s `releaseLock` call sites say so. The Client keeps retransmitting
 * the same request until it has the answer, and those retransmissions arrive while the link is
 * still up; if the claim were dropped there, they would fall through to the replay cache, which has
 * already recorded this challenge and answers "replay", and the link would be torn down — exactly
 * the symptom this gate exists to remove. Holding the claim instead makes such a retransmission a
 * silent [Verdict.DUPLICATE_IN_FLIGHT]. Nothing legitimate is swallowed by that: a new
 * authentication always carries a new challenge, and a different peer replaying the captured bytes
 * still falls through to the replay check.
 */
internal class BleAuthRequestGate(
    private val isReplay: (challenge: ByteArray, timestampUnixSeconds: Long) -> Boolean,
    private val elapsedMillis: () -> Long,
) {

    enum class Verdict {
        /** First arrival for this challenge from this peer: process it. */
        PROCESS,

        /** Same peer, same challenge, still in flight: ignore without touching the replay cache. */
        DUPLICATE_IN_FLIGHT,

        /** The replay cache rejected the request: reject and disconnect exactly as before. */
        REPLAY,
    }

    private class InFlight(val peerAddress: String, val startedAtMillis: Long)

    private val inFlight = ConcurrentHashMap<String, InFlight>()

    /** Number of challenges currently held as in flight (tests and diagnostics). */
    val inFlightCount: Int
        get() = inFlight.size

    fun evaluate(
        challenge: ByteArray,
        timestampUnixSeconds: Long,
        peerAddress: String,
    ): Verdict {
        val challengeKey = challenge.toHex()
        pruneExpired()

        // Claim the challenge BEFORE the replay check so two arrivals that race each other cannot
        // both pass it: exactly one wins putIfAbsent and the other is a duplicate. A different
        // peer leaves the owner's entry untouched and falls through to the replay check below.
        val claim = InFlight(peerAddress, elapsedMillis())
        val existing = inFlight.putIfAbsent(challengeKey, claim)
        if (existing != null && existing.peerAddress == peerAddress) {
            return Verdict.DUPLICATE_IN_FLIGHT
        }

        if (isReplay(challenge, timestampUnixSeconds)) {
            // Nothing is in flight for this arrival, so drop the claim we just installed (if it was
            // ours) and let a later legitimate request be treated as a first arrival again.
            if (existing == null) {
                inFlight.remove(challengeKey, claim)
            }
            return Verdict.REPLAY
        }

        return Verdict.PROCESS
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

    /** Forget everything in flight for [peerAddress], whose GATT link is gone. */
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
