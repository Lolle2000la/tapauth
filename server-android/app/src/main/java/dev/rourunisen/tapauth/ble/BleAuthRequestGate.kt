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
 * has to be re-examined yet. An entry is concluded when the Client abandons the challenge
 * ([conclude] — a verified `AuthenticationCancel` from the peer, or the daemon's own cancel of that
 * challenge), when the service stops ([clear]), and — for a link that never reports its teardown —
 * once it is older than [IN_FLIGHT_MAX_AGE_MS]. The disconnect grace does *not* conclude an entry:
 * it releases the peer's claims for a retry ([releaseForRetry], driven by the grace timer
 * `BleGattService` starts on `STATE_DISCONNECTED` — deliberately *not* by the disconnect itself).
 *
 * A disconnect is therefore not a release either: the Client reconnects to deliver the request it
 * is still retransmitting, and that reconnect presents the same challenge from the same peer on a
 * new GATT handle. With the claim held that arrival is a [Decision.Duplicate] and the prompt the
 * user is answering survives; concluding it on the disconnect would send the arrival to the replay
 * cache, which reports the retransmitted challenge as a replay and tears the new link down.
 *
 * There are two flavours of that duplicate, and the `releasedForRetry` mark separates them. A claim
 * the grace has not released answers a repeat silently while its prompt is open, or re-delivers the
 * answer already held for it when the Client lost the link the answer was written to. A claim
 * released at a past grace expiry has no prompt left to answer, so the service answers its repeat
 * with a fresh prompt instead ([retryStarted] consumes the mark, so exactly one retry follows each
 * release) — in both cases without the replay cache ever being consulted.
 *
 * The release covers a claim whose prompt was *answered* too, because "answered" would only ever
 * mean the grant or denial was built: the bytes can be recorded for an answer the user gave while
 * the link was down and then fail to write on the handle that was already dead. A Client that
 * retransmits after the grace is a Client that did not get the verdict, so its challenge is
 * released for a retry like an unanswered one, and the completed approval is not thrown away on top
 * of what would otherwise be a permanent outage. Nothing but [conclude], [clear] and
 * [IN_FLIGHT_MAX_AGE_MS] concludes a challenge.
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
 *    replay cache, which is the whole point: its answer for those bytes is "replay". What the
 *    service does with it is [BleDisconnectGrace]'s question — a re-delivery when an answer is
 *    held, silence while the prompt is open, or a fresh prompt when the claim was released for a
 *    retry.
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

        /**
         * Same peer, same challenge, still in flight: the service answers it — a re-delivery or a
         * fresh prompt — and the replay cache is never asked.
         */
        data object Duplicate : Decision()

        /** The replay cache rejected the request: reject and disconnect exactly as before. */
        data object Replay : Decision()

        /** First arrival for this challenge from this peer: process it. */
        data object Process : Decision()
    }

    private class InFlight(val peerAddress: String, val startedAtMillis: Long) {

        /**
         * The disconnect grace released this claim for a retry. The claim stays, so the challenge
         * never reaches the replay cache; the flag only says the prompt behind it is gone and the
         * next arrival has to raise a new one.
         */
        @Volatile var releasedForRetry: Boolean = false
    }

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
     * Handle the end of the disconnect grace for [peerAddress], whose link is gone.
     *
     * Every claim that peer holds is marked released for a retry, and none is removed — including
     * one whose prompt the user already answered. An answer being *built* is not the Client
     * receiving it: the write fails on the handle the link died under, so the verdict can be lost
     * while the claim looks concluded. A Client that retransmits after the grace is a Client that
     * did not get the verdict, so its challenge has to stay away from the replay cache — whose
     * "replay" answer disconnects the fresh link — and the arriving copy raises a fresh prompt
     * instead. The reconnect is scan-driven and routinely outlasts this grace ([BleDisconnectGrace]
     * documents the bound).
     *
     * Only a verified `AuthenticationCancel` (and the daemon's own cancel) concludes a challenge
     * outright ([conclude]).
     */
    fun releaseForRetry(peerAddress: String) {
        inFlight.forEach { (_, entry) ->
            if (entry.peerAddress == peerAddress) entry.releasedForRetry = true
        }
    }

    /** Whether [challenge]'s claim was released for a retry, i.e. its next arrival re-prompts. */
    fun wasReleasedForRetry(challenge: ByteArray): Boolean =
        inFlight[challenge.toHex()]?.releasedForRetry ?: false

    /**
     * Consume [challenge]'s released mark: the retry it announced is being raised now, so exactly
     * one fresh prompt follows each release.
     */
    fun retryStarted(challenge: ByteArray) {
        inFlight[challenge.toHex()]?.releasedForRetry = false
    }

    /**
     * Whether any challenge is still claimed for [peerAddress]; the disconnect grace's `claimHeld`
     * input.
     */
    fun holdsClaimFor(peerAddress: String): Boolean =
        inFlight.values.any { it.peerAddress == peerAddress }

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
