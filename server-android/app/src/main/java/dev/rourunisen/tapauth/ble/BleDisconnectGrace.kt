package dev.rourunisen.tapauth.ble

/**
 * Decides what the disconnect grace and a duplicate-in-flight arrival mean, so [BleGattService]
 * performs one effect per outcome and decides nothing itself.
 *
 * ### Why the grace is a prompt bound and not a reconnect bound
 *
 * The grace started on `STATE_DISCONNECTED` is the bound on how long an unanswered prompt and this
 * transport's claim on its challenge are kept once the link is dead. It is *not* a bound on the
 * reconnect, and it cannot be one: the Phone is the BLE central, so it only reconnects when its
 * `SCAN_MODE_LOW_POWER` scan next reports the Client's advertisement — a 512 ms window every 5 s,
 * so up to ~4.5 s before the advertisement is even seen, plus the `PendingIntent` hop into the
 * foreground service, then connect, service discovery, MTU negotiation, the CCCD writes and the
 * initial characteristic read. A reconnect therefore routinely takes longer than the grace, and no
 * constant can promise otherwise while the discovery of the peer is a scan's business.
 *
 * So the expiry may drop the *prompt* — nothing is left on this transport to answer — but it must
 * not conclude the challenge. [Outcome.Retry] is what makes the difference: a claim released for a
 * retry is still held by [BleAuthRequestGate], marked `releasedForRetry`, so the retransmission
 * that arrives on the reconnected link is still a duplicate in flight and raises a fresh prompt.
 * That covers a claim whose prompt was answered as much as one that never was: the answer only
 * being *built* says nothing about the Client receiving it, and a Client that retransmits is a
 * Client that did not get the verdict. Concluding it instead (which is what releasing it used to
 * mean) sends that same arrival to the replay cache, which answers "replay", and the Phone
 * disconnects the link it just rebuilt — then rescans, reconnects and is rejected again for the
 * rest of the desktop's 120 s window. That is a permanent outage, with a completed approval thrown
 * away on top of it; [Outcome.Retry] turns it into a recoverable retry.
 *
 * ### [onGraceExpired], first match wins
 *
 * 1. [Outcome.NothingHeld] — no claim is held for the peer, so there is nothing to release and no
 *    prompt to cancel. The grace also fires for a link that dropped before any request was
 *    admitted, which is most of them.
 * 2. [Outcome.KeepWaiting] — the peer reconnected. A live link keeps its claim: releasing a
 *    reconnected peer's claim is the original bug, because its next retransmission would then be
 *    answered as a replay and the fresh link torn down. This rung is checked *before* the elapsed
 *    time on purpose: once the grace has passed, an elapsed check first would release a peer that
 *    is demonstrably connected right now.
 * 3. [Outcome.KeepWaiting] — no drop was ever recorded for the claim, so no grace can be measured
 *    and releasing would be a release nobody asked for.
 * 4. [Outcome.KeepWaiting] — the grace has not elapsed yet: a live claim is never dropped early.
 * 5. [Outcome.ReleaseAndCancel] — the link is down and the grace is over: cancel the prompt and
 *    release the claim for a retry, whatever its answer state (see the class documentation).
 *
 * ### [onDuplicate], first match wins
 *
 * 1. [Outcome.NothingHeld] — no claim, so this arrival is not this gate's to answer.
 * 2. [Outcome.Retry] — the claim was released for a retry at a past grace expiry and no answer is
 *    held for it: the prompt behind the claim is gone, so this is a fresh attempt and not a replay
 *    of a concluded challenge. It raises a new prompt (the caller also clears the released mark, so
 *    exactly one retry follows each release).
 * 3. [Outcome.AnswerOnLiveHandle] — an answer (grant or denial) was built and sent: the bytes go to
 *    whoever reconnected, which is what lets the Client collect the verdict on its new link.
 * 4. [Outcome.KeepWaiting] — the prompt is still open on the link that is up; the copy is ignored
 *    without creating a second prompt.
 */
internal class BleDisconnectGrace(
    private val graceMillis: Long,
    private val elapsedMillis: () -> Long,
) {

    /**
     * What the service knows about the peer when the grace expires: whether it still holds a claim
     * on that peer's challenge, when that peer's link dropped, and whether a link exists again.
     */
    data class LinkFacts(
        val claimHeld: Boolean,
        /** Clock reading taken when the peer's link dropped; null when none was ever seen. */
        val disconnectedAtMillis: Long?,
        /** A live GATT link to the peer exists now. */
        val reconnected: Boolean,
    )

    /**
     * What the service knows about the challenge when a duplicate-in-flight arrival of it comes in.
     */
    data class ArrivalFacts(
        val claimHeld: Boolean,
        /** An answer (grant or denial) is held for this challenge. */
        val promptAnswered: Boolean,
        /** The gate released this claim for a retry at a past grace expiry. */
        val releasedForRetry: Boolean,
    )

    /** What the caller does for one question. Exactly one of these is returned. */
    sealed class Outcome {
        /** No claim is held for the peer or the challenge: no effect. */
        data object NothingHeld : Outcome()

        /** The claim (and any open prompt) stays as it is: no effect. */
        data object KeepWaiting : Outcome()

        /** Re-deliver the answer already built on the handle the Client reconnected on. */
        data object AnswerOnLiveHandle : Outcome()

        /**
         * Release the claim for a retry and cancel the prompt: the link is gone for good, and the
         * claim is not concluded — whatever its answer state, because an answer that was built may
         * never have reached the Client.
         */
        data object ReleaseAndCancel : Outcome()

        /** Raise a fresh prompt: the prompt behind the claim is gone and this is a retry. */
        data object Retry : Outcome()
    }

    /** See the class documentation for the rules and their order. */
    fun onGraceExpired(facts: LinkFacts): Outcome {
        if (!facts.claimHeld) return Outcome.NothingHeld
        if (facts.reconnected) return Outcome.KeepWaiting
        val disconnectedAtMillis = facts.disconnectedAtMillis ?: return Outcome.KeepWaiting
        if (elapsedMillis() - disconnectedAtMillis < graceMillis) return Outcome.KeepWaiting
        return Outcome.ReleaseAndCancel
    }

    /** See the class documentation for the rules and their order. */
    fun onDuplicate(facts: ArrivalFacts): Outcome {
        if (!facts.claimHeld) return Outcome.NothingHeld
        if (facts.releasedForRetry && !facts.promptAnswered) return Outcome.Retry
        if (facts.promptAnswered) return Outcome.AnswerOnLiveHandle
        return Outcome.KeepWaiting
    }
}
