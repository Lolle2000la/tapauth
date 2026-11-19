package dev.rourunisen.tapauth.ble

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The two decisions [BleGattService] asks [BleDisconnectGrace] for: what the end of the disconnect
 * grace means for a peer that dropped ([onGraceExpired]), and what a duplicate-in-flight arrival of
 * a challenge means for the prompt behind it ([onDuplicate]).
 *
 * The clock is a fixed reading the test advances, so "the grace has elapsed" is a property of the
 * readings passed in and not of the speed of the machine.
 */
class BleDisconnectGraceTest {

    private var nowMillis = 1_000_000L

    private val graceMillis = 5_000L
    private val grace = BleDisconnectGrace(graceMillis) { nowMillis }

    private fun linkFacts(
        claimHeld: Boolean = true,
        droppedAt: Long? = nowMillis,
        reconnected: Boolean = false,
    ) =
        BleDisconnectGrace.LinkFacts(
            claimHeld = claimHeld,
            disconnectedAtMillis = droppedAt,
            reconnected = reconnected,
        )

    private fun arrivalFacts(
        claimHeld: Boolean = true,
        promptAnswered: Boolean = false,
        releasedForRetry: Boolean = false,
    ) =
        BleDisconnectGrace.ArrivalFacts(
            claimHeld = claimHeld,
            promptAnswered = promptAnswered,
            releasedForRetry = releasedForRetry,
        )

    @Test
    fun aReconnectInsideTheGraceIsNeverReleased() {
        val droppedAt = nowMillis
        nowMillis += graceMillis - 1

        assertEquals(
            BleDisconnectGrace.Outcome.KeepWaiting,
            grace.onGraceExpired(linkFacts(droppedAt = droppedAt, reconnected = true)),
        )
    }

    /**
     * The elapsed check must come after the reconnect check: with the two swapped, a peer whose
     * grace has run out is released even though a live link to it exists right now, and its next
     * retransmission is answered as a replay — the original bug, one rung higher.
     */
    @Test
    fun aReconnectAfterTheGraceIsStillNeverReleased() {
        val droppedAt = nowMillis
        nowMillis += graceMillis * 3

        assertEquals(
            BleDisconnectGrace.Outcome.KeepWaiting,
            grace.onGraceExpired(linkFacts(droppedAt = droppedAt, reconnected = true)),
        )
    }

    @Test
    fun aLiveClaimIsNeverDroppedEarlyAndIsReleasedExactlyAtTheGrace() {
        val droppedAt = nowMillis

        // One millisecond short of the grace: the prompt is still worth waiting for.
        nowMillis = droppedAt + graceMillis - 1
        assertEquals(
            BleDisconnectGrace.Outcome.KeepWaiting,
            grace.onGraceExpired(linkFacts(droppedAt = droppedAt)),
        )

        // The boundary itself is the expiry, not one millisecond later.
        nowMillis = droppedAt + graceMillis
        assertEquals(
            BleDisconnectGrace.Outcome.ReleaseAndCancel,
            grace.onGraceExpired(linkFacts(droppedAt = droppedAt)),
        )
    }

    @Test
    fun nothingIsHeldSoNothingIsReleased() {
        nowMillis += graceMillis * 10

        assertEquals(
            BleDisconnectGrace.Outcome.NothingHeld,
            grace.onGraceExpired(linkFacts(claimHeld = false)),
        )
        // Nor is a prompt retried or an answer re-delivered for a challenge the gate does not hold.
        assertEquals(
            BleDisconnectGrace.Outcome.NothingHeld,
            grace.onDuplicate(arrivalFacts(claimHeld = false)),
        )
    }

    @Test
    fun aGraceThatWasNeverMeasuredNeverReleases() {
        nowMillis += graceMillis * 10

        // No drop reading was ever taken for this claim, so no grace can have elapsed on it.
        assertEquals(
            BleDisconnectGrace.Outcome.KeepWaiting,
            grace.onGraceExpired(linkFacts(droppedAt = null)),
        )
    }

    /**
     * The defect this replaces: the release used to conclude the challenge, so the retransmission
     * that arrives after a scan-driven reconnect (which routinely outlasts the grace) was handed to
     * the replay cache, called a replay, and the link was torn down — permanently, for the rest of
     * the Desktop's window. A released prompt has to be re-offered instead.
     */
    @Test
    fun aReleasedUnansweredClaimIsRetriedNotSwallowed() {
        assertEquals(
            BleDisconnectGrace.Outcome.Retry,
            grace.onDuplicate(arrivalFacts(promptAnswered = false, releasedForRetry = true)),
        )
    }

    @Test
    fun aReleasedClaimWithAHeldAnswerIsRedeliveredInsteadOfPromptedAgain() {
        // The user answered after the grace dropped the prompt: the bytes exist, so re-prompting
        // would ask a second time for a verdict that is already on the wire.
        assertEquals(
            BleDisconnectGrace.Outcome.AnswerOnLiveHandle,
            grace.onDuplicate(arrivalFacts(promptAnswered = true, releasedForRetry = true)),
        )
    }

    @Test
    fun anOpenPromptIsNeverRaisedTwice() {
        // The prompt is still on screen and nothing was released: the copy of the challenge is a
        // duplicate of what the user is already looking at.
        assertEquals(
            BleDisconnectGrace.Outcome.KeepWaiting,
            grace.onDuplicate(arrivalFacts(promptAnswered = false, releasedForRetry = false)),
        )
    }

    @Test
    fun anAnsweredPromptFromATransportThatNeverSawTheDropIsRedelivered() {
        // No release happened at all (the link never dropped, or the grace has not expired), yet
        // the copy arrived on another handle: the answer built on the first one has to travel.
        assertEquals(
            BleDisconnectGrace.Outcome.AnswerOnLiveHandle,
            grace.onDuplicate(arrivalFacts(promptAnswered = true, releasedForRetry = false)),
        )
    }
}
