package dev.rourunisen.tapauth.network

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The commit/close boundary: either the device record begins to be written and a close defers to
 * the confirmation, or a close wins and nothing is persisted at all. Never both — and once the
 * confirmation has completed, a close releases again instead of deferring forever.
 *
 * The transitions are exercised here directly — this class needs no transport, no Android `Context`
 * and no coroutines — and again in [PairingConfirmPhaseTest] and [PairingSessionLifecycleTest]
 * through the code that ships.
 */
class PairingCommitLatchTest {

    /**
     * The commit comes first, so the session must keep running: for as long as the confirmation is
     * in flight the close reports "deferred" and keeps doing so, however often it is asked.
     *
     * The defect this catches: a close that releases anyway when it arrives after the commit — the
     * phone persists the device and cancels the confirmation that would have told the desktop.
     */
    @Test
    fun aCloseAfterTheCommitIsDeferredEveryTime() {
        val latch = PairingCommitLatch()

        assertTrue("The commit must be allowed to begin", latch.beginCommit())
        assertEquals("The close must be deferred", CloseOutcome.Deferred, latch.requestClose())
        assertEquals(
            "A repeated close must still be deferred",
            CloseOutcome.Deferred,
            latch.requestClose(),
        )
    }

    /**
     * A close that is deferred does not undo the commit: the boundary stays on the commit side, so
     * the confirmation that follows the persist may run, and nothing about the deferred close turns
     * into "the close won".
     *
     * The defect this catches: a deferred close that also records itself as the winner, which would
     * make the next `beginCommit()` refuse and strand a persisted device with no confirmation.
     */
    @Test
    fun aDeferredCloseDoesNotFlipTheBoundaryToTheCloseSide() {
        val latch = PairingCommitLatch()

        assertTrue(latch.beginCommit())
        assertEquals(
            "The close must be deferred",
            CloseOutcome.Deferred,
            latch.requestClose(),
        )

        assertTrue(
            "The close was deferred, so the commit side must still hold",
            latch.beginCommit(),
        )
    }

    /**
     * The close comes first, so nothing may follow it: the commit is refused and the device is
     * never written.
     *
     * The defect this catches: a `beginCommit()` that only records intent instead of consulting the
     * close, so a released session still persists a device the desktop will never hear about.
     */
    @Test
    fun aCommitAfterTheCloseIsRefused() {
        val latch = PairingCommitLatch()

        assertEquals(
            "The close may release immediately",
            CloseOutcome.Released,
            latch.requestClose(),
        )
        assertFalse("The commit must be refused", latch.beginCommit())
        assertEquals(
            "A repeated close may still release",
            CloseOutcome.Released,
            latch.requestClose(),
        )
        assertFalse("The refusal must not be undone", latch.beginCommit())
    }

    /**
     * A close that arrives once the confirmation has completed releases like any other: there is no
     * persist left to protect, so answering "deferred" would leave the session (its coroutine, its
     * socket, its key entry) with no release path at all — the ViewModel has already dropped the
     * attempt scope by then.
     *
     * The defect this catches: a `Committed` that is permanent. `completeCommit()` without the
     * release transition, or a `requestClose()` with no `Completed` case, keeps answering
     * "deferred" for the rest of the session's life, including after the linger finished and the
     * keys were zeroized.
     */
    @Test
    fun aCloseAfterTheCompletionReleasesInsteadOfDeferring() {
        val latch = PairingCommitLatch()

        assertTrue("The commit must be allowed to begin", latch.beginCommit())
        assertEquals(
            "A close during the confirmation must defer",
            CloseOutcome.Deferred,
            latch.requestClose(),
        )

        latch.completeCommit()

        assertEquals(
            "A close after the completion must release",
            CloseOutcome.Released,
            latch.requestClose(),
        )
        assertEquals(
            "A repeated close still reports the release",
            CloseOutcome.Released,
            latch.requestClose(),
        )
        assertFalse(
            "The close that released also refuses a later commit",
            latch.beginCommit(),
        )
    }

    /**
     * Completing a commit that never began changes nothing: the close side is still Open, so the
     * close wins and a later commit is refused.
     *
     * The defect this catches: a `completeCommit()` that moves `Open` to `Completed`, which would
     * make a session that never reached the confirmation refuse its own release.
     */
    @Test
    fun aCompletionWithoutACommitLeavesTheCloseSideIntact() {
        val latch = PairingCommitLatch()

        latch.completeCommit()

        assertEquals("The close must release", CloseOutcome.Released, latch.requestClose())
        assertFalse("The commit must stay refused", latch.beginCommit())
    }

    /**
     * Two threads race the boundary `ROUNDS` times, and every round has exactly one winner: either
     * the commit began (and the close is deferred) or the close won (and the commit is refused).
     * "Persisted **and** cancelled" is unreachable.
     *
     * The threads are held in a spin loop until both are running and only then released, because a
     * blocking gate (`CyclicBarrier`, a `CountDownLatch`) wakes the second thread microseconds late
     * — enough for the first to finish the whole transition, which serialises the race instead of
     * running it. Overlapping transitions are the only way the missing mutual exclusion shows, so
     * without the spin this test would pass against a check-then-act latch.
     *
     * The defect this catches: check-then-act — reading the state and acting on it without one lock
     * covering both, so each transition sees "the other has not happened yet" and both proceed. The
     * device is then written and the coroutine that would confirm it is cancelled.
     */
    @Test
    fun theTwoTransitionsAreMutuallyExclusiveUnderContention() {
        val pool = Executors.newFixedThreadPool(2)
        try {
            repeat(ROUNDS) { round ->
                val latch = PairingCommitLatch()
                val go = AtomicBoolean(false)
                val arrived = AtomicInteger(0)

                fun <T> racer(transition: () -> T) =
                    Callable<T> {
                        arrived.incrementAndGet()
                        // Both racers spin on the same flag, so they leave it together on-CPU.
                        while (!go.get()) {}
                        transition()
                    }

                val commit = pool.submit(racer { latch.beginCommit() })
                val close = pool.submit(racer { latch.requestClose() })
                while (arrived.get() < 2) {}
                go.set(true)

                val commitBegun = commit.get(TIMEOUT_S, TimeUnit.SECONDS)
                val closeDeferred = close.get(TIMEOUT_S, TimeUnit.SECONDS)
                // `requestClose()` answering `Released` means the close released immediately, i.e.
                // it won the boundary; `Deferred` means the commit had already won.
                val closeWon = closeDeferred == CloseOutcome.Released

                assertTrue(
                    "Round $round resolved to two winners: commitBegun=$commitBegun, " +
                        "closeWon=$closeWon",
                    commitBegun != closeWon,
                )
                assertEquals(
                    "Round $round must resolve to exactly one winner",
                    1,
                    (if (commitBegun) 1 else 0) + (if (closeWon) 1 else 0),
                )
            }
        } finally {
            pool.shutdownNow()
        }
    }

    private companion object {
        /** Enough rounds to overlap the two transitions, few enough to stay a unit test. */
        const val ROUNDS = 2_000

        const val TIMEOUT_S = 5L
    }
}
