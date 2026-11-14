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
 * the confirmation, or a close wins and nothing is persisted at all. Never both.
 *
 * The two transitions are exercised here directly — this class needs no transport, no Android
 * `Context` and no coroutines — and again in [PairingConfirmPhaseTest] through the code that ships.
 */
class PairingCommitLatchTest {

    /**
     * The commit comes first, so the session must keep running: the close reports "deferred" and
     * keeps doing so, however often it is asked.
     *
     * The defect this catches: a close that releases anyway when it arrives after the commit — the
     * phone persists the device and cancels the confirmation that would have told the desktop.
     */
    @Test
    fun aCloseAfterTheCommitIsDeferredEveryTime() {
        val latch = PairingCommitLatch()

        assertTrue("The commit must be allowed to begin", latch.beginCommit())
        assertTrue("The close must be deferred", latch.requestClose())
        assertTrue("A repeated close must still be deferred", latch.requestClose())
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
        assertTrue(latch.requestClose())

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

        assertFalse("The close may release immediately", latch.requestClose())
        assertFalse("The commit must be refused", latch.beginCommit())
        assertFalse("A repeated close may still release", latch.requestClose())
        assertFalse("The refusal must not be undone", latch.beginCommit())
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

                fun racer(transition: () -> Boolean) =
                    Callable<Boolean> {
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
                // `requestClose()` answering false means the close released immediately, i.e. it
                // won
                // the boundary; answering true means the commit had already won.
                val closeWon = !closeDeferred

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
