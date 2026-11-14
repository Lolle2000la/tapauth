package dev.rourunisen.tapauth.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The release side of a pairing: `PairingSession.close()` delegates here, because the decision it
 * makes cannot be tested through the session itself (an Android `Context`, a live transport and the
 * generated UniFFI object are all required).
 *
 * What is asserted is the pair of facts the ViewModel depends on: the returned Boolean, which
 * `PairingViewModel.releaseSession()` uses to decide whether to cancel the attempt scope, and
 * whether the release (the injected `onRelease`) ran at all.
 */
class PairingSessionReleaseTest {

    /** The release body: in production, cancel the job, close the links and zeroize the keys. */
    private class Releases {
        var count = 0

        fun run() {
            count += 1
        }
    }

    /**
     * A close that arrives once the commit has begun is deferred: it answers "true" — the
     * confirmation is still in flight — and does not release anything.
     *
     * The defect this catches, and the one this test exists for: `close()` rewritten to
     * `PairingSessionRelease(latch) { … }` with the answer ignored, e.g. `{ latch.requestClose();
     * false }` or `{ onRelease(); false }`. Either cancels the coroutine (and closes the socket)
     * between the persist and the `PairingConfirmServer` burst, so the phone is paired and the
     * desktop times out.
     */
    @Test
    fun aCloseAfterTheCommitIsDeferredAndReleasesNothing() {
        val latch = PairingCommitLatch()
        val releases = Releases()
        val release = PairingSessionRelease(latch) { releases.run() }
        assertTrue("The commit must be allowed to begin", latch.beginCommit())

        assertTrue("The close must report the deferral", release.requestClose())
        assertEquals("A deferred close must not release", 0, releases.count)

        assertTrue("A repeated close must still report the deferral", release.requestClose())
        assertEquals("A deferred close must never release", 0, releases.count)
    }

    /**
     * A close that wins the boundary releases immediately, and only once however often it is asked:
     * the job cancellation, the link close and the key zeroization are a single event.
     *
     * The defect this catches: a release that runs on every close call, so a second
     * `DisposableEffect`/back press reaches into a session that has already been torn down, and the
     * Boolean stopping reflecting what happened.
     */
    @Test
    fun aCloseWithoutACommitReleasesExactlyOnce() {
        val latch = PairingCommitLatch()
        val releases = Releases()
        val release = PairingSessionRelease(latch) { releases.run() }

        assertFalse("The close may release now", release.requestClose())
        assertEquals("The release must run", 1, releases.count)

        assertFalse("A repeated close still reports a release", release.requestClose())
        assertEquals("The release must not run twice", 1, releases.count)
    }

    /**
     * The deferral is the latch's answer, not a value the release can drift from: after a deferred
     * close, a commit still going and then completing leaves every further close deferred, and a
     * close that wins first refuses the commit afterwards.
     *
     * The defect this catches: a release that answers from its own bookkeeping instead of asking
     * the latch — returning "true" because it once deferred, or "false" because it once released —
     * which is how a dereferenced scope or a cancelled confirmation gets through.
     */
    @Test
    fun theAnswerTracksTheLatchInBothDirections() {
        val committedLatch = PairingCommitLatch()
        val committedReleases = Releases()
        val committed = PairingSessionRelease(committedLatch) { committedReleases.run() }
        committedLatch.beginCommit()

        repeat(3) { assertTrue("Close #$it must stay deferred", committed.requestClose()) }
        assertEquals(0, committedReleases.count)

        val closedLatch = PairingCommitLatch()
        val closedReleases = Releases()
        val closed = PairingSessionRelease(closedLatch) { closedReleases.run() }

        repeat(3) { assertFalse("Close #$it must report a release", closed.requestClose()) }
        assertEquals("The release must run exactly once", 1, closedReleases.count)
        assertFalse("The commit must stay refused", closedLatch.beginCommit())
    }
}
