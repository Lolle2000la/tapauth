package dev.rourunisen.tapauth.network

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A pairing coroutine cancelled while the confirmation lingers.
 *
 * The claim this pins is the one the whole commit window rests on: *the latch is always released
 * and the session keys are always concluded*. Both live in `finally` bodies — `completeCommit()` in
 * [PairingSessionLifecycle.finish] and `crypto.conclude()` in [PairingConfirmPhase.finish] — and
 * neither is followed by a `NonCancellable` block anywhere, so the claim holds exactly as long as
 * those bodies stay non-suspending. Nothing else in the suite cancels a confirmation in flight:
 * `PairingSessionLifecycleTest` covers a confirmation that *throws*, which is a different unwind
 * path (an exception leaves the coroutine running, so a suspending `finally` would still complete;
 * a cancellation does not).
 *
 * Cancellation mid-linger is the production case: `PairingSession.close()` cannot cut a `Committed`
 * confirmation, but the attempt scope that owns [PairingSession.runSession] can still be cancelled
 * — a destroyed ViewModel, a process teardown, a scope cancelled by the caller — and the
 * confirmation is then parked in `receive` inside the 1.25 s window with the device already
 * persisted. What must survive is the state the *next* close reads: a latch left `Committed` would
 * answer a later close "deferred" forever and never release the transports, and an unconcluded
 * session leaves the ephemeral keys to the Rust `Drop` backstop alone.
 *
 * The window is driven by the transport double rather than by virtual time, because
 * `kotlinx-coroutines-test` is not a test dependency of this module: the fake link hands the linger
 * a read that never returns, so the phase is provably parked *inside* it (the read it was given is
 * recorded) and the test cancels from there. No wall-clock sleep, and the linger's own deadline —
 * [PairingCompletion.DEFAULT_LINGER_MS], the production value — is never reached.
 */
class PairingConfirmationCancellationTest {

    /**
     * The locked transport, held mid-linger.
     *
     * [send] records the burst; [receive] records the slice it was handed, then parks on [never] —
     * which the test never completes. That park is the cancellation point, and it is also the
     * assertion that the cancellation landed inside the linger: the only way [receive] is reached
     * is after the burst has gone out, and the only way it returns is cancellation.
     */
    private class HeldLink(
        private val parked: CompletableDeferred<Unit>,
        private val never: CompletableDeferred<ByteArray?>,
    ) : PairingLink {
        /** Every frame written, by reference. */
        val sends = mutableListOf<ByteArray>()

        /** The timeout of every read the phase asked for, in order. */
        val reads = mutableListOf<Long>()

        var closed = false

        override suspend fun send(packet: ByteArray): Boolean {
            sends += packet
            return true
        }

        override suspend fun receive(timeoutMs: Long): ByteArray? {
            reads += timeoutMs
            parked.complete(Unit)
            return never.await()
        }

        override fun close() {
            closed = true
        }
    }

    /**
     * Stands in for the Rust session: it *records* the conclusion instead of faking it away, so a
     * confirmation that never concludes is visible as a zero count.
     */
    private class RecordingCrypto : PairingConfirmationCrypto {
        var buildCount = 0

        /** How many times the session was concluded — the value the `finally` exists to make 1. */
        var concludeCount = 0

        override fun createConfirmServer(csk: ByteArray): ByteArray {
            buildCount++
            return CONFIRMATION
        }

        override fun processConfirmClient(packet: ByteArray): ByteArray? = null

        override fun conclude() {
            concludeCount++
        }
    }

    /**
     * A close arrives while the `PairingConfirmServer` burst is out and the linger is still
     * answering: the coroutine is cancelled in `receive`, and both `finally` bodies must still run
     * — the session is concluded exactly once, and the latch has left `Committed` so the close that
     * follows *releases* instead of deferring to a confirmation that no longer exists.
     *
     * Read of the latch: the assertion is behavioural, not a getter. Persisting once proves
     * `beginCommit()` returned true (`PairingConfirmPhase.finish` persists only after it), which is
     * the only transition into `Committed`; nothing asked for a close before the cancelled
     * confirmation ended (the release body has not run and `isClosed()` is still false), so
     * `RequestClose` could only have been answered from `Completed` — `Closed` and `Open` are both
     * unreachable at that point. `Deferred` is what a latch stuck in `Committed` answers, and that
     * is the defect: the transports and the key entry would have no release path left.
     *
     * Nothing may suspend between the point of cancellation and those two statements either — that
     * is the property under test, so the test states no timing at all: it parks the phase, cancels
     * the job and joins it.
     */
    @Test
    fun aCancellationMidLingerStillConcludesTheSessionAndEndsTheDeferral() = runBlocking {
        val crypto = RecordingCrypto()
        val parked = CompletableDeferred<Unit>()
        val never = CompletableDeferred<ByteArray?>()
        val link = HeldLink(parked, never)
        var closes = 0
        var zeroizes = 0
        val lifecycle =
            PairingSessionLifecycle(
                // `PairingSession`'s own release body: cancel the coroutine, close the transports.
                onClose = {
                    closes += 1
                    link.close()
                },
                zeroize = { zeroizes += 1 },
            )
        // Production wiring: the same slice the session's own reader uses (RECEIVE_SLICE_MS), the
        // production linger, and a clock that never advances — the linger's deadline is never
        // reached, so the only thing that can end the confirmation is the cancellation.
        val phase =
            PairingConfirmPhase(
                crypto = crypto,
                frameReader = PairingFrameReader(sliceMs = SLICE_MS, nowMs = { 0L }),
                completion =
                    PairingCompletion(
                        lingerMs = PairingCompletion.DEFAULT_LINGER_MS,
                        nowMs = { 0L },
                        sliceMs = SLICE_MS,
                    ),
                belongsToSession = { true },
            )
        var persists = 0

        val job = launch {
            lifecycle.finish(phase, link, CSK, burstDelaysMs = listOf(0L)) {
                persists += 1
                DEVICE
            }
        }

        // The phase is now parked inside the linger: the burst is out, the device is persisted and
        // the session has not been concluded, because concluding waits for the linger to return.
        parked.await()
        assertEquals("The burst must have gone out before the linger", 1, link.sends.size)
        assertEquals(
            "The test must cancel inside the linger's first receive slice, got ${link.reads}",
            listOf(SLICE_MS),
            link.reads,
        )
        assertEquals("The device must already be persisted", 1, persists)
        assertEquals("The proof must be built exactly once", 1, crypto.buildCount)
        assertEquals(
            "Nothing may be concluded while the linger still answers",
            0,
            crypto.concludeCount,
        )
        assertFalse("The session must not be closed by the cancellation yet", lifecycle.isClosed())

        job.cancelAndJoin()

        assertTrue("The job must really have been cancelled", job.isCancelled)
        assertEquals(
            "The confirmation's `finally` must still conclude the session after a cancellation",
            1,
            crypto.concludeCount,
        )
        // A cancellation is not a release: the release body (transports down, keys dropped) is the
        // close's work, and it has not been asked for.
        assertFalse("A cancelled confirmation must not release the session", lifecycle.isClosed())
        assertEquals("The release body must not have run", 0, closes)
        assertEquals("The keys must not have been zeroized by the cancellation", 0, zeroizes)

        assertEquals(
            "After a cancelled confirmation the latch must no longer defer a close; `Deferred` here " +
                "means the latch is stuck in Committed and the session can never be released",
            CloseOutcome.Released,
            lifecycle.close(),
        )
        assertEquals("The release body must run on the close", 1, closes)
        assertEquals("The release must drop the keys exactly once", 1, zeroizes)
        assertTrue("The closed flag must be set by the release", lifecycle.isClosed())
        assertTrue("The transport must be closed by the release body", link.closed)
    }

    private companion object {
        val CSK = ByteArray(32) { 0x0C }

        /** The serialized `PairingConfirmServer`, built once and re-sent verbatim. */
        val CONFIRMATION = byteArrayOf(0xC0.toByte(), 0x0F)

        /** What `persist` returns. */
        const val DEVICE = "paired-device"

        /** `PairingSession.RECEIVE_SLICE_MS`: the production receive slice. */
        const val SLICE_MS = 200L
    }
}
