package dev.rourunisen.tapauth.network

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The assembly `PairingSession` ships: the commit/close boundary the confirmation phase is gated
 * on, the closed flag the linger reads, and the release body.
 *
 * `PairingSession` itself cannot be built here — an Android `Context`, a live transport and the
 * generated UniFFI object are all required — so it delegates these decisions to
 * [PairingSessionLifecycle] and this test drives that object with fakes. Unlike the phase's own
 * tests, nothing here arms the phase with a hand-written `beginCommit = { true }`: the test calls
 * [PairingSessionLifecycle.finish], which hands the phase the lifecycle's own boundary, so the
 * wiring the production close competes with is the wiring under test.
 *
 * The confirmation inside these tests is the real [PairingConfirmPhase] over a fake link, a fake
 * crypto and a fake clock.
 */
class PairingSessionLifecycleTest {

    /** A clock the test advances itself, shared by the reader, the linger and the fake link. */
    private class FakeClock(var now: Long = 0L) {
        fun advance(ms: Long) {
            now += ms
        }
    }

    /**
     * The locked transport: every read consumes exactly the time it was given, so the sum of the
     * reads is the time the linger spent and an unbounded linger cannot end the test by itself.
     */
    private class FakeLink(
        private val clock: FakeClock,
        private val frameAt: (Long) -> ByteArray? = { null },
    ) : PairingLink {
        /** Every frame written, by reference. */
        val sends = mutableListOf<ByteArray>()

        var closed = false

        override suspend fun send(packet: ByteArray): Boolean {
            sends += packet
            return true
        }

        override suspend fun receive(timeoutMs: Long): ByteArray? {
            clock.advance(timeoutMs)
            return frameAt(clock.now)
        }

        override fun close() {
            closed = true
        }
    }

    /** Stands in for the Rust session's confirmation half. */
    private class FakeCrypto : PairingConfirmationCrypto {
        var buildCount = 0
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

    /** The two side effects the lifecycle injects: tear the transport down, drop the keys. */
    private class Effects {
        var closes = 0
        var zeroizes = 0
    }

    private fun lifecycle(effects: Effects) =
        PairingSessionLifecycle(
            onClose = { effects.closes += 1 },
            zeroize = { effects.zeroizes += 1 },
        )

    private fun phase(clock: FakeClock, crypto: FakeCrypto) =
        PairingConfirmPhase(
            crypto = crypto,
            frameReader = PairingFrameReader(sliceMs = SLICE_MS, nowMs = { clock.now }),
            completion =
                PairingCompletion(lingerMs = LINGER_MS, nowMs = { clock.now }, sliceMs = SLICE_MS),
            belongsToSession = { true },
        )

    /**
     * The close won the boundary before the confirmation started, so the phase must persist
     * nothing, send nothing and report nothing — and the session must already be closed, with the
     * release body having run.
     *
     * The defect this catches: a phase armed with `beginCommit = { true }` instead of the
     * lifecycle's (the persist then runs — a device record the desktop was never told about), and a
     * release body that closes the transports without dropping the keys.
     */
    @Test
    fun aCloseThatWonTheBoundaryRefusesThePersist() = runBlocking {
        val effects = Effects()
        val lifecycle = lifecycle(effects)

        assertEquals("The close may release now", CloseOutcome.Released, lifecycle.close())
        assertTrue("The closed flag must be set by the release", lifecycle.isClosed())
        assertEquals("The release body must run", 1, effects.closes)
        assertEquals("The release must drop the keys", 1, effects.zeroizes)

        val clock = FakeClock()
        val link = FakeLink(clock)
        var persists = 0

        val device =
            lifecycle.finish(phase(clock, FakeCrypto()), link, CSK, listOf(0L)) {
                persists += 1
                "paired-device"
            }

        assertNull("A refused commit must report no device", device)
        assertEquals("Nothing may be persisted", 0, persists)
        assertEquals("Nothing may be sent", 0, link.sends.size)
        assertEquals("The linger must not run", 0L, clock.now)
    }

    /**
     * A close that arrives while the confirmation is in flight is deferred: the device is persisted
     * and reported, the burst and the linger still run to their deadline, and the closed flag stays
     * clear so the linger keeps answering — then the success path zeroizes the keys.
     *
     * This is the one test that fails on both halves of the wiring at once. With `beginCommit` not
     * taken from the lifecycle the close inside the persist wins instead of deferring, the release
     * runs, and the linger stops immediately (the clock never reaches its deadline). With
     * `isClosed` not the lifecycle's closed flag the linger stops or runs regardless of the close,
     * and either the deadline or the deferral assertion fails.
     */
    @Test
    fun aCloseDuringTheConfirmationIsDeferredAndTheLingerStillRuns() = runBlocking {
        val effects = Effects()
        val lifecycle = lifecycle(effects)
        val clock = FakeClock()
        val link = FakeLink(clock)
        var deferred = false

        val device =
            lifecycle.finish(phase(clock, FakeCrypto()), link, CSK, listOf(0L)) {
                deferred = lifecycle.close() == CloseOutcome.Deferred
                "paired-device"
            }

        assertTrue("A close during the commit must be deferred", deferred)
        assertEquals("The device must be persisted and reported", "paired-device", device)
        assertEquals("The deferred close must not release", 0, effects.closes)
        assertFalse("A deferred close must not stop the linger", lifecycle.isClosed())
        assertEquals(
            "The linger must run to its deadline, got ${clock.now}ms",
            LINGER_MS,
            clock.now,
        )
        assertEquals("The burst must still go out", 1, link.sends.size)
        assertEquals("The success path must zeroize the keys", 1, effects.zeroizes)
    }

    /**
     * Once the confirmation has completed a close releases like any other, and the release body
     * runs exactly once while the keys are zeroized exactly once across both paths — the success
     * path asks for it and so does the session epilogue.
     *
     * The defect this catches: the commit being permanent, so a close after a finished pairing is
     * answered "deferred" forever (the transports and the key entry then have no release path); a
     * success path that never zeroizes; and a release or an epilogue that zeroizes a second time.
     */
    @Test
    fun aCloseAfterTheCompletionReleasesAndTheKeysAreZeroizedOnce() = runBlocking {
        val effects = Effects()
        val lifecycle = lifecycle(effects)
        val clock = FakeClock()
        val link = FakeLink(clock)

        val device =
            lifecycle.finish(phase(clock, FakeCrypto()), link, CSK, listOf(0L)) { "paired-device" }

        assertEquals("The device must be reported", "paired-device", device)
        assertEquals("The success path must zeroize the keys", 1, effects.zeroizes)

        // `runSession`'s epilogue asks again; the assembly must not run it twice.
        lifecycle.zeroizeEphemeralState()
        assertEquals("The epilogue must not zeroize a second time", 1, effects.zeroizes)

        assertEquals(
            "A close after the completion must release",
            CloseOutcome.Released,
            lifecycle.close(),
        )
        assertTrue("The closed flag must be set by the release", lifecycle.isClosed())
        assertEquals("The release body must run", 1, effects.closes)
        assertEquals("The release must not zeroize a second time", 1, effects.zeroizes)

        assertEquals(
            "A repeated close still reports the release",
            CloseOutcome.Released,
            lifecycle.close(),
        )
        assertEquals("The release body must run once", 1, effects.closes)
    }

    /**
     * A confirmation that dies half-way still ends the deferral: the device may already be durable,
     * so a close that arrives afterwards must release instead of deferring to a confirmation that
     * is never coming.
     *
     * The defect this catches: `completeCommit` on the success path only, which leaves the latch
     * `Committed` forever after a transport failure that reached the phase's `finally`.
     */
    @Test
    fun aConfirmationThatThrowsStillEndsTheDeferral() = runBlocking {
        val effects = Effects()
        val lifecycle = lifecycle(effects)
        val clock = FakeClock()
        val crypto = FakeCrypto()
        val link =
            object : PairingLink {
                override suspend fun send(packet: ByteArray): Boolean =
                    throw IllegalStateException("the transport went away")

                override suspend fun receive(timeoutMs: Long): ByteArray? = null

                override fun close() = Unit
            }

        val thrown = runCatching {
            lifecycle.finish(phase(clock, crypto), link, CSK, listOf(0L)) { "paired-device" }
        }

        assertEquals(
            "The transport failure must reach the caller",
            "the transport went away",
            (thrown.exceptionOrNull() as? IllegalStateException)?.message,
        )
        assertEquals("The failed confirmation must still conclude", 1, crypto.concludeCount)

        assertEquals(
            "A close after the failed confirmation must release",
            CloseOutcome.Released,
            lifecycle.close(),
        )
        assertEquals("The release body must run", 1, effects.closes)
        assertEquals("The release must drop the keys", 1, effects.zeroizes)
    }

    private companion object {
        val CSK = ByteArray(32) { 0x0C }

        val CONFIRMATION = byteArrayOf(0xC0.toByte(), 0x0F)

        /** One second of linger, in slices the fake link consumes exactly. */
        const val LINGER_MS = 1_000L

        const val SLICE_MS = 100L
    }
}
