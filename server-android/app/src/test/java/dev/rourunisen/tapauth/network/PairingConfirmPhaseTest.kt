package dev.rourunisen.tapauth.network

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The confirmation phase — persistence, the `PairingConfirmServer` burst, the retransmission linger
 * and the conclusion — driven through the wiring `PairingSession` ships.
 *
 * The fake crypto stands in for the generated UniFFI object, which `./gradlew test` cannot load;
 * everything else (the frame intake, its budget accounting, the retransmission predicate, the
 * linger and the conclusion) is the production code path. A fake clock keeps the 1.25 s linger off
 * the wall clock.
 */
class PairingConfirmPhaseTest {

    /** A clock the test advances itself, shared by the reader, the linger and the fake link. */
    private class FakeClock(var now: Long = 0L) {
        fun advance(ms: Long) {
            now += ms
        }
    }

    /**
     * The locked transport, as the phase sees it.
     *
     * A read consumes the timeout it was given before returning its scripted frame, which is what
     * makes the sum of [reads] the time the linger actually spent: a read that returned early would
     * make the budget accounting unobservable.
     */
    private class FakeLink(
        private val clock: FakeClock,
        private val log: MutableList<String>,
        private val frameAt: (Long) -> ByteArray?,
    ) : PairingLink {
        /** The timeout of every read the phase asked for, in order. */
        val reads = mutableListOf<Long>()

        /** Every frame written, by reference: identity is what "the same bytes" means here. */
        val sends = mutableListOf<ByteArray>()

        var closed = false

        override suspend fun send(packet: ByteArray): Boolean {
            sends += packet
            log += "send@${clock.now}"
            return true
        }

        override suspend fun receive(timeoutMs: Long): ByteArray? {
            reads += timeoutMs
            clock.advance(timeoutMs)
            return frameAt(clock.now)
        }

        override fun close() {
            closed = true
        }
    }

    /** Stands in for the Rust session: the proof, the decrypt and the conclusion. */
    private class FakeCrypto(
        private val confirmation: ByteArray,
        private val confirmClient: ByteArray,
        private val log: MutableList<String>,
    ) : PairingConfirmationCrypto {
        var buildCount = 0

        /** Every frame the retransmission predicate consulted the session about, in order. */
        val decrypted = mutableListOf<ByteArray>()

        var concludeCount = 0

        override fun createConfirmServer(csk: ByteArray): ByteArray {
            buildCount++
            log += "build"
            return confirmation
        }

        override fun processConfirmClient(packet: ByteArray): ByteArray? {
            decrypted += packet
            return if (packet.contentEquals(confirmClient)) packet else null
        }

        override fun conclude() {
            concludeCount++
            log += "conclude"
        }
    }

    private companion object {
        val CSK = ByteArray(32) { 0x0C }

        /** The serialized `PairingConfirmServer`, built once and re-sent verbatim. */
        val CONFIRMATION = byteArrayOf(0xC0.toByte(), 0x0F)

        /** The desktop's verbatim retransmission of `PairingConfirmClient`. */
        val CONFIRM_CLIENT = byteArrayOf(0x7A)

        /** Some other pairing's frame on the shared pairing port. */
        val FOREIGN = byteArrayOf(0x11)

        /** One second of linger in the tests that do not care about the exact bound. */
        const val LINGER_MS = 1_000L

        /** A single 100 ms slice for both the linger and the reader, so the arithmetic is exact. */
        const val SLICE_MS = 100L

        /** Stops a stream whose reader would otherwise never return inside the test. */
        const val STREAM_GUARD_MS = 10_000L
    }

    private fun phase(
        clock: FakeClock,
        crypto: PairingConfirmationCrypto,
        lingerMs: Long = LINGER_MS,
        belongsToSession: (ByteArray) -> Boolean,
    ) =
        PairingConfirmPhase(
            crypto = crypto,
            frameReader = PairingFrameReader(sliceMs = SLICE_MS, nowMs = { clock.now }),
            completion =
                PairingCompletion(lingerMs = lingerMs, nowMs = { clock.now }, sliceMs = SLICE_MS),
            belongsToSession = belongsToSession,
        )

    /**
     * A LAN peer spraying frames of *another* pairing at the ephemeral pairing port must not
     * stretch the linger: every dropped frame is paid for out of the same budget the linger handed
     * down, so the confirmation still completes at its own deadline — and is then concluded —
     * whatever the peer sends.
     *
     * The defect this catches: a frame intake that does not forward the caller's budget (a fixed or
     * default slice instead), or one that re-arms a full slice per dropped frame. Either way the
     * linger's clock is only re-read after the stream has spent longer than the linger, so the
     * ephemeral keys stay alive past their bound and `PairingUpdate.Complete` is never emitted.
     *
     * The bound here is the production [PairingCompletion.DEFAULT_LINGER_MS], and the fake link
     * consumes exactly the slice it is given, so the sum of the reads *is* the time the linger
     * spent. A reader handed a fixed 200 ms slice instead of the linger's own last, partial one
     * overshoots to 1 400 ms; one that re-arms a slice per dropped frame is only stopped by
     * [STREAM_GUARD_MS].
     */
    @Test
    fun aStreamOfForeignFramesSpendsExactlyTheLingerBudget() = runBlocking {
        val clock = FakeClock()
        val log = mutableListOf<String>()
        val crypto = FakeCrypto(CONFIRMATION, CONFIRM_CLIENT, log)
        val link = FakeLink(clock, log) { now -> if (now > STREAM_GUARD_MS) null else FOREIGN }
        var persists = 0

        val device =
            phase(
                    clock,
                    crypto,
                    lingerMs = PairingCompletion.DEFAULT_LINGER_MS,
                    belongsToSession = { false },
                )
                .finish(
                    link = link,
                    csk = CSK,
                    burstDelaysMs = listOf(0L),
                    persist = {
                        persists += 1
                        "paired-device"
                    },
                    beginCommit = { true },
                )

        assertEquals("The persisted device must be returned", "paired-device", device)
        assertEquals("The device must be persisted exactly once", 1, persists)
        assertEquals(1, link.sends.size)
        assertSame("Foreign frames must not be answered", CONFIRMATION, link.sends.single())
        assertEquals(
            "The linger must spend its whole budget and no more, whatever the peer sends; the " +
                "link was asked for ${link.reads.sum()} ms in ${link.reads.size} reads",
            PairingCompletion.DEFAULT_LINGER_MS,
            link.reads.sum(),
        )
        assertEquals(
            "The linger must end at its own deadline",
            PairingCompletion.DEFAULT_LINGER_MS,
            clock.now,
        )
        assertEquals(
            "The session must be concluded once, after the linger",
            1,
            crypto.concludeCount,
        )
    }

    /**
     * The desktop re-sends the same `PairingConfirmClient` during the linger, and each one is
     * answered with the *same* `PairingConfirmServer` bytes and nothing else happens: the proof is
     * built once and the device is persisted once.
     *
     * The defect this catches: rebuilding the proof per retransmission — a second
     * `create_confirm_server` draws a fresh AEAD nonce, so the desktop would receive a different
     * message than the one it is retrying for (and Rust refuses the second call anyway) — or
     * persisting on every retransmission.
     */
    @Test
    fun everyRetransmissionIsAnsweredWithTheSameBytesAndConsulted() = runBlocking {
        val clock = FakeClock()
        val log = mutableListOf<String>()
        val crypto = FakeCrypto(CONFIRMATION, CONFIRM_CLIENT, log)
        val link =
            FakeLink(clock, log) { now ->
                // A retransmission at 400 ms and again at 800 ms; other frames otherwise.
                if (now == 400L || now == 800L) CONFIRM_CLIENT else FOREIGN
            }
        var persists = 0

        phase(clock, crypto, belongsToSession = { true })
            .finish(
                link = link,
                csk = CSK,
                burstDelaysMs = listOf(0L),
                persist = {
                    persists += 1
                    "paired-device"
                },
                beginCommit = { true },
            )

        assertEquals("The proof must be built exactly once", 1, crypto.buildCount)
        assertEquals("The device must be persisted exactly once", 1, persists)
        assertEquals(
            "The burst and the two answers must be the same frame, got sends at " +
                log.filter { it.startsWith("send") },
            3,
            link.sends.size,
        )
        for (sent in link.sends) {
            assertSame(
                "Every send must be the exact PairingConfirmServer bytes, not a rebuilt proof",
                CONFIRMATION,
                sent,
            )
        }
        assertEquals(
            "Every received frame must be offered to the retransmission predicate, got " +
                crypto.decrypted.size +
                " for " +
                link.reads.size +
                " reads",
            link.reads.size,
            crypto.decrypted.size,
        )
        assertEquals(
            "The retransmissions must be answered at 400 ms and 800 ms",
            listOf(400L, 800L),
            log.filter { it.startsWith("send") }.drop(1).map { it.removePrefix("send@").toLong() },
        )
    }

    /**
     * The session is concluded once, after the linger and therefore after the last frame has been
     * answered — never before it, or a retransmission would arrive at a session whose keys are
     * already gone and Rust would report `State` instead of decrypting it.
     *
     * The defect this catches: concluding when the proof is built (the old `create_confirm_server`
     * being terminal), or concluding between the burst and the linger.
     */
    @Test
    fun theSessionIsConcludedExactlyOnceAfterTheLastSend() = runBlocking {
        val clock = FakeClock()
        val log = mutableListOf<String>()
        val crypto = FakeCrypto(CONFIRMATION, CONFIRM_CLIENT, log)
        val link = FakeLink(clock, log) { now -> if (now == 700L) CONFIRM_CLIENT else FOREIGN }

        phase(clock, crypto, belongsToSession = { true })
            .finish(
                link = link,
                csk = CSK,
                burstDelaysMs = listOf(0L),
                persist = { "paired-device" },
                beginCommit = { true },
            )

        assertEquals("The session must be concluded exactly once", 1, crypto.concludeCount)
        assertEquals("Concluding must be the last thing the phase does", "conclude", log.last())
        assertTrue(
            "The retransmission must be answered before the conclusion, got $log",
            log.indexOfFirst { it.startsWith("send") } < log.indexOf("conclude"),
        )
        assertEquals(
            "The answered retransmission must be at 700 ms, got " +
                log.filter { it.startsWith("send") },
            2,
            link.sends.size,
        )
        assertEquals(
            "The linger must still end at its deadline",
            LINGER_MS,
            clock.now,
        )
    }

    /**
     * A burst that dies half-way still concludes the session: the keys were keyed and the proof was
     * built, so leaving the conclusion to the Rust `Drop` alone would make the backstop the normal
     * path for every transport failure.
     *
     * The defect this catches: a `conclude()` placed on the success path only, which a transport
     * exception skips.
     */
    @Test
    fun aFailedBurstStillConcludesTheSession() = runBlocking {
        val clock = FakeClock()
        val log = mutableListOf<String>()
        val crypto = FakeCrypto(CONFIRMATION, CONFIRM_CLIENT, log)
        val link =
            object : PairingLink {
                override suspend fun send(packet: ByteArray): Boolean =
                    throw IllegalStateException("the transport went away")

                override suspend fun receive(timeoutMs: Long): ByteArray? = null

                override fun close() = Unit
            }

        val thrown = runCatching {
            phase(clock, crypto, belongsToSession = { true })
                .finish(
                    link = link,
                    csk = CSK,
                    burstDelaysMs = listOf(0L),
                    persist = { "paired-device" },
                    beginCommit = { true },
                )
        }

        assertEquals(
            "The transport failure must reach the caller",
            "the transport went away",
            (thrown.exceptionOrNull() as? IllegalStateException)?.message,
        )
        assertEquals("The session must still be concluded", 1, crypto.concludeCount)
    }

    /**
     * When the close wins the commit boundary first, the phase persists nothing and sends nothing:
     * a device record the desktop was never told about is exactly the "phone paired, desktop timed
     * out" state the boundary exists to prevent.
     *
     * The defect this catches: a commit gate that is consulted only after the persist lambda has
     * already run, or one whose refusal is ignored (`finish` persisting anyway), which leaves the
     * record on disk with no `PairingConfirmServer` behind it.
     */
    @Test
    fun aCloseThatWonTheBoundaryPersistsAndSendsNothing() = runBlocking {
        val clock = FakeClock()
        val log = mutableListOf<String>()
        val crypto = FakeCrypto(CONFIRMATION, CONFIRM_CLIENT, log)
        val link = FakeLink(clock, log) { CONFIRM_CLIENT }
        var persists = 0
        var commits = 0

        val device =
            phase(clock, crypto, belongsToSession = { true })
                .finish(
                    link = link,
                    csk = CSK,
                    burstDelaysMs = listOf(0L),
                    persist = {
                        persists += 1
                        "paired-device"
                    },
                    // The latch reports that a close won before the commit could be taken.
                    beginCommit = {
                        commits += 1
                        false
                    },
                )

        assertEquals("Nothing may be persisted", 0, persists)
        assertEquals("Nothing may be sent", 0, link.sends.size)
        assertEquals("The commit must be refused exactly once", 1, commits)
        assertEquals("No proof may be built for a refused commit", 0, crypto.buildCount)
        assertEquals("The refused phase must report nothing persisted", null, device)
        assertEquals("The linger must not run", 0L, clock.now)
        assertEquals("The session must still be concluded", 1, crypto.concludeCount)
    }
}
