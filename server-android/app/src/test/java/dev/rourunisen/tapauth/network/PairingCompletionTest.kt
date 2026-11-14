package dev.rourunisen.tapauth.network

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The post-completion linger: the window in which a pairing that is already persisted still answers
 * the desktop's `PairingConfirmClient` retransmissions.
 *
 * Everything is driven from a fake clock, so the 1.25 s window costs no wall time.
 */
class PairingCompletionTest {

    /** A clock the test advances itself. */
    private class FakeClock(var now: Long = 0L) {
        fun advance(ms: Long) {
            now += ms
        }
    }

    /** The serialized `PairingConfirmServer`, built once. */
    private val confirmation = byteArrayOf(0xC0.toByte(), 0x0F)

    /** The desktop's verbatim retransmission of `PairingConfirmClient`. */
    private val retransmit = byteArrayOf(0x7A)

    /** An authenticated `PairingAbort`, which the linger must ignore. */
    private val abort = byteArrayOf(0xAB.toByte())

    private fun completion(clock: FakeClock) =
        PairingCompletion(lingerMs = 1_250L, nowMs = { clock.now }, sliceMs = 100L)

    @Test
    fun theDefaultLingerCoversTheDesktopRetrySchedule() {
        assertTrue(
            "The linger must cover the desktop's 500 ms retries past 1.2 s, got " +
                PairingCompletion.DEFAULT_LINGER_MS,
            PairingCompletion.DEFAULT_LINGER_MS >= 1_200L,
        )
    }

    /**
     * A burst that is entirely dropped is recovered by answering the retransmission: the phone must
     * still answer at 700 ms, with the same bytes it sent in the burst, and the device must have
     * been persisted exactly once before the first frame went out.
     *
     * The defect this catches: completing (and closing the socket) right after the burst, which
     * leaves the desktop retrying into a closed port.
     */
    @Test
    fun answersARetransmissionThatArrivesDuringTheLinger() = runBlocking {
        val clock = FakeClock()
        val events = mutableListOf<String>()
        var answeredAt = -1L
        var answeredWith: ByteArray? = null

        val device =
            completion(clock)
                .confirm(
                    burstDelaysMs = listOf(0L),
                    buildConfirmation = {
                        events.add("build")
                        confirmation
                    },
                    persist = {
                        events.add("persist")
                        "paired-device"
                    },
                    send = { packet ->
                        events.add("send@${clock.now}")
                        if (clock.now > 0) {
                            answeredAt = clock.now
                            answeredWith = packet
                        }
                    },
                    receive = { slice ->
                        clock.advance(slice)
                        if (clock.now >= 700 && answeredAt < 0) retransmit else null
                    },
                    isRetransmission = { it.contentEquals(retransmit) },
                )

        assertEquals("The persisted device must be returned", "paired-device", device)
        assertEquals("The retransmission must be answered at 700 ms", 700L, answeredAt)
        assertSame(
            "The answer must re-send the exact PairingConfirmServer bytes, not a new proof",
            confirmation,
            answeredWith,
        )
        assertEquals(
            "The device must be persisted exactly once, got $events",
            1,
            events.count { it == "persist" },
        )
        assertTrue(
            "Persisting must precede the first send, got $events",
            events.indexOf("persist") in 1 until events.indexOfFirst { it.startsWith("send") },
        )
    }

    /**
     * The window is bounded: a retransmission that only shows up after the linger is over must not
     * be answered, and the receive loop must stop at the deadline rather than keep the link open.
     *
     * The defect this catches: an unbounded linger (`while (true)`) that answers forever.
     */
    @Test
    fun stopsAnsweringOnceTheLingerEnds() = runBlocking {
        val clock = FakeClock()
        val sends = mutableListOf<Long>()
        var lastReceiveAt = -1L

        completion(clock)
            .confirm(
                burstDelaysMs = listOf(0L),
                buildConfirmation = { confirmation },
                persist = { "paired-device" },
                send = { sends.add(clock.now) },
                receive = { slice ->
                    lastReceiveAt = clock.now
                    clock.advance(slice)
                    if (clock.now >= 1_300L) retransmit else null
                },
                isRetransmission = { it.contentEquals(retransmit) },
            )

        assertEquals("Only the burst may be sent, got sends at $sends", listOf(0L), sends)
        assertTrue(
            "The linger must not receive past its 1250 ms deadline, last receive at $lastReceiveAt",
            lastReceiveAt <= 1_250L,
        )
    }

    /**
     * An authenticated abort during the linger must not resurrect a completed pairing: no answer,
     * no second persist, no failure.
     *
     * The defect this catches: answering every frame that arrives during the linger, or treating an
     * abort as a reason to re-run the completion.
     */
    @Test
    fun anAbortDuringTheLingerIsNeitherAnsweredNorPersistedAgain() = runBlocking {
        val clock = FakeClock()
        val sends = mutableListOf<Long>()
        var persists = 0

        val device =
            completion(clock)
                .confirm(
                    burstDelaysMs = listOf(0L),
                    buildConfirmation = { confirmation },
                    persist = {
                        persists += 1
                        "paired-device"
                    },
                    send = { sends.add(clock.now) },
                    receive = { slice ->
                        clock.advance(slice)
                        if (clock.now in 300L..399L) abort else null
                    },
                    isRetransmission = { it.contentEquals(retransmit) },
                )

        assertEquals("paired-device", device)
        assertEquals("The abort must not be answered, got sends at $sends", listOf(0L), sends)
        assertEquals("The pairing must be persisted once", 1, persists)
    }

    /**
     * Closing the session (the user leaves the pairing screen) ends the linger at once instead of
     * holding the transport for the rest of the window.
     *
     * The defect this catches: a linger that only looks at its deadline, so a closed session keeps
     * spinning its receive loop until 1.25 s have elapsed.
     */
    @Test
    fun aClosedSessionEndsTheLingerImmediately() = runBlocking {
        val clock = FakeClock()

        completion(clock)
            .confirm(
                burstDelaysMs = listOf(0L),
                buildConfirmation = { confirmation },
                persist = { "paired-device" },
                send = {},
                receive = { slice ->
                    clock.advance(slice)
                    null
                },
                isRetransmission = { false },
                isClosed = { clock.now >= 400L },
            )

        assertEquals("The linger must stop at the close, not the deadline", 400L, clock.now)
    }

    /**
     * A continuous stream of frames belonging to another session must not stretch the linger: the
     * reader's budget, not the number of frames, decides when the wait ends, so the pairing still
     * completes (and the session is still zeroized) at the deadline.
     *
     * The defect this catches: a read that re-arms a full slice for every dropped frame (the shape
     * `PairingSession.receivePacket` had before the budget), so a LAN peer spraying datagrams at
     * the ephemeral pairing port keeps the linger from ever re-reading its clock — the ephemeral
     * keys stay alive far past the bound and `PairingUpdate.Complete` is never emitted, so the
     * pairing screen never closes.
     */
    @Test
    fun aStreamOfForeignFramesDoesNotExtendTheLinger() = runBlocking {
        val clock = FakeClock()
        val reader = PairingFrameReader(sliceMs = 100L, nowMs = { clock.now })
        val sends = mutableListOf<Long>()
        val foreign = byteArrayOf(0x11)
        var persists = 0

        completion(clock)
            .confirm(
                burstDelaysMs = listOf(0L),
                buildConfirmation = { confirmation },
                persist = {
                    persists += 1
                    "paired-device"
                },
                send = { sends.add(clock.now) },
                receive = { budget ->
                    reader.awaitOwnFrame(
                        budgetMs = budget,
                        // Another pairing, forever: the stream only stops long after the linger
                        // would have, so an unbounded read cannot end the test by itself.
                        receive = { slice ->
                            clock.advance(slice)
                            if (clock.now > 5_000L) null else foreign
                        },
                        belongsToSession = { false },
                    )
                },
                isRetransmission = { false },
            )
        // The session's epilogue (zeroize + close) runs as soon as the linger returns.
        val zeroizedAt = clock.now

        assertEquals(
            "The linger must end at its 1250 ms deadline despite the foreign stream, " +
                "zeroized at $zeroizedAt",
            1_250L,
            zeroizedAt,
        )
        assertEquals("Foreign frames must not be answered, got sends at $sends", listOf(0L), sends)
        assertEquals("The pairing must be persisted once, before the linger", 1, persists)
    }

    /**
     * A retransmission that arrives behind foreign frames must still be answered, with the exact
     * bytes of the burst, and the linger must still end at its deadline.
     *
     * The defect this catches: a "fix" that treats the first foreign frame as nothing to read and
     * returns, which drops the desktop's retransmission and leaves it retrying into a closed socket
     * — the phone would be paired and the desktop never.
     */
    @Test
    fun aRetransmissionBehindForeignFramesIsStillAnswered() = runBlocking {
        val clock = FakeClock()
        val reader = PairingFrameReader(sliceMs = 100L, nowMs = { clock.now })
        val sends = mutableListOf<Long>()
        var answeredWith: ByteArray? = null

        completion(clock)
            .confirm(
                burstDelaysMs = listOf(0L),
                buildConfirmation = { confirmation },
                persist = { "paired-device" },
                send = { packet ->
                    sends.add(clock.now)
                    if (clock.now > 0) answeredWith = packet
                },
                receive = { budget ->
                    reader.awaitOwnFrame(
                        budgetMs = budget,
                        receive = { slice ->
                            clock.advance(slice)
                            // Another session's frames up to 600 ms, then this session's one
                            // retransmission, then foreign frames again — and the stream stops
                            // long after the linger would have, so an unbounded read cannot end
                            // this test by itself.
                            when {
                                clock.now in 600L..699L -> retransmit
                                clock.now > 5_000L -> null
                                else -> byteArrayOf(0x11)
                            }
                        },
                        belongsToSession = { it.contentEquals(retransmit) },
                    )
                },
                isRetransmission = { it.contentEquals(retransmit) },
            )

        assertEquals(
            "The retransmission must be answered once, at 600 ms, got sends at $sends",
            listOf(0L, 600L),
            sends,
        )
        assertSame(
            "The answer must re-send the exact PairingConfirmServer bytes, not a new proof",
            confirmation,
            answeredWith,
        )
        assertEquals("The linger must still end at its deadline", 1_250L, clock.now)
    }
}
