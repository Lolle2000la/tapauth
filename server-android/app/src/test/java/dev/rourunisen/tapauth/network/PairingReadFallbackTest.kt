package dev.rourunisen.tapauth.network

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * The BLE read fallback: polling the readable pairing value when notifications stop arriving, with
 * a first-wins rule so a frame that is both notified and readable is delivered once.
 *
 * Driven from a fake clock and scripted sources, so no GATT stack is involved.
 */
class PairingReadFallbackTest {

    private class FakeClock(var now: Long = 0L) {
        fun advance(ms: Long) {
            now += ms
        }
    }

    /** The frame that is currently readable on the pairing characteristic. */
    private val frame = byteArrayOf(1, 2, 3)

    /** A newer frame, written after [frame]. */
    private val later = byteArrayOf(4, 5, 6)

    /**
     * A dropped notification must be replaced by a poll, and the poll must not fire before the
     * interval: polling on every 200 ms slice would hammer the GATT link for nothing.
     *
     * The defect this catches: no read fallback at all (the wait then never returns), or one that
     * reads immediately on every wait (reads at 0 ms and 200 ms instead of 500 ms and 1000 ms).
     */
    @Test
    fun pollsTheCharacteristicOnlyAfterTheIntervalWithoutANotification() = runBlocking {
        val clock = FakeClock()
        val fallback = PairingReadFallback(intervalMs = 500L, nowMs = { clock.now })
        val readsAt = mutableListOf<Long>()

        val result =
            fallback.awaitFrame(
                isClosed = { false },
                awaitNotification = { slice ->
                    clock.advance(minOf(slice, 200L))
                    null
                },
                pollNotification = { null },
                readValue = {
                    readsAt.add(clock.now)
                    // The first poll sees nothing new (the desktop has not written yet).
                    if (readsAt.size >= 2) frame else null
                },
            )

        assertSame("The polled frame must be delivered", frame, result)
        assertEquals(
            "Polls must be one interval apart and none before it, got $readsAt",
            listOf(500L, 1_000L),
            readsAt,
        )
    }

    /**
     * A poll that repeats the frame the waiter already received must be dropped, and the wait must
     * continue to the next frame.
     *
     * The defect this catches: delivering the readable value unconditionally, so the state machine
     * sees the same `PairingResponse`/`PairingConfirmClient` twice — over BLE the retransmission
     * this produces rings the desktop for a handshake it has already finished.
     */
    @Test
    fun aPollThatRepeatsTheNotifiedFrameIsNotDeliveredTwice() = runBlocking {
        val clock = FakeClock()
        val fallback = PairingReadFallback(intervalMs = 500L, nowMs = { clock.now })
        var polls = 0

        val notified =
            fallback.awaitFrame(
                isClosed = { false },
                awaitNotification = {
                    clock.advance(100)
                    frame
                },
                pollNotification = { null },
                readValue = { error("a notified frame must not need a read") },
            )
        assertSame("The notified frame must be delivered", frame, notified)

        val second =
            fallback.awaitFrame(
                isClosed = { false },
                awaitNotification = { slice ->
                    clock.advance(minOf(slice, 200L))
                    null
                },
                pollNotification = { null },
                readValue = {
                    polls += 1
                    // The characteristic still holds the notified frame, then the next one.
                    if (polls == 1) frame else later
                },
            )

        assertSame("The stale poll must be dropped and the next frame delivered", later, second)
        assertEquals("The wait must poll twice to get past the stale value", 2, polls)
    }

    /**
     * A notification that is already queued when a poll becomes due wins over the poll, so the
     * fresher frame is delivered and the older readable value is never read.
     *
     * The defect this catches: reading first and delivering the stale readable value while a fresh
     * notification sits in the queue, which delivers an old frame and leaves the new one for a
     * later wait.
     */
    @Test
    fun aQueuedNotificationWinsOverThePoll() = runBlocking {
        val clock = FakeClock()
        val fallback = PairingReadFallback(intervalMs = 500L, nowMs = { clock.now })
        var reads = 0

        val result =
            fallback.awaitFrame(
                isClosed = { false },
                awaitNotification = { slice ->
                    clock.advance(minOf(slice, 500L))
                    null
                },
                pollNotification = { frame },
                readValue = {
                    reads += 1
                    later
                },
            )

        assertSame("The queued notification must be delivered", frame, result)
        assertEquals("No read may be issued while a notification is queued", 0, reads)
    }

    /**
     * A closed link ends the wait without polling: the client's `readValue` returns null once the
     * GATT link is gone, so a loop that ignored `isClosed` would spin for the caller's whole
     * deadline (30 s while racing for a response, 120 s while awaiting the provision payload).
     *
     * The defect this catches: a wait loop that keeps polling after close.
     */
    @Test
    fun aClosedLinkStopsWaitingWithoutReading() = runBlocking {
        val fallback = PairingReadFallback(intervalMs = 500L, nowMs = { 0L })
        var reads = 0

        val result =
            fallback.awaitFrame(
                isClosed = { true },
                awaitNotification = { error("a closed link must not be waited on") },
                pollNotification = { error("a closed link must not be polled") },
                readValue = {
                    reads += 1
                    frame
                },
            )

        assertNull("A closed link must end the wait", result)
        assertEquals("A closed link must not read", 0, reads)
    }
}
