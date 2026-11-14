package dev.rourunisen.tapauth.ble

import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The decision a duplicate-in-flight BLE arrival needs: are the bytes already built for this
 * challenge owed to the handle it just arrived on?
 *
 * The handle is a plain object here on purpose — the class under test compares handles by identity
 * only, and a `BluetoothGatt` cannot be constructed in a JVM test.
 */
class BleResponseHandoffTest {

    private class Handle(val address: String)

    private var nowMillis = 1_000_000L

    private val handoff = BleResponseHandoff<Handle> { nowMillis }

    private val challengeKey = "0a0b0c"
    private val peer = "AA:BB:CC:DD:EE:01"
    private val otherPeer = "AA:BB:CC:DD:EE:02"
    private val deadHandle = Handle(peer)
    private val liveHandle = Handle(peer)
    private val response = ByteArray(48) { it.toByte() }

    @Test
    fun recordedAnswerIsNotRedeliveredToTheHandleItIsAlreadyGoingTo() {
        handoff.record(challengeKey, peer, deadHandle, response)

        // The re-notification of the same request on the link that is already being written: a
        // second write would race the retransmission loop, and nothing is owed.
        assertNull(handoff.redeliverOn(challengeKey, peer, deadHandle))
        assertEquals(1, handoff.pendingCount)
    }

    @Test
    fun reconnectOnANewHandleGetsTheSameBytesAndStopsTheOldLoop() {
        val first = handoff.record(challengeKey, peer, deadHandle, response)
        val stops = AtomicInteger(0)
        first.onRetransmission { stops.incrementAndGet() }

        val redelivery = requireNotNull(handoff.redeliverOn(challengeKey, peer, liveHandle))
        val delivery = redelivery.delivery

        assertSame("the same bytes must be written, not a new answer", response, delivery.response)
        assertSame(liveHandle, delivery.handle)
        assertEquals(challengeKey, delivery.challengeKey)
        assertEquals(peer, delivery.peerAddress)
        // The loop writing the dead handle has to be stopped before the new one starts, and the
        // stop handle is handed over exactly once.
        assertNotNull(redelivery.cancelPrevious)
        redelivery.cancelPrevious?.invoke()
        assertEquals(1, stops.get())
        // A loop that had not taken its first step must see that it was superseded.
        assertTrue(first.superseded)
        assertEquals(1, handoff.pendingCount)

        // A third arrival on yet another handle must not cancel the loop on the live handle through
        // the stale stop handle of the first one: none has been registered for the live one yet.
        val third = handoff.redeliverOn(challengeKey, peer, Handle(peer))
        assertNotNull(third)
        assertNull(third?.cancelPrevious)
        assertEquals(1, handoff.pendingCount)
    }

    @Test
    fun foreignPeerIsNeverHandedTheBytes() {
        handoff.record(challengeKey, peer, deadHandle, response)

        // Another device replaying the captured request must not be answered at all; the gate calls
        // it a replay and the service disconnects it.
        assertNull(handoff.redeliverOn(challengeKey, otherPeer, Handle(otherPeer)))
        assertEquals(1, handoff.pendingCount)
    }

    @Test
    fun duplicateOnANewHandleWithNoAnswerBuiltYetHasNothingToRedeliver() {
        // The prompt is still open: the request was accepted but the user has not answered, so
        // there are no bytes and the arriving copy must simply be ignored.
        assertNull(handoff.redeliverOn(challengeKey, peer, liveHandle))
        assertEquals(0, handoff.pendingCount)
    }

    @Test
    fun confirmedDeliveryIsRetiredAndNoLongerRedelivered() {
        val delivery = handoff.record(challengeKey, peer, deadHandle, response)

        handoff.finish(delivery)

        assertEquals(0, handoff.pendingCount)
        assertFalse(delivery.superseded)
        // The Client already has the answer, so a later copy must not put it back on the wire.
        assertNull(handoff.redeliverOn(challengeKey, peer, liveHandle))
    }

    @Test
    fun staleLoopFinishingAfterARedeliveryKeepsTheNewDelivery() {
        val first = handoff.record(challengeKey, peer, deadHandle, response)
        assertNotNull(handoff.redeliverOn(challengeKey, peer, liveHandle))

        // The cancelled loop on the dead handle unwinds and reports itself finished. That must not
        // retire the delivery aimed at the live handle, or the reconnect would be answered by
        // nothing while the retransmission loop on the new link is still running.
        handoff.finish(first)

        assertEquals(1, handoff.pendingCount)
        assertNull(
            "the live handle is already being written",
            handoff.redeliverOn(challengeKey, peer, liveHandle),
        )
        // And the new delivery can still be handed to a third handle after another reconnect.
        assertNotNull(handoff.redeliverOn(challengeKey, peer, Handle(peer)))
    }

    @Test
    fun expiredAnswerIsPrunedInsteadOfBeingRedelivered() {
        // A link whose teardown is never reported to the service: the grace never runs, so the age
        // bound is what stops the held bytes from living for the process lifetime.
        handoff.record(challengeKey, peer, deadHandle, response)
        nowMillis += 600_001L

        assertNull(handoff.redeliverOn(challengeKey, peer, liveHandle))
        assertEquals(0, handoff.pendingCount)
    }

    @Test
    fun abandonedPeerLosesOnlyItsOwnAnswers() {
        val otherKey = "0d0e0f"
        handoff.record(challengeKey, peer, deadHandle, response)
        handoff.record(otherKey, otherPeer, Handle(otherPeer), response)

        // The grace expires for the first peer: nothing it was owed may stay held, and the other
        // peer's answer is untouched.
        handoff.abandonPeer(peer)

        assertEquals(1, handoff.pendingCount)
        assertNull(handoff.redeliverOn(challengeKey, peer, liveHandle))
        assertNotNull(handoff.redeliverOn(otherKey, otherPeer, Handle(otherPeer)))

        handoff.clear()
        assertEquals(0, handoff.pendingCount)
    }
}
