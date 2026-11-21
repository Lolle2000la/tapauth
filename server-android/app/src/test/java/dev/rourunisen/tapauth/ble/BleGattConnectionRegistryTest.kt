package dev.rourunisen.tapauth.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The bookkeeping that keeps a torn-down `BluetoothGatt` from being mistaken for a live connection
 * after its entry is dropped.
 *
 * The service drives this with `BluetoothGatt` keys, which no JVM test can construct (the class is
 * final with a package-private constructor), so the registry is generic and the test drives it with
 * plain strings: the decisions under test — what a torn-down key may still get, and what a grace
 * expiry drops — are the same ones the service relies on.
 */
class BleGattConnectionRegistryTest {

    private class ConnectionState {
        @Volatile var closed = false
    }

    private fun registry() =
        BleGattConnectionRegistry<String, ConnectionState> { ConnectionState() }

    @Test
    fun aLiveHandleGetsOneStableState() {
        val registry = registry()

        val first = registry.liveOrCreate("handle")

        assertNotNull(first)
        assertSame(first, registry.liveOrCreate("handle"))
        assertEquals(first, registry.stateFor("handle"))
    }

    @Test
    fun theGraceExpiryDropsTheTornDownHandlesEntry() {
        val registry = registry()

        registry.markTornDown("handle").closed = true
        // The retransmission loop and a coroutine that was still holding the handle may both look
        // the state up during the grace, so it is kept until the grace expires.
        assertNotNull(registry.stateFor("handle"))

        registry.forget("handle")

        assertNull(
            "the torn-down handle's state must be dropped at grace expiry, or one entry is kept " +
                "per reconnection for the life of the service",
            registry.stateFor("handle"),
        )
    }

    @Test
    fun aForgottenHandleIsNeverGivenALiveStateAgain() {
        val registry = registry()
        registry.markTornDown("handle").closed = true
        registry.forget("handle")

        assertNull(
            "a coroutine that resumes after the teardown must not be handed a live-looking state " +
                "for the closed handle",
            registry.liveOrCreate("handle"),
        )
        // …and asking for it must not have re-created the entry it just dropped.
        assertNull(registry.stateFor("handle"))
        assertTrue(registry.isTornDown("handle"))
    }

    @Test
    fun aReconnectOnANewHandleGetsItsOwnLiveState() {
        val registry = registry()
        registry.markTornDown("old").closed = true
        registry.forget("old")

        val reconnected = registry.liveOrCreate("new")

        assertNotNull(reconnected)
        assertFalse(reconnected!!.closed)
        assertNull(registry.liveOrCreate("old"))
    }

    @Test
    fun forgettingAHandleTwiceLeavesNoEntryAndKeepsItTornDown() {
        val registry = registry()
        registry.markTornDown("handle").closed = true

        registry.forget("handle")
        registry.forget("handle")

        assertNull(registry.stateFor("handle"))
        assertTrue(registry.isTornDown("handle"))
        assertNull(registry.liveOrCreate("handle"))
    }

    @Test
    fun clearingDropsEntriesAndTombstones() {
        val registry = registry()
        registry.markTornDown("dead").closed = true
        registry.liveOrCreate("live")

        registry.clear()

        assertNull(registry.stateFor("dead"))
        assertNull(registry.stateFor("live"))
        assertFalse(registry.isTornDown("dead"))
        // A handle seen for the first time after the clear is live again, exactly as after a
        // restart of the service.
        assertNotNull(registry.liveOrCreate("dead"))
    }
}
