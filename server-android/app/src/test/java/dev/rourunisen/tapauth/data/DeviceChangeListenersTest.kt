package dev.rourunisen.tapauth.data

import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Registration semantics of the paired-device observer registry.
 *
 * Both transports hold an observer (the UDP temporal-ID cache and the BLE temporal-ID index), so a
 * registry that keeps a single slot silently drops one of them: that is the defect these tests are
 * aimed at.
 */
class DeviceChangeListenersTest {

    private val registry = DeviceChangeListeners()

    @Test
    fun everyRegisteredObserverIsInvoked() {
        val udpRuns = AtomicInteger(0)
        val bleRuns = AtomicInteger(0)
        registry.add { udpRuns.incrementAndGet() }
        registry.add { bleRuns.incrementAndGet() }
        assertEquals(2, registry.size)

        registry.dispatch()

        assertEquals("both transports must be notified", 1, udpRuns.get())
        assertEquals("both transports must be notified", 1, bleRuns.get())
    }

    @Test
    fun removedObserverIsNotInvoked() {
        val keptRuns = AtomicInteger(0)
        val removedRuns = AtomicInteger(0)
        val kept: () -> Unit = { keptRuns.incrementAndGet() }
        val removed: () -> Unit = { removedRuns.incrementAndGet() }
        registry.add(kept)
        registry.add(removed)

        assertTrue(registry.remove(removed))
        registry.dispatch()

        assertEquals(1, keptRuns.get())
        assertEquals("a stopped service must not keep being notified", 0, removedRuns.get())
        assertEquals(1, registry.size)
    }

    @Test
    fun duplicateRegistrationIsIdempotent() {
        val runs = AtomicInteger(0)
        val listener: () -> Unit = { runs.incrementAndGet() }

        assertTrue(registry.add(listener))
        assertFalse("registering the same observer twice must be a no-op", registry.add(listener))

        registry.dispatch()

        assertEquals(1, registry.size)
        assertEquals(1, runs.get())
    }

    @Test
    fun observerRemovingItselfDuringDispatchDoesNotDisturbTheOthers() {
        val selfRuns = AtomicInteger(0)
        val laterRuns = AtomicInteger(0)
        var self: (() -> Unit)? = null
        self = {
            selfRuns.incrementAndGet()
            registry.remove(self!!)
        }
        registry.add(self)
        registry.add { laterRuns.incrementAndGet() }

        registry.dispatch()

        assertEquals(1, selfRuns.get())
        assertEquals(
            "an observer after the one that unregistered must still run",
            1,
            laterRuns.get(),
        )
        assertEquals(1, registry.size)
    }

    @Test
    fun clearRemovesEveryObserverAndStaysUsable() {
        val runs = AtomicInteger(0)
        registry.add { runs.incrementAndGet() }
        registry.add { runs.incrementAndGet() }

        registry.clear()
        registry.dispatch()
        assertEquals(0, registry.size)
        assertEquals(0, runs.get())

        // Registration after a clear must work again (no stale generation of listeners).
        registry.add { runs.incrementAndGet() }
        registry.dispatch()
        assertEquals(1, runs.get())
    }
}
