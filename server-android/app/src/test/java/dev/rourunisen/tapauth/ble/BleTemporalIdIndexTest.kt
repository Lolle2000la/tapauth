package dev.rourunisen.tapauth.ble

import dev.rourunisen.tapauth.data.PairedDevice
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Bookkeeping of [BleTemporalIdIndex]: when it rebuilds, and which identifiers resolve.
 *
 * The identifier functions are stand-ins for the Rust HMAC (a JDK digest over CSK‖window) so the
 * index can run on the JVM; what is under test is when the maps are rebuilt and what they are keyed
 * on, not the derivation itself.
 */
class BleTemporalIdIndexTest {

    private var window = 28_333_333L
    private val deviceReads = AtomicInteger(0)
    private val devices = mutableListOf<PairedDevice>()
    private var failForCsk: ByteArray? = null

    private val index =
        BleTemporalIdIndex(
            devices = {
                deviceReads.incrementAndGet()
                devices.toList()
            },
            currentWindow = { window },
            advertisementId = { csk, atWindow, _ ->
                derive(csk, atWindow, ADVERTISEMENT_BYTES)
            },
            packetId = { csk, atWindow, _ -> derive(csk, atWindow, PACKET_BYTES) },
        )

    private val cskA = ByteArray(32) { 0x11 }
    private val cskB = ByteArray(32) { 0x22 }
    private val deviceA = device("device-a", cskA)
    private val deviceB = device("device-b", cskB)

    @Test
    fun devicePairedMidWindowResolvesImmediately() {
        assertNull(index.lookupPacket(packetIdHex(cskA)))

        // Paired while the 60 s window is still the same: only the device-change notification
        // arrives, no window rollover.
        devices.add(deviceA)
        index.invalidate()

        assertEquals(deviceA, index.lookupPacket(packetIdHex(cskA)))
        assertEquals(deviceA, index.lookupAdvertisement(advertisementIdHex(cskA)))
        // The previous window is indexed too, so a packet sent just before a rollover resolves.
        assertEquals(deviceA, index.lookupPacket(packetIdHex(cskA, window - 1)))
    }

    @Test
    fun deviceRemovedMidWindowStopsResolvingImmediately() {
        devices.add(deviceA)
        devices.add(deviceB)
        index.invalidate()
        assertEquals(deviceA, index.lookupPacket(packetIdHex(cskA)))
        assertEquals(deviceB, index.lookupPacket(packetIdHex(cskB)))

        devices.remove(deviceB)
        index.invalidate()

        assertNull(index.lookupPacket(packetIdHex(cskB)))
        assertNull(index.lookupAdvertisement(advertisementIdHex(cskB)))
        assertEquals(
            "the remaining pairing must still resolve",
            deviceA,
            index.lookupPacket(packetIdHex(cskA)),
        )
    }

    @Test
    fun lookupsDoNotReReadTheDeviceList() {
        devices.add(deviceA)
        index.refresh()
        val readsAfterWarmUp = deviceReads.get()

        repeat(100) {
            index.lookupPacket(packetIdHex(cskA))
            index.lookupAdvertisement(advertisementIdHex(cskA))
        }

        assertEquals(
            "lookups must be map reads, not a device-list rebuild",
            readsAfterWarmUp,
            deviceReads.get(),
        )
    }

    @Test
    fun windowRolloverRebuildsWithoutInvalidation() {
        devices.add(deviceA)
        index.refresh()
        assertEquals(deviceA, index.lookupPacket(packetIdHex(cskA)))

        // Two windows later the identifiers have rolled: the old one is neither current nor
        // previous any more, the new one must resolve without anyone calling invalidate().
        window += 2

        assertNull(index.lookupPacket(packetIdHex(cskA, window - 2)))
        assertEquals(deviceA, index.lookupPacket(packetIdHex(cskA)))
    }

    @Test
    fun advertisementAndPacketIdentifiersDoNotMix() {
        devices.add(deviceA)
        index.refresh()

        assertNull(index.lookupPacket(advertisementIdHex(cskA)))
        assertNull(index.lookupAdvertisement(packetIdHex(cskA)))
        assertEquals(deviceA, index.lookupPacket(packetIdHex(cskA)))
        assertEquals(deviceA, index.lookupAdvertisement(advertisementIdHex(cskA)))
    }

    @Test
    fun unusableCskSkipsOnlyThatDevice() {
        failForCsk = cskB
        devices.add(deviceA)
        devices.add(deviceB)

        index.refresh()

        assertEquals(deviceA, index.lookupPacket(packetIdHex(cskA)))
        assertNull(index.lookupPacket(packetIdHex(cskB)))
    }

    /** Stand-in for the Rust HMAC: a JDK digest over CSK‖window, truncated to the wire length. */
    private fun digest(csk: ByteArray, atWindow: Long, size: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(csk)
        digest.update(ByteBuffer.allocate(8).putLong(atWindow).array())
        return digest.digest().copyOf(size)
    }

    private fun derive(csk: ByteArray, atWindow: Long, size: Int): ByteArray {
        if (failForCsk != null && csk.contentEquals(failForCsk)) {
            throw IllegalArgumentException("unusable CSK")
        }
        return digest(csk, atWindow, size)
    }

    private fun packetIdHex(csk: ByteArray, atWindow: Long = window): String =
        digest(csk, atWindow, PACKET_BYTES).toHex()

    private fun advertisementIdHex(csk: ByteArray, atWindow: Long = window): String =
        digest(csk, atWindow, ADVERTISEMENT_BYTES).toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun device(id: String, csk: ByteArray) =
        PairedDevice(
            deviceId = id,
            publicKey = ByteArray(32) { 0x33 },
            csk = csk,
            displayName = id,
            pairedAt = 0L,
            allowedUsers = listOf("alice"),
        )

    private companion object {
        const val ADVERTISEMENT_BYTES = 10
        const val PACKET_BYTES = 16
    }
}
