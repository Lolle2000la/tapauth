package dev.rourunisen.tapauth.ble

import dev.rourunisen.tapauth.crypto.currentTimeWindow
import dev.rourunisen.tapauth.crypto.generateBleTemporalIdentifier
import dev.rourunisen.tapauth.crypto.generateTemporalIdentifier
import dev.rourunisen.tapauth.data.PairedDevice
import java.util.concurrent.atomic.AtomicLong

/**
 * Temporal-identifier index for the BLE paths, in two namespaces:
 * - [lookupAdvertisement] takes the 10-byte identifier carried in the advertisement's Service Data
 *   (`generateBleTemporalIdentifier`, the truncated form).
 * - [lookupPacket] takes the 16-byte identifier inside a GATT `EncryptedPacket`
 *   (`generateTemporalIdentifier`), the same derivation UDP uses.
 *
 * Both are one map read. The maps are rebuilt only when the 60 s window rolls over or when the
 * paired-device list changed ([invalidate]), never per advertisement and never per GATT packet —
 * the previous code re-read every device from disk and re-derived every identifier for each
 * incoming packet, and could not see a device paired mid-window at all.
 *
 * Each identifier is derived for the current and the previous window, so a request sent just before
 * a rollover still resolves. Window derivation and HMAC input are identical to
 * [dev.rourunisen.tapauth.service.TemporalIdCache]: `unix_seconds / 60`, hashed with the algorithm
 * the pairing negotiated.
 */
internal class BleTemporalIdIndex(
    private val devices: () -> List<PairedDevice>,
    private val currentWindow: () -> Long = { currentTimeWindow() },
    private val advertisementId: (ByteArray, Long, Int) -> ByteArray = { csk, window, algorithm ->
        generateBleTemporalIdentifier(csk, window, algorithm)
    },
    private val packetId: (ByteArray, Long, Int) -> ByteArray = { csk, window, algorithm ->
        generateTemporalIdentifier(csk, window, algorithm)
    },
) {

    private class Snapshot(
        /** Window the identifiers were derived for. */
        val window: Long,
        /**
         * [generation] when the rebuild started; a later [invalidate] makes this snapshot stale.
         */
        val generation: Long,
        val advertisements: Map<String, PairedDevice>,
        val packets: Map<String, PairedDevice>,
    )

    /** Bumped by [invalidate]; a rebuild that started before a bump cannot publish its result. */
    private val generation = AtomicLong(0)

    @Volatile private var snapshot: Snapshot? = null

    /** Mark the paired-device list as changed, so the next lookup rebuilds. */
    fun invalidate() {
        generation.incrementAndGet()
    }

    /** Rebuild now instead of on the next lookup (used to warm the index at service start). */
    fun refresh() {
        generation.incrementAndGet()
        current()
    }

    fun lookupAdvertisement(temporalIdHex: String): PairedDevice? =
        current().advertisements[temporalIdHex]

    fun lookupPacket(temporalIdHex: String): PairedDevice? = current().packets[temporalIdHex]

    private fun current(): Snapshot {
        val window = currentWindow()
        val existing = snapshot
        if (
            existing != null && existing.window == window && existing.generation == generation.get()
        ) {
            return existing
        }
        return synchronized(this) {
            val windowNow = currentWindow()
            val rebuilt =
                snapshot?.takeIf {
                    it.window == windowNow && it.generation == generation.get()
                } ?: rebuild(windowNow)
            snapshot = rebuilt
            rebuilt
        }
    }

    private fun rebuild(window: Long): Snapshot {
        // Read the generation before the device list: an invalidation that lands while this
        // rebuild runs then leaves the published snapshot with an older generation, so the next
        // lookup rebuilds again instead of serving a list that is already known to be stale.
        val startedAt = generation.get()
        val previousWindow = window - 1

        val advertisements = HashMap<String, PairedDevice>()
        val packets = HashMap<String, PairedDevice>()

        for (device in devices()) {
            try {
                advertisements[advertisementId(device.csk, window, device.hashAlgorithm).toHex()] =
                    device
                advertisements[
                    advertisementId(device.csk, previousWindow, device.hashAlgorithm).toHex()] =
                    device
                packets[packetId(device.csk, window, device.hashAlgorithm).toHex()] = device
                packets[packetId(device.csk, previousWindow, device.hashAlgorithm).toHex()] = device
            } catch (e: Exception) {
                // One pairing with an unusable CSK must not take the whole index down.
                android.util.Log.e(
                    "BleTemporalIdIndex",
                    "Failed to derive temporal IDs for device ${device.deviceId}",
                    e,
                )
            }
        }

        return Snapshot(window, startedAt, advertisements, packets)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
