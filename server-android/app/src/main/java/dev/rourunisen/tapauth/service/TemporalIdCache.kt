package dev.rourunisen.tapauth.service

import android.util.Log
import dev.rourunisen.tapauth.crypto.generateTemporalId
import dev.rourunisen.tapauth.data.DeviceRepository
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * Pre-authentication DoS mitigation via temporal identifier caching.
 *
 * Per specification:
 * - Pre-calculate valid temporal_identifiers for all paired clients
 * - Cache both current and previous time window IDs
 * - Check incoming packets against cache before attempting decryption
 * - Silently drop packets with invalid temporal IDs
 *
 * The precomputed ID set is refreshed when the 60s window rolls over (checked lazily on the first
 * packet of a new window, so a Doze-frozen coroutine loop can never leave it stale) and immediately
 * whenever the paired-device list changes.
 */
class TemporalIdCache(
    private val deviceRepository: DeviceRepository,
    private val scope: CoroutineScope,
) {

    // Maps temporal_id (hex string) -> client device ID
    @Volatile private var validIds = ConcurrentHashMap<String, String>()

    @Volatile private var cachedDevices: List<CachedDevice> = emptyList()
    @Volatile private var lastComputedWindow: Long = -1

    /**
     * Whether the paired-device list has been successfully read at least once.
     *
     * Distinguishes "not loaded yet" (retry the disk read when a packet arrives) from "loaded and
     * genuinely empty" (trust the [DeviceRepository] change listener for additions and never touch
     * disk on the packet path — otherwise every packet against a device with zero paired devices
     * would trigger a SharedPreferences read + JSON parse).
     */
    @Volatile private var devicesLoaded = false

    private data class CachedDevice(val deviceId: String, val csk: ByteArray)

    fun start() {
        stop()
        DeviceRepository.setOnDevicesChangedListener {
            scope.launch { refreshDeviceList() }
        }
        scope.launch { refreshDeviceList() }
        Log.d(TAG, "Started temporal ID cache")
    }

    fun stop() {
        DeviceRepository.setOnDevicesChangedListener(null)
        validIds.clear()
        cachedDevices = emptyList()
        lastComputedWindow = -1
        devicesLoaded = false
        Log.d(TAG, "Stopped temporal ID cache")
    }

    /**
     * Check if the given temporal identifier is valid.
     *
     * Uses in-memory O(1) cache lookup across precomputed current and previous time windows for all
     * paired devices, providing instantaneous verification without disk I/O or JNI overhead.
     *
     * @param temporalId The 16-byte temporal identifier from the packet
     * @return Pair of (isValid, deviceId) - deviceId is null if invalid
     */
    fun isValidTemporalId(temporalId: ByteArray): Pair<Boolean, String?> {
        if (temporalId.size != 16) {
            Log.w(TAG, "Invalid temporal ID length: ${temporalId.size}")
            return Pair(false, null)
        }

        val idHex = temporalId.toHex()
        ensureCacheIsCurrent()

        val deviceId = validIds[idHex]
        return if (deviceId != null) {
            Pair(true, deviceId)
        } else {
            Pair(false, null)
        }
    }

    private fun ensureCacheIsCurrent() {
        val now = System.currentTimeMillis()
        val currentWindow = now / TIME_WINDOW_MS

        if (currentWindow != lastComputedWindow || !devicesLoaded) {
            synchronized(this) {
                if (currentWindow != lastComputedWindow || !devicesLoaded) {
                    recomputeCache(currentWindow)
                }
            }
        }
    }

    private fun recomputeCache(currentWindow: Long) {
        var devices = cachedDevices
        if (!devicesLoaded) {
            // Lazy-path reload: the first packet can arrive before start()'s initial
            // refreshDeviceList() completes, so load the paired devices here as well. Only a
            // successful load (or a refreshDeviceList() call) sets devicesLoaded; a load failure
            // returns early without advancing lastComputedWindow so the next packet retries.
            devices =
                deviceRepository.getAllPairedDevicesSync().map {
                    CachedDevice(it.deviceId, it.csk)
                }
            cachedDevices = devices
            devicesLoaded = true
        }

        validIds = computeValidIds(devices, currentWindow)
        lastComputedWindow = currentWindow
        Log.d(
            TAG,
            "Recomputed cache on-demand: ${validIds.size} valid IDs for ${devices.size} devices",
        )
    }

    suspend fun refreshDeviceList() {
        try {
            val pairedDevices = deviceRepository.getAllPairedDevices()
            val mapped = pairedDevices.map { CachedDevice(it.deviceId, it.csk) }
            synchronized(this) {
                cachedDevices = mapped
                devicesLoaded = true
                val currentWindow = System.currentTimeMillis() / TIME_WINDOW_MS
                validIds = computeValidIds(mapped, currentWindow)
                lastComputedWindow = currentWindow
            }
            Log.d(TAG, "Refreshed device list: ${mapped.size} paired devices")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to refresh device list", e)
        }
    }

    /**
     * Compute the valid temporal ID set for [devices] across the current and previous 60s windows.
     */
    private fun computeValidIds(
        devices: List<CachedDevice>,
        currentWindow: Long,
    ): ConcurrentHashMap<String, String> {
        val previousWindow = currentWindow - 1
        val newIds = ConcurrentHashMap<String, String>()

        for (device in devices) {
            try {
                newIds[generateTemporalIdentifier(device.csk, currentWindow * TIME_WINDOW_MS)] =
                    device.deviceId

                newIds[generateTemporalIdentifier(device.csk, previousWindow * TIME_WINDOW_MS)] =
                    device.deviceId
            } catch (e: Exception) {
                Log.w(TAG, "Failed to generate temporal IDs for device ${device.deviceId}", e)
            }
        }

        return newIds
    }

    private fun generateTemporalIdentifier(csk: ByteArray, timestampMs: Long): String {
        val timestampSeconds = timestampMs / 1000
        return generateTemporalId(csk, timestampSeconds).toHex()
    }

    private fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val TAG = "TemporalIdCache"

        // Time window: 60 seconds (60,000 milliseconds)
        private const val TIME_WINDOW_MS = 60_000L
    }
}
