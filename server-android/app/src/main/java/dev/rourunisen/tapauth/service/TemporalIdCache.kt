package dev.rourunisen.tapauth.service

import android.util.Log
import dev.rourunisen.tapauth.crypto.generateTemporalId
import dev.rourunisen.tapauth.data.DeviceRepository
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
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
 * Uses on-demand (lazy evaluation) to compute temporal IDs at the exact moment a packet arrives,
 * avoiding stale caches caused by Doze mode freezing background coroutine loops.
 */
class TemporalIdCache(
    private val deviceRepository: DeviceRepository,
    private val scope: CoroutineScope,
) {

    // Maps temporal_id (hex string) -> client device ID
    @Volatile private var validIds = ConcurrentHashMap<String, String>()

    @Volatile private var cachedDevices: List<CachedDevice> = emptyList()
    @Volatile private var lastComputedWindow: Long = -1

    private var deviceRefreshJob: Job? = null

    private data class CachedDevice(val deviceId: String, val csk: ByteArray)

    fun start() {
        stop()
        deviceRefreshJob = scope.launch { refreshDeviceList() }
        Log.d(TAG, "Started temporal ID cache")
    }

    fun stop() {
        deviceRefreshJob?.cancel()
        deviceRefreshJob = null
        validIds.clear()
        cachedDevices = emptyList()
        lastComputedWindow = -1
        Log.d(TAG, "Stopped temporal ID cache")
    }

    /**
     * Check if the given temporal identifier is valid.
     *
     * Uses on-demand computation: if the cached map doesn't contain the ID (e.g. after Doze),
     * recomputes temporal IDs for the current time window before returning.
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

        if (currentWindow != lastComputedWindow) {
            synchronized(this) {
                if (currentWindow != lastComputedWindow) {
                    recomputeCache(currentWindow)
                }
            }
        }
    }

    private fun recomputeCache(currentWindow: Long) {
        val devices = cachedDevices
        if (devices.isEmpty()) {
            lastComputedWindow = currentWindow
            return
        }

        val previousWindow = currentWindow - 1
        val newIds = ConcurrentHashMap<String, String>()

        for (device in devices) {
            try {
                val currentIdHex =
                    generateTemporalIdentifier(device.csk, currentWindow * TIME_WINDOW_MS)
                newIds[currentIdHex] = device.deviceId

                val previousIdHex =
                    generateTemporalIdentifier(device.csk, previousWindow * TIME_WINDOW_MS)
                newIds[previousIdHex] = device.deviceId
            } catch (e: Exception) {
                Log.w(TAG, "Failed to generate temporal IDs for device ${device.deviceId}", e)
            }
        }

        validIds = newIds
        lastComputedWindow = currentWindow
        Log.d(
            TAG,
            "Recomputed cache on-demand: ${newIds.size} valid IDs for ${devices.size} devices",
        )
    }

    suspend fun refreshDeviceList() {
        try {
            val pairedDevices = deviceRepository.getAllPairedDevices()
            cachedDevices = pairedDevices.map { CachedDevice(it.deviceId, it.csk) }
            lastComputedWindow = -1
            ensureCacheIsCurrent()
            Log.d(TAG, "Refreshed device list: ${cachedDevices.size} paired devices")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to refresh device list", e)
        }
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
