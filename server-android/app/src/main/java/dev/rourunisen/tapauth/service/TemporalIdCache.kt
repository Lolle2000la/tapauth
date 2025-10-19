package dev.rourunisen.tapauth.service

import android.util.Log
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.crypto.generateTemporalId
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Pre-authentication DoS mitigation via temporal identifier caching.
 * 
 * Per specification:
 * - Pre-calculate valid temporal_identifiers for all paired clients
 * - Cache both current and previous time window IDs
 * - Check incoming packets against cache before attempting decryption
 * - Silently drop packets with invalid temporal IDs
 * 
 * This prevents resource exhaustion from replay attacks by avoiding
 * expensive HMAC and decryption operations on invalid packets.
 */
class TemporalIdCache(
    private val deviceRepository: DeviceRepository,
    private val scope: CoroutineScope
) {
    
    // Maps temporal_id (hex string) -> client device ID
    private val validIds = ConcurrentHashMap<String, String>()
    
    private var updateJob: Job? = null
    
    /**
     * Start the cache update loop.
     * Updates cache on startup and every 60 seconds (when time window changes).
     */
    fun start() {
        stop()
        
        // Initial update (launch in coroutine)
        scope.launch {
            updateCache()
        }
        
        // Schedule periodic updates
        updateJob = scope.launch(Dispatchers.Default) {
            while (isActive) {
                try {
                    // Wait until the next time window boundary
                    val now = System.currentTimeMillis()
                    val nextWindowStart = ((now / TIME_WINDOW_MS) + 1) * TIME_WINDOW_MS
                    val delayMs = nextWindowStart - now
                    
                    Log.d(TAG, "Next cache update in ${delayMs}ms")
                    delay(delayMs + 100)  // Add 100ms buffer
                    
                    updateCache()
                } catch (e: Exception) {
                    if (isActive) {
                        Log.e(TAG, "Error in update loop", e)
                        delay(5000)  // Wait 5s before retry
                    }
                }
            }
        }
        
        Log.d(TAG, "Started temporal ID cache")
    }
    
    /**
     * Stop the cache update loop.
     */
    fun stop() {
        updateJob?.cancel()
        updateJob = null
        validIds.clear()
        Log.d(TAG, "Stopped temporal ID cache")
    }
    
    /**
     * Check if the given temporal identifier is valid.
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
        val deviceId = validIds[idHex]
        
        return if (deviceId != null) {
            Pair(true, deviceId)
        } else {
            Pair(false, null)
        }
    }
    
    /**
     * Generate temporal identifier for a given timestamp and CSK
     */
    private fun generateTemporalIdentifier(csk: ByteArray, timestampMs: Long): String {
        val timestampSeconds = timestampMs / 1000
        return generateTemporalId(csk, timestampSeconds)
    }
    
    /**
     * Update the cache with current and previous time window IDs.
     */
    private suspend fun updateCache() {
        try {
            val pairedDevices = deviceRepository.getAllPairedDevices()
            val now = System.currentTimeMillis()
            val currentWindow = now / TIME_WINDOW_MS
            val previousWindow = currentWindow - 1
            
            // Clear old cache
            validIds.clear()
            
            // For each paired device, calculate both time windows
            for (device in pairedDevices) {
                try {
                    // Current time window (timestamp in seconds)
                    val currentIdHex = generateTemporalIdentifier(device.csk, currentWindow * TIME_WINDOW_MS)
                    validIds[currentIdHex] = device.deviceId
                    
                    // Previous time window (for clock skew tolerance)
                    val previousIdHex = generateTemporalIdentifier(device.csk, previousWindow * TIME_WINDOW_MS)
                    validIds[previousIdHex] = device.deviceId
                    
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to generate temporal IDs for device ${device.deviceId}", e)
                }
            }
            
            Log.d(TAG, "Updated cache: ${validIds.size} valid temporal IDs for ${pairedDevices.size} devices")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update cache", e)
        }
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
