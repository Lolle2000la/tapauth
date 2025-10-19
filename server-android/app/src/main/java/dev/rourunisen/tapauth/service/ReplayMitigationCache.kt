package dev.rourunisen.tapauth.service

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs

/**
 * Cache for mitigating replay attacks according to authentication-flow.md Section 2.2.
 * 
 * Implements two defenses:
 * 1. Nonce Check (Primary): Maintains cache of all received challenge nonces
 * 2. Timestamp Check (Secondary): Validates 60-second validity window
 */
class ReplayMitigationCache {
    
    private val challengeCache = ConcurrentHashMap<String, Long>()
    
    companion object {
        private const val TAG = "ReplayMitigationCache"
        private const val TIMESTAMP_VALIDITY_SECONDS = 60L // 60-second validity window per spec
        private const val CACHE_EXPIRY_SECONDS = 120L // 120-second session timeout per spec
        
        @Volatile
        private var instance: ReplayMitigationCache? = null
        
        fun getInstance(): ReplayMitigationCache {
            return instance ?: synchronized(this) {
                instance ?: ReplayMitigationCache().also { instance = it }
            }
        }
    }
    
    /**
     * Check if a request is a replay attack.
     * 
     * @param challenge The challenge nonce from the authentication request
     * @param timestampUnixSeconds The timestamp from the authentication request
     * @return true if the request is a replay (should be rejected), false otherwise
     */
    fun isReplay(challenge: ByteArray, timestampUnixSeconds: Long): Boolean {
        val challengeHex = challenge.toHex()
        val nowSeconds = System.currentTimeMillis() / 1000
        
        // Defense 1: Timestamp Check (Secondary Defense)
        // Reject if timestamp is outside the 60-second validity window
        val timestampDelta = abs(nowSeconds - timestampUnixSeconds)
        if (timestampDelta > TIMESTAMP_VALIDITY_SECONDS) {
            Log.w(TAG, "Replay detected: Stale timestamp (delta=${timestampDelta}s, threshold=${TIMESTAMP_VALIDITY_SECONDS}s)")
            return true
        }
        
        // Defense 2: Nonce Check (Primary Defense)
        // Reject if we've seen this challenge before
        if (challengeCache.containsKey(challengeHex)) {
            Log.w(TAG, "Replay detected: Challenge nonce already seen (challenge=${challengeHex.take(16)}...)")
            return true
        }
        
        // Clean expired entries periodically
        cleanExpired()
        
        // Add this challenge to the cache with its expiry time
        val expiryTime = nowSeconds + CACHE_EXPIRY_SECONDS
        challengeCache[challengeHex] = expiryTime
        
        Log.d(TAG, "Challenge accepted (cache size=${challengeCache.size}, challenge=${challengeHex.take(16)}...)")
        return false
    }
    
    /**
     * Remove expired entries from the cache.
     * Called periodically during isReplay() checks.
     */
    private fun cleanExpired() {
        val nowSeconds = System.currentTimeMillis() / 1000
        val sizeBefore = challengeCache.size
        
        challengeCache.entries.removeIf { (_, expiryTime) ->
            expiryTime < nowSeconds
        }
        
        val sizeAfter = challengeCache.size
        if (sizeBefore != sizeAfter) {
            Log.d(TAG, "Cleaned ${sizeBefore - sizeAfter} expired entries from cache (remaining=${sizeAfter})")
        }
    }
    
    /**
     * Clear all cached challenges. Useful for testing or manual cache reset.
     */
    fun clear() {
        challengeCache.clear()
        Log.d(TAG, "Cache cleared")
    }
    
    /**
     * Get current cache statistics for debugging.
     */
    fun getStats(): Map<String, Any> {
        return mapOf(
            "cache_size" to challengeCache.size,
            "oldest_entry_age_seconds" to getOldestEntryAge()
        )
    }
    
    private fun getOldestEntryAge(): Long {
        val nowSeconds = System.currentTimeMillis() / 1000
        return challengeCache.values.minOrNull()?.let { oldestExpiry ->
            nowSeconds - (oldestExpiry - CACHE_EXPIRY_SECONDS)
        } ?: 0
    }
}

/**
 * Extension function to convert ByteArray to hex string
 */
private fun ByteArray.toHex(): String {
    return joinToString("") { "%02x".format(it) }
}
