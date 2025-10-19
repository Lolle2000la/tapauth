package dev.rourunisen.tapauth.service

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * Rate limiter for post-authentication requests.
 * 
 * Implements escalating backoff per specification:
 * - After receiving a valid AuthenticationRequest from a client, subsequent requests
 *   from the same client are ignored for a cooldown period
 * - Initial cooldown: 1 second
 * - Escalation: Doubles on each subsequent request (2s, 4s, 8s, 16s, 32s)
 * - Maximum cooldown: 60 seconds
 * - Reset: On successful authentication, cancel, or timeout
 * 
 * This prevents notification spam from malicious or malfunctioning clients.
 */
class RequestRateLimiter {
    
    private data class BackoffState(
        val lastRequestTime: Long,
        val backoffSeconds: Int
    )
    
    private val clientBackoffs = ConcurrentHashMap<String, BackoffState>()
    
    /**
     * Check if a request from the given client should be accepted.
     * 
     * @param clientPublicKey The client's Ed25519 public key (hex string)
     * @return true if request should be accepted, false if rate limited
     */
    fun shouldAcceptRequest(clientPublicKey: String): Boolean {
        val now = System.currentTimeMillis()
        val state = clientBackoffs[clientPublicKey]
        
        if (state == null) {
            // First request from this client
            clientBackoffs[clientPublicKey] = BackoffState(now, INITIAL_BACKOFF_SECONDS)
            return true
        }
        
        val timeSinceLastRequest = (now - state.lastRequestTime) / 1000  // Convert to seconds
        
        if (timeSinceLastRequest < state.backoffSeconds) {
            // Still in cooldown period
            Log.w(TAG, "Rate limiting client $clientPublicKey: ${state.backoffSeconds - timeSinceLastRequest}s remaining")
            return false
        }
        
        // Cooldown expired, accept request but escalate backoff
        val newBackoff = min(state.backoffSeconds * 2, MAX_BACKOFF_SECONDS)
        clientBackoffs[clientPublicKey] = BackoffState(now, newBackoff)
        
        Log.d(TAG, "Accepting request from $clientPublicKey, new backoff: ${newBackoff}s")
        return true
    }
    
    /**
     * Reset the rate limit for a client.
     * 
     * Call this when:
     * - User successfully authenticates
     * - User cancels authentication
     * - Authentication times out
     */
    fun resetClient(clientPublicKey: String) {
        clientBackoffs.remove(clientPublicKey)
        Log.d(TAG, "Reset rate limit for client $clientPublicKey")
    }
    
    /**
     * Clean up old backoff states to prevent memory leaks.
     * Call periodically (e.g., every 5 minutes).
     */
    fun cleanup() {
        val now = System.currentTimeMillis()
        val expiredClients = mutableListOf<String>()
        
        for ((clientKey, state) in clientBackoffs) {
            val ageSeconds = (now - state.lastRequestTime) / 1000
            if (ageSeconds > CLEANUP_AGE_SECONDS) {
                expiredClients.add(clientKey)
            }
        }
        
        expiredClients.forEach { clientBackoffs.remove(it) }
        
        if (expiredClients.isNotEmpty()) {
            Log.d(TAG, "Cleaned up ${expiredClients.size} expired backoff states")
        }
    }
    
    companion object {
        private const val TAG = "RequestRateLimiter"
        
        // Initial backoff: 1 second
        private const val INITIAL_BACKOFF_SECONDS = 1
        
        // Maximum backoff: 60 seconds
        private const val MAX_BACKOFF_SECONDS = 60
        
        // Remove backoff states older than 5 minutes
        private const val CLEANUP_AGE_SECONDS = 300
    }
}
