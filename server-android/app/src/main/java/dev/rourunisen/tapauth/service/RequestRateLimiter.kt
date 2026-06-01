package dev.rourunisen.tapauth.service

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * Rate limiter for post-authentication requests.
 *
 * Implements burst-tolerant escalating backoff:
 * - First [BURST_MAX] requests within [BURST_WINDOW_MS] are all accepted without penalty, allowing
 *   concurrent multi-transport delivery (BLE + UDP) and network retransmissions.
 * - After the burst window, requests outside the cooldown period are accepted but do NOT escalate
 *   the backoff. Escalation only happens when a request is *rejected* (i.e. arrives during the
 *   active cooldown).
 * - Escalation sequence: 1s → 2s → 4s → 5s (capped).
 * - Reset: On successful authentication, cancel, or timeout.
 *
 * This prevents notification spam from malicious or malfunctioning clients without penalizing
 * legitimate multi-transport or retransmission traffic.
 */
class RequestRateLimiter {

    private data class BackoffState(
        val lastRequestTime: Long,
        val backoffSeconds: Int,
        val requestCount: Int = 1,
        val burstWindowStart: Long = lastRequestTime,
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
            clientBackoffs[clientPublicKey] = BackoffState(now, INITIAL_BACKOFF_SECONDS)
            return true
        }

        val timeInBurstWindow = now - state.burstWindowStart
        if (timeInBurstWindow < BURST_WINDOW_MS && state.requestCount < BURST_MAX) {
            // Within burst allowance: accept without penalty
            clientBackoffs[clientPublicKey] =
                state.copy(lastRequestTime = now, requestCount = state.requestCount + 1)
            Log.d(TAG, "Burst-accepting request #${state.requestCount + 1} from $clientPublicKey")
            return true
        }

        val timeSinceLastRequest = (now - state.lastRequestTime) / 1000

        if (timeSinceLastRequest < state.backoffSeconds) {
            val remaining = state.backoffSeconds - timeSinceLastRequest
            Log.w(TAG, "Rate limiting client $clientPublicKey: ${remaining}s remaining")

            // Escalate backoff only when a request is actually rejected
            val newBackoff = min(state.backoffSeconds * 2, MAX_BACKOFF_SECONDS)
            clientBackoffs[clientPublicKey] = BackoffState(now, newBackoff)

            return false
        }

        // Cooldown expired: accept but do NOT escalate (no penalty for legitimate retransmissions)
        clientBackoffs[clientPublicKey] = state.copy(lastRequestTime = now)

        Log.d(
            TAG,
            "Accepting request from $clientPublicKey, backoff unchanged: ${state.backoffSeconds}s",
        )
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
     * Clean up old backoff states to prevent memory leaks. Call periodically (e.g., every 5
     * minutes).
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

        // Maximum requests accepted without penalty within the burst window
        private const val BURST_MAX = 3

        // Burst window: 2 seconds. Requests within this window from the same client
        // are counted toward the burst allowance before any backoff is applied.
        private const val BURST_WINDOW_MS = 2000L

        // Initial backoff: 1 second (applied only after burst allowance is exhausted)
        private const val INITIAL_BACKOFF_SECONDS = 1

        // Maximum backoff: 5 seconds
        private const val MAX_BACKOFF_SECONDS = 5

        // Remove backoff states older than 5 minutes
        private const val CLEANUP_AGE_SECONDS = 300
    }
}
