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
 * - After the burst window, every subsequent request escalates the backoff (1s → 2s → 4s → 5s max).
 * - If a client has been silent for at least [MAX_BACKOFF_SECONDS], the backoff resets to
 *   [INITIAL_BACKOFF_SECONDS]. This prevents permanent penalty for infrequent legitimate users
 *   while still blocking 1Hz spam (spammers never wait 5s).
 * - The cooldown timer updates on every request (accepted or rejected); a client must stop sending
 *   for the full cooldown duration before the next request is accepted.
 * - State is fully reset on session end (grant, cancel, deny, timeout).
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
        val now = android.os.SystemClock.elapsedRealtime()

        var accepted = false
        clientBackoffs.compute(clientPublicKey) { _, existing ->
            if (existing == null) {
                accepted = true
                return@compute BackoffState(now, INITIAL_BACKOFF_SECONDS)
            }

            val timeInBurstWindow = now - existing.burstWindowStart
            if (timeInBurstWindow < BURST_WINDOW_MS && existing.requestCount < BURST_MAX) {
                accepted = true
                Log.d(
                    TAG,
                    "Burst-accepting request #${existing.requestCount + 1} from $clientPublicKey",
                )
                return@compute existing.copy(
                    lastRequestTime = now,
                    requestCount = existing.requestCount + 1,
                )
            }

            val elapsedMs = now - existing.lastRequestTime
            val backoffMs = existing.backoffSeconds * 1000L

            if (elapsedMs < backoffMs) {
                accepted = false
                val remaining = existing.backoffSeconds - (elapsedMs / 1000)
                Log.w(TAG, "Rate limiting client $clientPublicKey: ${remaining}s remaining")

                val newBackoff = min(existing.backoffSeconds * 2, MAX_BACKOFF_SECONDS)
                return@compute existing.copy(
                    lastRequestTime = now,
                    backoffSeconds = newBackoff,
                    requestCount = BURST_MAX,
                )
            }

            accepted = true
            val newBackoff =
                if (elapsedMs >= MAX_BACKOFF_SECONDS * 1000L) {
                    INITIAL_BACKOFF_SECONDS
                } else {
                    min(existing.backoffSeconds * 2, MAX_BACKOFF_SECONDS)
                }
            Log.d(TAG, "Accepting request from $clientPublicKey, new backoff: ${newBackoff}s")
            if (timeInBurstWindow >= BURST_WINDOW_MS) {
                return@compute BackoffState(
                    lastRequestTime = now,
                    backoffSeconds = newBackoff,
                    requestCount = 1,
                    burstWindowStart = now,
                )
            } else {
                return@compute existing.copy(lastRequestTime = now, backoffSeconds = newBackoff)
            }
        }
        return accepted
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
        val now = android.os.SystemClock.elapsedRealtime()
        var removed = 0

        val iterator = clientBackoffs.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastRequestTime > CLEANUP_AGE_MS) {
                if (clientBackoffs.remove(entry.key, entry.value)) {
                    removed++
                }
            }
        }

        if (removed > 0) {
            Log.d(TAG, "Cleaned up $removed expired backoff states")
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
        private const val CLEANUP_AGE_MS = CLEANUP_AGE_SECONDS * 1000L
    }
}
