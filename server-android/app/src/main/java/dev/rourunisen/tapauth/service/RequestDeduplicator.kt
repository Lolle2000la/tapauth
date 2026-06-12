package dev.rourunisen.tapauth.service

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * De-duplicates identical request payloads within a sliding time window.
 *
 * When the same authentication request arrives multiple times (e.g., network retransmissions,
 * concurrent multi-transport delivery over BLE + UDP), this class ensures only the first instance
 * is evaluated. Subsequent duplicates within [DEDUP_WINDOW_MS] return the cached accept/reject
 * result without affecting rate-limiter backoff state.
 *
 * Thread-safe: backed by [ConcurrentHashMap].
 */
class RequestDeduplicator {

    private data class DeduplicationEntry(val timestamp: Long, val accepted: Boolean)

    private val recentRequests = ConcurrentHashMap<String, DeduplicationEntry>()

    /**
     * Check if a request with the given identifier was recently seen.
     *
     * @param requestIdentifier An opaque identifier for the request (e.g., SHA-256 hash of the
     *   decrypted message payload).
     * @return The cached result if this is a duplicate within the dedup window, or `null` if this
     *   is a new request that should be evaluated normally.
     */
    fun checkDuplicate(requestIdentifier: String): Boolean? {
        val now = android.os.SystemClock.elapsedRealtime()
        val existing = recentRequests[requestIdentifier]
        if (existing != null) {
            if ((now - existing.timestamp) < DEDUP_WINDOW_MS) {
                Log.d(TAG, "De-duplicate hit for request $requestIdentifier: ${existing.accepted}")
                return existing.accepted
            } else {
                recentRequests.remove(requestIdentifier, existing)
            }
        }
        return null
    }

    /**
     * Record the result of a request evaluation for future de-duplication.
     *
     * @param requestIdentifier The opaque identifier for the request.
     * @param accepted Whether the request was accepted or rejected by the rate limiter.
     */
    fun record(requestIdentifier: String, accepted: Boolean) {
        val now = android.os.SystemClock.elapsedRealtime()
        recentRequests.compute(requestIdentifier) { _, existing ->
            if (existing != null && existing.accepted && !accepted) {
                existing
            } else {
                DeduplicationEntry(now, accepted)
            }
        }
    }

    /**
     * Remove expired deduplication entries. Call periodically (e.g., every 5 minutes) to prevent
     * memory leaks.
     *
     * @return The number of entries removed.
     */
    fun cleanup(): Int {
        val now = android.os.SystemClock.elapsedRealtime()
        var removed = 0

        val iterator = recentRequests.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.timestamp > DEDUP_WINDOW_MS) {
                if (recentRequests.remove(entry.key, entry.value)) {
                    removed++
                }
            }
        }

        return removed
    }

    companion object {
        private const val TAG = "RequestDeduplicator"

        // De-duplication window: 2 seconds. Requests with the same identifier within
        // this window return the cached result without affecting backoff state.
        private const val DEDUP_WINDOW_MS = 2000L
    }
}
