package dev.rourunisen.tapauth.service

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * Rate limiter for post-authentication requests.
 *
 * ### One limiter, both transports
 *
 * There is exactly one instance per process — [getInstance] — and both post-authentication paths
 * call it: the UDP path in [dev.rourunisen.tapauth.service.AuthenticationService] and the BLE path
 * in [dev.rourunisen.tapauth.ble.BleGattService]. They call [shouldAcceptAuthenticatedRequest],
 * which is where the two halves of "the same request" are fixed — the paired Client's Ed25519
 * public key and SHA-256 of the verified `WrapperMessage` — so a Client has one budget whichever
 * transport it hammers. A second limiter on the BLE path would be a second schedule to keep in sync
 * and a budget that doubles for a Client alternating transports; that is why the BLE path shares
 * this instance instead of constructing its own.
 *
 * Implements burst-tolerant escalating backoff with request de-duplication:
 * - First [BURST_MAX] requests within [BURST_WINDOW_MS] are all accepted without penalty, allowing
 *   concurrent multi-transport delivery (BLE + UDP) and network retransmissions.
 * - Duplicate requests (same [requestIdentifier]) are handled by [RequestDeduplicator]: they return
 *   the cached result without affecting backoff state.
 * - Backoff only escalates when a request is *rejected* (sent while cooldown is active). Accepted
 *   requests after cooldown expiry reset the backoff to [INITIAL_BACKOFF_SECONDS], since paired
 *   clients are trusted and the rate limiter targets third-party replay/DoS attacks only.
 * - [resetClient] clears a Client outright. The UDP path calls it at each point its own prompt
 *   callback resolves: a verified grant confirmation, a verified cancel, an explicit denial, and a
 *   timeout. The BLE path answers the same messages on its own link and does not call it, so a
 *   BLE-only Client's budget recovers through the cooldown above (which any request spaced more
 *   than one backoff period ago already reaches) and through [cleanup], never by a reset it did not
 *   get.
 *
 * This prevents notification spam from malicious or malfunctioning clients without penalizing
 * legitimate multi-transport or retransmission traffic.
 */
class RequestRateLimiter(
    private val timeProvider: () -> Long = { android.os.SystemClock.elapsedRealtime() },
) {

    private data class BackoffState(
        val lastRequestTime: Long,
        val backoffSeconds: Int,
        val requestCount: Int = 1,
        val burstWindowStart: Long = lastRequestTime,
    )

    private val clientBackoffs = ConcurrentHashMap<String, BackoffState>()
    private val deduplicator = RequestDeduplicator(timeProvider)

    /**
     * Check if a request from the given client should be accepted.
     *
     * @param clientPublicKey The client's Ed25519 public key (hex string)
     * @param requestIdentifier An opaque identifier for this specific request (e.g., hash of
     *   message payload). If a request with the same identifier was recently seen, the duplicate is
     *   handled without escalating backoff: accepted duplicates pass through, rejected duplicates
     *   are silently dropped.
     * @return true if request should be accepted, false if rate limited
     */
    fun shouldAcceptRequest(clientPublicKey: String, requestIdentifier: String? = null): Boolean {
        val dedupKey = requestIdentifier?.let { "$clientPublicKey:$it" }
        if (dedupKey != null) {
            val cached = deduplicator.checkDuplicate(dedupKey)
            if (cached != null) {
                return cached
            }
        }

        val now = timeProvider()
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
            Log.d(
                TAG,
                "Accepting request from $clientPublicKey, backoff resets to ${INITIAL_BACKOFF_SECONDS}s",
            )
            return@compute BackoffState(
                lastRequestTime = now,
                backoffSeconds = INITIAL_BACKOFF_SECONDS,
                requestCount = 1,
                burstWindowStart = now,
            )
        }

        if (dedupKey != null) {
            deduplicator.record(dedupKey, accepted)
        }

        return accepted
    }

    /**
     * The post-authentication admission check both transports run.
     *
     * The key material and the request identifier are fixed here, once, so the two call sites
     * cannot drift: [clientPublicKey] is the paired Client's Ed25519 public key — the only identity
     * in a request that is neither chosen by the peer nor rotating — and [wrapperMessageBytes] is
     * the signature-verified `WrapperMessage` (both transports decrypt to the same bytes), hashed
     * into the de-duplication identifier. That hash is what lets one request delivered over UDP and
     * BLE at once cost a single burst slot.
     *
     * Nothing spoofable pre-authentication is consulted: keying on the temporal identifier would
     * throttle a Client's own second request inside a 60 s window (one value per Client per
     * window), and keying on a peer address would let anyone spend another Client's budget.
     *
     * @param clientPublicKey The paired Client's Ed25519 public key, as stored on its pairing.
     * @param wrapperMessageBytes The verified request's `WrapperMessage` bytes.
     * @return true if the request may raise a prompt, false if it is rate limited.
     */
    fun shouldAcceptAuthenticatedRequest(
        clientPublicKey: ByteArray,
        wrapperMessageBytes: ByteArray,
    ): Boolean = shouldAcceptRequest(clientPublicKey.toHex(), sha256Hex(wrapperMessageBytes))

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /**
     * Hex SHA-256 of [data], used only as a stable de-duplication key.
     *
     * Retransmissions and multi-transport deliveries of one request decrypt to identical
     * `WrapperMessage` bytes, so they collapse to one request id. This is not protocol crypto and
     * deliberately has no JNI export.
     */
    private fun sha256Hex(data: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(data).toHex()

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
     * Clean up old backoff states and deduplication entries to prevent memory leaks. Call
     * periodically (e.g., every 5 minutes).
     */
    fun cleanup() {
        val now = timeProvider()
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

        removed += deduplicator.cleanup()

        if (removed > 0) {
            Log.d(TAG, "Cleaned up $removed expired rate-limiter entries")
        }
    }

    companion object {
        private const val TAG = "RequestRateLimiter"

        /**
         * The one limiter this process has, shared by the UDP and BLE paths.
         *
         * State lives here, in memory, for the life of the process: it is not persisted, and a
         * service (re)start reuses whatever budget the process already holds rather than handing
         * every Client a fresh burst allowance.
         */
        @Volatile private var instance: RequestRateLimiter? = null

        fun getInstance(): RequestRateLimiter {
            return instance
                ?: synchronized(this) { instance ?: RequestRateLimiter().also { instance = it } }
        }

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
