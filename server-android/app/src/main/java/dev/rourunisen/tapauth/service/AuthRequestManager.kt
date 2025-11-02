package dev.rourunisen.tapauth.service

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import dev.rourunisen.tapauth.TapAuthApplication
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.data.KeypairRepository
import dev.rourunisen.tapauth.data.TransportType
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Manages pending authentication requests and coordinates between services and UI */
class AuthRequestManager private constructor() {

    private val pendingRequests = ConcurrentHashMap<String, PendingAuthRequest>()
    private val scope = CoroutineScope(Dispatchers.IO)

    // Track BLE device addresses to request IDs for disconnection handling
    private val bleDeviceRequests = ConcurrentHashMap<String, MutableSet<String>>()
    // Index challenges (Base64) to request IDs for fast cancel-by-challenge
    private val challengeIndex = ConcurrentHashMap<String, MutableSet<String>>()
    // Debug registry removed: no longer tracking posted notification IDs

    // Track recently cancelled challenges to handle out-of-order cancel vs request arrival
    private val cancelledChallenges = ConcurrentHashMap<String, Long>()
    private val CANCEL_TTL_MS = 10_000L // Keep cancellation intent for 10 seconds

    private fun pruneCancelledChallenges(now: Long = System.currentTimeMillis()) {
        cancelledChallenges.entries.removeIf { (_, ts) -> now - ts > CANCEL_TTL_MS }
    }

    fun markCancelledChallenge(challenge: ByteArray) {
        val key = Base64.encodeToString(challenge, Base64.NO_WRAP)
        cancelledChallenges[key] = System.currentTimeMillis()
        pruneCancelledChallenges()
        Log.d(TAG, "Marked challenge as cancelled (ttl=${CANCEL_TTL_MS}ms)")
    }

    fun isChallengeCancelled(challenge: ByteArray): Boolean {
        pruneCancelledChallenges()
        val key = Base64.encodeToString(challenge, Base64.NO_WRAP)
        val ts = cancelledChallenges[key] ?: return false
        val stillValid = (System.currentTimeMillis() - ts) <= CANCEL_TTL_MS
        if (!stillValid) {
            cancelledChallenges.remove(key)
        }
        return stillValid
    }

    data class PendingAuthRequest(
        val authRequest: AuthRequest,
        val callback:
            (Boolean, ByteArray?, Boolean) -> Unit, // (approved, signedChallenge, explicitDenial)
        val appContext: android.content.Context,
        val bleDeviceAddress: String? = null, // BLE MAC address if this is a BLE request
    )

    /** Submit an authentication request for user approval Returns a request ID */
    fun submitRequest(
        context: Context,
        deviceId: String,
        deviceName: String,
        username: String,
        hostname: String,
        challenge: ByteArray,
        timestamp: Long,
        transportType: TransportType,
        bleDeviceAddress: String? = null, // Optional: BLE MAC address for tracking disconnections
        callback: (approved: Boolean, signedChallenge: ByteArray?, explicitDenial: Boolean) -> Unit,
    ): String {
        // Derive stable notification ID from challenge bytes (SHA-256 -> first 4 bytes -> int)
        val notificationId = notificationIdFor(challenge)
        // If this challenge was already cancelled (cancel may arrive before request), drop it
        if (isChallengeCancelled(challenge)) {
            val droppedId = UUID.randomUUID().toString()
            Log.d(
                TAG,
                "Dropping submitRequest for already-cancelled challenge; no notification will be posted",
            )
            // Invoke callback as cancelled (not explicit denial)
            scope.launch { callback(false, null, false) }
            return droppedId
        }

        val requestId = UUID.randomUUID().toString()

        val authRequest =
            AuthRequest(
                requestId = requestId,
                deviceId = deviceId,
                deviceName = deviceName,
                username = username,
                hostname = hostname,
                challenge = challenge,
                timestamp = timestamp,
                transportType = transportType,
            )

        // Store the pending request
        pendingRequests[requestId] =
            PendingAuthRequest(authRequest, callback, context.applicationContext, bleDeviceAddress)

        // Index by challenge for fast cancellation
        runCatching {
                val key = Base64.encodeToString(challenge, Base64.NO_WRAP)
                challengeIndex.getOrPut(key) { mutableSetOf() }.add(requestId)
            }
            .onFailure { e ->
                Log.w(TAG, "Failed to index challenge for request $requestId: ${e.message}")
            }

        // If this is a BLE request, track it by device address
        if (bleDeviceAddress != null) {
            bleDeviceRequests.getOrPut(bleDeviceAddress) { mutableSetOf() }.add(requestId)
        }

        // Broadcast to MainActivity
        val intent =
            Intent(ACTION_AUTH_REQUEST).apply {
                putExtra(EXTRA_AUTH_REQUEST, authRequest)
                setPackage(context.packageName)
            }
        context.sendBroadcast(intent)

        // Also post a persistent notification so the user can tap to open the app and approve
        try {
            val activityIntent =
                Intent(context, dev.rourunisen.tapauth.MainActivity::class.java).apply {
                    action = ACTION_AUTH_REQUEST
                    putExtra(EXTRA_AUTH_REQUEST, authRequest)
                }

            // Use bytes-derived stable notification ID (already computed at function start)

            val pendingIntent =
                PendingIntent.getActivity(
                    context,
                    notificationId,
                    activityIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )

            // Action: Approve -> open app and show biometric prompt
            val approveIntent =
                Intent(context, dev.rourunisen.tapauth.MainActivity::class.java).apply {
                    action = ACTION_AUTH_REQUEST
                    putExtra(EXTRA_AUTH_REQUEST, authRequest)
                    putExtra("notification_action", "approve")
                }
            val approvePending =
                PendingIntent.getActivity(
                    context,
                    (requestId + "_approve").hashCode(),
                    approveIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )

            // Action: Deny -> quick deny handled by BroadcastReceiver (no UI)
            // Create HMAC token over the request ID using the server private key to prevent
            // spoofing
            var hmacBytes: ByteArray? = null
            try {
                val keypairRepo = KeypairRepository(context)
                val hmacKey = keypairRepo.getOrCreateHmacKey()
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(hmacKey)
                hmacBytes = mac.doFinal(requestId.toByteArray(Charsets.UTF_8))
            } catch (e: Exception) {
                Log.w(TAG, "Failed to compute HMAC for deny action: ${e.message}")
            }

            val denyBroadcast =
                Intent(context, dev.rourunisen.tapauth.service.AuthActionReceiver::class.java)
                    .apply {
                        action =
                            dev.rourunisen.tapauth.service.AuthActionReceiver
                                .ACTION_NOTIFICATION_ACTION
                        putExtra("notification_action", "deny")
                        putExtra(EXTRA_AUTH_REQUEST, authRequest)
                        hmacBytes?.let { putExtra("hmac", it) }
                    }
            val denyPending =
                PendingIntent.getBroadcast(
                    context,
                    (requestId + "_deny").hashCode(),
                    denyBroadcast,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )

            // Calculate timeout: session timeout minus time already elapsed since request timestamp
            val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
            val sessionTimeoutMs = config.sessionTimeoutSeconds * 1000
            val currentTime = System.currentTimeMillis()
            val timeElapsed = currentTime - timestamp
            val remainingTimeout = (sessionTimeoutMs - timeElapsed).coerceAtLeast(0)

            val notification =
                NotificationCompat.Builder(context, TapAuthApplication.AUTH_CHANNEL_ID)
                    .setSmallIcon(dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground)
                    .setContentTitle("Authentication request")
                    .setContentText("${deviceName}: ${username}@${hostname}")
                    .setContentIntent(pendingIntent)
                    .addAction(
                        dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground,
                        "Approve",
                        approvePending,
                    )
                    .addAction(
                        dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground,
                        "Deny",
                        denyPending,
                    )
                    .setOngoing(true)
                    .setAutoCancel(false)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setTimeoutAfter(remainingTimeout)
                    .build()

            val challengeHex = challenge.joinToString("") { "%02x".format(it) }
            Log.d(
                TAG,
                "Posting auth notification (id=$notificationId) for $deviceName @ $username@$hostname, challenge=${challengeHex.take(16)}...",
            )

            val nm = NotificationManagerCompat.from(context)
            try {
                if (nm.areNotificationsEnabled()) {
                    nm.notify(notificationId, notification)
                } else {
                    Log.w(TAG, "Notifications disabled; skipping notify (id=$notificationId)")
                }
            } catch (se: SecurityException) {
                Log.w(
                    TAG,
                    "Missing notification permission; skipping notify (id=$notificationId): ${se.message}",
                )
            }
            Log.d(TAG, "Posted auth notification (id=$notificationId)")

            // Schedule state cleanup on timeout to mirror setTimeoutAfter
            try {
                if (remainingTimeout > 0) {
                    scope.launch {
                        try {
                            delay(remainingTimeout + 250)
                            if (pendingRequests.containsKey(requestId)) {
                                Log.d(TAG, "Timeout reached; cancelling pending request $requestId")
                                cancelRequest(requestId)
                            }
                        } catch (_: Exception) {}
                    }
                }
            } catch (_: Exception) {}
        } catch (e: Exception) {
            Log.w(TAG, "Failed to post auth request notification: ${e.message}")
        }

        Log.d(TAG, "Submitted auth request $requestId for ${username}@${hostname}")

        return requestId
    }

    /**
     * Handle response from MainActivity (approved or denied)
     *
     * @param explicitDenial: true if user clicked "Deny", false if timeout/cancel
     */
    fun handleResponse(
        requestId: String,
        approved: Boolean,
        signedChallenge: ByteArray?,
        explicitDenial: Boolean = false,
    ) {
        val pending = pendingRequests.remove(requestId)
        if (pending != null) {
            Log.d(
                TAG,
                "Auth request $requestId ${if (approved) "approved" else if (explicitDenial) "explicitly denied" else "timed out/cancelled"}",
            )

            // Remove from BLE tracking if applicable
            pending.bleDeviceAddress?.let { address ->
                bleDeviceRequests[address]?.remove(requestId)
                if (bleDeviceRequests[address]?.isEmpty() == true) {
                    bleDeviceRequests.remove(address)
                }
            }

            // Remove from challenge index
            runCatching {
                val key = Base64.encodeToString(pending.authRequest.challenge, Base64.NO_WRAP)
                challengeIndex[key]?.remove(requestId)
                if (challengeIndex[key]?.isEmpty() == true) {
                    challengeIndex.remove(key)
                }
            }

            // Launch callback on IO dispatcher to avoid NetworkOnMainThreadException
            scope.launch { pending.callback(approved, signedChallenge, explicitDenial) }
            // Cancel the persistent notification
            try {
                val notificationId = notificationIdFor(pending.authRequest.challenge)
                Log.d(TAG, "Cancelling notification for request $requestId (id=$notificationId)")
                NotificationManagerCompat.from(pending.appContext).cancel(notificationId)
            } catch (_: Exception) {}
        } else {
            Log.w(TAG, "Received response for unknown request ID: $requestId")
        }
    }

    /**
     * Cancel a pending request (e.g., on timeout) This is NOT an explicit user denial - just
     * silently cancel
     */
    fun cancelRequest(requestId: String) {
        val pending = pendingRequests.remove(requestId)
        if (pending != null) {
            Log.d(TAG, "Cancelled auth request $requestId (timeout)")

            // Remove from BLE tracking if applicable
            pending.bleDeviceAddress?.let { address ->
                bleDeviceRequests[address]?.remove(requestId)
                if (bleDeviceRequests[address]?.isEmpty() == true) {
                    bleDeviceRequests.remove(address)
                }
            }

            // Remove from challenge index
            runCatching {
                val key = Base64.encodeToString(pending.authRequest.challenge, Base64.NO_WRAP)
                challengeIndex[key]?.remove(requestId)
                if (challengeIndex[key]?.isEmpty() == true) {
                    challengeIndex.remove(key)
                }
            }

            // Cancel the notification and remove from registry
            try {
                val notificationId = notificationIdFor(pending.authRequest.challenge)
                Log.d(
                    TAG,
                    "Cancelling notification for timed-out request $requestId (id=$notificationId)",
                )
                NotificationManagerCompat.from(pending.appContext).cancel(notificationId)
            } catch (_: Exception) {}

            // Launch callback on IO dispatcher - explicitDenial = false
            scope.launch { pending.callback(false, null, false) }
        }
    }

    /** Get a pending request by ID */
    fun getPendingRequest(requestId: String): AuthRequest? {
        return pendingRequests[requestId]?.authRequest
    }

    /** Get count of pending requests */
    fun getPendingCount(): Int = pendingRequests.size

    /**
     * Cancel all pending requests that match the given challenge This is used when an
     * AuthenticationCancel message is received
     *
     * @param challenge The challenge bytes to match against
     * @return true if any requests were cancelled
     */
    fun cancelRequestsByChallenge(challenge: ByteArray): Boolean {
        var cancelledAny = false

        val challengeHex = challenge.joinToString("") { "%02x".format(it) }
        Log.d(TAG, "cancelRequestsByChallenge: challenge=${challengeHex.take(16)}...")

        // Look up request IDs by challenge index first
        val key = Base64.encodeToString(challenge, Base64.NO_WRAP)
        val requestIds = challengeIndex.remove(key)?.toList().orEmpty()
        if (requestIds.isNotEmpty()) {
            Log.d(TAG, "Cancelling ${requestIds.size} request(s) by challenge index")
        }

        val idsToCancel: List<String> =
            if (requestIds.isNotEmpty()) {
                requestIds
            } else {
                // Fallback: scan map (in case index missed older entries)
                pendingRequests
                    .filter { (_, pending) ->
                        pending.authRequest.challenge.contentEquals(challenge)
                    }
                    .keys
                    .toList()
            }

        idsToCancel.forEach { requestId ->
            val pending = pendingRequests.remove(requestId)
            if (pending != null) {
                Log.d(TAG, "Cancelled auth request $requestId due to AuthenticationCancel")

                // Invoke callback with cancelled status (not explicit denial)
                scope.launch { pending.callback(false, null, false) }

                // Dismiss the notification
                try {
                    val notificationId = notificationIdFor(pending.authRequest.challenge)
                    Log.d(
                        TAG,
                        "Dismissing notification for cancelled request $requestId (id=$notificationId)",
                    )
                    NotificationManagerCompat.from(pending.appContext).cancel(notificationId)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to dismiss notification for $requestId: ${e.message}")
                }

                cancelledAny = true
            }
        }

        // Remember this cancellation briefly in case the request arrives slightly after cancel
        markCancelledChallenge(challenge)

        return cancelledAny
    }

    /**
     * Cancel all pending requests associated with a BLE device that disconnected
     *
     * @param bleDeviceAddress The BLE MAC address of the disconnected device
     * @return true if any requests were cancelled
     */
    fun cancelRequestsByBleDisconnection(bleDeviceAddress: String): Boolean {
        val requestIds = bleDeviceRequests.remove(bleDeviceAddress) ?: return false

        if (requestIds.isEmpty()) return false

        Log.d(
            TAG,
            "BLE device $bleDeviceAddress disconnected, cancelling ${requestIds.size} pending requests",
        )

        requestIds.forEach { requestId ->
            val pending = pendingRequests.remove(requestId)
            if (pending != null) {
                // Invoke callback with cancelled status (not explicit denial)
                scope.launch { pending.callback(false, null, false) }

                // Dismiss the notification
                try {
                    val notificationId = notificationIdFor(pending.authRequest.challenge)
                    Log.d(
                        TAG,
                        "Dismissing notification for BLE-disconnected request $requestId (id=$notificationId)",
                    )
                    NotificationManagerCompat.from(pending.appContext).cancel(notificationId)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to dismiss notification for $requestId: ${e.message}")
                }

                // Remove from challenge index
                runCatching {
                    val key = Base64.encodeToString(pending.authRequest.challenge, Base64.NO_WRAP)
                    challengeIndex[key]?.remove(requestId)
                    if (challengeIndex[key]?.isEmpty() == true) {
                        challengeIndex.remove(key)
                    }
                }
            }
        }

        return true
    }

    companion object {
        private const val TAG = "AuthRequestManager"

        // Notification IDs derived from challenge so multiple requests can coexist and be
        // individually dismissed.

        const val ACTION_AUTH_REQUEST = "dev.rourunisen.tapauth.AUTH_REQUEST"
        const val ACTION_AUTH_RESPONSE = "dev.rourunisen.tapauth.AUTH_RESPONSE"
        const val EXTRA_AUTH_REQUEST = "auth_request"
        const val EXTRA_REQUEST_ID = "request_id"
        const val EXTRA_APPROVED = "approved"
        const val EXTRA_SIGNED_CHALLENGE = "signed_challenge"

        @Volatile private var instance: AuthRequestManager? = null

        fun getInstance(): AuthRequestManager {
            return instance
                ?: synchronized(this) { instance ?: AuthRequestManager().also { instance = it } }
        }

        /**
         * Compute a stable, deterministic notification ID from challenge bytes. Uses SHA-256 and
         * maps the first 4 bytes to a non-negative Int.
         */
        fun notificationIdFor(challenge: ByteArray): Int {
            return try {
                val challengeHex = challenge.joinToString("") { "%02x".format(it) }
                val digest = java.security.MessageDigest.getInstance("SHA-256").digest(challenge)
                val b0 = (digest[0].toInt() and 0xFF)
                val b1 = (digest[1].toInt() and 0xFF)
                val b2 = (digest[2].toInt() and 0xFF)
                val b3 = (digest[3].toInt() and 0xFF)
                val raw = (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
                val notificationId = raw and 0x7FFFFFFF // ensure non-negative
                Log.d(
                    TAG,
                    "notificationIdFor: challenge=${challengeHex.take(16)}... → id=$notificationId",
                )
                notificationId
            } catch (_: Exception) {
                // Fallback: use Kotlin contentHashCode masked to positive
                (challenge.contentHashCode() and 0x7FFFFFFF)
            }
        }
    }

    // Debug helper methods removed
}

private fun ByteArray.toHexPreview(maxBytes: Int = 8): String {
    val take = kotlin.math.min(this.size, maxBytes)
    return this.take(take).joinToString("") { "%02x".format(it) } +
        if (this.size > take) "…" else ""
}
