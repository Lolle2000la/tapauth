package dev.rourunisen.tapauth.service

import android.content.Context
import android.content.Intent
import android.util.Log
import android.app.PendingIntent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import dev.rourunisen.tapauth.TapAuthApplication
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.data.TransportType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import dev.rourunisen.tapauth.data.KeypairRepository
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages pending authentication requests and coordinates between services and UI
 */
class AuthRequestManager private constructor() {
    
    private val pendingRequests = ConcurrentHashMap<String, PendingAuthRequest>()
    private val scope = CoroutineScope(Dispatchers.IO)
    
    data class PendingAuthRequest(
        val authRequest: AuthRequest,
        val callback: (Boolean, ByteArray?, Boolean) -> Unit,  // (approved, signedChallenge, explicitDenial)
        val appContext: android.content.Context
    )
    
    /**
     * Submit an authentication request for user approval
     * Returns a request ID
     */
    fun submitRequest(
        context: Context,
        deviceId: String,
        deviceName: String,
        username: String,
        hostname: String,
        challenge: ByteArray,
        timestamp: Long,
        transportType: TransportType,
        callback: (approved: Boolean, signedChallenge: ByteArray?, explicitDenial: Boolean) -> Unit
    ): String {
        val requestId = UUID.randomUUID().toString()
        
        val authRequest = AuthRequest(
            requestId = requestId,
            deviceId = deviceId,
            deviceName = deviceName,
            username = username,
            hostname = hostname,
            challenge = challenge,
            timestamp = timestamp,
            transportType = transportType
        )
        
    // Store the pending request
    pendingRequests[requestId] = PendingAuthRequest(authRequest, callback, context.applicationContext)
        
        // Broadcast to MainActivity
        val intent = Intent(ACTION_AUTH_REQUEST).apply {
            putExtra(EXTRA_AUTH_REQUEST, authRequest)
            setPackage(context.packageName)
        }
        context.sendBroadcast(intent)

        // Also post a persistent notification so the user can tap to open the app and approve
        try {
            val activityIntent = Intent(context, dev.rourunisen.tapauth.MainActivity::class.java).apply {
                action = ACTION_AUTH_REQUEST
                putExtra(EXTRA_AUTH_REQUEST, authRequest)
            }

            val pendingIntent = PendingIntent.getActivity(
                context,
                requestId.hashCode(),
                activityIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            // Action: Approve -> open app and show biometric prompt
            val approveIntent = Intent(context, dev.rourunisen.tapauth.MainActivity::class.java).apply {
                action = ACTION_AUTH_REQUEST
                putExtra(EXTRA_AUTH_REQUEST, authRequest)
                putExtra("notification_action", "approve")
            }
            val approvePending = PendingIntent.getActivity(
                context,
                (requestId + "_approve").hashCode(),
                approveIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            // Action: Deny -> quick deny handled by BroadcastReceiver (no UI)
            // Create HMAC token over the request ID using the server private key to prevent spoofing
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

            val denyBroadcast = Intent(context, dev.rourunisen.tapauth.service.AuthActionReceiver::class.java).apply {
                action = dev.rourunisen.tapauth.service.AuthActionReceiver.ACTION_NOTIFICATION_ACTION
                putExtra("notification_action", "deny")
                putExtra(EXTRA_AUTH_REQUEST, authRequest)
                hmacBytes?.let { putExtra("hmac", it) }
            }
            val denyPending = PendingIntent.getBroadcast(
                context,
                (requestId + "_deny").hashCode(),
                denyBroadcast,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val notification = NotificationCompat.Builder(context, TapAuthApplication.AUTH_CHANNEL_ID)
                .setSmallIcon(dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground)
                .setContentTitle("Authentication request")
                .setContentText("${deviceName}: ${username}@${hostname}")
                .setContentIntent(pendingIntent)
                .addAction(dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground, "Approve", approvePending)
                .addAction(dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground, "Deny", denyPending)
                .setOngoing(true)
                .setAutoCancel(false)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()

            NotificationManagerCompat.from(context).notify(requestId.hashCode(), notification)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to post auth request notification: ${e.message}")
        }
        
        Log.d(TAG, "Submitted auth request $requestId for ${username}@${hostname}")
        
        return requestId
    }
    
    /**
     * Handle response from MainActivity (approved or denied)
     * @param explicitDenial: true if user clicked "Deny", false if timeout/cancel
     */
    fun handleResponse(requestId: String, approved: Boolean, signedChallenge: ByteArray?, explicitDenial: Boolean = false) {
        val pending = pendingRequests.remove(requestId)
        if (pending != null) {
            Log.d(TAG, "Auth request $requestId ${if (approved) "approved" else if (explicitDenial) "explicitly denied" else "timed out/cancelled"}")
            // Launch callback on IO dispatcher to avoid NetworkOnMainThreadException
            scope.launch {
                pending.callback(approved, signedChallenge, explicitDenial)
            }
            // Cancel the persistent notification
            try {
                NotificationManagerCompat.from(pending.appContext).cancel(requestId.hashCode())
            } catch (_: Exception) { }
        } else {
            Log.w(TAG, "Received response for unknown request ID: $requestId")
        }
    }
    
    /**
     * Cancel a pending request (e.g., on timeout)
     * This is NOT an explicit user denial - just silently cancel
     */
    fun cancelRequest(requestId: String) {
        val pending = pendingRequests.remove(requestId)
        if (pending != null) {
            Log.d(TAG, "Cancelled auth request $requestId (timeout)")
            // Launch callback on IO dispatcher - explicitDenial = false
            scope.launch {
                pending.callback(false, null, false)
            }
        }
    }
    
    /**
     * Get a pending request by ID
     */
    fun getPendingRequest(requestId: String): AuthRequest? {
        return pendingRequests[requestId]?.authRequest
    }
    
    /**
     * Get count of pending requests
     */
    fun getPendingCount(): Int = pendingRequests.size
    
    companion object {
        private const val TAG = "AuthRequestManager"
        
        const val ACTION_AUTH_REQUEST = "dev.rourunisen.tapauth.AUTH_REQUEST"
        const val ACTION_AUTH_RESPONSE = "dev.rourunisen.tapauth.AUTH_RESPONSE"
        const val EXTRA_AUTH_REQUEST = "auth_request"
        const val EXTRA_REQUEST_ID = "request_id"
        const val EXTRA_APPROVED = "approved"
        const val EXTRA_SIGNED_CHALLENGE = "signed_challenge"
        
        @Volatile
        private var instance: AuthRequestManager? = null
        
        fun getInstance(): AuthRequestManager {
            return instance ?: synchronized(this) {
                instance ?: AuthRequestManager().also { instance = it }
            }
        }
    }
}
