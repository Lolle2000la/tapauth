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
        val callback: (Boolean, ByteArray?) -> Unit
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
        callback: (approved: Boolean, signedChallenge: ByteArray?) -> Unit
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
        pendingRequests[requestId] = PendingAuthRequest(authRequest, callback)
        
        // Broadcast to MainActivity
        val intent = Intent(ACTION_AUTH_REQUEST).apply {
            putExtra(EXTRA_AUTH_REQUEST, authRequest)
            setPackage(context.packageName)
        }
        context.sendBroadcast(intent)

        // Also post a notification so the user can tap to open the app and approve
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

            val notification = NotificationCompat.Builder(context, TapAuthApplication.CHANNEL_ID)
                .setSmallIcon(dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground)
                .setContentTitle("Authentication request")
                .setContentText("${deviceName}: ${username}@${hostname}")
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
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
     */
    fun handleResponse(requestId: String, approved: Boolean, signedChallenge: ByteArray?) {
        val pending = pendingRequests.remove(requestId)
        if (pending != null) {
            Log.d(TAG, "Auth request $requestId ${if (approved) "approved" else "denied"}")
            // Launch callback on IO dispatcher to avoid NetworkOnMainThreadException
            scope.launch {
                pending.callback(approved, signedChallenge)
            }
        } else {
            Log.w(TAG, "Received response for unknown request ID: $requestId")
        }
    }
    
    /**
     * Cancel a pending request (e.g., on timeout)
     */
    fun cancelRequest(requestId: String) {
        val pending = pendingRequests.remove(requestId)
        if (pending != null) {
            Log.d(TAG, "Cancelled auth request $requestId")
            // Launch callback on IO dispatcher
            scope.launch {
                pending.callback(false, null)
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
