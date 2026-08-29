package dev.rourunisen.tapauth.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.data.KeypairRepository
import java.security.MessageDigest
import javax.crypto.Mac

class AuthActionReceiver : BroadcastReceiver() {

    companion object {
        const val TAG = "AuthActionReceiver"
        const val ACTION_NOTIFICATION_ACTION = "dev.rourunisen.tapauth.ACTION_NOTIFICATION_ACTION"
        /** Debug-only action to simulate explicit denial from automated test runners. */
        const val ACTION_DEV_DENY = "dev.rourunisen.tapauth.ACTION_DEV_DENY"
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent == null) return
        if (intent.action == ACTION_DEV_DENY && dev.rourunisen.tapauth.BuildConfig.E2E_TESTING) {
            Log.d(TAG, "Handling dev explicit denial broadcast")
            val manager = AuthRequestManager.getInstance()
            for (reqId in manager.getActiveRequestIds()) {
                Log.d(TAG, "Applying dev explicit denial to request $reqId")
                manager.handleResponse(
                    reqId,
                    approved = false,
                    signedChallenge = null,
                    explicitDenial = true,
                )
            }
            return
        }
        if (intent.action != ACTION_NOTIFICATION_ACTION) return

        val notifAction = intent.getStringExtra("notification_action")
        if (notifAction == "deny") {
            // Extract auth request from extras
            val authRequest =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(
                        AuthRequestManager.EXTRA_AUTH_REQUEST,
                        AuthRequest::class.java,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<AuthRequest>(AuthRequestManager.EXTRA_AUTH_REQUEST)
                }

            if (authRequest != null) {
                // Verify HMAC token
                val hmac = intent.getByteArrayExtra("hmac")
                var ok = false
                if (hmac != null) {
                    try {
                        val keypairRepo = KeypairRepository(context!!)
                        val hmacKey = keypairRepo.getOrCreateHmacKey()
                        val mac = Mac.getInstance("HmacSHA256")
                        mac.init(hmacKey)
                        val expected =
                            mac.doFinal(authRequest.requestId.toByteArray(Charsets.UTF_8))
                        ok = MessageDigest.isEqual(expected, hmac)
                    } catch (e: Exception) {
                        Log.w(TAG, "HMAC verification failed: ${e.message}")
                    }
                }

                if (ok) {
                    Log.d(TAG, "Quick deny for request ${authRequest.requestId}")
                    try {
                        // Notification "Deny" button is explicit user denial
                        AuthRequestManager.getInstance()
                            .handleResponse(
                                authRequest.requestId,
                                approved = false,
                                signedChallenge = null,
                                explicitDenial = true,
                            )
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to handle quick deny", e)
                    }
                } else {
                    Log.w(
                        TAG,
                        "Rejected deny: HMAC missing or invalid for request ${authRequest.requestId}",
                    )
                }
            } else {
                Log.w(TAG, "Received deny action without auth request payload")
            }
        }
    }
}
