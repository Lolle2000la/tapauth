package dev.rourunisen.tapauth

import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.service.AuthRequestManager

/**
 * Transparent activity that shows the biometric prompt directly from a notification. This activity
 * shows over other apps and doesn't bring the app to the foreground.
 */
class BiometricPromptActivity : FragmentActivity() {

    private lateinit var biometricPrompt: BiometricPrompt
    private var currentAuthRequest: AuthRequest? = null

    companion object {
        private const val TAG = "BiometricPromptActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Make this activity appear over the lock screen and other apps
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
            )
        }

        // Don't show app in task switcher
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            window.addFlags(WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL)
        }

        // Extract auth request from intent
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

        if (authRequest == null) {
            Log.e(TAG, "No auth request found in intent, finishing")
            finish()
            return
        }

        currentAuthRequest = authRequest
        setupBiometricPrompt()

        // Check if biometric authentication is available
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                // Show biometric prompt immediately
                showBiometricPrompt(authRequest)
            }
            else -> {
                // Biometric not available, deny request and finish
                Log.e(TAG, "Biometric authentication not available")
                handleAuthResponse(authRequest.requestId, approved = false, signedChallenge = null)
                finish()
            }
        }
    }

    private fun setupBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(this)
        biometricPrompt =
            BiometricPrompt(
                this,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        Log.d(TAG, "Biometric authentication error: $errString (code: $errorCode)")

                        currentAuthRequest?.let { authRequest ->
                            when (errorCode) {
                                BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                                    // User explicitly clicked "Deny" button
                                    Log.d(TAG, "User explicitly denied authentication")
                                    handleAuthResponse(
                                        authRequest.requestId,
                                        approved = false,
                                        signedChallenge = null,
                                        explicitDenial = true,
                                    )
                                }
                                BiometricPrompt.ERROR_USER_CANCELED -> {
                                    // User dismissed prompt (back button, tapped outside)
                                    Log.d(TAG, "User dismissed biometric prompt")
                                    // Don't send denial, just clear
                                }
                                else -> {
                                    // Other errors (timeout, lockout, etc.)
                                    Log.w(TAG, "Biometric error (code: $errorCode)")
                                    // Don't send denial for system errors
                                }
                            }
                        }

                        // Always finish the activity when authentication ends
                        finish()
                    }

                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        super.onAuthenticationSucceeded(result)
                        Log.d(TAG, "Biometric authentication succeeded")

                        currentAuthRequest?.let { authRequest ->
                            // Sign the challenge with server keypair
                            try {
                                val keypairRepo =
                                    dev.rourunisen.tapauth.data.KeypairRepository(
                                        this@BiometricPromptActivity
                                    )
                                val privateKey = keypairRepo.getPrivateKey()
                                Log.d(
                                    TAG,
                                    "Signing challenge (trunc): ${authRequest.challenge.take(8).joinToString("") { "%02x".format(it) }}…",
                                )
                                val signedChallenge =
                                    dev.rourunisen.tapauth.crypto.signData(
                                        privateKey,
                                        authRequest.challenge,
                                    )

                                Log.d(
                                    TAG,
                                    "Successfully signed challenge (${signedChallenge.size} bytes)",
                                )
                                handleAuthResponse(
                                    authRequest.requestId,
                                    approved = true,
                                    signedChallenge = signedChallenge,
                                )
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to sign challenge", e)
                                handleAuthResponse(
                                    authRequest.requestId,
                                    approved = false,
                                    signedChallenge = null,
                                    explicitDenial = false,
                                )
                            }
                        }

                        // Always finish the activity when authentication ends
                        finish()
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        Log.w(TAG, "Biometric authentication failed (retry available)")
                        // Don't finish - user can retry
                    }
                },
            )
    }

    private fun showBiometricPrompt(authRequest: AuthRequest) {
        val promptInfo =
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authentication Request")
                .setSubtitle("Approve login for ${authRequest.username}@${authRequest.hostname}")
                .setDescription(
                    "From device: ${authRequest.deviceName} via ${authRequest.transportType.displayName}"
                )
                .setNegativeButtonText("Deny")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(false) // Don't require additional confirmation
                .build()

        biometricPrompt.authenticate(promptInfo)
    }

    private fun handleAuthResponse(
        requestId: String,
        approved: Boolean,
        signedChallenge: ByteArray?,
        explicitDenial: Boolean = false,
    ) {
        val authRequestManager = AuthRequestManager.getInstance()
        authRequestManager.handleResponse(requestId, approved, signedChallenge, explicitDenial)
    }

    override fun onDestroy() {
        super.onDestroy()
        currentAuthRequest = null
    }
}
