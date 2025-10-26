package dev.rourunisen.tapauth.biometric

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Helper class for biometric authentication
 */
class BiometricHelper(private val context: Context) {
    
    /**
     * Check if biometric authentication is available
     */
    fun isBiometricAvailable(): BiometricAvailability {
        val biometricManager = BiometricManager.from(context)
        
        return when (biometricManager.canAuthenticate(AUTHENTICATORS)) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                BiometricAvailability.Available
            
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                BiometricAvailability.NoHardware
            
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                BiometricAvailability.HardwareUnavailable
            
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                BiometricAvailability.NoneEnrolled
            
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                BiometricAvailability.SecurityUpdateRequired
            
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED ->
                BiometricAvailability.Unsupported
            
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN ->
                BiometricAvailability.Unknown
            
            else -> BiometricAvailability.Unknown
        }
    }
    
    /**
     * Authenticate using biometric
     * Returns true if authentication succeeded
     */
    suspend fun authenticate(
        activity: FragmentActivity,
        title: String = "Authentication Required",
        subtitle: String = "Verify your identity to continue",
        negativeButtonText: String = "Cancel"
    ): BiometricResult = suspendCancellableCoroutine { continuation ->
        
        val executor = ContextCompat.getMainExecutor(context)
        
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (continuation.isActive) {
                        continuation.resume(BiometricResult.Error(errorCode, errString.toString()))
                    }
                }
                
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    if (continuation.isActive) {
                        // Check the authentication type - only accept hardware-backed biometrics
                        val authenticationType = result.authenticationType
                        if (authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC) {
                            // True biometric authentication (fingerprint, iris, etc.)
                            continuation.resume(BiometricResult.Success)
                        } else {
                            // Device credential or other non-biometric authentication
                            continuation.resume(BiometricResult.Error(
                                BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                                "Only biometric authentication is allowed"
                            ))
                        }
                    }
                }
                
                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // Don't resume here - user can retry
                }
            }
        )
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButtonText)
            .setAllowedAuthenticators(AUTHENTICATORS)
            .setConfirmationRequired(false)  // Don't require additional confirmation after biometric
            .build()
        
        biometricPrompt.authenticate(promptInfo)
        
        continuation.invokeOnCancellation {
            biometricPrompt.cancelAuthentication()
        }
    }
    
    companion object {
        // Only allow BIOMETRIC_STRONG (Class 3 biometrics):
        // - Fingerprint sensors
        // - Iris scanners
        // - Secure face unlock (on devices with dedicated secure hardware)
        // This excludes weak face unlock and device credentials (PIN/password)
        private const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG
    }
}

sealed class BiometricAvailability {
    object Available : BiometricAvailability()
    object NoHardware : BiometricAvailability()
    object HardwareUnavailable : BiometricAvailability()
    object NoneEnrolled : BiometricAvailability()
    object SecurityUpdateRequired : BiometricAvailability()
    object Unsupported : BiometricAvailability()
    object Unknown : BiometricAvailability()
}

sealed class BiometricResult {
    object Success : BiometricResult()
    data class Error(val errorCode: Int, val message: String) : BiometricResult()
}
