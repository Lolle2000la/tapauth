package dev.rourunisen.tapauth

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.*
import androidx.core.content.ContextCompat
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.service.AuthRequestManager
import dev.rourunisen.tapauth.ui.home.HomeScreen
import dev.rourunisen.tapauth.ui.scanner.QRScannerScreen
import dev.rourunisen.tapauth.ui.pairing.PairingScreen
import dev.rourunisen.tapauth.ui.devices.DeviceListScreen
import dev.rourunisen.tapauth.ui.settings.SettingsScreen
import dev.rourunisen.tapauth.ui.theme.TapAuthTheme
import dev.rourunisen.tapauth.data.PairingUrl

class MainActivity : ComponentActivity() {
    
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var authRequestReceiver: BroadcastReceiver
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setupBiometricPrompt()
        setupAuthRequestReceiver()
        
        enableEdgeToEdge()
        setContent {
            TapAuthTheme {
                TapAuthApp()
            }
        }
    }
    
    private fun setupBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.e(TAG, "Biometric authentication error: $errString")
                    // Handle current auth request denial
                    currentAuthRequest?.let { authRequest ->
                        handleAuthResponse(authRequest.requestId, approved = false, signedChallenge = null)
                        currentAuthRequest = null
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.d(TAG, "Biometric authentication succeeded")
                    // Handle current auth request approval
                    currentAuthRequest?.let { authRequest ->
                        // Sign the challenge with server keypair
                        try {
                            val keypairRepo = dev.rourunisen.tapauth.data.KeypairRepository(this@MainActivity)
                            val privateKey = keypairRepo.getPrivateKey()
                            val signedChallenge = dev.rourunisen.tapauth.crypto.signData(privateKey, authRequest.challenge)
                            
                            Log.d(TAG, "Successfully signed challenge (${signedChallenge.size} bytes)")
                            handleAuthResponse(authRequest.requestId, approved = true, signedChallenge = signedChallenge)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to sign challenge", e)
                            handleAuthResponse(authRequest.requestId, approved = false, signedChallenge = null)
                        }
                        currentAuthRequest = null
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Log.w(TAG, "Biometric authentication failed")
                }
            })
    }
    
    private var currentAuthRequest: AuthRequest? = null
    
    private fun setupAuthRequestReceiver() {
        authRequestReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == AuthRequestManager.ACTION_AUTH_REQUEST) {
                    val authRequest = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(
                            AuthRequestManager.EXTRA_AUTH_REQUEST,
                            AuthRequest::class.java
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(AuthRequestManager.EXTRA_AUTH_REQUEST)
                    }
                    
                    authRequest?.let { handleAuthRequest(it) }
                }
            }
        }
        
        val filter = IntentFilter(AuthRequestManager.ACTION_AUTH_REQUEST)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(authRequestReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(authRequestReceiver, filter)
        }
    }
    
    private fun handleAuthRequest(authRequest: AuthRequest) {
        Log.d(TAG, "Received auth request for ${authRequest.username}@${authRequest.hostname}")
        
        // Check if biometric authentication is available
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                // Show biometric prompt
                currentAuthRequest = authRequest
                showBiometricPrompt(authRequest)
            }
            else -> {
                // Biometric not available, deny request
                Log.e(TAG, "Biometric authentication not available")
                handleAuthResponse(authRequest.requestId, approved = false, signedChallenge = null)
            }
        }
    }
    
    private fun showBiometricPrompt(authRequest: AuthRequest) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentication Request")
            .setSubtitle("Approve login for ${authRequest.username}@${authRequest.hostname}")
            .setDescription("From device: ${authRequest.deviceName}")
            .setNegativeButtonText("Deny")
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
    
    private fun handleAuthResponse(requestId: String, approved: Boolean, signedChallenge: ByteArray?) {
        val authRequestManager = AuthRequestManager.getInstance()
        authRequestManager.handleResponse(requestId, approved, signedChallenge)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(authRequestReceiver)
    }
    
    companion object {
        private const val TAG = "MainActivity"
    }
}

@Composable
fun TapAuthApp() {
    var currentScreen by remember { mutableStateOf<AppScreen>(AppScreen.Home) }
    
    when (val screen = currentScreen) {
        is AppScreen.Home -> {
            HomeScreen(
                onStartScanning = { currentScreen = AppScreen.Scanner },
                onViewDevices = { currentScreen = AppScreen.DeviceList },
                onSettings = { currentScreen = AppScreen.Settings }
            )
        }
        is AppScreen.Scanner -> {
            QRScannerScreen(
                onQRCodeScanned = { pairingUrl ->
                    currentScreen = AppScreen.Pairing(pairingUrl)
                },
                onBack = { currentScreen = AppScreen.Home }
            )
        }
        is AppScreen.Pairing -> {
            PairingScreen(
                pairingUrl = screen.url,
                onPairingComplete = { currentScreen = AppScreen.Home },
                onPairingFailed = { /* TODO: Show error */ },
                onBack = { currentScreen = AppScreen.Home }
            )
        }
        is AppScreen.DeviceList -> {
            DeviceListScreen(
                onBack = { currentScreen = AppScreen.Home }
            )
        }
        is AppScreen.Settings -> {
            SettingsScreen(
                onBack = { currentScreen = AppScreen.Home }
            )
        }
    }
}

sealed class AppScreen {
    object Home : AppScreen()
    object Scanner : AppScreen()
    data class Pairing(val url: PairingUrl) : AppScreen()
    object DeviceList : AppScreen()
    object Settings : AppScreen()
}