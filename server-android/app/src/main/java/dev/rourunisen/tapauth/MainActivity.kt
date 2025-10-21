package dev.rourunisen.tapauth

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.google.accompanist.permissions.*
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.service.AuthRequestManager
import dev.rourunisen.tapauth.ui.home.HomeScreen
import dev.rourunisen.tapauth.ui.scanner.QRScannerScreen
import dev.rourunisen.tapauth.ui.pairing.PairingScreen
import dev.rourunisen.tapauth.ui.devices.DeviceListScreen
import dev.rourunisen.tapauth.ui.settings.SettingsScreen
import dev.rourunisen.tapauth.ui.theme.TapAuthTheme
import dev.rourunisen.tapauth.data.PairingUrl

class MainActivity : FragmentActivity() {
    
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
                            Log.d(TAG, "Signing challenge: ${authRequest.challenge.joinToString("") { "%02x".format(it) }}")
                            val signedChallenge = dev.rourunisen.tapauth.crypto.signData(privateKey, authRequest.challenge)
                            
                            Log.d(TAG, "Successfully signed challenge (${signedChallenge.size} bytes)")
                            Log.d(TAG, "Signed challenge: ${signedChallenge.joinToString("") { "%02x".format(it) }}")
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

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun TapAuthApp() {
    // List of required permissions
    val permissions = buildList {
        add(Manifest.permission.CAMERA)
        add(Manifest.permission.INTERNET)
        add(Manifest.permission.ACCESS_NETWORK_STATE)
        add(Manifest.permission.ACCESS_WIFI_STATE)
        add(Manifest.permission.CHANGE_WIFI_MULTICAST_STATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            add(Manifest.permission.BLUETOOTH_CONNECT)
            add(Manifest.permission.BLUETOOTH_ADVERTISE)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    
    val permissionsState = rememberMultiplePermissionsState(permissions)
    
    // Request permissions on first composition
    LaunchedEffect(Unit) {
        if (!permissionsState.allPermissionsGranted) {
            permissionsState.launchMultiplePermissionRequest()
        }
    }
    
    // Show permission request screen if not all granted
    if (!permissionsState.allPermissionsGranted) {
        PermissionRequestScreen(
            permissionsState = permissionsState,
            onRequestPermissions = {
                permissionsState.launchMultiplePermissionRequest()
            }
        )
        return
    }
    
    // All permissions granted, show main app
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

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun PermissionRequestScreen(
    permissionsState: MultiplePermissionsState,
    onRequestPermissions: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "Permissions Required",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            Text(
                text = "TapAuth needs the following permissions to work:",
                style = MaterialTheme.typography.bodyLarge,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            val permissionDescriptions = mapOf(
                Manifest.permission.CAMERA to "Camera - for scanning QR codes",
                Manifest.permission.BLUETOOTH_CONNECT to "Bluetooth - for BLE authentication",
                Manifest.permission.BLUETOOTH_ADVERTISE to "Bluetooth - for BLE advertisement",
                Manifest.permission.POST_NOTIFICATIONS to "Notifications - for auth requests"
            )
            
            permissionsState.permissions.forEach { permState ->
                permissionDescriptions[permState.permission]?.let { description ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (permState.status.isGranted) "✓" else "○",
                            style = MaterialTheme.typography.bodyLarge,
                            color = if (permState.status.isGranted) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            }
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = description,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(32.dp))
            
            Button(
                onClick = onRequestPermissions,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Grant Permissions")
            }
            
            if (permissionsState.permissions.any { it.status.shouldShowRationale }) {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Some permissions were denied. Please grant them in Settings if the prompt doesn't appear.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }
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