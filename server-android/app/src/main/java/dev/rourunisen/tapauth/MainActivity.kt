package dev.rourunisen.tapauth

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
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
    
    // Track individual permission states
    internal val cameraGranted = mutableStateOf(false)
    internal val bluetoothGranted = mutableStateOf(false)
    internal val locationGranted = mutableStateOf(false)
    internal val notificationGranted = mutableStateOf(false)
    
    // Request codes for classic permission requests
    companion object {
        private const val TAG = "MainActivity"
        private const val REQUEST_CAMERA = 1
        private const val REQUEST_BLUETOOTH = 2
        private const val REQUEST_LOCATION = 3
        private const val REQUEST_NOTIFICATION = 4
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Check initial permission status
        checkAllPermissions()
        
        setupBiometricPrompt()
        setupAuthRequestReceiver()
        // If activity was launched via notification intent containing an auth request,
        // process it now.
        intent?.let { incoming ->
            if (incoming.action == AuthRequestManager.ACTION_AUTH_REQUEST) {
                val authRequest = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    incoming.getParcelableExtra(AuthRequestManager.EXTRA_AUTH_REQUEST, AuthRequest::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    incoming.getParcelableExtra<AuthRequest>(AuthRequestManager.EXTRA_AUTH_REQUEST)
                }
                authRequest?.let {
                    val notifAction = incoming.getStringExtra("notification_action")
                    when (notifAction) {
                        "deny" -> {
                            // Immediately deny without UI
                            handleAuthResponse(it.requestId, approved = false, signedChallenge = null)
                        }
                        "approve" -> {
                            // Start the biometric approval flow
                            handleAuthRequest(it)
                        }
                        else -> {
                            // Default behavior: open approval UI
                            handleAuthRequest(it)
                        }
                    }
                }
            }
        }
        
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
                            Log.d(TAG, "Signing challenge (trunc): ${authRequest.challenge.take(8).joinToString("") { "%02x".format(it) }}…")
                            val signedChallenge = dev.rourunisen.tapauth.crypto.signData(privateKey, authRequest.challenge)
                            
                            Log.d(TAG, "Successfully signed challenge (${signedChallenge.size} bytes)")
                            Log.d(TAG, "Signed challenge (trunc): ${signedChallenge.take(8).joinToString("") { "%02x".format(it) }}…")
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
            .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
    
    private fun handleAuthResponse(requestId: String, approved: Boolean, signedChallenge: ByteArray?) {
        val authRequestManager = AuthRequestManager.getInstance()
        authRequestManager.handleResponse(requestId, approved, signedChallenge)
    }
    
    private fun checkAllPermissions() {
        // Check camera
        cameraGranted.value = ContextCompat.checkSelfPermission(
            this, Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
        
        // Check Bluetooth permissions (Android 12+)
        bluetoothGranted.value = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_SCAN
            ).all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }
        } else {
            true // Not needed on older versions
        }
        
        // Check location (Android 10+)
        locationGranted.value = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ContextCompat.checkSelfPermission(
                this, Manifest.permission.ACCESS_FINE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true // Not needed on older versions
        }
        
        // Check notifications (Android 13+)
        notificationGranted.value = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true // Not needed on older versions
        }
    }
    
    fun requestCamera() {
        requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
    }
    
    fun requestBluetooth() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            requestPermissions(arrayOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_SCAN
            ), REQUEST_BLUETOOTH)
        } else {
            bluetoothGranted.value = true
            checkAllPermissions()
        }
    }
    
    fun requestLocation() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), REQUEST_LOCATION)
        } else {
            locationGranted.value = true
            checkAllPermissions()
        }
    }
    
    fun requestNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATION)
        } else {
            notificationGranted.value = true
            checkAllPermissions()
        }
    }
    
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        
        when (requestCode) {
            REQUEST_CAMERA -> {
                cameraGranted.value = grantResults.isNotEmpty() && 
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
            }
            REQUEST_BLUETOOTH -> {
                bluetoothGranted.value = grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            }
            REQUEST_LOCATION -> {
                locationGranted.value = grantResults.isNotEmpty() && 
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
            }
            REQUEST_NOTIFICATION -> {
                notificationGranted.value = grantResults.isNotEmpty() && 
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
            }
        }
        
        checkAllPermissions()
    }
    
    fun allPermissionsGranted(): Boolean {
        return cameraGranted.value && bluetoothGranted.value && 
               locationGranted.value && notificationGranted.value
    }
    
    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(authRequestReceiver)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { incoming ->
            if (incoming.action == AuthRequestManager.ACTION_AUTH_REQUEST) {
                val authRequest = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    incoming.getParcelableExtra(AuthRequestManager.EXTRA_AUTH_REQUEST, AuthRequest::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    incoming.getParcelableExtra<AuthRequest>(AuthRequestManager.EXTRA_AUTH_REQUEST)
                }
                authRequest?.let {
                    val notifAction = incoming.getStringExtra("notification_action")
                    when (notifAction) {
                        "deny" -> handleAuthResponse(it.requestId, approved = false, signedChallenge = null)
                        "approve" -> handleAuthRequest(it)
                        else -> handleAuthRequest(it)
                    }
                }
            }
        }
    }
}

@Composable
fun TapAuthApp() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? MainActivity
    
    // Observe individual permission states from activity
    val allGranted = activity?.allPermissionsGranted() ?: false
    
    // Show permission request screen if not all granted
    if (!allGranted) {
        PermissionRequestScreen(activity)
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

@Composable
fun PermissionRequestScreen(activity: MainActivity?) {
    // Observe permission states
    val cameraGranted by activity?.cameraGranted ?: remember { mutableStateOf(false) }
    val bluetoothGranted by activity?.bluetoothGranted ?: remember { mutableStateOf(false) }
    val locationGranted by activity?.locationGranted ?: remember { mutableStateOf(false) }
    val notificationGranted by activity?.notificationGranted ?: remember { mutableStateOf(false) }
    
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
                text = "Grant each permission individually:",
                style = MaterialTheme.typography.bodyLarge,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Camera Permission
            PermissionButton(
                label = "Camera",
                description = "For scanning QR codes",
                isGranted = cameraGranted,
                onClick = { activity?.requestCamera() }
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Bluetooth Permission
            PermissionButton(
                label = "Bluetooth",
                description = "For BLE authentication",
                isGranted = bluetoothGranted,
                onClick = { activity?.requestBluetooth() }
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Location Permission
            PermissionButton(
                label = "Location",
                description = "Required for BLE scanning",
                isGranted = locationGranted,
                onClick = { activity?.requestLocation() }
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Notification Permission
            PermissionButton(
                label = "Notifications",
                description = "For auth requests",
                isGranted = notificationGranted,
                onClick = { activity?.requestNotification() }
            )
        }
    }
}

@Composable
fun PermissionButton(
    label: String,
    description: String,
    isGranted: Boolean,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (isGranted) {
                MaterialTheme.colorScheme.primaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            }
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleMedium,
                    color = if (isGranted) {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (isGranted) {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
            }
            
            if (isGranted) {
                Text(
                    text = "✓",
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            } else {
                Button(onClick = onClick) {
                    Text("Grant")
                }
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