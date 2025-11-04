package dev.rourunisen.tapauth

import android.Manifest
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.service.AuthRequestManager
import dev.rourunisen.tapauth.ui.devices.DeviceListScreen
import dev.rourunisen.tapauth.ui.home.HomeScreen
import dev.rourunisen.tapauth.ui.pairing.PairingScreen
import dev.rourunisen.tapauth.ui.scanner.QRScannerScreen
import dev.rourunisen.tapauth.ui.settings.SettingsScreen
import dev.rourunisen.tapauth.ui.theme.TapAuthTheme

class MainActivity : FragmentActivity() {

    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var authRequestReceiver: BroadcastReceiver

    // Track individual permission states
    internal val cameraGranted = mutableStateOf(false)
    internal val bluetoothGranted = mutableStateOf(false)
    internal val locationGranted = mutableStateOf(false)
    internal val backgroundLocationGranted = mutableStateOf(false)
    internal val notificationGranted = mutableStateOf(false)

    // Request codes for classic permission requests
    companion object {
        private const val TAG = "MainActivity"
        private const val REQUEST_CAMERA = 1
        private const val REQUEST_BLUETOOTH = 2
        private const val REQUEST_LOCATION = 3
        private const val REQUEST_NOTIFICATION = 4
        private const val REQUEST_BACKGROUND_LOCATION = 5
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Check initial permission status
        checkAllPermissions()

        setupBiometricPrompt()
        setupAuthRequestReceiver()

        // Note: We no longer handle auth requests via intent here in onCreate.
        // The BiometricPromptActivity handles notification taps directly.
        // This MainActivity only processes auth requests if it's already running
        // (via the broadcast receiver).

        enableEdgeToEdge()
        setContent { TapAuthTheme { TapAuthApp() } }
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
                        Log.e(TAG, "Biometric authentication error: $errString (code: $errorCode)")
                        // Handle current auth request
                        currentAuthRequest?.let { authRequest ->
                            // Only ERROR_NEGATIVE_BUTTON is an explicit denial (user
                            // clicked
                            // "Deny")
                            // All other errors are either dismissals, system errors, or
                            // temporary
                            // conditions
                            when (errorCode) {
                                BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                                    // User explicitly clicked "Deny" button - send denial
                                    // response
                                    Log.d(TAG, "User explicitly denied authentication")
                                    handleAuthResponse(
                                        authRequest.requestId,
                                        approved = false,
                                        signedChallenge = null,
                                        explicitDenial = true,
                                    )
                                    currentAuthRequest = null
                                }
                                BiometricPrompt.ERROR_USER_CANCELED -> {
                                    // User dismissed prompt (back button, tapped outside) -
                                    // just
                                    // clear, don't send denial
                                    Log.d(
                                        TAG,
                                        "User dismissed biometric prompt, clearing request without sending denial",
                                    )
                                    currentAuthRequest = null
                                }
                                BiometricPrompt.ERROR_CANCELED -> {
                                    // System canceled (e.g., another biometric prompt) -
                                    // keep
                                    // request active
                                    Log.d(
                                        TAG,
                                        "Biometric prompt canceled by system, keeping request active",
                                    )
                                }
                                BiometricPrompt.ERROR_TIMEOUT -> {
                                    // Biometric timeout - user can still retry, keep
                                    // request active
                                    Log.d(
                                        TAG,
                                        "Biometric timeout, keeping request active for retry",
                                    )
                                }
                                BiometricPrompt.ERROR_LOCKOUT -> {
                                    // Too many attempts - temporary lockout, keep request
                                    // active
                                    Log.d(
                                        TAG,
                                        "Biometric lockout (temporary), keeping request active",
                                    )
                                }
                                BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                                BiometricPrompt.ERROR_HW_NOT_PRESENT,
                                BiometricPrompt.ERROR_HW_UNAVAILABLE,
                                BiometricPrompt.ERROR_NO_BIOMETRICS,
                                BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> {
                                    // Permanent errors - clear request without sending
                                    // denial (not
                                    // user's fault)
                                    Log.w(
                                        TAG,
                                        "Permanent biometric error (code: $errorCode), clearing request without denial",
                                    )
                                    currentAuthRequest = null
                                }
                                else -> {
                                    // Unknown error - clear request without sending denial
                                    Log.w(
                                        TAG,
                                        "Unknown biometric error (code: $errorCode), clearing request without denial",
                                    )
                                    currentAuthRequest = null
                                }
                            }
                        }
                    }

                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        super.onAuthenticationSucceeded(result)
                        Log.d(TAG, "Biometric authentication succeeded")
                        // Handle current auth request approval
                        currentAuthRequest?.let { authRequest ->
                            // Sign the challenge with server keypair
                            try {
                                val keypairRepo =
                                    dev.rourunisen.tapauth.data.KeypairRepository(this@MainActivity)
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
                                Log.d(
                                    TAG,
                                    "Signed challenge (trunc): ${signedChallenge.take(8).joinToString("") { "%02x".format(it) }}…",
                                )
                                handleAuthResponse(
                                    authRequest.requestId,
                                    approved = true,
                                    signedChallenge = signedChallenge,
                                )
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to sign challenge", e)
                                // Signature failure is not explicit denial - just error
                                handleAuthResponse(
                                    authRequest.requestId,
                                    approved = false,
                                    signedChallenge = null,
                                    explicitDenial = false,
                                )
                            }
                            currentAuthRequest = null
                        }
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        Log.w(TAG, "Biometric authentication failed")
                    }
                },
            )
    }

    private var currentAuthRequest: AuthRequest? = null

    private fun setupAuthRequestReceiver() {
        authRequestReceiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action == AuthRequestManager.ACTION_AUTH_REQUEST) {
                        val authRequest =
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                intent.getParcelableExtra(
                                    AuthRequestManager.EXTRA_AUTH_REQUEST,
                                    AuthRequest::class.java,
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
            registerReceiver(authRequestReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            // For older versions, use ContextCompat which handles the flag appropriately
            ContextCompat.registerReceiver(
                this,
                authRequestReceiver,
                filter,
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
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
        val promptInfo =
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authentication Request")
                .setSubtitle("Approve login for ${authRequest.username}@${authRequest.hostname}")
                .setDescription("From device: ${authRequest.deviceName}")
                .setNegativeButtonText("Deny")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
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

    private fun checkAllPermissions() {
        // Check camera
        cameraGranted.value =
            ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED

        // Check Bluetooth permissions (Android 12+)
        bluetoothGranted.value =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                listOf(
                        Manifest.permission.BLUETOOTH_CONNECT,
                        Manifest.permission.BLUETOOTH_ADVERTISE,
                        Manifest.permission.BLUETOOTH_SCAN,
                    )
                    .all {
                        ContextCompat.checkSelfPermission(this, it) ==
                            PackageManager.PERMISSION_GRANTED
                    }
            } else {
                true // Not needed on older versions
            }

        // Check location (Android 10+)
        locationGranted.value =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) ==
                    PackageManager.PERMISSION_GRANTED
            } else {
                true // Not needed on older versions
            }

        // Check background location (Android 10+)
        backgroundLocationGranted.value =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.ACCESS_BACKGROUND_LOCATION,
                ) == PackageManager.PERMISSION_GRANTED
            } else {
                true // Not needed on older versions
            }

        // Check notifications (Android 13+)
        notificationGranted.value =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
                    PackageManager.PERMISSION_GRANTED
            } else {
                true // Not needed on older versions
            }
    }

    fun requestCamera() {
        requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
    }

    fun requestBluetooth() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            requestPermissions(
                arrayOf(
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_SCAN,
                ),
                REQUEST_BLUETOOTH,
            )
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

    fun requestBackgroundLocation() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Show explanation dialog before requesting
            val builder = AlertDialog.Builder(this)
            builder.setTitle("Background Location Permission")
            builder.setMessage(
                "To keep BLE scanning active when the app is in the background, TapAuth needs background location permission.\n\n" +
                    "On the next screen:\n" +
                    "1. Tap 'Permissions'\n" +
                    "2. Tap 'Location'\n" +
                    "3. Select 'Allow all the time'\n\n" +
                    "Note: TapAuth does not track your location. This permission is only required by Android for BLE scanning."
            )
            builder.setPositiveButton("Open Settings") { dialog: DialogInterface, which: Int ->
                try {
                    val intent =
                        Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                            .apply {
                                data = android.net.Uri.parse("package:$packageName")
                                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                    startActivity(intent)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to open settings", e)
                }
            }
            builder.setNegativeButton("Cancel") { _: DialogInterface, _: Int -> }
            builder.show()
        }
    }

    fun requestNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_NOTIFICATION,
            )
        } else {
            notificationGranted.value = true
            checkAllPermissions()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        when (requestCode) {
            REQUEST_CAMERA -> {
                cameraGranted.value =
                    grantResults.isNotEmpty() &&
                        grantResults[0] == PackageManager.PERMISSION_GRANTED
            }
            REQUEST_BLUETOOTH -> {
                bluetoothGranted.value =
                    grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            }
            REQUEST_LOCATION -> {
                locationGranted.value =
                    grantResults.isNotEmpty() &&
                        grantResults[0] == PackageManager.PERMISSION_GRANTED
            }
            REQUEST_NOTIFICATION -> {
                notificationGranted.value =
                    grantResults.isNotEmpty() &&
                        grantResults[0] == PackageManager.PERMISSION_GRANTED

                // If notification permission was just granted, start the background services
                if (notificationGranted.value) {
                    try {
                        dev.rourunisen.tapauth.service.AuthenticationService.start(this)
                        val bleIntent =
                            Intent(this, dev.rourunisen.tapauth.ble.BleGattService::class.java)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            startForegroundService(bleIntent)
                        } else {
                            startService(bleIntent)
                        }
                        android.util.Log.i(
                            "MainActivity",
                            "Started services after notification permission granted",
                        )
                    } catch (e: Exception) {
                        android.util.Log.e("MainActivity", "Failed to start services: ${e.message}")
                    }
                }
            }
        }

        checkAllPermissions()
    }

    fun allPermissionsGranted(): Boolean {
        return cameraGranted.value &&
            bluetoothGranted.value &&
            locationGranted.value &&
            notificationGranted.value
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(authRequestReceiver)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        // Note: Auth request intents from notifications now go to BiometricPromptActivity
        // This onNewIntent is kept for compatibility but shouldn't receive auth requests
        // unless MainActivity is explicitly targeted (which it no longer is)
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
                onSettings = { currentScreen = AppScreen.Settings },
            )
        }
        is AppScreen.Scanner -> {
            QRScannerScreen(
                onQRCodeScanned = { pairingUrl -> currentScreen = AppScreen.Pairing(pairingUrl) },
                onBack = { currentScreen = AppScreen.Home },
            )
        }
        is AppScreen.Pairing -> {
            PairingScreen(
                pairingUrl = screen.url,
                onPairingComplete = { currentScreen = AppScreen.Home },
                onPairingFailed = { /* Handle error specifically if necessary (currently this callback is unused) */
                },
                onBack = { currentScreen = AppScreen.Home },
            )
        }
        is AppScreen.DeviceList -> {
            DeviceListScreen(onBack = { currentScreen = AppScreen.Home })
        }
        is AppScreen.Settings -> {
            SettingsScreen(onBack = { currentScreen = AppScreen.Home })
        }
    }
}

@Composable
fun PermissionRequestScreen(activity: MainActivity?) {
    // Observe permission states
    val cameraGranted by activity?.cameraGranted ?: remember { mutableStateOf(false) }
    val bluetoothGranted by activity?.bluetoothGranted ?: remember { mutableStateOf(false) }
    val locationGranted by activity?.locationGranted ?: remember { mutableStateOf(false) }
    val backgroundLocationGranted by
        activity?.backgroundLocationGranted ?: remember { mutableStateOf(false) }
    val notificationGranted by activity?.notificationGranted ?: remember { mutableStateOf(false) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "Permissions Required",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Grant each permission individually:",
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Camera Permission
            PermissionButton(
                label = "Camera",
                description = "For scanning QR codes",
                isGranted = cameraGranted,
                onClick = { activity?.requestCamera() },
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Bluetooth Permission
            PermissionButton(
                label = "Bluetooth",
                description = "For BLE authentication",
                isGranted = bluetoothGranted,
                onClick = { activity?.requestBluetooth() },
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Location Permission
            PermissionButton(
                label = "Location",
                description = "Required for BLE scanning",
                isGranted = locationGranted,
                onClick = { activity?.requestLocation() },
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Background Location Permission (Android 10+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                PermissionButton(
                    label = "Background Location",
                    description = "Required for BLE scanning when app is in background",
                    isGranted = backgroundLocationGranted,
                    onClick = { activity?.requestBackgroundLocation() },
                )

                Spacer(modifier = Modifier.height(12.dp))
            }

            // Notification Permission
            PermissionButton(
                label = "Notifications",
                description = "For auth requests",
                isGranted = notificationGranted,
                onClick = { activity?.requestNotification() },
            )
        }
    }
}

@Composable
fun PermissionButton(label: String, description: String, isGranted: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors =
            CardDefaults.cardColors(
                containerColor =
                    if (isGranted) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    }
            ),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleMedium,
                    color =
                        if (isGranted) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color =
                        if (isGranted) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                )
            }

            if (isGranted) {
                Icon(
                    imageVector = Icons.Default.Check,
                    contentDescription = "Granted",
                    modifier = Modifier.size(32.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
            } else {
                Button(onClick = onClick) { Text("Grant") }
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
