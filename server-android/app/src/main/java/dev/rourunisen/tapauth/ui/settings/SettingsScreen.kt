package dev.rourunisen.tapauth.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.content.Intent as AndroidIntent
import androidx.compose.material3.Switch
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.platform.LocalLifecycleOwner as ComposeLocalLifecycleOwner
import kotlinx.coroutines.withTimeoutOrNull
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import android.content.Intent
import android.net.Uri
import android.provider.Settings
// Switch removed; toggles are deprecated in this screen
import androidx.compose.ui.platform.LocalContext
import dev.rourunisen.tapauth.data.AppConfiguration
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val config = AppConfiguration.getInstance(context)
    val coroutineScope = rememberCoroutineScope()
    var showBatteryConfirm by remember { mutableStateOf(false) }
    // Observe live state from ServiceStatusManager
    val udpState by dev.rourunisen.tapauth.service.ServiceStatusManager.udpRunning.collectAsState(initial = config.udpRunning)
    val bleState by dev.rourunisen.tapauth.service.ServiceStatusManager.bleRunning.collectAsState(initial = config.bleRunning)
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Text("←")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Information Section
            Text(
                text = "About Encryption",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Client Symmetric Key (CSK)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Each paired desktop client generates its own CSK and shares it with you during pairing. " +
                        "This key is used to encrypt all authentication communication. " +
                        "The CSK is controlled by the desktop client, not this app.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Divider(modifier = Modifier.padding(vertical = 8.dp))
                    Text(
                        text = "Security Note",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "If a desktop client rotates its CSK, you will need to re-pair with that device. " +
                        "Each paired device maintains its own separate encryption key.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            
            // About Section
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "About",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    InfoRow("App Version", "1.0.0")
                    HorizontalDivider()
                    InfoRow("Protocol Version", "1")
                    Divider()
                    InfoRow("Encryption", "AES-256-GCM")
                    Divider()
                    InfoRow("Key Exchange", "X25519")
                    Divider()
                    InfoRow("Signing", "Ed25519")
                }
            }
            
            // Removed weight spacer so content can size naturally and the
            // verticalScroll modifier allows the page to scroll when needed.
            // Background / Runtime controls
            Text(
                text = "Background",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Divider()

                    // Battery optimization prompt
                    Button(onClick = { showBatteryConfirm = true }) {
                        Text("Allow background operation / Battery optimizations")
                    }

                    // Service running switches
                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("UDP Service", style = MaterialTheme.typography.bodyMedium)
                            Text("UDP listener for auth requests", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        var udpBusy by remember { mutableStateOf(false) }
                        Switch(checked = udpState, onCheckedChange = { checked ->
                            coroutineScope.launch {
                                udpBusy = true
                                config.udpRunning = checked
                                try {
                                    if (checked) dev.rourunisen.tapauth.service.AuthenticationService.start(context)
                                    else dev.rourunisen.tapauth.service.AuthenticationService.stop(context)
                                } catch (_: Exception) {}
                                // wait briefly for service to report state; timeout after 2s
                                withTimeoutOrNull(2000) { kotlinx.coroutines.delay(600) }
                                udpBusy = false
                            }
                        })
                        if (udpBusy) CircularProgressIndicator(modifier = Modifier.size(18.dp))
                    }

                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("BLE GATT Server", style = MaterialTheme.typography.bodyMedium)
                            Text("BLE advertisement and GATT server", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        var bleBusy by remember { mutableStateOf(false) }
                        Switch(checked = bleState, onCheckedChange = { checked ->
                            coroutineScope.launch {
                                bleBusy = true
                                config.bleRunning = checked
                                try {
                                    if (checked) dev.rourunisen.tapauth.ble.BleGattService.start(context)
                                    else dev.rourunisen.tapauth.ble.BleGattService.stop(context)
                                } catch (_: Exception) {}
                                withTimeoutOrNull(2000) { kotlinx.coroutines.delay(600) }
                                bleBusy = false
                            }
                        })
                        if (bleBusy) CircularProgressIndicator(modifier = Modifier.size(18.dp))
                    }

                    // Service status display
                    val df = DateFormat.getDateTimeInstance()
                    val udpLast = if (config.udpLastStartMillis == 0L) "never" else df.format(Date(config.udpLastStartMillis))
                    val bleLast = if (config.bleLastStartMillis == 0L) "never" else df.format(Date(config.bleLastStartMillis))

                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Service status:")
                    Text("UDP listener last started: $udpLast", style = MaterialTheme.typography.bodySmall)
                    Text("BLE GATT last started: $bleLast", style = MaterialTheme.typography.bodySmall)
                }
            }

            if (showBatteryConfirm) {
                AlertDialog(
                    onDismissRequest = { showBatteryConfirm = false },
                    confirmButton = {
                        TextButton(onClick = {
                            showBatteryConfirm = false
                            try {
                                val pm = context.getSystemService(android.content.Context.POWER_SERVICE) as android.os.PowerManager
                                val packageName = context.packageName
                                if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                                    val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                    context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                                } else {
                                    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + packageName))
                                    context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                                }
                            } catch (_: Exception) { }
                        }) { Text("Open settings") }
                    },
                    dismissButton = {
                        TextButton(onClick = { showBatteryConfirm = false }) { Text("Cancel") }
                    },
                    title = { Text("Allow background operation?") },
                    text = { Text("To ensure TapAuth can respond to authentication requests while the app is closed, please allow the app to be excluded from battery optimizations. You will be taken to the system settings screen to do this.") }
                )
            }
            // Footer
            Text(
                text = "TapAuth - Secure biometric authentication",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}
