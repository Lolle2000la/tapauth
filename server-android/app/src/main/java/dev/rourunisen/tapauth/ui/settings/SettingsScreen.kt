package dev.rourunisen.tapauth.ui.settings

// Switch removed; toggles are deprecated in this screen

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.util.Log
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.rourunisen.tapauth.R
import dev.rourunisen.tapauth.data.AppConfiguration
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val config = AppConfiguration.getInstance(context)
    val coroutineScope = rememberCoroutineScope()
    var showBatteryConfirm by remember { mutableStateOf(false) }
    var udpPortText by remember { mutableStateOf(config.udpPort.toString()) }
    var udpPortError by remember { mutableStateOf<String?>(null) }

    // Local state to represent the persistent 'Enabled' preference
    // These are initialized from saved preferences and updated when the user toggles
    var udpEnabledState by remember { mutableStateOf(config.udpEnabled) }
    var bleEnabledState by remember { mutableStateOf(config.bleEnabled) }

    // Snackbar for showing error messages to the user
    val snackbarHostState = remember { SnackbarHostState() }

    // Check background location permission status (re-check when screen is visible)
    var hasBackgroundLocation by remember { mutableStateOf(false) }
    androidx.compose.runtime.LaunchedEffect(Unit) {
        while (true) {
            hasBackgroundLocation =
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    androidx.core.content.ContextCompat.checkSelfPermission(
                        context,
                        android.Manifest.permission.ACCESS_BACKGROUND_LOCATION,
                    ) == android.content.pm.PackageManager.PERMISSION_GRANTED
                } else {
                    true
                }
            kotlinx.coroutines.delay(1000) // Check every second
        }
    }

    // Observe live state from ServiceStatusManager
    val udpState by
        dev.rourunisen.tapauth.service.ServiceStatusManager.udpRunning.collectAsState(
            initial = config.udpRunning
        )
    val bleState by
        dev.rourunisen.tapauth.service.ServiceStatusManager.bleRunning.collectAsState(
            initial = config.bleRunning
        )

    // Handle system back button
    BackHandler(onBack = onBack)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.general_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            modifier =
                Modifier.fillMaxSize()
                    .padding(padding)
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Information Section
            Text(
                text = stringResource(R.string.settings_about_encryption),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = stringResource(R.string.settings_csk_label),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = stringResource(R.string.settings_csk_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 8.dp),
                        thickness = DividerDefaults.Thickness,
                        color = DividerDefaults.color,
                    )
                    Text(
                        text = stringResource(R.string.settings_security_note),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = stringResource(R.string.settings_security_note_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            // About Section
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.settings_about),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    InfoRow(
                        stringResource(R.string.settings_app_version),
                        "1.0.0",
                    )
                    HorizontalDivider()
                    InfoRow(
                        stringResource(R.string.settings_protocol_version),
                        "1",
                    )
                    HorizontalDivider(
                        Modifier,
                        DividerDefaults.Thickness,
                        DividerDefaults.color,
                    )
                    InfoRow(
                        stringResource(R.string.settings_encryption),
                        "AES-256-GCM",
                    )
                    HorizontalDivider(
                        Modifier,
                        DividerDefaults.Thickness,
                        DividerDefaults.color,
                    )
                    InfoRow(
                        stringResource(R.string.settings_key_exchange),
                        "X25519",
                    )
                    HorizontalDivider(
                        Modifier,
                        DividerDefaults.Thickness,
                        DividerDefaults.color,
                    )
                    InfoRow(
                        stringResource(R.string.settings_signing),
                        "Ed25519",
                    )
                }
            }

            // Removed weight spacer so content can size naturally and the
            // verticalScroll modifier allows the page to scroll when needed.
            // Background / Runtime controls
            Text(
                text = stringResource(R.string.settings_background),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    // UDP Port Configuration
                    Text(
                        text = stringResource(R.string.settings_network_config),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )

                    OutlinedTextField(
                        value = udpPortText,
                        onValueChange = { newValue ->
                            udpPortText = newValue
                            val port = newValue.toIntOrNull()
                            when {
                                port == null -> {
                                    udpPortError =
                                        context.getString(R.string.settings_port_must_be_number)
                                }
                                port < 1024 -> {
                                    udpPortError =
                                        context.getString(R.string.settings_port_min)
                                }
                                port > 65535 -> {
                                    udpPortError =
                                        context.getString(R.string.settings_port_max)
                                }
                                else -> {
                                    udpPortError = null
                                    config.udpPort = port
                                    // Restart UDP service if running to apply new port
                                    coroutineScope.launch {
                                        if (udpState) {
                                            dev.rourunisen.tapauth.service.AuthenticationService
                                                .stop(context)
                                            kotlinx.coroutines.delay(500)
                                            dev.rourunisen.tapauth.service.AuthenticationService
                                                .start(context)
                                        }
                                    }
                                }
                            }
                        },
                        label = { Text(stringResource(R.string.settings_udp_port_label)) },
                        supportingText = {
                            Text(
                                if (udpPortError != null) udpPortError!!
                                else stringResource(R.string.settings_udp_port_default),
                                color =
                                    if (udpPortError != null) MaterialTheme.colorScheme.error
                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        },
                        isError = udpPortError != null,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )

                    HorizontalDivider(
                        Modifier,
                        DividerDefaults.Thickness,
                        DividerDefaults.color,
                    )

                    // Battery optimization prompt
                    Button(onClick = { showBatteryConfirm = true }) {
                        Text(stringResource(R.string.settings_allow_background))
                    }

                    // Service running switches
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                stringResource(R.string.settings_udp_service),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Text(
                                stringResource(R.string.settings_udp_listener_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        var udpBusy by remember { mutableStateOf(false) }
                        Switch(
                            checked = udpEnabledState,
                            onCheckedChange = { checked ->
                                coroutineScope.launch {
                                    udpBusy = true
                                    try {
                                        if (checked) {
                                            dev.rourunisen.tapauth.service.AuthenticationService
                                                .start(context)
                                        } else {
                                            dev.rourunisen.tapauth.service.AuthenticationService
                                                .stop(context)
                                        }
                                        // Save preference and update UI state after successful
                                        // start/stop
                                        config.udpEnabled = checked
                                        udpEnabledState = checked
                                    } catch (e: Exception) {
                                        // Log the error for debugging
                                        Log.e(
                                            "SettingsScreen",
                                            "Failed to ${if (checked) "start" else "stop"} UDP service",
                                            e,
                                        )
                                        // Revert UI state to saved preference on failure
                                        udpEnabledState = config.udpEnabled
                                        // Show error message to user
                                        val action = if (checked) "start" else "stop"
                                        snackbarHostState.showSnackbar(
                                            message =
                                                context.getString(
                                                    R.string.settings_failed_start_udp,
                                                    action,
                                                    e.message ?: "Unknown error",
                                                ),
                                            duration = SnackbarDuration.Short,
                                        )
                                    }
                                    // wait briefly for service to report state; timeout after
                                    // 2s
                                    withTimeoutOrNull(2000) {
                                        kotlinx.coroutines.delay(600)
                                    }
                                    udpBusy = false
                                }
                            },
                        )
                        if (udpBusy) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp))
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                stringResource(R.string.settings_ble_server),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Text(
                                stringResource(R.string.settings_ble_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        var bleBusy by remember { mutableStateOf(false) }
                        Switch(
                            checked = bleEnabledState,
                            onCheckedChange = { checked ->
                                coroutineScope.launch {
                                    bleBusy = true
                                    try {
                                        if (checked) {
                                            dev.rourunisen.tapauth.ble.BleGattService.start(
                                                context
                                            )
                                        } else {
                                            dev.rourunisen.tapauth.ble.BleGattService.stop(
                                                context
                                            )
                                        }
                                        // Save preference and update UI state after successful
                                        // start/stop
                                        config.bleEnabled = checked
                                        bleEnabledState = checked
                                    } catch (e: Exception) {
                                        // Log the error for debugging
                                        Log.e(
                                            "SettingsScreen",
                                            "Failed to ${if (checked) "start" else "stop"} BLE service",
                                            e,
                                        )
                                        // Revert UI state to saved preference on failure
                                        bleEnabledState = config.bleEnabled
                                        // Show error message to user
                                        val action = if (checked) "start" else "stop"
                                        snackbarHostState.showSnackbar(
                                            message =
                                                context.getString(
                                                    R.string.settings_failed_start_ble,
                                                    action,
                                                    e.message ?: "Unknown error",
                                                ),
                                            duration = SnackbarDuration.Short,
                                        )
                                    }
                                    withTimeoutOrNull(2000) {
                                        kotlinx.coroutines.delay(600)
                                    }
                                    bleBusy = false
                                }
                            },
                        )
                        if (bleBusy) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp))
                        }
                    }

                    // Background location permission warning for BLE (Android 10+)
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                        if (!hasBackgroundLocation && bleEnabledState) {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors =
                                    CardDefaults.cardColors(
                                        containerColor =
                                            MaterialTheme.colorScheme.errorContainer
                                    ),
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        stringResource(
                                            R.string.settings_location_required_title
                                        ),
                                        style = MaterialTheme.typography.titleSmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer,
                                        fontWeight = FontWeight.Bold,
                                    )
                                    Text(
                                        stringResource(
                                            R.string.settings_location_required_description
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer,
                                        modifier = Modifier.padding(vertical = 4.dp),
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        stringResource(
                                            R.string.settings_location_steps_title
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer,
                                        fontWeight = FontWeight.Bold,
                                    )
                                    Text(
                                        stringResource(
                                            R.string.settings_location_steps
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer,
                                        modifier =
                                            Modifier.padding(
                                                start = 8.dp,
                                                top = 4.dp,
                                                bottom = 8.dp,
                                            ),
                                    )
                                    Button(
                                        onClick = {
                                            try {
                                                val intent =
                                                    Intent(
                                                            Settings
                                                                .ACTION_APPLICATION_DETAILS_SETTINGS
                                                        )
                                                        .apply {
                                                            data =
                                                                Uri.parse(
                                                                    "package:${context.packageName}"
                                                                )
                                                            flags =
                                                                Intent.FLAG_ACTIVITY_NEW_TASK
                                                        }
                                                context.startActivity(intent)
                                            } catch (_: Exception) {}
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text(stringResource(R.string.settings_open_settings))
                                    }
                                }
                            }
                        }
                    }

                    // Service status display
                    val df = DateFormat.getDateTimeInstance()
                    val udpLast =
                        if (config.udpLastStartMillis == 0L) {
                            stringResource(R.string.settings_never)
                        } else df.format(Date(config.udpLastStartMillis))
                    val bleLast =
                        if (config.bleLastStartMillis == 0L) {
                            stringResource(R.string.settings_never)
                        } else df.format(Date(config.bleLastStartMillis))

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(stringResource(R.string.settings_service_status))
                    Text(
                        stringResource(R.string.settings_udp_last_started, udpLast),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        stringResource(R.string.settings_ble_last_started, bleLast),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            if (showBatteryConfirm) {
                AlertDialog(
                    onDismissRequest = { showBatteryConfirm = false },
                    confirmButton = {
                        TextButton(
                            onClick = {
                                showBatteryConfirm = false
                                try {
                                    val pm =
                                        context.getSystemService(
                                            android.content.Context.POWER_SERVICE
                                        ) as android.os.PowerManager
                                    val packageName = context.packageName
                                    if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                                        val intent =
                                            Intent(
                                                Settings
                                                    .ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS
                                            )
                                        context.startActivity(
                                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        )
                                    } else {
                                        val intent =
                                            Intent(
                                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                                Uri.parse("package:" + packageName),
                                            )
                                        context.startActivity(
                                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        )
                                    }
                                } catch (_: Exception) {}
                            }
                        ) {
                            Text(stringResource(R.string.settings_open_system_settings))
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showBatteryConfirm = false }) {
                            Text(stringResource(R.string.general_cancel))
                        }
                    },
                    title = {
                        Text(
                            stringResource(
                                R.string.settings_allow_background_dialog_title
                            )
                        )
                    },
                    text = {
                        Text(
                            stringResource(
                                R.string.settings_allow_background_dialog_message
                            )
                        )
                    },
                )
            }
            // Footer
            Text(
                text = stringResource(R.string.settings_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
    }
}
