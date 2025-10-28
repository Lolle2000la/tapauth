package dev.rourunisen.tapauth.ui.devices

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.data.PairedDevice
import java.text.SimpleDateFormat
import java.util.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceListScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val repository = remember { DeviceRepository(context) }
    val scope = rememberCoroutineScope()

    var devices by remember { mutableStateOf<List<PairedDevice>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var deviceToDelete by remember { mutableStateOf<PairedDevice?>(null) }
    var userToRemove by remember { mutableStateOf<Pair<PairedDevice, String>?>(null) }

    // Handle system back button
    BackHandler(onBack = onBack)

    LaunchedEffect(Unit) {
        devices = repository.getAllPairedDevices()
        isLoading = false
    }

    // Confirmation dialog for removing a specific user
    if (userToRemove != null) {
        val (device, username) = userToRemove!!
        val isLastUser = device.allowedUsers.size == 1

        AlertDialog(
            onDismissRequest = { userToRemove = null },
            title = { Text(if (isLastUser) "Remove Device?" else "Remove User?") },
            text = {
                Text(
                    if (isLastUser) {
                        "Remove user \"$username\" from \"${device.displayName}\"?\n\nThis is the last user, so the entire pairing will be removed."
                    } else {
                        "Remove user \"$username\" from \"${device.displayName}\"?\n\nOther users (${device.allowedUsers.filter { it != username }.joinToString(", ")}) will still be able to authenticate."
                    }
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            repository.removeUserFromDevice(device.deviceId, username)
                            devices = repository.getAllPairedDevices()
                            userToRemove = null
                        }
                    }
                ) {
                    Text("Remove", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { userToRemove = null }) { Text("Cancel") } },
        )
    }

    // Confirmation dialog for device removal (all users)
    if (deviceToDelete != null) {
        val device = deviceToDelete!!
        val multipleUsers = device.allowedUsers.size > 1

        AlertDialog(
            onDismissRequest = { deviceToDelete = null },
            title = { Text("Remove Entire Pairing?") },
            text = {
                Column {
                    if (multipleUsers) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Default.Warning,
                                contentDescription = "Warning",
                                tint = MaterialTheme.colorScheme.error,
                            )
                            Text(
                                "WARNING: This pairing is used by ${device.allowedUsers.size} users!",
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Users: ${device.allowedUsers.joinToString(", ")}")
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    Text(
                        "Are you sure you want to remove \"${device.displayName}\"? ${if (multipleUsers) "All users" else "You"} will need to pair again to authenticate with this device."
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            repository.removePairedDevice(device.deviceId)
                            devices = repository.getAllPairedDevices()
                            deviceToDelete = null
                        }
                    }
                ) {
                    Text("Remove All", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { deviceToDelete = null }) { Text("Cancel") } },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Paired Devices") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
            )
        }
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when {
                isLoading -> {
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
                }
                devices.isEmpty() -> {
                    EmptyState(modifier = Modifier.align(Alignment.Center))
                }
                else -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(devices) { device ->
                            DeviceCard(
                                device = device,
                                onRemoveDevice = { deviceToDelete = device },
                                onRemoveUser = { username -> userToRemove = device to username },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyState(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "No Paired Devices",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "Pair a device by scanning a QR code from your computer",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun DeviceCard(
    device: PairedDevice,
    onRemoveDevice: () -> Unit,
    onRemoveUser: (String) -> Unit,
) {
    val dateFormat = remember { SimpleDateFormat("MMM dd, yyyy 'at' HH:mm", Locale.getDefault()) }
    val pairedDate = remember(device.pairedAt) { dateFormat.format(Date(device.pairedAt)) }

    var showUserMenu by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = device.displayName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Paired $pairedDate",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "ID: ${device.deviceId.take(16)}...",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    )

                    // Show allowed users
                    if (device.allowedUsers.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Allowed users: ${device.allowedUsers.joinToString(", ")}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.Medium,
                        )
                    }
                }

                Column(horizontalAlignment = Alignment.End) {
                    // Remove entire device button
                    IconButton(onClick = onRemoveDevice) {
                        Icon(
                            imageVector = Icons.Default.Delete,
                            contentDescription = "Remove device",
                            tint = MaterialTheme.colorScheme.error,
                        )
                    }

                    // Manage users button (only show if multiple users)
                    if (device.allowedUsers.size > 1) {
                        IconButton(onClick = { showUserMenu = !showUserMenu }) {
                            Icon(
                                imageVector = Icons.Default.Person,
                                contentDescription = "Manage users",
                            )
                        }
                    }
                }
            }

            // User management menu
            if (showUserMenu && device.allowedUsers.size > 1) {
                Spacer(modifier = Modifier.height(12.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Remove individual user:",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Bold,
                )

                Spacer(modifier = Modifier.height(8.dp))

                device.allowedUsers.forEach { username ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(text = username, style = MaterialTheme.typography.bodyMedium)
                        TextButton(onClick = { onRemoveUser(username) }) {
                            Text("Remove", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        }
    }
}
