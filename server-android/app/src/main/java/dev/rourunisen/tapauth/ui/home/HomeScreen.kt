package dev.rourunisen.tapauth.ui.home

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import android.content.Intent
import dev.rourunisen.tapauth.service.AuthenticationService
import dev.rourunisen.tapauth.ble.BleGattService

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onStartScanning: () -> Unit,
    onViewDevices: () -> Unit,
    onSettings: () -> Unit
) {
    // Status display only; toggles were removed in favor of Settings controls
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("TapAuth") }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Spacer(modifier = Modifier.height(32.dp))
            
            // UDP Service Status Card
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "UDP Service",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Port 36692",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            
            // BLE Service Status Card
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "BLE GATT Server",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Advertising",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Pair New Device Button
            Button(
                onClick = onStartScanning,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
            ) {
                Text(
                    text = "Pair New Device",
                    style = MaterialTheme.typography.titleMedium
                )
            }
            
            // View Paired Devices Button
            OutlinedButton(
                onClick = onViewDevices,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
            ) {
                Text(
                    text = "Paired Devices",
                    style = MaterialTheme.typography.titleMedium
                )
            }
            
            // Settings Button
            OutlinedButton(
                onClick = onSettings,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
            ) {
                Text(
                    text = "Settings",
                    style = MaterialTheme.typography.titleMedium
                )
            }
            
            Spacer(modifier = Modifier.weight(1f))
            
            // Info Text
            Text(
                text = "TapAuth allows you to authenticate to your computer by simply tapping your phone",
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 32.dp)
            )
        }
    }
}
