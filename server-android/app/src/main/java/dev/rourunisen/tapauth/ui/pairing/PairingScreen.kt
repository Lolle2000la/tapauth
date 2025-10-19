package dev.rourunisen.tapauth.ui.pairing

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.network.PairingClient
import dev.rourunisen.tapauth.network.PairingResult
import kotlinx.coroutines.launch

@Composable
fun PairingScreen(
    pairingUrl: PairingUrl,
    onPairingComplete: () -> Unit,
    onPairingFailed: (String) -> Unit,
    onBack: () -> Unit
) {
    var pairingState by remember { mutableStateOf<PairingState>(PairingState.Connecting) }
    val scope = rememberCoroutineScope()
    val pairingClient = remember { PairingClient() }
    
    LaunchedEffect(pairingUrl) {
        scope.launch {
            // Prefer IPv4 if available, fallback to IPv6
            val ipAddress = pairingUrl.ipv4 ?: pairingUrl.ipv6 ?: run {
                pairingState = PairingState.Failed("No IP address available")
                return@launch
            }
            
            // Phase 1: Initiate pairing and get SAS for verification
            val initResult = pairingClient.initiatePairing(
                ipAddress, 
                pairingUrl.port, 
                pairingUrl.publicKey
            )
            
            when (initResult) {
                is dev.rourunisen.tapauth.network.PairingInitResult.AwaitingSASVerification -> {
                    pairingState = PairingState.VerifySAS(
                        sas = initResult.sas,
                        socket = initResult.socket,
                        psk = initResult.psk,
                        clientPublicKey = initResult.clientPublicKey
                    )
                }
                is dev.rourunisen.tapauth.network.PairingInitResult.Error -> {
                    pairingState = PairingState.Failed(initResult.message)
                }
            }
        }
    }
    
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text("Device Pairing") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Text("←")
                    }
                }
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentAlignment = Alignment.Center
        ) {
            when (val state = pairingState) {
                is PairingState.Connecting -> {
                    ConnectingView()
                }
                is PairingState.VerifySAS -> {
                    VerifySASView(
                        sas = state.sas,
                        onConfirm = {
                            pairingState = PairingState.Confirming
                            scope.launch {
                                // Phase 2: Complete pairing after SAS verification
                                val result = pairingClient.completePairing(
                                    socket = state.socket,
                                    psk = state.psk,
                                    clientPublicKey = state.clientPublicKey,
                                    sasConfirmed = true
                                )
                                
                                when (result) {
                                    is PairingResult.Success -> {
                                        // TODO: Save device to repository
                                        pairingState = PairingState.Success
                                        onPairingComplete()
                                    }
                                    is PairingResult.Error -> {
                                        pairingState = PairingState.Failed(result.message)
                                        onPairingFailed(result.message)
                                    }
                                }
                            }
                        },
                        onCancel = {
                            // Close socket and discard PSK
                            state.socket.close()
                            state.psk.fill(0)
                            pairingState = PairingState.Failed("User cancelled")
                            onPairingFailed("Pairing cancelled")
                        }
                    )
                }
                is PairingState.Confirming -> {
                    ConfirmingView()
                }
                is PairingState.Success -> {
                    SuccessView(onDone = onPairingComplete)
                }
                is PairingState.Failed -> {
                    FailedView(
                        message = state.message,
                        onRetry = {
                            pairingState = PairingState.Connecting
                        },
                        onBack = onBack
                    )
                }
            }
        }
    }
}

@Composable
private fun ConnectingView() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        CircularProgressIndicator()
        Text(
            text = "Connecting to device...",
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            text = "Please wait",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun VerifySASView(
    sas: String,
    onConfirm: () -> Unit,
    onCancel: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        Text(
            text = "Verify Security Code",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = "Compare this code with the one shown on your computer:",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center
        )
        
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer
            )
        ) {
            Text(
                text = sas,
                modifier = Modifier.padding(32.dp),
                style = MaterialTheme.typography.displayLarge,
                fontWeight = FontWeight.Bold,
                fontSize = 48.sp,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
        
        Text(
            text = "Do the codes match?",
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center
        )
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.weight(1f)
            ) {
                Text("No, Cancel")
            }
            
            Button(
                onClick = onConfirm,
                modifier = Modifier.weight(1f)
            ) {
                Text("Yes, Pair")
            }
        }
    }
}

@Composable
private fun ConfirmingView() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        CircularProgressIndicator()
        Text(
            text = "Finalizing pairing...",
            style = MaterialTheme.typography.titleMedium
        )
    }
}

@Composable
private fun SuccessView(onDone: () -> Unit) {
    Column(
        modifier = Modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        Text(
            text = "✓",
            style = MaterialTheme.typography.displayLarge,
            fontSize = 72.sp,
            color = MaterialTheme.colorScheme.primary
        )
        
        Text(
            text = "Pairing Successful!",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = "Your device is now paired and ready for authentication",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = onDone,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Done")
        }
    }
}

@Composable
private fun FailedView(
    message: String,
    onRetry: () -> Unit,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        Text(
            text = "✗",
            style = MaterialTheme.typography.displayLarge,
            fontSize = 72.sp,
            color = MaterialTheme.colorScheme.error
        )
        
        Text(
            text = "Pairing Failed",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = message,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f)
            ) {
                Text("Back")
            }
            
            Button(
                onClick = onRetry,
                modifier = Modifier.weight(1f)
            ) {
                Text("Retry")
            }
        }
    }
}

private sealed class PairingState {
    object Connecting : PairingState()
    data class VerifySAS(
        val sas: String,
        val socket: java.net.Socket,
        val psk: ByteArray,
        val clientPublicKey: ByteArray
    ) : PairingState()
    object Confirming : PairingState()
    object Success : PairingState()
    data class Failed(val message: String) : PairingState()
}
