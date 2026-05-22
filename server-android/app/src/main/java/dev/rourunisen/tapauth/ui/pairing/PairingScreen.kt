package dev.rourunisen.tapauth.ui.pairing

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.rourunisen.tapauth.R
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.network.PairingClient
import dev.rourunisen.tapauth.network.PairingResult
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(
    pairingUrl: PairingUrl,
    onPairingComplete: () -> Unit,
    onPairingFailed: (String) -> Unit,
    onBack: () -> Unit,
) {
    var pairingState by remember { mutableStateOf<PairingState>(PairingState.Connecting) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val pairingClient = remember { PairingClient(context) }
    val deviceRepository = remember { DeviceRepository(context) }

    // Handle system back button
    BackHandler(onBack = onBack)

    LaunchedEffect(pairingUrl) {
        scope.launch {
            // Prefer IPv4 if available, fallback to IPv6
            val ipAddress =
                pairingUrl.ipv4
                    ?: pairingUrl.ipv6
                    ?: run {
                        pairingState =
                            PairingState.Failed(context.getString(R.string.pairing_no_ip))
                        return@launch
                    }

            // Phase 1: Initiate pairing and get SAS for verification
            val initResult = pairingClient.initiatePairing(ipAddress, pairingUrl.port)

            when (initResult) {
                is dev.rourunisen.tapauth.network.PairingInitResult.AwaitingSASVerification -> {
                    pairingState =
                        PairingState.VerifySAS(
                            sas = initResult.sas,
                            socket = initResult.socket,
                            psk = initResult.psk,
                            clientEd25519Key = initResult.clientEd25519Key,
                            clientDeviceName = initResult.clientDeviceName,
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
            TopAppBar(
                title = { Text(text = stringResource(R.string.pairing_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.general_back),
                        )
                    }
                },
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentAlignment = Alignment.Center,
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
                                val result =
                                    pairingClient.completePairing(
                                        socket = state.socket,
                                        psk = state.psk,
                                        clientEd25519Key = state.clientEd25519Key,
                                        clientDeviceName = state.clientDeviceName,
                                        sasConfirmed = true,
                                    )

                                when (result) {
                                    is PairingResult.Success -> {
                                        // Save device to repository
                                        deviceRepository.savePairedDevice(result.device)
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
                            pairingState =
                                PairingState.Failed(
                                    context.getString(R.string.pairing_user_cancelled)
                                )
                            onPairingFailed(context.getString(R.string.pairing_cancelled_message))
                        },
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
                        onRetry = { pairingState = PairingState.Connecting },
                        onBack = onBack,
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
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        CircularProgressIndicator()
        Text(
            text = stringResource(R.string.pairing_connecting),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.general_please_wait),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun VerifySASView(sas: String, onConfirm: () -> Unit, onCancel: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Text(
            text = stringResource(R.string.pairing_verify_sas_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )

        Text(
            text = stringResource(R.string.pairing_compare_code),
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors =
                CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Text(
                text = sas,
                modifier = Modifier.padding(32.dp),
                style = MaterialTheme.typography.displayLarge,
                fontWeight = FontWeight.Bold,
                fontSize = 48.sp,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }

        Text(
            text = stringResource(R.string.pairing_codes_match),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.pairing_no_cancel))
            }

            Button(onClick = onConfirm, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.pairing_yes_pair))
            }
        }
    }
}

@Composable
private fun ConfirmingView() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        CircularProgressIndicator()
        Text(
            text = stringResource(R.string.pairing_finalizing),
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
private fun SuccessView(onDone: () -> Unit) {
    Column(
        modifier = Modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Icon(
            imageVector = Icons.Default.CheckCircle,
            contentDescription = stringResource(R.string.general_success),
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.primary,
        )

        Text(
            text = stringResource(R.string.pairing_success),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )

        Text(
            text = stringResource(R.string.pairing_success_message),
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.general_done))
        }
    }
}

@Composable
private fun FailedView(message: String, onRetry: () -> Unit, onBack: () -> Unit) {
    Column(
        modifier = Modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Icon(
            imageVector = Icons.Default.Close,
            contentDescription = stringResource(R.string.general_error),
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.error,
        )

        Text(
            text = stringResource(R.string.pairing_failed),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )

        Text(
            text = message,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.general_back))
            }

            Button(onClick = onRetry, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.general_retry))
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
        val clientEd25519Key: ByteArray,
        val clientDeviceName: String,
    ) : PairingState()

    object Confirming : PairingState()

    object Success : PairingState()

    data class Failed(val message: String) : PairingState()
}
