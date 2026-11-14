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
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.network.PairingTransport
import dev.rourunisen.tapauth.network.PairingUpdate

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(
    pairingUrl: PairingUrl,
    viewModel: PairingViewModel,
    onPairingComplete: () -> Unit,
    onPairingFailed: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    // The session lives in the ViewModel, so this collector only renders what it reports.
    val update by viewModel.update.collectAsState()

    // Idempotent: an attempt that is still running for this QR code is reused, so a re-created
    // composition (rotation) re-attaches to it instead of starting a second handshake.
    LaunchedEffect(pairingUrl) { viewModel.beginPairing(pairingUrl) }

    // Terminal outcomes arrive as events, once each, from the ViewModel. They are deliberately not
    // re-derived from the collected state: that state stays `Complete` after a successful pairing,
    // so a screen seeded with it would report the previous attempt's outcome as the *next* one's
    // and send the user straight back to Home — before the new session's `Connecting` even reached
    // the collector, leaving that session running with no screen to show its SAS.
    LaunchedEffect(Unit) {
        viewModel.outcomes.collect { outcome ->
            when (outcome) {
                is PairingUpdate.Complete -> onPairingComplete()
                is PairingUpdate.Failed -> onPairingFailed(outcome.message)
                PairingUpdate.Cancelled ->
                    onPairingFailed(context.getString(R.string.pairing_cancelled_message))
                else -> Unit
            }
        }
    }

    // Disposing the composition is not a user decision. The ViewModel keeps the session alive and
    // sends no `PairingAbort`, which is what makes a rotation during the SAS a non-event; only the
    // explicit exits below end the pairing.
    DisposableEffect(pairingUrl) {
        onDispose { viewModel.leave(PairingExit.ScreenDisposed) }
    }

    // A deliberate exit, by contrast, has to tell the desktop: the ViewModel aborts a live SAS
    // prompt. It no longer waits here for the abort to be written, because the session outlives
    // this screen — leaving immediately cannot cancel it.
    val leavePairing: () -> Unit = {
        viewModel.leave(PairingExit.UserRequested)
        onBack()
    }

    BackHandler(onBack = leavePairing)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(text = stringResource(R.string.pairing_title)) },
                navigationIcon = {
                    IconButton(onClick = leavePairing) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.general_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentAlignment = Alignment.Center,
        ) {
            when (val state = update) {
                is PairingUpdate.Connecting -> {
                    ConnectingView()
                }
                is PairingUpdate.AwaitingSas -> {
                    VerifySASView(
                        sas = state.sas,
                        transport = state.transport,
                        onConfirm = { viewModel.approveSas() },
                        onCancel = { viewModel.rejectSas() },
                    )
                }
                is PairingUpdate.Confirming -> {
                    ConfirmingView()
                }
                is PairingUpdate.Complete -> {
                    SuccessView(onDone = onPairingComplete)
                }
                is PairingUpdate.Failed -> {
                    FailedView(
                        message = state.message,
                        onRetry = { viewModel.retry() },
                        onBack = leavePairing,
                    )
                }
                PairingUpdate.Cancelled -> {
                    FailedView(
                        message = stringResource(R.string.pairing_user_cancelled),
                        onRetry = { viewModel.retry() },
                        onBack = leavePairing,
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
private fun VerifySASView(
    sas: String,
    transport: PairingTransport,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
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

        Text(
            text =
                when (transport) {
                    PairingTransport.BLE -> stringResource(R.string.pairing_via_bluetooth)
                    PairingTransport.UDP -> stringResource(R.string.pairing_via_network)
                },
            style = MaterialTheme.typography.labelLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors =
                CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
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
