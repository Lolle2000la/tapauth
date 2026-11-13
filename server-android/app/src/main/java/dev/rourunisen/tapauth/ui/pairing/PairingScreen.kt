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
import dev.rourunisen.tapauth.network.PairingSession
import dev.rourunisen.tapauth.network.PairingTransport
import dev.rourunisen.tapauth.network.PairingUpdate
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** How long a deferred back-out waits for the session's terminal update before leaving anyway. */
private const val EXIT_FALLBACK_MS = 1_500L

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(
    pairingUrl: PairingUrl,
    onPairingComplete: () -> Unit,
    onPairingFailed: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    // The composition scope is main-dispatched, so updates reported from a background dispatcher
    // are marshalled onto the main thread by the `scope.launch` in the collector below.
    val scope = rememberCoroutineScope()

    // Bumped by the retry button: it recreates the session (and its coroutines) from scratch.
    var attempt by remember(pairingUrl) { mutableStateOf(0) }
    val session = remember(pairingUrl, attempt) { PairingSession(context, pairingUrl) }
    var update by
        remember(pairingUrl, attempt) {
            mutableStateOf<PairingUpdate>(PairingUpdate.Connecting)
        }
    // Terminal outcomes reach the host exactly once, no matter which path reports them first.
    var terminalReported by remember(pairingUrl, attempt) { mutableStateOf(false) }
    // Set while a back-out waits for the abort to be written; the screen leaves on the terminal
    // update (or the fallback below), never before.
    var pendingExit by remember(pairingUrl, attempt) { mutableStateOf(false) }
    var exited by remember(pairingUrl, attempt) { mutableStateOf(false) }

    val reportComplete: () -> Unit = {
        if (!terminalReported) {
            terminalReported = true
            onPairingComplete()
        }
    }

    LaunchedEffect(pairingUrl, attempt) {
        session.start(scope) { newUpdate ->
            scope.launch {
                update = newUpdate
                when {
                    newUpdate is PairingUpdate.Complete -> reportComplete()
                    newUpdate is PairingUpdate.Failed && !terminalReported -> {
                        terminalReported = true
                        onPairingFailed(newUpdate.message)
                    }
                    newUpdate is PairingUpdate.Cancelled && !terminalReported -> {
                        terminalReported = true
                        onPairingFailed(context.getString(R.string.pairing_cancelled_message))
                    }
                }
            }
        }
    }

    DisposableEffect(pairingUrl, attempt) { onDispose { session.close() } }

    // Leaving the screen disposes it, and disposal closes the session — so a back-out during the
    // SAS must not navigate immediately or the reject's `PairingAbort(USER_REJECTED_SAS)` is
    // cancelled before it is written and the desktop never learns. It records the decision, then
    // leaves when the terminal update reports the abort is out; the fallback below guarantees the
    // user can never be stuck here.
    val navigateAway: () -> Unit = {
        if (!exited) {
            exited = true
            if (!terminalReported) {
                terminalReported = true
                onPairingFailed(context.getString(R.string.pairing_cancelled_message))
            }
            onBack()
        }
    }

    val leavePairing: () -> Unit = {
        if (update is PairingUpdate.AwaitingSas && !pendingExit) {
            pendingExit = true
            session.rejectSas()
        } else {
            navigateAway()
        }
    }

    if (pendingExit) {
        LaunchedEffect(update) {
            if (update is PairingUpdate.Cancelled || update is PairingUpdate.Failed) navigateAway()
        }
        LaunchedEffect(Unit) {
            delay(EXIT_FALLBACK_MS)
            navigateAway()
        }
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
                        onConfirm = { session.approveSas() },
                        onCancel = { session.rejectSas() },
                    )
                }
                is PairingUpdate.Confirming -> {
                    ConfirmingView()
                }
                is PairingUpdate.Complete -> {
                    SuccessView(onDone = reportComplete)
                }
                is PairingUpdate.Failed -> {
                    FailedView(
                        message = state.message,
                        onRetry = { attempt++ },
                        onBack = leavePairing,
                    )
                }
                PairingUpdate.Cancelled -> {
                    FailedView(
                        message = stringResource(R.string.pairing_user_cancelled),
                        onRetry = { attempt++ },
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
