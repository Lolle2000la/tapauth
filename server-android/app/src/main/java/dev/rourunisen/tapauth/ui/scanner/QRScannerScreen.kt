package dev.rourunisen.tapauth.ui.scanner

import android.Manifest
import android.util.Log
import android.util.Size
import androidx.activity.compose.BackHandler
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import dev.rourunisen.tapauth.data.PairingUrl
import java.util.concurrent.Executors

@OptIn(ExperimentalPermissionsApi::class, ExperimentalMaterial3Api::class)
@Composable
fun QRScannerScreen(onQRCodeScanned: (PairingUrl) -> Unit, onBack: () -> Unit) {
    val cameraPermissionState = rememberPermissionState(Manifest.permission.CAMERA)
    var scanStatus by remember { mutableStateOf("Initializing camera...") }
    var lastScannedCode by remember { mutableStateOf<String?>(null) }

    // Handle system back button
    BackHandler(onBack = onBack)

    LaunchedEffect(Unit) {
        if (!cameraPermissionState.status.isGranted) {
            cameraPermissionState.launchPermissionRequest()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan QR Code") },
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
                cameraPermissionState.status.isGranted -> {
                    Box(modifier = Modifier.fillMaxSize()) {
                        CameraPreview(
                            onQRCodeScanned = onQRCodeScanned,
                            onScanStatus = { status -> scanStatus = status },
                            onCodeDetected = { code -> lastScannedCode = code },
                        )

                        // Status overlay
                        Column(
                            modifier =
                                Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(16.dp)
                        ) {
                            Card(
                                colors =
                                    CardDefaults.cardColors(
                                        containerColor =
                                            MaterialTheme.colorScheme.surface.copy(alpha = 0.9f)
                                    )
                            ) {
                                Column(modifier = Modifier.padding(16.dp)) {
                                    Text(
                                        text = "Status: $scanStatus",
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    lastScannedCode?.let { code ->
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            text = "Last detected: ${code.take(50)}...",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.primary,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
                else -> {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text("Camera permission is required to scan QR codes")
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(onClick = { cameraPermissionState.launchPermissionRequest() }) {
                            Text("Grant Permission")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CameraPreview(
    onQRCodeScanned: (PairingUrl) -> Unit,
    onScanStatus: (String) -> Unit,
    onCodeDetected: (String) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val cameraProviderFuture = remember { ProcessCameraProvider.getInstance(context) }
    var hasScanned by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) { onScanStatus("Camera starting...") }

    errorMessage?.let { error ->
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text("Camera initialization failed:")
            Text(error, color = MaterialTheme.colorScheme.error)
        }
        return
    }

    AndroidView(
        factory = { ctx ->
            val previewView = PreviewView(ctx)
            val executor = ContextCompat.getMainExecutor(ctx)

            cameraProviderFuture.addListener(
                {
                    try {
                        val cameraProvider = cameraProviderFuture.get()

                        val preview =
                            Preview.Builder().build().also {
                                it.setSurfaceProvider(previewView.surfaceProvider)
                            }

                        // Create resolution selector for higher resolution QR code detection
                        val resolutionSelector =
                            ResolutionSelector.Builder()
                                .setResolutionStrategy(
                                    ResolutionStrategy(
                                        Size(1920, 1080),
                                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                                    )
                                )
                                .build()

                        val imageAnalysis =
                            ImageAnalysis.Builder()
                                .setResolutionSelector(resolutionSelector)
                                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                                .build()
                                .also {
                                    onScanStatus("Scanning for QR codes...")
                                    it.setAnalyzer(
                                        Executors.newSingleThreadExecutor(),
                                        QRCodeAnalyzer { qrCode ->
                                            if (!hasScanned) {
                                                Log.d("QRScanner", "QR Code detected: $qrCode")
                                                onCodeDetected(qrCode)
                                                onScanStatus("QR code detected! Parsing...")

                                                // Try to parse as pairing URL
                                                val pairingUrl = PairingUrl.parse(qrCode)
                                                if (pairingUrl != null) {
                                                    Log.d(
                                                        "QRScanner",
                                                        "Valid pairing URL parsed successfully",
                                                    )
                                                    onScanStatus("Valid pairing URL! Connecting...")
                                                    hasScanned = true
                                                    onQRCodeScanned(pairingUrl)
                                                } else {
                                                    Log.w(
                                                        "QRScanner",
                                                        "QR code content doesn't match expected format",
                                                    )
                                                    Log.w(
                                                        "QRScanner",
                                                        "Expected: tapauth://pair?v=1&pk=...&p=...",
                                                    )
                                                    Log.w("QRScanner", "Received: $qrCode")
                                                    onScanStatus(
                                                        "Invalid QR code format. Expected tapauth:// URL"
                                                    )
                                                }
                                            }
                                        },
                                    )
                                }

                        val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

                        try {
                            cameraProvider.unbindAll()
                            cameraProvider.bindToLifecycle(
                                lifecycleOwner,
                                cameraSelector,
                                preview,
                                imageAnalysis,
                            )
                            Log.d("QRScanner", "Camera bound successfully")
                            onScanStatus("Camera ready - point at QR code")
                        } catch (e: Exception) {
                            android.util.Log.e("QRScanner", "Camera binding failed", e)
                            errorMessage = e.message ?: "Unknown camera error"
                            e.printStackTrace()
                        }
                    } catch (e: Exception) {
                        android.util.Log.e("QRScanner", "Camera initialization failed", e)
                        errorMessage = e.message ?: "Camera initialization failed"
                        e.printStackTrace()
                    }
                },
                executor,
            )

            previewView
        },
        modifier = Modifier.fillMaxSize(),
    )
}
