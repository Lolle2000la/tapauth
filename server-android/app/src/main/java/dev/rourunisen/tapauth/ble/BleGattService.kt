package dev.rourunisen.tapauth.ble

import android.Manifest
import android.content.Context
import android.app.Service
import android.bluetooth.*
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Intent
import android.content.pm.PackageManager
import android.app.Notification
import android.app.PendingIntent
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.ActivityCompat
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.biometric.BiometricHelper
import dev.rourunisen.tapauth.service.ReplayMitigationCache
import kotlinx.coroutines.*
import java.util.UUID

/**
 * BLE GATT Service - Scanner/Central Role
 * 
 * According to the specification:
 * - Client (desktop) acts as Advertiser/Peripheral
 * - Server (Android) acts as Scanner/Central
 * 
 * This service scans for BLE advertisements from paired clients that contain
 * temporal identifiers. When a match is found, it connects to the client's
 * GATT server to exchange authentication messages.
 */
class BleGattService : Service() {
    
    companion object {
        private const val TAG = "BleGattService"
        private const val NOTIFICATION_ID = 2
        
        // UUIDs from shared library specification
        val SERVICE_UUID: UUID = UUID.fromString("b4ad84c0-2adb-4876-8315-b39d983b2bde")
        val CLIENT_COMMAND_CHAR_UUID: UUID = UUID.fromString("caf54438-9d78-4697-8886-0a4cfa87ba8d")
        val SERVER_RESPONSE_CHAR_UUID: UUID = UUID.fromString("ca6238be-c194-49b7-855b-58f41d3da626")
        
        fun start(context: Context) {
            val intent = Intent(context, BleGattService::class.java)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            try {
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                config.bleLastStartMillis = System.currentTimeMillis()
            } catch (_: Exception) { }
        }

        fun stop(context: Context) {
            val intent = Intent(context, BleGattService::class.java)
            context.stopService(intent)
            try {
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                config.bleRunning = false
                val b = Intent("dev.rourunisen.tapauth.ACTION_SERVICE_STATE_CHANGE").apply {
                    putExtra("ble_running", false)
                }
                context.sendBroadcast(b)
            } catch (_: Exception) { }
        }
    }
    
    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothLeScanner: BluetoothLeScanner? = null
    private var bluetoothGatt: BluetoothGatt? = null
    
    private lateinit var deviceRepository: DeviceRepository
    private lateinit var keypairRepository: dev.rourunisen.tapauth.data.KeypairRepository
    private lateinit var biometricHelper: BiometricHelper
    private val replayMitigationCache = ReplayMitigationCache.getInstance()
    
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    // Map of temporal IDs to device CSKs for quick lookup
    private val temporalIdCache = mutableMapOf<String, String>()
    private var cacheUpdateJob: Job? = null
    
    // Scan callback to discover client advertisements
    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            super.onScanResult(callbackType, result)
            
            // Extract service data containing temporal identifier
            val serviceData = result.scanRecord?.getServiceData(ParcelUuid(SERVICE_UUID))
            if (serviceData != null && serviceData.size == 16) {
                val temporalIdHex = serviceData.toHex()
                Log.d(TAG, "Found TapAuth advertisement with temporal ID: ${temporalIdHex.take(16)}...")
                
                // Check if this temporal ID matches any of our paired devices
                serviceScope.launch {
                    val matchedCsk = temporalIdCache[temporalIdHex]
                    if (matchedCsk != null) {
                        Log.i(TAG, "Temporal ID matches paired device, connecting...")
                        connectToClient(result.device, matchedCsk)
                    } else {
                        Log.d(TAG, "Temporal ID does not match any paired device")
                    }
                }
            }
        }
        
        override fun onScanFailed(errorCode: Int) {
            super.onScanFailed(errorCode)
            Log.e(TAG, "BLE scan failed with error: $errorCode")
            try { 
                dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this@BleGattService }, false) 
            } catch (_: Exception) { }
        }
    }
    
    // GATT client callback for connecting to client's GATT server
    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.i(TAG, "Connected to client GATT server: ${gatt.device.address}")
                    if (ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        gatt.discoverServices()
                    }
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.i(TAG, "Disconnected from client GATT server: ${gatt.device.address}")
                    gatt.close()
                }
            }
        }
        
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.d(TAG, "Services discovered on client GATT server")
                
                // Find the TapAuth service
                val service = gatt.getService(SERVICE_UUID)
                if (service != null) {
                    val clientCommandChar = service.getCharacteristic(CLIENT_COMMAND_CHAR_UUID)
                    val serverResponseChar = service.getCharacteristic(SERVER_RESPONSE_CHAR_UUID)
                    
                    if (clientCommandChar != null && serverResponseChar != null) {
                        Log.i(TAG, "Found TapAuth characteristics, reading authentication request")
                        
                        // Read the authentication request from the client command characteristic
                        if (ActivityCompat.checkSelfPermission(
                                this@BleGattService,
                                Manifest.permission.BLUETOOTH_CONNECT
                            ) == PackageManager.PERMISSION_GRANTED
                        ) {
                            gatt.readCharacteristic(clientCommandChar)
                        }
                    } else {
                        Log.e(TAG, "TapAuth characteristics not found")
                        gatt.disconnect()
                    }
                } else {
                    Log.e(TAG, "TapAuth service not found")
                    gatt.disconnect()
                }
            } else {
                Log.e(TAG, "Service discovery failed with status: $status")
                gatt.disconnect()
            }
        }
        
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int
        ) {
            if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == CLIENT_COMMAND_CHAR_UUID) {
                Log.d(TAG, "Read authentication request from client: ${value.size} bytes")
                
                // Handle the authentication request
                serviceScope.launch {
                    handleAuthenticationRequest(gatt, value)
                }
            }
        }
        
        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.d(TAG, "Successfully wrote response to client")
            } else {
                Log.e(TAG, "Failed to write response to client, status: $status")
            }
            
            // Disconnect after writing response
            if (ActivityCompat.checkSelfPermission(
                    this@BleGattService,
                    Manifest.permission.BLUETOOTH_CONNECT
                ) == PackageManager.PERMISSION_GRANTED
            ) {
                gatt.disconnect()
            }
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        deviceRepository = DeviceRepository(this)
        keypairRepository = dev.rourunisen.tapauth.data.KeypairRepository(this)
        biometricHelper = BiometricHelper(this)
        
        bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter
        bluetoothLeScanner = bluetoothAdapter?.bluetoothLeScanner
        
        if (bluetoothAdapter == null || bluetoothLeScanner == null) {
            Log.e(TAG, "Bluetooth or BLE scanning not supported on this device")
            stopSelf()
            return
        }
        
        // Start as foreground so the system keeps the service alive in background
        try {
            startForeground(NOTIFICATION_ID, createNotification())
            try {
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(this)
                config.bleLastStartMillis = System.currentTimeMillis()
            } catch (_: Exception) { }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start foreground for BLE service: ${e.message}")
        }

        startTemporalIdCache()
        startScanning()
    }

    private fun createNotification(): Notification {
        val notificationIntent = Intent(this, dev.rourunisen.tapauth.MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notificationIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        return androidx.core.app.NotificationCompat.Builder(this, dev.rourunisen.tapauth.TapAuthApplication.CHANNEL_ID)
            .setContentTitle("TapAuth BLE")
            .setContentText("BLE scanner active, listening for paired clients")
            .setSmallIcon(dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
    
    private fun startTemporalIdCache() {
        // Build cache of valid temporal IDs for all paired devices
        cacheUpdateJob?.cancel()
        cacheUpdateJob = serviceScope.launch {
            while (isActive) {
                updateTemporalIdCache()
                
                // Wait until next 60-second boundary to update cache
                val now = System.currentTimeMillis()
                val nextBoundary = ((now / 60_000) + 1) * 60_000
                val delayMs = nextBoundary - now
                delay(delayMs)
            }
        }
    }
    
    private suspend fun updateTemporalIdCache() {
        temporalIdCache.clear()
        
        val pairedDevices = deviceRepository.getAllPairedDevices()
        val currentWindow = System.currentTimeMillis() / 60_000
        
        for (device in pairedDevices) {
            try {
                // Generate both current and previous temporal IDs
                val currentId = dev.rourunisen.tapauth.crypto.generateTemporalId(device.csk, currentWindow)
                val previousId = dev.rourunisen.tapauth.crypto.generateTemporalId(device.csk, currentWindow - 1)
                
                // Store CSK as hex string for later retrieval
                val cskHex = device.csk.toHex()
                temporalIdCache[currentId] = cskHex
                temporalIdCache[previousId] = cskHex
                
                Log.d(TAG, "Cached temporal IDs for device: ${device.displayName}")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to generate temporal ID for device ${device.deviceId}", e)
            }
        }
        
        Log.i(TAG, "Updated temporal ID cache with ${temporalIdCache.size} entries for ${pairedDevices.size} devices")
    }
    
    private fun startScanning() {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_SCAN
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_SCAN permission not granted")
            return
        }
        
        // Create scan filter for TapAuth service UUID
        val scanFilter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()
        
        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        
        bluetoothLeScanner?.startScan(listOf(scanFilter), scanSettings, scanCallback)
        Log.i(TAG, "BLE scanning started for TapAuth service")
        
        try { 
            dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this }, true) 
        } catch (_: Exception) { }
    }
    
    private fun stopScanning() {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_SCAN
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            bluetoothLeScanner?.stopScan(scanCallback)
            Log.i(TAG, "BLE scanning stopped")
        }
        cacheUpdateJob?.cancel()
    }
    
    private fun connectToClient(device: BluetoothDevice, csk: String) {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            return
        }
        
        Log.i(TAG, "Connecting to client GATT server: ${device.address}")
        bluetoothGatt = device.connectGatt(this, false, gattCallback)
    }
    
    private suspend fun handleAuthenticationRequest(gatt: BluetoothGatt, data: ByteArray) {
        try {
            Log.d(TAG, "Handling BLE authentication request: ${data.size} bytes from ${gatt.device.address}")
            
            // Step 1: Parse the encrypted packet
            val authRequest = try {
                dev.rourunisen.tapauth.protocol.ProtobufParser.parseAuthRequest(data)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse BLE auth request", e)
                sendResponseToClient(gatt, "PARSE_ERROR".toByteArray())
                return
            }
            
            Log.d(TAG, "Parsed BLE request: username=${authRequest.username}, hostname=${authRequest.hostname}")
            
            // Decode Base64 strings to ByteArrays
            val challengeBytes = android.util.Base64.decode(authRequest.challenge, android.util.Base64.NO_WRAP)
            val signatureBytes = android.util.Base64.decode(authRequest.signature, android.util.Base64.NO_WRAP)
            
            // Step 2: Replay attack mitigation
            if (replayMitigationCache.isReplay(challengeBytes, authRequest.timestampUnixSeconds)) {
                Log.w(TAG, "BLE replay attack detected, rejecting request")
                sendResponseToClient(gatt, "REPLAY_DETECTED".toByteArray())
                return
            }
            
            // Step 3: Find paired device and verify signature
            val pairedDevices = deviceRepository.getAllPairedDevices()
            
            if (pairedDevices.isEmpty()) {
                Log.w(TAG, "No paired devices found, rejecting BLE request")
                sendResponseToClient(gatt, "NO_PAIRED_DEVICES".toByteArray())
                return
            }
            
            Log.d(TAG, "Found ${pairedDevices.size} paired device(s)")
            
            // Reconstruct message for verification
            val gson = com.google.gson.Gson()
            val requestJson = gson.toJson(authRequest)
            val messageForVerification = try {
                dev.rourunisen.tapauth.crypto.serializeAuthRequestForVerification(requestJson)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to serialize BLE request for verification", e)
                sendResponseToClient(gatt, "VERIFICATION_ERROR".toByteArray())
                return
            }
            
            // Try to verify signature against each paired device
            var matchedDevice: dev.rourunisen.tapauth.data.PairedDevice? = null
            for (pairedDev in pairedDevices) {
                try {
                    val isValid = dev.rourunisen.tapauth.crypto.verifySignature(
                        pairedDev.publicKey,
                        messageForVerification,
                        signatureBytes
                    )
                    if (isValid) {
                        matchedDevice = pairedDev
                        Log.d(TAG, "BLE signature verified for device: ${pairedDev.displayName} (${pairedDev.deviceId})")
                        break
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to verify BLE signature for device ${pairedDev.deviceId}", e)
                }
            }
            
            if (matchedDevice == null) {
                Log.w(TAG, "BLE signature verification failed for all devices, rejecting request")
                sendResponseToClient(gatt, "INVALID_SIGNATURE".toByteArray())
                return
            }
            
            // Step 4: Request biometric authentication via AuthRequestManager
            val authRequestManager = dev.rourunisen.tapauth.service.AuthRequestManager.getInstance()
            authRequestManager.submitRequest(
                context = this,
                deviceId = matchedDevice.deviceId,
                deviceName = matchedDevice.displayName,
                username = authRequest.username,
                hostname = authRequest.hostname,
                challenge = challengeBytes,
                timestamp = authRequest.timestampUnixSeconds,
                transportType = dev.rourunisen.tapauth.data.TransportType.BLE
            ) { approved, signedChallenge ->
                // Step 5: Create and send encrypted grant/denial
                if (approved && signedChallenge != null) {
                    Log.d(TAG, "BLE auth request approved, creating encrypted grant")
                    try {
                        // Get server private key for signing
                        val privateKey = keypairRepository.getPrivateKey()
                        
                        // Create WrapperMessage containing AuthenticationGrant
                        val wrapperMessage = dev.rourunisen.tapauth.crypto.createGrantWrapperMessage(
                            signedChallenge,
                            privateKey
                        )
                        
                        // Create proper EncryptedPacket per specification
                        val encryptedPacket = dev.rourunisen.tapauth.crypto.createEncryptedPacket(
                            matchedDevice.csk,
                            wrapperMessage
                        )
                        
                        sendResponseToClient(gatt, encryptedPacket)
                        Log.d(TAG, "Sent encrypted grant via BLE (${encryptedPacket.size} bytes)")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send BLE grant", e)
                        sendResponseToClient(gatt, "ERROR".toByteArray())
                    }
                } else {
                    Log.d(TAG, "BLE auth request denied or timed out")
                    sendResponseToClient(gatt, "AUTH_DENIED".toByteArray())
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error handling BLE authentication request", e)
            sendResponseToClient(gatt, "ERROR".toByteArray())
        }
    }
    
    private fun sendResponseToClient(gatt: BluetoothGatt, response: ByteArray) {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            return
        }
        
        // Write to the server response characteristic on the client's GATT server
        val service = gatt.getService(SERVICE_UUID)
        val characteristic = service?.getCharacteristic(SERVER_RESPONSE_CHAR_UUID)
        
        if (characteristic != null) {
            characteristic.value = response
            gatt.writeCharacteristic(characteristic)
            Log.d(TAG, "Wrote response: ${response.size} bytes to ${gatt.device.address}")
        } else {
            Log.e(TAG, "Server response characteristic not found on client")
            gatt.disconnect()
        }
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "BLE GATT Service started (Scanner/Central mode)")
        return START_STICKY
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onDestroy() {
        super.onDestroy()
        stopScanning()
        
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            bluetoothGatt?.close()
        }
        
        try { 
            dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this }, false) 
        } catch (_: Exception) { }
        serviceScope.cancel()
        Log.i(TAG, "BLE GATT Service destroyed")
    }
    
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
