package dev.rourunisen.tapauth.ble

import android.Manifest
import android.app.Service
import android.bluetooth.*
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Intent
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.ActivityCompat
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.biometric.BiometricHelper
import kotlinx.coroutines.*
import java.util.UUID

class BleGattService : Service() {
    
    companion object {
        private const val TAG = "BleGattService"
        
        // UUIDs from shared library specification
        val SERVICE_UUID: UUID = UUID.fromString("b4ad84c0-2adb-4876-8315-b39d983b2bde")
        val CLIENT_COMMAND_CHAR_UUID: UUID = UUID.fromString("caf54438-9d78-4697-8886-0a4cfa87ba8d")
        val SERVER_RESPONSE_CHAR_UUID: UUID = UUID.fromString("ca6238be-c194-49b7-855b-58f41d3da626")
    }
    
    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothGattServer: BluetoothGattServer? = null
    private var bluetoothLeAdvertiser: BluetoothLeAdvertiser? = null
    
    private lateinit var deviceRepository: DeviceRepository
    private lateinit var biometricHelper: BiometricHelper
    
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    private val gattServerCallback = object : BluetoothGattServerCallback() {
        
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            Log.d(TAG, "Connection state changed for ${device.address}: $newState")
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.i(TAG, "Device connected: ${device.address}")
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.i(TAG, "Device disconnected: ${device.address}")
                }
            }
        }
        
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            Log.d(TAG, "Write request on ${characteristic.uuid} from ${device.address}")
            
            if (characteristic.uuid == CLIENT_COMMAND_CHAR_UUID) {
                // Send success response
                if (responseNeeded) {
                    if (ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        bluetoothGattServer?.sendResponse(
                            device,
                            requestId,
                            BluetoothGatt.GATT_SUCCESS,
                            0,
                            null
                        )
                    }
                }
                
                // Handle the command asynchronously
                serviceScope.launch {
                    handleClientCommand(device, value)
                }
            } else {
                if (responseNeeded) {
                    if (ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        bluetoothGattServer?.sendResponse(
                            device,
                            requestId,
                            BluetoothGatt.GATT_WRITE_NOT_PERMITTED,
                            0,
                            null
                        )
                    }
                }
            }
        }
        
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            Log.d(TAG, "Read request on ${characteristic.uuid} from ${device.address}")
            
            if (ActivityCompat.checkSelfPermission(
                    this@BleGattService,
                    Manifest.permission.BLUETOOTH_CONNECT
                ) == PackageManager.PERMISSION_GRANTED
            ) {
                bluetoothGattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    0,
                    characteristic.value
                )
            }
        }
    }
    
    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            Log.i(TAG, "BLE advertising started successfully")
        }
        
        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "BLE advertising failed with error: $errorCode")
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        deviceRepository = DeviceRepository(this)
        biometricHelper = BiometricHelper(this)
        
        bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter
        bluetoothLeAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        
        if (bluetoothAdapter == null || bluetoothLeAdvertiser == null) {
            Log.e(TAG, "Bluetooth or BLE advertising not supported on this device")
            stopSelf()
            return
        }
        
        startGattServer()
        startAdvertising()
    }
    
    private fun startGattServer() {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            return
        }
        
        bluetoothGattServer = bluetoothManager?.openGattServer(this, gattServerCallback)
        
        // Create the service
        val service = BluetoothGattService(
            SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )
        
        // Client command characteristic (client writes authentication requests)
        val clientCommandChar = BluetoothGattCharacteristic(
            CLIENT_COMMAND_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        
        // Server response characteristic (server notifies with responses)
        val serverResponseChar = BluetoothGattCharacteristic(
            SERVER_RESPONSE_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        
        // Add CCC descriptor for notifications
        val cccDescriptor = BluetoothGattDescriptor(
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"), // Standard CCC UUID
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        serverResponseChar.addDescriptor(cccDescriptor)
        
        service.addCharacteristic(clientCommandChar)
        service.addCharacteristic(serverResponseChar)
        
        bluetoothGattServer?.addService(service)
        Log.i(TAG, "GATT server started with service UUID: $SERVICE_UUID")
    }
    
    private fun startAdvertising() {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_ADVERTISE permission not granted")
            return
        }
        
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .build()
        
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()
        
        bluetoothLeAdvertiser?.startAdvertising(settings, data, advertiseCallback)
    }
    
    private fun stopAdvertising() {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
            Log.i(TAG, "BLE advertising stopped")
        }
    }
    
    private suspend fun handleClientCommand(device: BluetoothDevice, data: ByteArray) {
        try {
            Log.d(TAG, "Handling BLE command: ${data.size} bytes from ${device.address}")
            
            // Step 1: Parse the authentication request
            val authRequest = try {
                dev.rourunisen.tapauth.protocol.ProtobufParser.parseAuthRequest(data)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse BLE auth request", e)
                sendResponse(device, "PARSE_ERROR".toByteArray())
                return
            }
            
            Log.d(TAG, "Parsed BLE request: username=${authRequest.username}, hostname=${authRequest.hostname}")
            
            // Step 2: Find paired device
            val pairedDevices = deviceRepository.getAllPairedDevices()
            
            if (pairedDevices.isEmpty()) {
                Log.w(TAG, "No paired devices found, rejecting BLE request")
                sendResponse(device, "NO_PAIRED_DEVICES".toByteArray())
                return
            }
            
            Log.d(TAG, "Found ${pairedDevices.size} paired device(s)")
            
            // Step 3: Verify signature
            // Reconstruct the message with signature field empty
            val gson = com.google.gson.Gson()
            val requestJson = gson.toJson(authRequest)
            val messageForVerification = try {
                dev.rourunisen.tapauth.crypto.serializeAuthRequestForVerification(requestJson)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to serialize BLE request for verification", e)
                sendResponse(device, "VERIFICATION_ERROR".toByteArray())
                return
            }
            
            // Try to verify signature against each paired device
            var matchedDevice: dev.rourunisen.tapauth.data.PairedDevice? = null
            for (pairedDev in pairedDevices) {
                try {
                    val isValid = dev.rourunisen.tapauth.crypto.verifySignature(
                        pairedDev.publicKey,
                        messageForVerification,
                        authRequest.signature
                    )
                    if (isValid) {
                        matchedDevice = pairedDev
                        Log.d(TAG, "BLE signature verified for device: ${pairedDev.name} (${pairedDev.deviceId})")
                        break
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to verify BLE signature for device ${pairedDev.deviceId}", e)
                }
            }
            
            if (matchedDevice == null) {
                Log.w(TAG, "BLE signature verification failed for all devices, rejecting request")
                sendResponse(device, "INVALID_SIGNATURE".toByteArray())
                return
            }
            
            // Step 4: Request biometric authentication via AuthRequestManager
            val authRequestManager = dev.rourunisen.tapauth.service.AuthRequestManager.getInstance()
            authRequestManager.submitRequest(
                context = this,
                deviceId = matchedDevice.deviceId,
                deviceName = matchedDevice.name,
                username = authRequest.username,
                hostname = authRequest.hostname,
                challenge = authRequest.challenge,
                timestamp = authRequest.timestamp,
                transportType = dev.rourunisen.tapauth.data.TransportType.BLE
            ) { approved, signedChallenge ->
                // Step 5: Create and send encrypted grant
                if (approved && signedChallenge != null) {
                    Log.d(TAG, "BLE auth request approved, creating encrypted grant")
                    try {
                        // Create AuthenticationGrant protobuf
                        val grantBytes = dev.rourunisen.tapauth.crypto.TapAuthCrypto.createAuthGrant(signedChallenge)
                        
                        // Encrypt the grant with the client's CSK
                        val encryptedGrant = dev.rourunisen.tapauth.crypto.encryptWithCsk(
                            matchedDevice.csk,
                            authRequest.challenge,
                            "auth_grant",
                            grantBytes
                        )
                        
                        // Generate temporal ID for the response
                        val temporalId = dev.rourunisen.tapauth.crypto.generateTemporalId(matchedDevice.csk)
                        
                        // Create EncryptedPacket wrapper
                        // TODO: Use proper protobuf serialization for EncryptedPacket
                        // For now, prepend temporal ID to encrypted data
                        val temporalIdBytes = dev.rourunisen.tapauth.crypto.TapAuthCrypto.run {
                            val hex = temporalId
                            hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                        }
                        
                        val response = temporalIdBytes + encryptedGrant
                        
                        sendResponse(device, response)
                        Log.d(TAG, "Sent encrypted grant via BLE (${response.size} bytes)")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send BLE grant", e)
                        sendResponse(device, "ERROR".toByteArray())
                    }
                } else {
                    Log.d(TAG, "BLE auth request denied or timed out")
                    sendResponse(device, "AUTH_DENIED".toByteArray())
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error handling BLE command", e)
            sendResponse(device, "ERROR".toByteArray())
        }
    }
    
    private fun sendResponse(device: BluetoothDevice, response: ByteArray) {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            return
        }
        
        val service = bluetoothGattServer?.getService(SERVICE_UUID)
        val characteristic = service?.getCharacteristic(SERVER_RESPONSE_CHAR_UUID)
        
        if (characteristic != null) {
            characteristic.value = response
            bluetoothGattServer?.notifyCharacteristicChanged(device, characteristic, false)
            Log.d(TAG, "Sent response: ${response.size} bytes to ${device.address}")
        } else {
            Log.e(TAG, "Server response characteristic not found")
        }
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "BLE GATT Service started")
        return START_STICKY
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onDestroy() {
        super.onDestroy()
        stopAdvertising()
        
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            bluetoothGattServer?.close()
        }
        
        serviceScope.cancel()
        Log.i(TAG, "BLE GATT Service destroyed")
    }
}
