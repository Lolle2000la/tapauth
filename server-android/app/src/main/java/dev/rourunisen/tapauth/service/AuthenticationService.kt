package dev.rourunisen.tapauth.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.rourunisen.tapauth.MainActivity
import dev.rourunisen.tapauth.R
import dev.rourunisen.tapauth.TapAuthApplication
import dev.rourunisen.tapauth.data.DeviceRepository
import kotlinx.coroutines.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Foreground service that listens for UDP authentication requests
 * and responds after biometric verification
 */
class AuthenticationService : Service() {
    
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var udpSocket: DatagramSocket? = null
    private var isRunning = false
    private lateinit var deviceRepository: DeviceRepository
    
    companion object {
        private const val TAG = "AuthenticationService"
        private const val NOTIFICATION_ID = 1
        private const val UDP_PORT = 8442 // Default UDP port for auth requests
        
        fun start(context: Context) {
            val intent = Intent(context, AuthenticationService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
        
        fun stop(context: Context) {
            val intent = Intent(context, AuthenticationService::class.java)
            context.stopService(intent)
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        deviceRepository = DeviceRepository(this)
        Log.d(TAG, "Authentication service created")
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            startForeground(NOTIFICATION_ID, createNotification())
            startListening()
            isRunning = true
            Log.d(TAG, "Authentication service started")
        }
        return START_STICKY
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onDestroy() {
        super.onDestroy()
        stopListening()
        serviceScope.cancel()
        Log.d(TAG, "Authentication service destroyed")
    }
    
    private fun startListening() {
        serviceScope.launch {
            try {
                udpSocket = DatagramSocket(UDP_PORT)
                Log.d(TAG, "Listening for auth requests on UDP port $UDP_PORT")
                
                val buffer = ByteArray(1024)
                
                while (isActive && isRunning) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        udpSocket?.receive(packet)
                        
                        val data = packet.data.copyOf(packet.length)
                        val senderAddress = packet.address
                        val senderPort = packet.port
                        
                        Log.d(TAG, "Received auth request from ${senderAddress.hostAddress}:$senderPort")
                        
                        // Process authentication request
                        launch {
                            handleAuthRequest(data, senderAddress, senderPort)
                        }
                        
                    } catch (e: Exception) {
                        if (isActive) {
                            Log.e(TAG, "Error receiving packet", e)
                        }
                    }
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start UDP listener", e)
            }
        }
    }
    
    private fun stopListening() {
        isRunning = false
        udpSocket?.close()
        udpSocket = null
        Log.d(TAG, "Stopped listening")
    }
    
    private suspend fun handleAuthRequest(
        data: ByteArray,
        senderAddress: InetAddress,
        senderPort: Int
    ) {
        try {
            Log.d(TAG, "Processing auth request (${data.size} bytes) from ${senderAddress.hostAddress}")
            
            // Step 1: Parse the EncryptedPacket
            // The data contains a protobuf-encoded EncryptedPacket
            val encryptedPacket = try {
                dev.rourunisen.tapauth.protocol.ProtobufParser.parseAuthRequest(data)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse auth request", e)
                return
            }
            
            Log.d(TAG, "Parsed auth request: username=${encryptedPacket.username}, hostname=${encryptedPacket.hostname}")
            
            // Step 2: Find the paired device by checking temporal identifier
            // TODO: For now, we'll just get all devices and try each one
            val pairedDevices = deviceRepository.getAllPairedDevices()
            
            if (pairedDevices.isEmpty()) {
                Log.w(TAG, "No paired devices found, ignoring request")
                return
            }
            
            Log.d(TAG, "Checking ${pairedDevices.size} paired device(s)")
            
            // Step 3: Verify signature
            // Reconstruct the message with signature field empty
            val gson = com.google.gson.Gson()
            val requestJson = gson.toJson(encryptedPacket)
            val messageForVerification = try {
                dev.rourunisen.tapauth.crypto.serializeAuthRequestForVerification(requestJson)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to serialize request for verification", e)
                return
            }
            
            // Try to verify signature against each paired device
            var matchedDevice: dev.rourunisen.tapauth.data.PairedDevice? = null
            for (device in pairedDevices) {
                try {
                    val isValid = dev.rourunisen.tapauth.crypto.verifySignature(
                        device.publicKey,
                        messageForVerification,
                        encryptedPacket.signature
                    )
                    if (isValid) {
                        matchedDevice = device
                        Log.d(TAG, "Signature verified for device: ${device.name} (${device.deviceId})")
                        break
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to verify signature for device ${device.deviceId}", e)
                }
            }
            
            if (matchedDevice == null) {
                Log.w(TAG, "Signature verification failed for all devices, rejecting request")
                return
            }
            
            // Step 4: Request biometric authentication via AuthRequestManager
            val authRequestManager = AuthRequestManager.getInstance()
            authRequestManager.submitRequest(
                context = this,
                deviceId = matchedDevice.deviceId,
                deviceName = matchedDevice.name,
                username = encryptedPacket.username,
                hostname = encryptedPacket.hostname,
                challenge = encryptedPacket.challenge,
                timestamp = encryptedPacket.timestamp,
                transportType = dev.rourunisen.tapauth.data.TransportType.UDP
            ) { approved, signedChallenge ->
                // Step 5: Create and send authentication grant
                if (approved && signedChallenge != null) {
                    Log.d(TAG, "Auth request approved, creating encrypted grant")
                    try {
                        // Create AuthenticationGrant protobuf
                        val grantBytes = dev.rourunisen.tapauth.crypto.TapAuthCrypto.createAuthGrant(signedChallenge)
                        
                        // Encrypt the grant with the client's CSK
                        val encryptedGrant = dev.rourunisen.tapauth.crypto.encryptWithCsk(
                            matchedDevice.csk,
                            encryptedPacket.challenge,
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
                        
                        val responsePacket = DatagramPacket(
                            response,
                            response.size,
                            senderAddress,
                            senderPort
                        )
                        udpSocket?.send(responsePacket)
                        Log.d(TAG, "Sent encrypted auth grant to ${senderAddress.hostAddress}:$senderPort (${response.size} bytes)")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send auth grant", e)
                    }
                } else {
                    Log.d(TAG, "Auth request denied or timed out")
                    // Optionally send a denial message
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle auth request", e)
        }
    }
    
    private fun createNotification(): Notification {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notificationIntent,
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, TapAuthApplication.CHANNEL_ID)
            .setContentTitle("TapAuth")
            .setContentText("Authentication service is running")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
