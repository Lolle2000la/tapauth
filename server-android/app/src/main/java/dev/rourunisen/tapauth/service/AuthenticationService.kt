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
import java.net.MulticastSocket
import java.net.NetworkInterface

/**
 * Foreground service that listens for UDP authentication requests
 * and responds after biometric verification
 */
class AuthenticationService : Service() {
    
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var udpSocket: MulticastSocket? = null
    private var isRunning = false
    private lateinit var deviceRepository: DeviceRepository
    private lateinit var keypairRepository: dev.rourunisen.tapauth.data.KeypairRepository
    private val replayMitigationCache = ReplayMitigationCache.getInstance()
    private val retransmissionManager = RetransmissionManager.getInstance()
    private val requestRateLimiter = RequestRateLimiter()
    private lateinit var temporalIdCache: TemporalIdCache
    private lateinit var appConfig: dev.rourunisen.tapauth.data.AppConfiguration
    
    companion object {
        private const val TAG = "AuthenticationService"
        private const val NOTIFICATION_ID = 1
        
        fun start(context: Context) {
            val intent = Intent(context, AuthenticationService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            try {
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                config.udpLastStartMillis = System.currentTimeMillis()
                config.udpRunning = true
                // broadcast running state change
                val b = Intent("dev.rourunisen.tapauth.ACTION_SERVICE_STATE_CHANGE").apply {
                    putExtra("udp_running", true)
                }
                context.sendBroadcast(b)
            } catch (_: Exception) { }
        }
        
        fun stop(context: Context) {
            val intent = Intent(context, AuthenticationService::class.java)
            context.stopService(intent)
            try {
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                config.udpRunning = false
                val b = Intent("dev.rourunisen.tapauth.ACTION_SERVICE_STATE_CHANGE").apply {
                    putExtra("udp_running", false)
                }
                context.sendBroadcast(b)
            } catch (_: Exception) { }
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        deviceRepository = DeviceRepository(this)
        keypairRepository = dev.rourunisen.tapauth.data.KeypairRepository(this)
        appConfig = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(this)
        temporalIdCache = TemporalIdCache(deviceRepository, serviceScope)
        temporalIdCache.start()
        
        // Start periodic cleanup of rate limiter
        serviceScope.launch {
            while (isActive) {
                delay(300_000)  // Every 5 minutes
                requestRateLimiter.cleanup()
            }
        }
        
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
        retransmissionManager.stopAll()
        temporalIdCache.stop()
        serviceScope.cancel()
        Log.d(TAG, "Authentication service destroyed")
    }
    
    private fun startListening() {
        serviceScope.launch {
            try {
                // Use MulticastSocket to support both unicast and multicast
                udpSocket = MulticastSocket(appConfig.udpPort)
                
                // Enable broadcast reception (for IPv4 255.255.255.255)
                udpSocket?.broadcast = true
                
                // Join IPv6 multicast group ff02::1 (all nodes on local segment)
                try {
                    val multicastGroup = InetAddress.getByName("ff02::1")
                    
                    // Join the multicast group on all available network interfaces
                    NetworkInterface.getNetworkInterfaces().toList().forEach { networkInterface ->
                        if (networkInterface.isUp && networkInterface.supportsMulticast()) {
                            try {
                                udpSocket?.joinGroup(
                                    java.net.InetSocketAddress(multicastGroup, appConfig.udpPort),
                                    networkInterface
                                )
                                Log.d(TAG, "Joined IPv6 multicast group ff02::1 on ${networkInterface.name}")
                            } catch (e: Exception) {
                                Log.w(TAG, "Failed to join multicast on ${networkInterface.name}: ${e.message}")
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to set up IPv6 multicast: ${e.message}")
                }
                
                Log.d(TAG, "Listening for auth requests on UDP port ${appConfig.udpPort}")
                Log.d(TAG, "  - IPv4 broadcast: enabled")
                Log.d(TAG, "  - IPv6 multicast: ff02::1")

                // Mark UDP as running once we've successfully opened the socket
                try {
                    dev.rourunisen.tapauth.service.ServiceStatusManager.setUdpRunning({ applicationContext }, true)
                } catch (_: Exception) { }
                
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
                            handleIncomingPacket(data, senderAddress, senderPort)
                        }
                        
                    } catch (e: Exception) {
                        if (isActive) {
                            Log.e(TAG, "Error receiving packet", e)
                        }
                    }
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start UDP listener", e)
                try { dev.rourunisen.tapauth.service.ServiceStatusManager.setUdpRunning({ applicationContext }, false) } catch (_: Exception) { }
            }
        }
    }
    
    private fun stopListening() {
        isRunning = false
        
        // Leave IPv6 multicast group before closing socket
        try {
            val multicastGroup = InetAddress.getByName("ff02::1")
            NetworkInterface.getNetworkInterfaces().toList().forEach { networkInterface ->
                if (networkInterface.isUp && networkInterface.supportsMulticast()) {
                    try {
                        udpSocket?.leaveGroup(
                            java.net.InetSocketAddress(multicastGroup, appConfig.udpPort),
                            networkInterface
                        )
                    } catch (e: Exception) {
                        // Ignore errors on cleanup
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore errors on cleanup
        }
        
        udpSocket?.close()
        udpSocket = null
        Log.d(TAG, "Stopped listening")
        try { dev.rourunisen.tapauth.service.ServiceStatusManager.setUdpRunning({ this }, false) } catch (_: Exception) { }
    }
    
    /**
     * Handle incoming packet and route to appropriate handler based on message type
     */
    private suspend fun handleIncomingPacket(
        data: ByteArray,
        senderAddress: InetAddress,
        senderPort: Int
    ) {
        try {
            Log.d(TAG, "Processing packet (${data.size} bytes) from ${senderAddress.hostAddress}:$senderPort")
            
            // Step 0: Pre-authentication DoS mitigation
            // Extract temporal_identifier from EncryptedPacket and check against cache
            // This avoids expensive decryption on invalid packets
            if (data.size < 16) {
                Log.w(TAG, "Packet too small, dropping")
                return
            }
            
            // EncryptedPacket has temporal_identifier as first field (16 bytes)
            // We need to parse the protobuf to extract it properly
            val temporalId = try {
                extractTemporalIdFromPacket(data)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to extract temporal ID", e)
                return
            }
            
            if (temporalId == null) {
                Log.w(TAG, "No temporal ID in packet, dropping")
                return
            }
            
            // Check temporal ID cache (O(1) lookup)
            val (isValid, deviceId) = temporalIdCache.isValidTemporalId(temporalId)
            if (!isValid) {
                Log.w(TAG, "Invalid temporal ID, silently dropping packet (DoS mitigation)")
                return
            }
            
            Log.d(TAG, "Temporal ID valid for device: $deviceId")
            
            // Now we know it's from a paired device, proceed with full decryption
            // and message routing
            
            // Get the device
            val device = deviceRepository.getPairedDevice(deviceId!!)
            if (device == null) {
                Log.w(TAG, "Device not found: $deviceId")
                return
            }
            
            // Decrypt the EncryptedPacket to get WrapperMessage
            val wrapperMessage = try {
                dev.rourunisen.tapauth.crypto.decryptEncryptedPacket(
                    device.csk,
                    data
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt packet", e)
                return
            }
            
            // Parse WrapperMessage to determine message type
            // The WrapperMessage has a oneof field for different message types
            val messageType = try {
                determineMessageType(wrapperMessage)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to determine message type", e)
                return
            }
            
            Log.d(TAG, "Message type: $messageType")
            
            // Route to appropriate handler
            when (messageType) {
                MessageType.AUTH_REQUEST -> {
                    handleAuthRequest(wrapperMessage, device, senderAddress, senderPort)
                }
                MessageType.GRANT_CONFIRMATION -> {
                    handleGrantConfirmation(wrapperMessage, device)
                }
                MessageType.AUTH_CANCEL -> {
                    handleAuthCancel(wrapperMessage, device)
                }
                else -> {
                    Log.w(TAG, "Unknown message type, ignoring")
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle incoming packet", e)
        }
    }
    
    private enum class MessageType {
        AUTH_REQUEST,
        GRANT_CONFIRMATION,
        AUTH_CANCEL,
        UNKNOWN
    }
    
    private fun extractTemporalIdFromPacket(data: ByteArray): ByteArray? {
        // Parse the EncryptedPacket protobuf to extract temporal_identifier
        // Field 1 is temporal_identifier (bytes)
        // Protobuf wire format: tag (varint) + length (varint) + data
        
        try {
            var pos = 0
            
            // Read field tag
            if (pos >= data.size) return null
            val tag = data[pos].toInt() and 0xFF
            pos++
            
            // Field 1, type 2 (length-delimited) = 0x0A
            if (tag != 0x0A) {
                Log.w(TAG, "Unexpected tag: 0x${tag.toString(16)}, expected 0x0A")
                return null
            }
            
            // Read length
            if (pos >= data.size) return null
            val length = data[pos].toInt() and 0xFF
            pos++
            
            if (length != 16) {
                Log.w(TAG, "Unexpected temporal ID length: $length, expected 16")
                return null
            }
            
            // Read temporal ID
            if (pos + 16 > data.size) return null
            return data.copyOfRange(pos, pos + 16)
            
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse temporal ID from packet", e)
            return null
        }
    }
    
    private fun determineMessageType(wrapperMessage: ByteArray): MessageType {
        // Parse WrapperMessage protobuf
        // The oneof field numbers are:
        // 1 = AuthenticationRequest
        // 2 = AuthenticationGrant
        // 3 = GrantConfirmation
        // 4 = AuthenticationCancel
        
        try {
            var pos = 0
            
            while (pos < wrapperMessage.size) {
                // Read field tag
                val tag = wrapperMessage[pos].toInt() and 0xFF
                pos++
                
                val fieldNumber = tag shr 3
                
                when (fieldNumber) {
                    1 -> return MessageType.AUTH_REQUEST
                    3 -> return MessageType.GRANT_CONFIRMATION
                    4 -> return MessageType.AUTH_CANCEL
                    else -> {
                        // Skip this field
                        // This is a simplified parser, just checking field presence
                        break
                    }
                }
            }
            
            return MessageType.UNKNOWN
            
        } catch (e: Exception) {
            Log.w(TAG, "Failed to determine message type", e)
            return MessageType.UNKNOWN
        }
    }
    
    private fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }
    }
    
    private suspend fun handleGrantConfirmation(
        wrapperMessage: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice
    ) {
        try {
            Log.d(TAG, "Handling GrantConfirmation from device: ${device.displayName}")
            
            // Parse the confirmation
            val confirmation = try {
                dev.rourunisen.tapauth.protocol.ProtobufParser.parseGrantConfirmation(wrapperMessage)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse GrantConfirmation", e)
                return
            }
            
            Log.d(TAG, "GrantConfirmation received for challenge: ${confirmation.challenge}")
            
            // Decode Base64 challenge to ByteArray for retransmission manager
            val challengeBytes = android.util.Base64.decode(confirmation.challenge, android.util.Base64.NO_WRAP)
            
            // Stop retransmission for this challenge
            retransmissionManager.stopRetransmission(challengeBytes)
            
            // Reset rate limiter for this device
            requestRateLimiter.resetClient(device.publicKey.toHex())
            
            Log.d(TAG, "Stopped retransmission and reset rate limiter for device: ${device.displayName}")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle GrantConfirmation", e)
        }
    }
    
    private suspend fun handleAuthCancel(
        wrapperMessage: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice
    ) {
        try {
            Log.d(TAG, "Handling AuthenticationCancel from device: ${device.displayName}")
            
            // Parse the cancel message
            val cancel = try {
                dev.rourunisen.tapauth.protocol.ProtobufParser.parseAuthenticationCancel(wrapperMessage)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse AuthenticationCancel", e)
                return
            }
            
            Log.d(TAG, "AuthenticationCancel received for challenge: ${cancel.challenge}")
            
            // Decode Base64 challenge to ByteArray for retransmission manager
            val challengeBytes = android.util.Base64.decode(cancel.challenge, android.util.Base64.NO_WRAP)
            
            // Stop retransmission for this challenge
            retransmissionManager.stopRetransmission(challengeBytes)
            
            // Reset rate limiter for this device
            requestRateLimiter.resetClient(device.publicKey.toHex())
            
            // Note: We don't automatically dismiss the auth request UI here
            // because the user may still want to see and approve it.
            // The timeout will handle cleanup if needed.
            
            Log.d(TAG, "Stopped retransmission and reset rate limiter for device: ${device.displayName}")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle AuthenticationCancel", e)
        }
    }
    
    private suspend fun handleAuthRequest(
        wrapperMessage: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice,
        senderAddress: InetAddress,
        senderPort: Int
    ) {
        try {
            Log.d(TAG, "Handling AuthenticationRequest from device: ${device.displayName}")
            
            // Post-authentication rate limiting
            // Check if we should accept this request from this device
            if (!requestRateLimiter.shouldAcceptRequest(device.publicKey.toHex())) {
                Log.w(TAG, "Rate limiting auth request from device: ${device.displayName}")
                return
            }
    
            // Parse the AuthenticationRequest from WrapperMessage
            val authRequest = try {
                dev.rourunisen.tapauth.protocol.ProtobufParser.parseAuthRequest(wrapperMessage)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse AuthenticationRequest", e)
                return
            }
            
            Log.d(TAG, "Parsed auth request: username=${authRequest.username}, hostname=${authRequest.hostname}")
            
            // CHECK: Verify this pairing is allowed to authenticate this user
            if (!device.isUserAllowed(authRequest.username)) {
                Log.w(TAG, "Pairing not authorized for user: ${authRequest.username}")
                Log.w(TAG, "  Device: ${device.displayName}")
                Log.w(TAG, "  Allowed users: ${device.allowedUsers}")
                // Silently reject - don't notify user to avoid information leakage about valid usernames
                return
            }
            
            Log.d(TAG, "Pairing authorized for user: ${authRequest.username}")
            
            // Decode Base64 strings to ByteArrays
            val challengeBytes = android.util.Base64.decode(authRequest.challenge, android.util.Base64.NO_WRAP)
            val signatureBytes = android.util.Base64.decode(authRequest.signature, android.util.Base64.NO_WRAP)
            
            // Replay attack mitigation
            // Check for replayed challenges and stale timestamps
            if (replayMitigationCache.isReplay(challengeBytes, authRequest.timestampUnixSeconds)) {
                Log.w(TAG, "Replay attack detected, rejecting request")
                return
            }
            
            // Verify signature
            // Reconstruct the message with signature field empty
            val gson = com.google.gson.Gson()
            val requestJson = gson.toJson(authRequest)
            val messageForVerification = try {
                dev.rourunisen.tapauth.crypto.serializeAuthRequestForVerification(requestJson)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to serialize request for verification", e)
                return
            }
            
            val isValid = dev.rourunisen.tapauth.crypto.verifySignature(
                device.publicKey,
                messageForVerification,
                signatureBytes
            )
            
            if (!isValid) {
                Log.w(TAG, "Signature verification failed for device ${device.deviceId}, rejecting request")
                return
            }
            
            Log.d(TAG, "Signature verified for device: ${device.displayName} (${device.deviceId})")
            
            // Step 5: Request biometric authentication via AuthRequestManager
            val authRequestManager = AuthRequestManager.getInstance()
            authRequestManager.submitRequest(
                context = this,
                deviceId = device.deviceId,
                deviceName = device.displayName,
                username = authRequest.username,
                hostname = authRequest.hostname,
                challenge = challengeBytes,
                timestamp = authRequest.timestampUnixSeconds * 1000,
                transportType = dev.rourunisen.tapauth.data.TransportType.UDP
            ) { approved, signedChallenge ->
                // Step 6: Create and send authentication grant
                if (approved && signedChallenge != null) {
                    Log.d(TAG, "Auth request approved, creating encrypted grant")
                    try {
                        // Get server private key for signing
                        val privateKey = keypairRepository.getPrivateKey()
                        val publicKey = keypairRepository.getPublicKey()
                        Log.d(TAG, "Signing grant with server public key (trunc): ${publicKey.take(8).joinToString("") { "%02x".format(it) }}…")
                        
                        // Create WrapperMessage containing AuthenticationGrant (now properly signed)
                        val wrapperMessage = dev.rourunisen.tapauth.crypto.createGrantWrapperMessage(
                            signedChallenge,
                            privateKey
                        )
                        
                        // Create proper EncryptedPacket per specification
                        val encryptedPacketBytes = dev.rourunisen.tapauth.crypto.createEncryptedPacket(
                            device.csk,
                            wrapperMessage
                        )
                        
                        // Send initial response
                        val responsePacket = DatagramPacket(
                            encryptedPacketBytes,
                            encryptedPacketBytes.size,
                            senderAddress,
                            senderPort
                        )
                        udpSocket?.send(responsePacket)
                        Log.d(TAG, "Sent encrypted auth grant to ${senderAddress.hostAddress}:$senderPort (${encryptedPacketBytes.size} bytes)")
                        
                        // Start retransmission (500ms fixed interval per spec)
                        udpSocket?.let { socket ->
                            retransmissionManager.startUdpRetransmission(
                                serviceScope,
                                RetransmissionManager.UdpRetransmissionRequest(
                                    challenge = challengeBytes,
                                    responseData = encryptedPacketBytes,
                                    socket = socket,
                                    destinationAddress = senderAddress,
                                    destinationPort = senderPort
                                )
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send auth grant", e)
                    }
                } else {
                    Log.d(TAG, "Auth request denied or timed out")
                    // Reset rate limiter since request was resolved
                    requestRateLimiter.resetClient(device.publicKey.toHex())
                    
                    // Send denial message with retransmission
                    try {
                        // Get server private key for signing
                        val privateKey = keypairRepository.getPrivateKey()
                        
                        // Create WrapperMessage containing AuthenticationDenial
                        val wrapperMessage = dev.rourunisen.tapauth.crypto.createDenialWrapperMessage(
                            challengeBytes,
                            privateKey
                        )
                        
                        // Create proper EncryptedPacket per specification
                        val encryptedPacketBytes = dev.rourunisen.tapauth.crypto.createEncryptedPacket(
                            device.csk,
                            wrapperMessage
                        )
                        
                        // Send initial denial response
                        val responsePacket = DatagramPacket(
                            encryptedPacketBytes,
                            encryptedPacketBytes.size,
                            senderAddress,
                            senderPort
                        )
                        udpSocket?.send(responsePacket)
                        Log.d(TAG, "Sent encrypted auth denial to ${senderAddress.hostAddress}:$senderPort (${encryptedPacketBytes.size} bytes)")
                        
                        // Start retransmission (500ms fixed interval per spec)
                        udpSocket?.let { socket ->
                            retransmissionManager.startUdpRetransmission(
                                serviceScope,
                                RetransmissionManager.UdpRetransmissionRequest(
                                    challenge = challengeBytes,
                                    responseData = encryptedPacketBytes,
                                    socket = socket,
                                    destinationAddress = senderAddress,
                                    destinationPort = senderPort
                                )
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send auth denial", e)
                    }
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
