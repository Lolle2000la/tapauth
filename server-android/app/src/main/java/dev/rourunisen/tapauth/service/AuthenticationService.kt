package dev.rourunisen.tapauth.service

import android.Manifest
import android.app.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.ActivityCompat
import dev.rourunisen.tapauth.TapAuthApplication
import dev.rourunisen.tapauth.crypto.TapAuthCrypto
import dev.rourunisen.tapauth.data.DeviceRepository
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketException
import kotlinx.coroutines.*

/**
 * Foreground service that listens for UDP authentication requests and responds after biometric
 * verification
 */
class AuthenticationService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile private var udpSocket: MulticastSocket? = null
    @Volatile private var isRunning = false
    private lateinit var deviceRepository: DeviceRepository
    private lateinit var keypairRepository: dev.rourunisen.tapauth.data.KeypairRepository
    private val replayMitigationCache = ReplayMitigationCache.getInstance()
    private val retransmissionManager = RetransmissionManager.getInstance()
    private val transportLockManager = TransportLockManager.getInstance()
    private val requestRateLimiter = RequestRateLimiter()
    private lateinit var temporalIdCache: TemporalIdCache
    private lateinit var appConfig: dev.rourunisen.tapauth.data.AppConfiguration
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var rejoinJob: Job? = null
    @Volatile private var listenerJob: Job? = null
    private val multicastLockLock = Any()
    @Volatile private var multicastLock: android.net.wifi.WifiManager.MulticastLock? = null

    private val screenStateReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> {
                        Log.d(TAG, "Screen on - acquiring multicast lock")
                        acquireMulticastLock()
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        Log.d(TAG, "Screen off - releasing multicast lock")
                        releaseMulticastLock()
                    }
                }
            }
        }

    companion object {
        private const val TAG = "AuthenticationService"
        // Use the global shared notification ID to avoid duplicate notifications
        private const val NOTIFICATION_ID = TapAuthApplication.FOREGROUND_NOTIFICATION_ID
        // Cached IPv6 multicast address to avoid repeated DNS lookups
        private val IPV6_MULTICAST_GROUP: InetAddress = InetAddress.getByName("ff02::1")
        // Debounce delay for multicast rejoin operations (milliseconds)
        private const val REJOIN_DEBOUNCE_MS = 500L

        // Broadcast actions for BLE communication
        const val ACTION_CANCEL_BLE_CONNECTION =
            "dev.rourunisen.tapauth.ACTION_CANCEL_BLE_CONNECTION"
        const val EXTRA_CHALLENGE = "challenge"
        const val EXTRA_DEVICE_ID = "device_id"

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
                val b =
                    Intent("dev.rourunisen.tapauth.ACTION_SERVICE_STATE_CHANGE").apply {
                        putExtra("udp_running", true)
                    }
                context.sendBroadcast(b)
            } catch (_: Exception) {}
        }

        fun stop(context: Context) {
            val intent = Intent(context, AuthenticationService::class.java)
            context.stopService(intent)
            try {
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                config.udpRunning = false
                val b =
                    Intent("dev.rourunisen.tapauth.ACTION_SERVICE_STATE_CHANGE").apply {
                        putExtra("udp_running", false)
                    }
                context.sendBroadcast(b)
            } catch (_: Exception) {}
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "onCreate() called, starting foreground immediately.")

        // Initialize repositories first so onDestroy() can safely access them
        deviceRepository = DeviceRepository(this)
        keypairRepository = dev.rourunisen.tapauth.data.KeypairRepository(this)
        appConfig = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(this)
        temporalIdCache = TemporalIdCache(deviceRepository, serviceScope)

        // Start as foreground immediately to prevent ForegroundServiceDidNotStartInTimeException
        // This is critical on Android 12+ when started via startForegroundService()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (
                    ActivityCompat.checkSelfPermission(
                        this,
                        Manifest.permission.POST_NOTIFICATIONS,
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    Log.e(
                        TAG,
                        "POST_NOTIFICATIONS permission not granted. Cannot start foreground service.",
                    )
                    stopSelf()
                    return
                }
            }
            startForeground(NOTIFICATION_ID, createNotification())
            Log.d(TAG, "Service is now in the foreground.")
        } catch (e: Exception) {
            Log.e(TAG, "FATAL: Failed to start foreground: ${e.message}", e)
            stopSelf()
            return
        }

        // Start the temporal ID cache after successful foreground start
        temporalIdCache.start()

        // Start periodic cleanup of rate limiter
        serviceScope.launch {
            while (isActive) {
                delay(300_000) // Every 5 minutes
                requestRateLimiter.cleanup()
            }
        }

        // Register network callback to handle connectivity changes
        registerNetworkCallback()

        // Register screen state receiver for multicast lock power management
        registerScreenStateReceiver()

        Log.d(TAG, "Authentication service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            // Foreground notification already started in onCreate()
            // Just start the UDP listener
            startListening()
            Log.d(TAG, "Authentication service started")
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        unregisterScreenStateReceiver()
        unregisterNetworkCallback()
        stopListening()
        retransmissionManager.stopAll()
        // Check if initialized before accessing
        if (::temporalIdCache.isInitialized) {
            temporalIdCache.stop()
        }
        serviceScope.cancel()
        Log.d(TAG, "Authentication service destroyed")
    }

    private fun startListening() {
        synchronized(multicastLockLock) {
            isRunning = true
            val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
            if (powerManager?.isInteractive == true) {
                acquireMulticastLock()
            }

            val oldJob = listenerJob
            val oldSocket = udpSocket
            try {
                oldSocket?.close()
            } catch (_: Exception) {}

            val newSocket: MulticastSocket
            try {
                newSocket = MulticastSocket(appConfig.udpPort)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to bind MulticastSocket", e)
                udpSocket = null
                return
            }
            udpSocket = newSocket

            listenerJob =
                serviceScope.launch {
                    oldJob?.cancelAndJoin()
                    try {
                        if (!isActive || !isRunning) {
                            return@launch
                        }

                        newSocket.broadcast = true

                        try {
                            NetworkInterface.getNetworkInterfaces()?.toList()?.forEach {
                                networkInterface ->
                                if (networkInterface.isUp && networkInterface.supportsMulticast()) {
                                    try {
                                        newSocket.joinGroup(
                                            java.net.InetSocketAddress(
                                                IPV6_MULTICAST_GROUP,
                                                appConfig.udpPort,
                                            ),
                                            networkInterface,
                                        )
                                        Log.d(
                                            TAG,
                                            "Joined IPv6 multicast group ff02::1 on ${networkInterface.name}",
                                        )
                                    } catch (e: Exception) {
                                        Log.w(
                                            TAG,
                                            "Failed to join multicast on ${networkInterface.name}: ${e.message}",
                                        )
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to set up IPv6 multicast: ${e.message}")
                        }

                        Log.d(TAG, "Listening for auth requests on UDP port ${appConfig.udpPort}")
                        Log.d(TAG, "  - IPv4 broadcast: enabled")
                        Log.d(TAG, "  - IPv6 multicast: ff02::1")

                        try {
                            dev.rourunisen.tapauth.service.ServiceStatusManager.setUdpRunning(
                                { applicationContext },
                                true,
                            )
                            updateNotification()
                        } catch (_: Exception) {}

                        val buffer = ByteArray(4096)

                        while (isActive && isRunning) {
                            try {
                                val packet = DatagramPacket(buffer, buffer.size)

                                newSocket.receive(packet)

                                val data = packet.data.copyOf(packet.length)
                                val senderAddress = packet.address
                                val senderPort = packet.port

                                Log.d(
                                    TAG,
                                    "Received auth request from ${senderAddress.hostAddress}:$senderPort",
                                )
                                Log.d(
                                    TAG,
                                    "Will respond to ${senderAddress.hostAddress}:${appConfig.udpPort} (configured port)",
                                )

                                launch { handleIncomingPacket(data, senderAddress, senderPort) }
                            } catch (e: SocketException) {
                                break
                            } catch (e: Exception) {
                                if (isActive && isRunning) {
                                    Log.e(TAG, "Error receiving packet", e)
                                }
                            }
                        }
                    } catch (e: Exception) {
                        if (isActive && isRunning) {
                            Log.e(TAG, "Failed to start UDP listener", e)
                            stopListening()
                        }
                    } finally {
                        newSocket.close()
                        if (udpSocket === newSocket) {
                            udpSocket = null
                        }
                    }
                }
        }
    }

    private fun stopListening() {
        isRunning = false

        releaseMulticastLock()

        listenerJob?.cancel()
        listenerJob = null

        // Cancel any pending rejoin operation
        rejoinJob?.cancel()
        rejoinJob = null

        // Leave IPv6 multicast group before closing socket
        try {
            NetworkInterface.getNetworkInterfaces()?.toList()?.forEach { networkInterface ->
                if (networkInterface.isUp && networkInterface.supportsMulticast()) {
                    try {
                        udpSocket?.leaveGroup(
                            java.net.InetSocketAddress(IPV6_MULTICAST_GROUP, appConfig.udpPort),
                            networkInterface,
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
        try {
            dev.rourunisen.tapauth.service.ServiceStatusManager.setUdpRunning({ this }, false)
        } catch (_: Exception) {}
    }

    private fun acquireMulticastLock() {
        if (!isRunning) return
        synchronized(multicastLockLock) {
            if (multicastLock == null) {
                try {
                    val wifiManager =
                        applicationContext.getSystemService(Context.WIFI_SERVICE)
                            as? android.net.wifi.WifiManager
                    multicastLock =
                        wifiManager?.createMulticastLock("TapAuthMulticastLock")?.apply {
                            setReferenceCounted(false)
                            acquire()
                        }
                    if (multicastLock != null) {
                        Log.d(TAG, "Acquired Wifi MulticastLock for UDP multicast reception")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to acquire Wifi MulticastLock: ${e.message}")
                }
            }
        }
    }

    private fun releaseMulticastLock() {
        synchronized(multicastLockLock) {
            try {
                multicastLock?.let {
                    if (it.isHeld) {
                        it.release()
                        Log.d(TAG, "Released Wifi MulticastLock")
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error while releasing MulticastLock: ${e.message}")
            }
            multicastLock = null
        }
    }

    private fun registerScreenStateReceiver() {
        val filter =
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
            }
        androidx.core.content.ContextCompat.registerReceiver(
            this,
            screenStateReceiver,
            filter,
            androidx.core.content.ContextCompat.RECEIVER_EXPORTED,
        )
        Log.d(TAG, "Registered screen state receiver")
    }

    private fun unregisterScreenStateReceiver() {
        try {
            unregisterReceiver(screenStateReceiver)
            Log.d(TAG, "Unregistered screen state receiver")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister screen state receiver: ${e.message}")
        }
    }

    /**
     * Register a network callback to monitor connectivity changes. When the network changes (e.g.,
     * Wi-Fi reconnects), we re-join multicast groups.
     */
    private fun registerNetworkCallback() {
        try {
            connectivityManager =
                getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            val networkRequest =
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                    .build()

            networkCallback =
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        Log.d(TAG, "Network available, re-joining multicast groups")
                        rejoinMulticastGroups()
                    }

                    override fun onLost(network: Network) {
                        Log.d(TAG, "Network lost")
                    }

                    override fun onCapabilitiesChanged(
                        network: Network,
                        networkCapabilities: NetworkCapabilities,
                    ) {
                        // Network capabilities changed (e.g., gained/lost internet)
                        // Re-join multicast groups to ensure we're on the right interfaces
                        Log.d(TAG, "Network capabilities changed, re-joining multicast groups")
                        rejoinMulticastGroups()
                    }
                }

            networkCallback?.let {
                connectivityManager?.registerNetworkCallback(networkRequest, it)
            }
            Log.d(TAG, "Registered network callback for connectivity monitoring")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback: ${e.message}")
        }
    }

    /** Unregister the network callback. */
    private fun unregisterNetworkCallback() {
        try {
            networkCallback?.let {
                connectivityManager?.unregisterNetworkCallback(it)
                Log.d(TAG, "Unregistered network callback")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister network callback: ${e.message}")
        }
        networkCallback = null
        connectivityManager = null
    }

    /**
     * Re-establish UDP multicast connectivity after a network change. Performs a complete teardown
     * and recreation of the socket to avoid stale file descriptors that can occur after Wi-Fi
     * low-power state transitions.
     *
     * Uses debouncing to prevent overlapping operations when multiple network callbacks fire in
     * quick succession (e.g., onAvailable followed by onCapabilitiesChanged).
     */
    private fun rejoinMulticastGroups() {
        rejoinJob?.cancel()
        rejoinJob =
            serviceScope.launch {
                delay(REJOIN_DEBOUNCE_MS)
                Log.d(TAG, "Recreating UDP socket after network change")
                startListening()
            }
    }

    /** Handle incoming packet and route to appropriate handler based on message type */
    @Suppress("UNUSED_PARAMETER")
    private suspend fun handleIncomingPacket(
        data: ByteArray,
        senderAddress: InetAddress,
        senderPort: Int,
    ) {
        try {
            Log.d(
                TAG,
                "Processing packet (${data.size} bytes) from ${senderAddress.hostAddress}:$senderPort",
            )

            // Step 0: Pre-authentication DoS mitigation
            // Extract temporal_identifier from EncryptedPacket and check against cache
            // This avoids expensive decryption on invalid packets
            if (data.size < 16) {
                Log.w(TAG, "Packet too small, dropping")
                return
            }

            // EncryptedPacket has temporal_identifier as first field (16 bytes)
            // We need to parse the protobuf to extract it properly
            val temporalId =
                try {
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
            val wrapperMessage =
                try {
                    dev.rourunisen.tapauth.crypto.decryptEncryptedPacket(device.csk, data)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to decrypt packet", e)
                    return
                }

            // Parse WrapperMessage to determine message type
            // The WrapperMessage has a oneof field for different message types
            val messageType =
                try {
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
        UNKNOWN,
    }

    /**
     * Extract temporal_identifier from EncryptedPacket without full deserialization.
     *
     * Uses the Rust prost library via JNI for robust protobuf parsing. This allows DoS mitigation
     * by checking the temporal_identifier before expensive decryption.
     */
    private fun extractTemporalIdFromPacket(data: ByteArray): ByteArray? {
        return try {
            TapAuthCrypto.extractTemporalIdentifier(data)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract temporal ID from packet", e)
            null
        }
    }

    private fun determineMessageType(wrapperMessage: ByteArray): MessageType {
        return try {
            val typeStr = TapAuthCrypto.determineMessageType(wrapperMessage)
            when (typeStr) {
                "AUTH_REQUEST" -> MessageType.AUTH_REQUEST
                "GRANT_CONFIRMATION" -> MessageType.GRANT_CONFIRMATION
                "AUTH_CANCEL" -> MessageType.AUTH_CANCEL
                else -> MessageType.UNKNOWN
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to determine message type", e)
            MessageType.UNKNOWN
        }
    }

    private fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }
    }

    private fun ByteArray.toHexPreview(maxBytes: Int = 8): String {
        val take = kotlin.math.min(this.size, maxBytes)
        return this.take(take).joinToString("") { "%02x".format(it) } +
            if (this.size > take) "…" else ""
    }

    private suspend fun handleGrantConfirmation(
        wrapperMessage: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice,
    ) {
        try {
            Log.d(TAG, "Handling GrantConfirmation from device: ${device.displayName}")

            // Parse the confirmation
            val confirmation =
                try {
                    dev.rourunisen.tapauth.protocol.ProtobufParser.parseGrantConfirmation(
                        wrapperMessage
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse GrantConfirmation", e)
                    return
                }

            Log.d(TAG, "GrantConfirmation received for challenge: ${confirmation.challenge}")

            // Decode Base64 challenge to ByteArray for retransmission manager
            val challengeBytes =
                android.util.Base64.decode(confirmation.challenge, android.util.Base64.NO_WRAP)

            // Stop retransmission for this challenge
            retransmissionManager.stopRetransmission(challengeBytes)

            // Reset rate limiter for this device
            requestRateLimiter.resetClient(device.publicKey.toHex())

            Log.d(
                TAG,
                "Stopped retransmission and reset rate limiter for device: ${device.displayName}",
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle GrantConfirmation", e)
        }
    }

    private suspend fun handleAuthCancel(
        wrapperMessage: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice,
    ) {
        try {
            Log.d(TAG, "Handling AuthenticationCancel from device: ${device.displayName}")

            // Parse the cancel message
            val cancel =
                try {
                    dev.rourunisen.tapauth.protocol.ProtobufParser.parseAuthenticationCancel(
                        wrapperMessage
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse AuthenticationCancel", e)
                    return
                }

            Log.d(TAG, "AuthenticationCancel received for challenge: ${cancel.challenge}")

            // Decode Base64 challenge to ByteArray for retransmission manager
            val challengeBytes =
                android.util.Base64.decode(cancel.challenge, android.util.Base64.NO_WRAP)
            Log.d(TAG, "Processing AuthenticationCancel for challenge")

            // Stop retransmission for this challenge
            retransmissionManager.stopRetransmission(challengeBytes)

            // Reset rate limiter for this device
            requestRateLimiter.resetClient(device.publicKey.toHex())

            // Cancel any pending authentication requests for this challenge and dismiss
            // notifications
            val authRequestManager = AuthRequestManager.getInstance()
            val dismissed = authRequestManager.cancelRequestsByChallenge(challengeBytes)

            if (dismissed) {
                Log.d(TAG, "Dismissed pending authentication request(s) for cancelled challenge")
            }

            // Notify BLE service to disconnect any active connections for this challenge
            val intent =
                Intent(ACTION_CANCEL_BLE_CONNECTION).apply {
                    putExtra(EXTRA_CHALLENGE, challengeBytes)
                    putExtra(EXTRA_DEVICE_ID, device.deviceId)
                    setPackage(packageName)
                }
            sendBroadcast(intent)

            Log.d(
                TAG,
                "Stopped retransmission, dismissed notifications, and notified BLE for device: ${device.displayName}",
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle AuthenticationCancel", e)
        }
    }

    private suspend fun handleAuthRequest(
        wrapperMessage: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice,
        senderAddress: InetAddress,
        senderPort: Int,
    ) {
        try {
            Log.d(TAG, "Handling AuthenticationRequest from device: ${device.displayName}")

            // Post-authentication rate limiting
            // Use a hash of the message payload as request identifier for de-duplication.
            // Retransmissions and multi-transport deliveries of the same request will have
            // identical wrapperMessage bytes after decryption, so they produce the same hash.
            val requestId = TapAuthCrypto.sha256(wrapperMessage)
            if (!requestRateLimiter.shouldAcceptRequest(device.publicKey.toHex(), requestId)) {
                Log.w(TAG, "Rate limiting auth request from device: ${device.displayName}")
                return
            }

            // Parse the AuthenticationRequest from WrapperMessage
            val authRequest =
                try {
                    dev.rourunisen.tapauth.protocol.ProtobufParser.parseAuthRequest(wrapperMessage)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse AuthenticationRequest", e)
                    return
                }

            Log.d(
                TAG,
                "Parsed auth request: username=${authRequest.username}, hostname=${authRequest.hostname}",
            )

            // CHECK: Verify this pairing is allowed to authenticate this user
            if (!device.isUserAllowed(authRequest.username)) {
                Log.w(TAG, "Pairing not authorized for user: ${authRequest.username}")
                Log.w(TAG, "  Device: ${device.displayName}")
                Log.w(TAG, "  Allowed users: ${device.allowedUsers}")
                // Silently reject - don't notify user to avoid information leakage about valid
                // usernames
                return
            }

            Log.d(TAG, "Pairing authorized for user: ${authRequest.username}")

            // Decode Base64 strings to ByteArrays
            val challengeBytes =
                android.util.Base64.decode(authRequest.challenge, android.util.Base64.NO_WRAP)
            val signatureBytes =
                android.util.Base64.decode(authRequest.signature, android.util.Base64.NO_WRAP)

            // Transport lock - ensure only one channel handles this request
            if (
                !transportLockManager.tryClaimTransport(
                    challengeBytes,
                    dev.rourunisen.tapauth.data.TransportType.UDP,
                )
            ) {
                Log.i(TAG, "UDP request ignored - challenge already claimed by another transport")
                return
            }

            // Replay attack mitigation
            // Check for replayed challenges and stale timestamps
            if (replayMitigationCache.isReplay(challengeBytes, authRequest.timestampUnixSeconds)) {
                Log.w(TAG, "Replay attack detected, rejecting request")
                return
            }

            // Verify signature
            // Reconstruct the message with signature field empty
            val messageForVerification =
                try {
                    dev.rourunisen.tapauth.crypto.serializeAuthRequestForVerification(
                        challengeBytes,
                        authRequest.username,
                        authRequest.hostname,
                        authRequest.timestampUnixSeconds,
                        authRequest.signatureAlgorithm,
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to serialize request for verification", e)
                    return
                }

            val isValid =
                dev.rourunisen.tapauth.crypto.verifySignature(
                    device.publicKey,
                    messageForVerification,
                    signatureBytes,
                )

            if (!isValid) {
                Log.w(
                    TAG,
                    "Signature verification failed for device ${device.deviceId}, rejecting request",
                )
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
                transportType = dev.rourunisen.tapauth.data.TransportType.UDP,
            ) { approved, signedChallenge, explicitDenial ->
                // Step 6: Create and send authentication grant
                if (approved && signedChallenge != null) {
                    Log.d(TAG, "Auth request approved, creating encrypted grant")
                    try {
                        // Get server private key for signing
                        val privateKey = keypairRepository.getPrivateKey()
                        val publicKey = keypairRepository.getPublicKey()
                        Log.d(
                            TAG,
                            "Signing grant with server public key (trunc): ${publicKey.take(8).joinToString("") { "%02x".format(it) }}…",
                        )

                        // Create WrapperMessage containing AuthenticationGrant (now properly
                        // signed)
                        val grantWrapperMessage =
                            dev.rourunisen.tapauth.crypto.createGrantWrapperMessage(
                                signedChallenge,
                                privateKey,
                            )

                        // Create proper EncryptedPacket per specification
                        val encryptedPacketBytes =
                            dev.rourunisen.tapauth.crypto.createEncryptedPacket(
                                device.csk,
                                grantWrapperMessage,
                            )

                        // Send initial response
                        val responsePacket =
                            DatagramPacket(
                                encryptedPacketBytes,
                                encryptedPacketBytes.size,
                                senderAddress,
                                appConfig.udpPort,
                            )
                        udpSocket?.send(responsePacket)
                        Log.d(
                            TAG,
                            "Sent encrypted auth grant to ${senderAddress.hostAddress}:${appConfig.udpPort} (${encryptedPacketBytes.size} bytes)",
                        )

                        // Release transport lock after successful grant
                        transportLockManager.releaseLock(challengeBytes)

                        // Start retransmission (500ms fixed interval per spec)
                        udpSocket?.let { socket ->
                            retransmissionManager.startUdpRetransmission(
                                serviceScope,
                                RetransmissionManager.UdpRetransmissionRequest(
                                    challenge = challengeBytes,
                                    responseData = encryptedPacketBytes,
                                    socket = socket,
                                    destinationAddress = senderAddress,
                                    destinationPort = appConfig.udpPort,
                                ),
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send auth grant", e)
                    }
                } else if (explicitDenial) {
                    // Only send denial if user explicitly denied (not timeout/error)
                    Log.d(TAG, "Auth request explicitly denied by user")
                    // Reset rate limiter since request was resolved
                    requestRateLimiter.resetClient(device.publicKey.toHex())

                    // Send denial message with retransmission
                    try {
                        // Get server private key for signing
                        val privateKey = keypairRepository.getPrivateKey()

                        // Create WrapperMessage containing AuthenticationDenial
                        val denialWrapperMessage =
                            dev.rourunisen.tapauth.crypto.createDenialWrapperMessage(
                                challengeBytes,
                                privateKey,
                            )

                        // Create proper EncryptedPacket per specification
                        val encryptedPacketBytes =
                            dev.rourunisen.tapauth.crypto.createEncryptedPacket(
                                device.csk,
                                denialWrapperMessage,
                            )

                        // Send initial denial response
                        val responsePacket =
                            DatagramPacket(
                                encryptedPacketBytes,
                                encryptedPacketBytes.size,
                                senderAddress,
                                appConfig.udpPort,
                            )
                        udpSocket?.send(responsePacket)
                        Log.d(
                            TAG,
                            "Sent encrypted auth denial to ${senderAddress.hostAddress}:${appConfig.udpPort} (${encryptedPacketBytes.size} bytes)",
                        )

                        // Release transport lock after denial
                        transportLockManager.releaseLock(challengeBytes)

                        // Start retransmission (500ms fixed interval per spec)
                        udpSocket?.let { socket ->
                            retransmissionManager.startUdpRetransmission(
                                serviceScope,
                                RetransmissionManager.UdpRetransmissionRequest(
                                    challenge = challengeBytes,
                                    responseData = encryptedPacketBytes,
                                    socket = socket,
                                    destinationAddress = senderAddress,
                                    destinationPort = appConfig.udpPort,
                                ),
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send auth denial", e)
                    }
                } else {
                    // Timeout or error - silently ignore, don't send denial
                    Log.d(TAG, "Auth request timed out or failed - no response sent")
                    // Reset rate limiter since request was resolved
                    requestRateLimiter.resetClient(device.publicKey.toHex())
                    // Release transport lock even on timeout
                    transportLockManager.releaseLock(challengeBytes)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle auth request", e)
        }
    }

    private fun createNotification(): Notification {
        return TapAuthApplication.buildUnifiedNotification(this)
    }

    private fun updateNotification() {
        // Refresh the shared notification with the latest service states
        val notification = TapAuthApplication.buildUnifiedNotification(this)
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(TapAuthApplication.FOREGROUND_NOTIFICATION_ID, notification)
    }
}
