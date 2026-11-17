package dev.rourunisen.tapauth.ble

import android.Manifest
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.*
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.ActivityCompat
import dev.rourunisen.tapauth.biometric.BiometricHelper
import dev.rourunisen.tapauth.crypto.TapauthException
import dev.rourunisen.tapauth.crypto.createDenialWrapperMessage
import dev.rourunisen.tapauth.crypto.createGrantWrapperMessage
import dev.rourunisen.tapauth.crypto.decryptEncryptedPacket
import dev.rourunisen.tapauth.crypto.determineMessageType
import dev.rourunisen.tapauth.crypto.extractTemporalIdentifier
import dev.rourunisen.tapauth.crypto.parseAndVerifyAuthCancel
import dev.rourunisen.tapauth.crypto.parseAndVerifyAuthRequest
import dev.rourunisen.tapauth.crypto.parseAndVerifyGrantConfirmation
import dev.rourunisen.tapauth.crypto.rawMessage
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.service.ReplayMitigationCache
import dev.rourunisen.tapauth.service.RequestRateLimiter
import dev.rourunisen.tapauth.service.TransportLockManager
import dev.rourunisen.tapauth.service.scrubLogValue
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * BLE GATT Service - Scanner/Central Role
 *
 * According to the specification:
 * - Client (desktop) acts as Advertiser/Peripheral
 * - Server (Android) acts as Scanner/Central
 *
 * This service scans for BLE advertisements from paired clients that contain temporal identifiers.
 * When a match is found, it connects to the client's GATT server to exchange authentication
 * messages.
 */
class BleGattService : Service() {

    companion object {
        private const val TAG = "BleGattService"
        // Use the global shared notification ID to avoid duplicate notifications
        private const val NOTIFICATION_ID =
            dev.rourunisen.tapauth.TapAuthApplication.FOREGROUND_NOTIFICATION_ID

        const val ACTION_SCAN_RESULT = "dev.rourunisen.tapauth.ACTION_BLE_SCAN_RESULT"

        /**
         * Grace after a GATT disconnect before the peer's prompt is cancelled and its claim
         * released for a retry.
         *
         * This bounds the prompt and this transport's claim, **not** the reconnect: the Phone is
         * the BLE central, so it reconnects only when its `SCAN_MODE_LOW_POWER` scan (512 ms window
         * / 5 s interval) next reports the Client's advertisement, and the foreground-service hop,
         * connect, discovery, MTU, CCCD and read sequence come on top — a scan-driven reconnect can
         * therefore exceed this by design of the scanner. That is why the expiry releases the claim
         * instead of concluding it ([BleDisconnectGrace], [BleAuthRequestGate.releaseForRetry]):
         * the retransmission that finally arrives raises a fresh prompt, where a concluded claim
         * would be answered as a replay and disconnect the link again.
         */
        const val BLE_DISCONNECT_CANCEL_GRACE_MS = 5_000L

        /**
         * Upper bound for a single serialized GATT operation. A stack that never delivers the
         * matching callback must not wedge the queue, so each queued op gives up after this and
         * releases the connection for the next one.
         */
        const val GATT_OPERATION_TIMEOUT_MS = 5_000L

        /** ATT MTU requested on connect: large enough for one whole EncryptedPacket write. */
        const val GATT_REQUESTED_MTU = 517

        /**
         * How long a retransmission tick waits for the CCCD notification carrying the Client's
         * GrantConfirmation before falling back to a characteristic read.
         */
        const val CONFIRMATION_NOTIFICATION_WAIT_MS = 15L

        // UUIDs from shared library specification
        // SERVICE_UUID is also used as the key for service data in BLE advertisements
        val SERVICE_UUID: UUID = UUID.fromString("b4ad84c0-2adb-4876-8315-b39d983b2bde")
        val CLIENT_COMMAND_CHAR_UUID: UUID = UUID.fromString("caf54438-9d78-4697-8886-0a4cfa87ba8d")
        val SERVER_RESPONSE_CHAR_UUID: UUID =
            UUID.fromString("ca6238be-c194-49b7-855b-58f41d3da626")
        val CLIENT_CONFIRMATION_CHAR_UUID: UUID =
            UUID.fromString("ace3e9ad-5f0d-48bf-825a-5b7f4dc49cdf")

        /** Client Characteristic Configuration Descriptor (0x2902). */
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        /** `reason` carried by the AuthenticationDenial sent when the user declines the prompt. */
        const val DENIAL_REASON_USER_DENIED = "Denied by user"

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
            } catch (_: Exception) {}
        }

        fun stop(context: Context) {
            val intent = Intent(context, BleGattService::class.java)
            context.stopService(intent)
            try {
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                config.bleRunning = false
                val b =
                    Intent("dev.rourunisen.tapauth.ACTION_SERVICE_STATE_CHANGE").apply {
                        putExtra("ble_running", false)
                    }
                context.sendBroadcast(b)
            } catch (_: Exception) {}
        }
    }

    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothLeScanner: BluetoothLeScanner? = null

    private lateinit var deviceRepository: DeviceRepository
    private lateinit var keypairRepository: dev.rourunisen.tapauth.data.KeypairRepository
    private lateinit var biometricHelper: BiometricHelper
    private val replayMitigationCache = ReplayMitigationCache.getInstance()
    private val transportLockManager = TransportLockManager.getInstance()

    /**
     * The process's one post-authentication limiter, shared with the UDP path.
     *
     * This is the same instance `AuthenticationService` holds: a Client that hammers one transport
     * and then the other is working against one budget, not two. See [RequestRateLimiter] for the
     * schedule and for why the key material is the paired Client's public key.
     */
    private val requestRateLimiter = RequestRateLimiter.getInstance()

    /**
     * Orders duplicate in-flight AuthenticationRequests ahead of the replay cache, so a same-peer
     * repeat of a challenge the user is approving on cannot be classified as a replay and tear the
     * GATT link down.
     */
    private val authRequestGate =
        BleAuthRequestGate(
            isReplay = { challenge, timestampUnixSeconds ->
                replayMitigationCache.isReplay(challenge, timestampUnixSeconds)
            },
            elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
        )

    /**
     * Decides what the disconnect grace and a duplicate-in-flight arrival mean, so this service
     * performs one effect per outcome: whether a peer that dropped still gets its claim released,
     * and whether a duplicate needs the held answer re-delivered, a fresh prompt, or nothing.
     */
    private val disconnectGrace =
        BleDisconnectGrace(
            graceMillis = BLE_DISCONNECT_CANCEL_GRACE_MS,
            elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
        )

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * The answer built for an in-flight BLE challenge, held until the Client confirms it.
     *
     * The bytes are written to the handle that was live when the user answered, but the Client can
     * lose that link before they land and reconnect retransmitting the same request. Holding them
     * here is what lets [redeliverPendingResponse] write them on the new handle; the class
     * documents the whole handover.
     */
    private val pendingResponses =
        BleResponseHandoff<BluetoothGatt>(
            elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
        )

    // Track active GATT connections by challenge for cancellation
    private val activeConnectionsByChallenge =
        java.util.concurrent.ConcurrentHashMap<String, BluetoothGatt>()

    // Track in-flight or active GATT connections by device address to prevent duplicate concurrent
    // connections
    private val connectingOrConnectedDevices =
        java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    /**
     * Per-connection serialized GATT operation state.
     *
     * A BluetoothGatt stack allows only ONE asynchronous operation in flight per connection, so
     * every async call routes through [runGattOperation], which holds [GattConnectionState.lock]
     * while it awaits the matching callback.
     *
     * A torn-down handle keeps its entry with [GattConnectionState.closed] set until the disconnect
     * grace expires ([BLE_DISCONNECT_CANCEL_GRACE_MS]), so its identity cannot be mistaken for a
     * live connection again; after that its entry is dropped and the registry's tombstone carries
     * that fact alone, so one entry per reconnection does not pile up. [onDestroy] clears both.
     */
    private val gattConnections =
        BleGattConnectionRegistry<BluetoothGatt, GattConnectionState> { GattConnectionState() }

    /** Paired device matched to each connection, so callbacks can verify what arrives on it. */
    private val connectionDevices =
        java.util.concurrent.ConcurrentHashMap<
            BluetoothGatt,
            dev.rourunisen.tapauth.data.PairedDevice,
        >()

    /** The single op kinds that a connection may have in flight, one at a time. */
    private enum class GattOperationKind {
        MTU,
        DISCOVER_SERVICES,
        DESCRIPTOR_WRITE,
        READ,
        WRITE,
    }

    private class GattOperationResult(val success: Boolean, val value: ByteArray? = null)

    private class PendingGattOperation(
        val kind: GattOperationKind,
        /** Characteristic the op targets, so a late callback for another one cannot satisfy it. */
        val characteristicUuid: UUID? = null,
    ) {
        val result = CompletableDeferred<GattOperationResult>()
    }

    private class GattConnectionState {
        val lock = Mutex()

        @Volatile var pending: PendingGattOperation? = null

        /**
         * Waiter for the CCCD notification carrying the in-flight challenge's GrantConfirmation.
         * Completed only once the notification has been verified, cleared when retransmission ends.
         */
        @Volatile var confirmationNotification: CompletableDeferred<ByteArray>? = null

        /**
         * Set once the GATT handle is torn down. State is never re-created for such a handle: a
         * coroutine resumed after teardown must fail instead of installing a live-looking entry for
         * a closed handle that nothing would ever remove.
         */
        @Volatile var closed: Boolean = false
    }

    // BroadcastReceiver for handling cancellation requests
    private val cancelReceiver =
        object : android.content.BroadcastReceiver() {
            override fun onReceive(
                context: android.content.Context?,
                intent: android.content.Intent?,
            ) {
                if (
                    intent?.action ==
                        dev.rourunisen.tapauth.service.AuthenticationService
                            .ACTION_CANCEL_BLE_CONNECTION
                ) {
                    val challengeBytes =
                        intent.getByteArrayExtra(
                            dev.rourunisen.tapauth.service.AuthenticationService.EXTRA_CHALLENGE,
                        )
                    if (challengeBytes != null) {
                        handleCancelConnection(challengeBytes)
                    }
                }
            }
        }

    /**
     * Temporal-ID → paired-device index for both BLE paths (advertisement ids and GATT packet ids).
     *
     * A lookup is a map read: the index is rebuilt only when the paired-device list changes
     * ([BleTemporalIdIndex.invalidate], driven by the [DeviceRepository] observer registered in
     * [startTemporalIdCache]) or the 60 s window rolls over, so a device paired mid-window resolves
     * immediately instead of at the next minute boundary, and a GATT packet never triggers a
     * device-list reload.
     */
    private val temporalIdIndex =
        BleTemporalIdIndex(devices = { deviceRepository.getAllPairedDevicesSync() })

    /** Registered in [onCreate], removed in [onDestroy], so the service holds no observer. */
    private val deviceChangeObserver: () -> Unit = { temporalIdIndex.invalidate() }

    private var scanPendingIntent: PendingIntent? = null

    // GATT client callback for connecting to client's GATT server
    private val gattCallback =
        object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                if (
                    status != BluetoothGatt.GATT_SUCCESS ||
                        newState == BluetoothProfile.STATE_DISCONNECTED
                ) {
                    Log.d(
                        TAG,
                        "Connection state change on ${gatt.device.address}: status=$status newState=$newState",
                    )
                    // A dead link never delivers the outstanding callback, so release every
                    // waiter or the serialized queue would stay wedged on this connection.
                    cancelPendingGattOperations(gatt, "connection state status=$status")
                }

                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        Log.i(TAG, "Connected to client GATT server: ${gatt.device.address}")
                        // MTU negotiation -> discovery -> CCCD subscriptions: each step is a
                        // queued op awaiting its own callback, so it cannot run on this thread.
                        serviceScope.launch { runConnectedSequence(gatt) }
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        val deviceAddress = gatt.device.address
                        Log.i(TAG, "Disconnected from client GATT server: $deviceAddress")

                        connectingOrConnectedDevices.remove(deviceAddress)
                        // The peer's in-flight challenges are NOT released here: a Client still
                        // waiting for its answer retransmits the same request and reconnects, and
                        // the reconnect presents that same challenge from the same peer. With the
                        // claim held it is a duplicate in flight and the prompt survives; released,
                        // the arrival would reach the replay cache, be called a replay and tear the
                        // new link down. The grace coroutine below asks BleDisconnectGrace what to
                        // do once the grace has passed.
                        val disconnectedAtMillis = android.os.SystemClock.elapsedRealtime()

                        // Drop any challenge-tracked connections that pointed at this (now dead)
                        // GATT handle so a stale response can never be written through it.
                        activeConnectionsByChallenge.values.removeAll { it == gatt }

                        // Authentication prompts are user-driven and must survive transient GATT
                        // reconnections, so requests are NOT cancelled immediately here. But a
                        // link that stays down must not leave an orphaned prompt (and its BLE
                        // connection intent) alive until the daemon timeout: once the grace has
                        // passed, a peer that has not reconnected has its prompt cancelled and its
                        // claim released for a retry. The grace bounds that prompt, not the
                        // reconnect — the reconnect is scan-driven and can outlast it — so the
                        // released claim keeps the challenge away from the replay cache.
                        serviceScope.launch {
                            delay(BLE_DISCONNECT_CANCEL_GRACE_MS)
                            // The handle is dead whether or not the device came back on another
                            // one: the stack reports nothing more on it, and the operations it had
                            // in flight were failed above, so their coroutines have already
                            // returned. Dropping its state here is what keeps a tombstone per
                            // reconnection from accumulating; the registry still knows the handle
                            // as torn down, so nothing can take it for a live connection again.
                            gattConnections.forget(gatt)
                            when (
                                disconnectGrace.onGraceExpired(
                                    BleDisconnectGrace.LinkFacts(
                                        claimHeld = authRequestGate.holdsClaimFor(deviceAddress),
                                        disconnectedAtMillis = disconnectedAtMillis,
                                        reconnected =
                                            connectingOrConnectedDevices.contains(deviceAddress),
                                    ),
                                )
                            ) {
                                BleDisconnectGrace.Outcome.ReleaseAndCancel -> {
                                    // The held answer has nobody left to reach and the prompt is
                                    // over. Both run BEFORE the release mark: a retransmission
                                    // landing in between is answered as a retry, and the cancel
                                    // below would claim and cancel the fresh prompt it raised —
                                    // leaving the challenge with no prompt, no mark and no
                                    // disconnect, a silent hang.
                                    pendingResponses.abandonPeer(deviceAddress)
                                    if (
                                        dev.rourunisen.tapauth.service.AuthRequestManager
                                            .getInstance()
                                            .cancelRequestsByBleDisconnection(deviceAddress)
                                    ) {
                                        Log.d(
                                            TAG,
                                            "Cancelled pending requests after prolonged BLE disconnect of $deviceAddress",
                                        )
                                    }
                                    // Last, so the retry it enables cannot be swallowed: the claim
                                    // stays held (the release concludes nothing), so a later
                                    // retransmission of this challenge is a retry and not a replay.
                                    authRequestGate.releaseForRetry(deviceAddress)
                                }
                                else -> Unit
                            }
                        }

                        // The handle is closed below, so nothing may wait on it any more, and no
                        // state may be re-created for it afterwards (a coroutine that resumes late
                        // would otherwise install a fresh entry for a closed handle that is never
                        // removed). The entry stays as that tombstone until the grace coroutine
                        // above drops it, from when on the registry remembers the handle alone.
                        gattConnections.markTornDown(gatt).closed = true
                        connectionDevices.remove(gatt)
                        gatt.close()
                    }
                }
            }

            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                Log.d(TAG, "MTU changed to $mtu (status=$status) on ${gatt.device.address}")
                completeGattOperation(
                    gatt,
                    GattOperationKind.MTU,
                    GattOperationResult(success = status == BluetoothGatt.GATT_SUCCESS),
                )
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                // Post-discovery work runs in runConnectedSequence, after the queue is released:
                // queueing a second op from inside this callback would deadlock on the mutex the
                // discovery op still holds.
                completeGattOperation(
                    gatt,
                    GattOperationKind.DISCOVER_SERVICES,
                    GattOperationResult(success = status == BluetoothGatt.GATT_SUCCESS),
                )
            }

            override fun onDescriptorWrite(
                gatt: BluetoothGatt,
                descriptor: BluetoothGattDescriptor,
                status: Int,
            ) {
                completeGattOperation(
                    gatt,
                    GattOperationKind.DESCRIPTOR_WRITE,
                    GattOperationResult(success = status == BluetoothGatt.GATT_SUCCESS),
                    descriptor.characteristic.uuid,
                )
            }

            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
                status: Int,
            ) {
                completeGattOperation(
                    gatt,
                    GattOperationKind.READ,
                    GattOperationResult(
                        success = status == BluetoothGatt.GATT_SUCCESS,
                        value = value,
                    ),
                    characteristic.uuid,
                )
            }

            @Deprecated("Deprecated in Java")
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                @Suppress("DEPRECATION") val value = characteristic.value ?: ByteArray(0)
                onCharacteristicRead(gatt, characteristic, value, status)
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    Log.d(TAG, "Successfully wrote response to client")
                } else {
                    Log.e(TAG, "Failed to write response to client, status: $status")
                }
                completeGattOperation(
                    gatt,
                    GattOperationKind.WRITE,
                    GattOperationResult(success = status == BluetoothGatt.GATT_SUCCESS),
                    characteristic.uuid,
                )
            }

            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
            ) {
                when (characteristic.uuid) {
                    CLIENT_CONFIRMATION_CHAR_UUID -> onConfirmationNotification(gatt, value)
                    CLIENT_COMMAND_CHAR_UUID -> {
                        Log.d(
                            TAG,
                            "Client command notification: ${value.size} bytes from ${gatt.device.address}",
                        )
                        // handleIncomingBleMessage verifies the WrapperMessage signature before
                        // acting, so an unverified AuthenticationCancel is ignored there.
                        serviceScope.launch { handleIncomingBleMessage(gatt, value) }
                    }
                    else -> Log.d(TAG, "Ignoring notification for ${characteristic.uuid}")
                }
            }

            @Deprecated("Deprecated in Java")
            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
            ) {
                @Suppress("DEPRECATION") val value = characteristic.value ?: ByteArray(0)
                onCharacteristicChanged(gatt, characteristic, value)
            }
        }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate() called, starting foreground immediately.")

        // Start as foreground immediately to prevent ForegroundServiceDidNotStartInTimeException
        // This is critical because subsequent checks might stop the service.
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
                    // We can't show a notification, so we can't satisfy the foreground service
                    // requirements.
                    // Stop the service gracefully. The app should handle requesting this
                    // permission.
                    stopSelf()
                    return
                }
            }
            startForeground(NOTIFICATION_ID, createNotification())
            Log.i(TAG, "Service is now in the foreground.")
        } catch (e: Exception) {
            Log.e(TAG, "FATAL: Failed to start foreground for BLE service: ${e.message}", e)
            // If this fails, the service cannot run as intended.
            stopSelf()
            return
        }

        Log.wtf(TAG, "=== BLE GATT SERVICE STARTING ===")

        deviceRepository = DeviceRepository(this)
        keypairRepository = dev.rourunisen.tapauth.data.KeypairRepository(this)
        biometricHelper = BiometricHelper(this)

        // Register broadcast receiver for cancellation requests
        val filter =
            android.content.IntentFilter(
                dev.rourunisen.tapauth.service.AuthenticationService.ACTION_CANCEL_BLE_CONNECTION,
            )
        androidx.core.content.ContextCompat.registerReceiver(
            this,
            cancelReceiver,
            filter,
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        Log.d(TAG, "Registered cancel broadcast receiver")

        bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter
        bluetoothLeScanner = bluetoothAdapter?.bluetoothLeScanner

        Log.i(TAG, "Bluetooth adapter: $bluetoothAdapter")
        Log.i(TAG, "BLE scanner: $bluetoothLeScanner")

        if (bluetoothAdapter == null || bluetoothLeScanner == null) {
            Log.e(TAG, "Bluetooth or BLE scanning not supported on this device")
            dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this }, false)
            updateNotification()
            stopSelf()
            return
        }

        // Check if Bluetooth is actually enabled
        val isEnabled = bluetoothAdapter?.isEnabled
        Log.i(TAG, "Bluetooth enabled: $isEnabled")
        if (isEnabled != true) {
            Log.e(TAG, "Bluetooth is disabled")
            dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this }, false)
            updateNotification()
            stopSelf()
            return
        }

        // Check for location permissions (required for BLE scanning on Android 10+)
        val hasFineLocation =
            ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED

        // Check for background location permission (required for background BLE scanning on Android
        // 10+)
        val hasBackgroundLocation =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ActivityCompat.checkSelfPermission(
                    this,
                    Manifest.permission.ACCESS_BACKGROUND_LOCATION,
                ) == PackageManager.PERMISSION_GRANTED
            } else {
                true // Not required before Android 10
            }

        Log.i(TAG, "Fine location permission: $hasFineLocation")
        Log.i(TAG, "Background location permission: $hasBackgroundLocation")

        if (!hasFineLocation) {
            Log.e(TAG, "ACCESS_FINE_LOCATION permission not granted - BLE scanning will fail")
            dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this }, false)
            updateNotification()
            stopSelf()
            return
        }

        if (!hasBackgroundLocation && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Log.w(
                TAG,
                "WARNING: ACCESS_BACKGROUND_LOCATION not granted - BLE scanning may be killed in background!",
            )
            // Don't stop the service, but warn the user
            // The service will work in foreground but may be killed when backgrounded
        }

        // Update config now that we know the service is likely to run
        try {
            val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(this)
            config.bleLastStartMillis = System.currentTimeMillis()
        } catch (_: Exception) {}

        startTemporalIdCache()

        Log.i(TAG, "About to start BLE scanning...")
        startScanning()
        Log.i(TAG, "Scanning start call completed")

        // Mark service as running after successful initialization
        dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this }, true)
        updateNotification()
        Log.i(TAG, "=== BLE GATT SERVICE STARTED SUCCESSFULLY ===")
    }

    private fun createNotification(): android.app.Notification {
        return dev.rourunisen.tapauth.TapAuthApplication.buildUnifiedNotification(this)
    }

    private fun updateNotification() {
        // Refresh the shared notification with the latest service states
        val notification = dev.rourunisen.tapauth.TapAuthApplication.buildUnifiedNotification(this)
        val notificationManager =
            getSystemService(android.content.Context.NOTIFICATION_SERVICE)
                as android.app.NotificationManager
        notificationManager.notify(
            dev.rourunisen.tapauth.TapAuthApplication.FOREGROUND_NOTIFICATION_ID,
            notification,
        )
    }

    private fun startTemporalIdCache() {
        DeviceRepository.addOnDevicesChangedListener(deviceChangeObserver)
        // Warm the index so the first advertisement does not pay for the rebuild.
        serviceScope.launch { temporalIdIndex.refresh() }
    }

    private fun startScanning() {
        Log.i(TAG, "startScanning() called")

        if (
            ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) !=
                PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_SCAN permission not granted")
            return
        }

        val filterData = ByteArray(10) { 0x00 }
        val filterMask = ByteArray(10) { 0x00 }

        val scanFilter =
            ScanFilter.Builder()
                .setServiceData(ParcelUuid(SERVICE_UUID), filterData, filterMask)
                .build()

        val scanSettings =
            ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .build()

        val intent =
            android.content.Intent(this, BleGattService::class.java).apply {
                action = ACTION_SCAN_RESULT
            }
        val pi =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                PendingIntent.getForegroundService(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                )
            } else {
                PendingIntent.getService(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                )
            }
        scanPendingIntent = pi

        bluetoothLeScanner?.startScan(listOf(scanFilter), scanSettings, pi)
        Log.i(TAG, "BLE PendingIntent scanning started (hardware-offloaded)")
    }

    private fun stopScanning() {
        if (
            ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) ==
                PackageManager.PERMISSION_GRANTED
        ) {
            scanPendingIntent?.let { bluetoothLeScanner?.stopScan(it) }
            Log.i(TAG, "BLE scanning stopped")
        }
        scanPendingIntent = null
    }

    private fun connectToClient(device: BluetoothDevice, csk: String) {
        if (
            ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) !=
                PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            return
        }

        if (!connectingOrConnectedDevices.add(device.address)) {
            Log.d(
                TAG,
                "Already connecting or connected to ${device.address}, ignoring duplicate scan result",
            )
            return
        }

        Log.i(TAG, "Connecting to client GATT server: ${device.address}")
        try {
            @Suppress("DEPRECATION")
            val gatt =
                when {
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> {
                        device.connectGatt(
                            this,
                            false,
                            gattCallback,
                            BluetoothDevice.TRANSPORT_LE,
                            BluetoothDevice.PHY_LE_1M_MASK or BluetoothDevice.PHY_LE_2M_MASK,
                            null,
                        )
                    }
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.O -> {
                        @Suppress("DEPRECATION")
                        device.connectGatt(
                            this,
                            false,
                            gattCallback,
                            BluetoothDevice.TRANSPORT_LE,
                            BluetoothDevice.PHY_LE_1M_MASK or BluetoothDevice.PHY_LE_2M_MASK,
                        )
                    }
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.M -> {
                        @Suppress("DEPRECATION")
                        device.connectGatt(this, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
                    }
                    else -> {
                        @Suppress("DEPRECATION") device.connectGatt(this, false, gattCallback)
                    }
                }
            if (gatt == null) {
                connectingOrConnectedDevices.remove(device.address)
            }
        } catch (e: Exception) {
            connectingOrConnectedDevices.remove(device.address)
            Log.e(TAG, "Failed to initiate connectGatt to ${device.address}: ${e.message}", e)
        }
    }

    // ===== Serialized GATT operation queue =====

    /**
     * State for [gatt], or null when that handle has been torn down.
     *
     * The registry refuses to create an entry for a handle it has already seen torn down, so a
     * coroutine that resumes after the teardown fails here instead of installing a live-looking
     * entry for a closed handle — the state it would have got is marked closed anyway.
     */
    private fun connectionState(gatt: BluetoothGatt): GattConnectionState? =
        gattConnections.liveOrCreate(gatt)?.takeUnless { it.closed }

    /**
     * Run one asynchronous [BluetoothGatt] operation and await its callback.
     *
     * The connection's mutex is held across the park, so at most one op is ever in flight on a
     * connection. Callbacks only complete the deferred: they must never queue another op here or
     * they would wait for the mutex held by the op that is waiting for them.
     *
     * @param kind the op kind whose callback completes this operation
     * @param characteristicUuid the characteristic the op targets, required to match in the
     *   callback so a late callback for another characteristic cannot satisfy it
     * @param start issues the stack call; returning false means no callback will follow.
     */
    private suspend fun runGattOperation(
        gatt: BluetoothGatt,
        kind: GattOperationKind,
        characteristicUuid: UUID? = null,
        start: () -> Boolean,
    ): GattOperationResult {
        val connection =
            connectionState(gatt)
                ?: run {
                    Log.d(TAG, "GATT ${kind.name.lowercase()} skipped: connection is closed")
                    return GattOperationResult(false)
                }
        return connection.lock.withLock {
            if (connection.closed) {
                Log.d(TAG, "GATT ${kind.name.lowercase()} skipped: connection was torn down")
                return@withLock GattOperationResult(false)
            }
            val pending = PendingGattOperation(kind, characteristicUuid)
            connection.pending = pending
            try {
                if (!start()) {
                    Log.w(TAG, "GATT ${kind.name.lowercase()} was rejected by the stack")
                    return@withLock GattOperationResult(false)
                }
                withTimeoutOrNull(GATT_OPERATION_TIMEOUT_MS) { pending.result.await() }
                    ?: run {
                        Log.w(
                            TAG,
                            "GATT ${kind.name.lowercase()} timed out after ${GATT_OPERATION_TIMEOUT_MS}ms",
                        )
                        GattOperationResult(false)
                    }
            } catch (e: CancellationException) {
                // Coroutine cancellation is not a GATT failure; let it unwind the caller.
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "GATT ${kind.name.lowercase()} failed: ${e.message}")
                GattOperationResult(false)
            } finally {
                connection.pending = null
            }
        }
    }

    /**
     * Complete the in-flight op of [kind] on [characteristicUuid], if the connection is still
     * waiting on exactly that op.
     *
     * Matching on the kind alone would let a timed-out read of one characteristic satisfy the
     * callback of another (for example a stale `CLIENT_COMMAND` read completing the confirmation
     * `READ`), so the characteristic has to match too.
     */
    private fun completeGattOperation(
        gatt: BluetoothGatt,
        kind: GattOperationKind,
        result: GattOperationResult,
        characteristicUuid: UUID? = null,
    ) {
        val pending = gattConnections.stateFor(gatt)?.pending
        if (
            pending != null &&
                pending.kind == kind &&
                pending.characteristicUuid == characteristicUuid
        ) {
            pending.result.complete(result)
        } else {
            Log.d(TAG, "Ignoring stray GATT callback for ${kind.name.lowercase()}")
        }
    }

    /**
     * Fail every waiter on a connection that can no longer answer, and let the queue drain. The
     * waiting ops then return a failure instead of parking until their timeout.
     */
    private fun cancelPendingGattOperations(gatt: BluetoothGatt, reason: String) {
        val connection = gattConnections.stateFor(gatt) ?: return
        connection.pending?.let { pending ->
            Log.d(TAG, "Cancelling pending GATT ${pending.kind.name.lowercase()}: $reason")
            pending.result.complete(GattOperationResult(false))
        }
        connection.confirmationNotification?.let { waiter ->
            waiter.cancel(CancellationException("GATT operation cancelled: $reason"))
        }
    }

    private suspend fun requestMtuQueued(gatt: BluetoothGatt, mtu: Int): Boolean =
        runGattOperation(gatt, GattOperationKind.MTU) { gatt.requestMtu(mtu) }.success

    private suspend fun discoverServicesQueued(gatt: BluetoothGatt): Boolean =
        runGattOperation(gatt, GattOperationKind.DISCOVER_SERVICES) { gatt.discoverServices() }
            .success

    private suspend fun writeDescriptorQueued(
        gatt: BluetoothGatt,
        descriptor: BluetoothGattDescriptor,
        value: ByteArray,
    ): Boolean =
        runGattOperation(
                gatt,
                GattOperationKind.DESCRIPTOR_WRITE,
                descriptor.characteristic.uuid,
            ) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    gatt.writeDescriptor(descriptor, value) == BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION")
                    descriptor.value = value
                    @Suppress("DEPRECATION") gatt.writeDescriptor(descriptor)
                }
            }
            .success

    private suspend fun writeCharacteristicQueued(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
    ): Boolean =
        runGattOperation(gatt, GattOperationKind.WRITE, characteristic.uuid) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    gatt.writeCharacteristic(
                        characteristic,
                        value,
                        BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                    ) == BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION")
                    characteristic.value = value
                    @Suppress("DEPRECATION") gatt.writeCharacteristic(characteristic)
                }
            }
            .success

    private suspend fun readCharacteristicQueued(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ): ByteArray? =
        runGattOperation(gatt, GattOperationKind.READ, characteristic.uuid) {
                gatt.readCharacteristic(characteristic)
            }
            .let { if (it.success) it.value else null }

    /**
     * Connect sequence: MTU, service discovery, CCCD subscriptions, then the initial read of the
     * client command characteristic (all of it previously done directly from the callbacks).
     */
    private suspend fun runConnectedSequence(gatt: BluetoothGatt) {
        if (
            ActivityCompat.checkSelfPermission(
                this@BleGattService,
                Manifest.permission.BLUETOOTH_CONNECT,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            return
        }

        // A refused or failed MTU negotiation only costs us long writes; discovery still runs.
        if (!requestMtuQueued(gatt, GATT_REQUESTED_MTU)) {
            Log.w(TAG, "MTU negotiation failed, continuing with the default ATT MTU")
        }

        if (!discoverServicesQueued(gatt)) {
            Log.e(TAG, "Service discovery failed on ${gatt.device.address}")
            disconnectGatt(gatt)
            return
        }
        Log.d(TAG, "Services discovered on client GATT server")

        val service = gatt.getService(SERVICE_UUID)
        if (service == null) {
            Log.e(TAG, "TapAuth service not found")
            gatt.disconnect()
            return
        }

        // Subscribe before reading, so a request the client has already queued still reaches us.
        // Only the two authentication characteristics are subscribed: nothing on this connection
        // reads or writes the pairing characteristic (pairing runs its own GATT connection in
        // BlePairingClient), so subscribing to it would cost a round-trip for a notification no
        // handler consumes.
        val notifyingCharacteristics =
            listOf(CLIENT_COMMAND_CHAR_UUID, CLIENT_CONFIRMATION_CHAR_UUID)
        for (uuid in notifyingCharacteristics) {
            enableCharacteristicNotifications(gatt, service, uuid)
        }

        val clientCommandChar = service.getCharacteristic(CLIENT_COMMAND_CHAR_UUID)
        val serverResponseChar = service.getCharacteristic(SERVER_RESPONSE_CHAR_UUID)
        if (clientCommandChar == null || serverResponseChar == null) {
            Log.e(TAG, "TapAuth characteristics not found")
            gatt.disconnect()
            return
        }

        Log.i(TAG, "Found TapAuth characteristics, reading authentication request")
        val requestBytes = readCharacteristicQueued(gatt, clientCommandChar)
        if (requestBytes != null && requestBytes.isNotEmpty()) {
            Log.d(TAG, "Read authentication request from client: ${requestBytes.size} bytes")
            handleIncomingBleMessage(gatt, requestBytes)
        } else {
            Log.d(TAG, "No authentication request readable yet; waiting for a notification")
        }
    }

    /** Enable CCCD notifications on one characteristic, skipping it when it is not present. */
    private suspend fun enableCharacteristicNotifications(
        gatt: BluetoothGatt,
        service: BluetoothGattService,
        characteristicUuid: UUID,
    ) {
        val characteristic = service.getCharacteristic(characteristicUuid)
        if (characteristic == null) {
            Log.d(TAG, "Characteristic $characteristicUuid absent, skipping notifications")
            return
        }
        if (!gatt.setCharacteristicNotification(characteristic, true)) {
            Log.w(TAG, "Unable to enable notifications for $characteristicUuid")
            return
        }
        val descriptor = characteristic.getDescriptor(CCCD_UUID)
        if (descriptor == null) {
            Log.w(TAG, "CCCD missing on $characteristicUuid")
            return
        }
        if (
            writeDescriptorQueued(
                gatt,
                descriptor,
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE,
            )
        ) {
            Log.d(TAG, "Subscribed to notifications on $characteristicUuid")
        } else {
            Log.w(TAG, "Failed to write CCCD for $characteristicUuid")
        }
    }

    private suspend fun handleIncomingBleMessage(gatt: BluetoothGatt, data: ByteArray) {
        try {
            Log.d(TAG, "Handling BLE message: ${data.size} bytes from ${gatt.device.address}")

            // Step 1: Extract the temporal identifier (16 bytes, same as UDP) before any crypto.
            val temporalIdBytes =
                try {
                    extractTemporalIdentifier(data)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse BLE EncryptedPacket", e)
                    // Silently disconnect on parse error - don't send invalid response
                    if (
                        ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT,
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        gatt.disconnect()
                    }
                    return
                }

            Log.d(
                TAG,
                "Parsed EncryptedPacket: temporal_id=${temporalIdBytes.toHexPreview()}..., ciphertext=${data.size} bytes",
            )

            // Step 2: Resolve the paired device by its temporal ID: one map read, with no
            // device-list reload and no re-derivation per packet.
            // Note: EncryptedPacket contains the 16-byte temporal ID (same as UDP), hashed with the
            // algorithm this pairing negotiated.
            val temporalIdHex = temporalIdBytes.toHex()
            val matchedDevice = temporalIdIndex.lookupPacket(temporalIdHex)

            if (matchedDevice == null) {
                Log.w(TAG, "No paired device matched the temporal ID")
                // Silently disconnect - no valid response possible without CSK
                if (
                    ActivityCompat.checkSelfPermission(
                        this@BleGattService,
                        Manifest.permission.BLUETOOTH_CONNECT,
                    ) == PackageManager.PERMISSION_GRANTED
                ) {
                    gatt.disconnect()
                }
                return
            }

            Log.d(TAG, "Temporal ID matched device: ${matchedDevice.displayName}")

            // Step 3: Decrypt the EncryptedPacket to get the WrapperMessage
            val wrapperMessageBytes =
                try {
                    decryptEncryptedPacket(
                        data,
                        matchedDevice.csk,
                        matchedDevice.symmetricAlgorithm,
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to decrypt EncryptedPacket", e)
                    // Silently disconnect on decryption error
                    if (
                        ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT,
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        gatt.disconnect()
                    }
                    return
                }

            // Remember which pairing owns this link so notifications can be verified against it.
            connectionDevices[gatt] = matchedDevice

            // Step 4: Determine message type and route accordingly
            val messageType =
                try {
                    determineMessageType(wrapperMessageBytes) ?: "UNKNOWN"
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to determine BLE message type", e)
                    gatt.disconnect()
                    return
                }

            Log.d(TAG, "BLE message type: $messageType")

            when (messageType) {
                "AUTH_REQUEST" -> handleAuthRequest(gatt, wrapperMessageBytes, matchedDevice)
                "AUTH_CANCEL" -> handleAuthCancelBle(gatt, wrapperMessageBytes, matchedDevice)
                else -> {
                    Log.w(TAG, "Unknown BLE message type: $messageType, disconnecting")
                    gatt.disconnect()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling BLE message", e)
            if (
                ActivityCompat.checkSelfPermission(
                    this@BleGattService,
                    Manifest.permission.BLUETOOTH_CONNECT,
                ) == PackageManager.PERMISSION_GRANTED
            ) {
                gatt.disconnect()
            }
        }
    }

    private suspend fun handleAuthCancelBle(
        gatt: BluetoothGatt,
        wrapperMessageBytes: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice,
    ) {
        try {
            Log.d(TAG, "Handling AuthenticationCancel via BLE from device: ${device.displayName}")

            // Verify the WrapperMessage signature before acting on the cancel: the request is
            // signed by the Client, so anything else is unauthenticated and must be ignored.
            val challengeBytes =
                try {
                    parseAndVerifyAuthCancel(
                        wrapperMessageBytes,
                        device.publicKey,
                        device.protocolVersion,
                        device.signatureAlgorithm,
                    )
                } catch (e: TapauthException.Security) {
                    Log.w(
                        TAG,
                        "BLE AuthenticationCancel failed verification for device ${device.deviceId}: ${e.rawMessage()}",
                    )
                    // An unverified cancel is ignored: no dismissal, no retransmission stop, no
                    // response, and the BLE link is left alone.
                    return
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse AuthenticationCancel via BLE", e)
                    gatt.disconnect()
                    return
                }

            Log.d(TAG, "Verified BLE AuthenticationCancel received")

            val challengeKey = challengeBytes.toHex()

            // Remove from active connections
            activeConnectionsByChallenge.remove(challengeKey)
            // The Client abandoned this authentication, so a later request carrying the same
            // challenge is a replay again, not a duplicate in flight.
            authRequestGate.conclude(challengeBytes)

            // Cancel pending auth requests
            val authRequestManager = dev.rourunisen.tapauth.service.AuthRequestManager.getInstance()
            authRequestManager.cancelRequestsByChallenge(challengeBytes)

            // Stop any retransmission
            val retransmissionManager =
                dev.rourunisen.tapauth.service.RetransmissionManager.getInstance()
            retransmissionManager.stopRetransmission(challengeBytes)

            // Release transport lock
            val transportLockManager =
                dev.rourunisen.tapauth.service.TransportLockManager.getInstance()
            transportLockManager.releaseLock(challengeBytes)

            Log.d(TAG, "BLE: Cancelled auth request and dismissed notification")

            // Disconnect the BLE connection
            if (
                ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) ==
                    PackageManager.PERMISSION_GRANTED
            ) {
                gatt.disconnect()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling BLE AuthenticationCancel", e)
            gatt.disconnect()
        }
    }

    private suspend fun handleAuthRequest(
        gatt: BluetoothGatt,
        wrapperMessageBytes: ByteArray,
        matchedDevice: dev.rourunisen.tapauth.data.PairedDevice,
    ) {
        try {
            // Rust verifies the WrapperMessage signature under the paired Client key before it
            // parses anything, so a returned request is always authentic for this pairing.
            val authRequest =
                try {
                    parseAndVerifyAuthRequest(
                        wrapperMessageBytes,
                        matchedDevice.publicKey,
                        matchedDevice.protocolVersion,
                        matchedDevice.signatureAlgorithm,
                    )
                } catch (e: TapauthException.Security) {
                    Log.w(
                        TAG,
                        "BLE auth request failed signature verification for device ${matchedDevice.deviceId}: ${e.rawMessage()}",
                    )
                    // Silently disconnect - an unverified request must not reach the user
                    if (
                        ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT,
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        gatt.disconnect()
                    }
                    return
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse BLE auth request from WrapperMessage", e)
                    // Silently disconnect on parse error
                    if (
                        ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT,
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        gatt.disconnect()
                    }
                    return
                }

            // The caller context the desktop sent is logged — scrubbed — by
            // AuthRequestManager.submitRequest, the one place both transports funnel through, so
            // `pam_service` and `process_name` are not repeated here. What this line adds is who
            // the request was for: `username` and `hostname` are the caller's own strings (Rust
            // caps the username's length but does not sanitize either), so they go through
            // [scrubLogValue] — a newline in them would otherwise forge an extra logcat line.
            Log.d(
                TAG,
                "Parsed and verified BLE request: username=${scrubLogValue(authRequest.username)}, hostname=${scrubLogValue(authRequest.hostname)}, ttyPresent=${authRequest.ttyPresent}",
            )

            // CHECK: Verify this pairing is allowed to authenticate this user
            if (!matchedDevice.isUserAllowed(authRequest.username)) {
                // The same two strings as the receipt line above — the request's `username` and
                // the entries `allowedUsers` took from a pairing provisioning's `username` — so
                // they are scrubbed here for the same reason.
                Log.w(
                    TAG,
                    "BLE pairing not authorized for user: ${scrubLogValue(authRequest.username)}",
                )
                Log.w(TAG, "  Device: ${matchedDevice.displayName}")
                Log.w(
                    TAG,
                    "  Allowed users: ${scrubLogValue(matchedDevice.allowedUsers.joinToString())}",
                )
                // Silently disconnect - this device shouldn't handle this user
                if (
                    ActivityCompat.checkSelfPermission(
                        this@BleGattService,
                        Manifest.permission.BLUETOOTH_CONNECT,
                    ) == PackageManager.PERMISSION_GRANTED
                ) {
                    gatt.disconnect()
                }
                return
            }

            Log.d(TAG, "BLE pairing authorized for user: ${scrubLogValue(authRequest.username)}")

            // The verified request carries the raw challenge bytes.
            val challengeBytes = authRequest.challenge
            val challengeKey = challengeBytes.toHex()

            // One call for the whole ladder — transport lock, duplicate in flight, replay cache,
            // fresh — so its order is a property of [BleAuthRequestGate] and cannot be edited
            // here. This method only performs the effect of the outcome it got.
            val decision =
                authRequestGate.decide(
                    challengeBytes,
                    authRequest.timestampUnixSeconds,
                    gatt.device.address,
                    claimTransport = {
                        transportLockManager.tryClaimTransport(
                            challengeBytes,
                            dev.rourunisen.tapauth.data.TransportType.BLE,
                        )
                    },
                )

            // A challenge another transport owns is not this link's to track; every other outcome
            // is. Registering it before the duplicate's answer is re-delivered is what makes the
            // reconnected handle the live one when the user answers.
            if (decision != BleAuthRequestGate.Decision.Claimed) {
                activeConnectionsByChallenge[challengeKey] = gatt
                Log.d(TAG, "Tracking BLE connection for challenge: $challengeKey")
            }

            // Step 6: one effect per outcome.
            //
            // A duplicate is a same-peer repeat of the challenge the user is approving on — a
            // notification racing the initial read, or a re-notification of the same request — and
            // must not reach the replay cache, which would report it as a replay and disconnect a
            // link whose prompt is still open. What it means for the prompt is BleDisconnectGrace's
            // question: an answer already built is written again on the handle the Client
            // reconnected
            // on, an open prompt swallows it, and a claim the grace released raises a fresh prompt
            // below. A different peer replaying the same captured bytes is decided as Replay and
            // disconnected exactly as before.
            var retryingReleasedChallenge = false
            when (decision) {
                BleAuthRequestGate.Decision.Claimed -> {
                    Log.i(
                        TAG,
                        "BLE request ignored - challenge already claimed by another transport (likely UDP)",
                    )
                    // IMPORTANT: Disconnect immediately to free resources - UDP is handling this
                    disconnectGatt(gatt)
                    return
                }
                BleAuthRequestGate.Decision.Duplicate -> {
                    Log.d(
                        TAG,
                        "BLE duplicate of in-flight challenge from ${gatt.device.address}, ignoring",
                    )
                    // What this copy means is decided by BleDisconnectGrace: a claim the grace
                    // released for a retry has no prompt left to answer (a fresh one is raised
                    // below, exactly like a first arrival), and an answer already built is written
                    // again — on the handle the Client reconnected on, when the link it was raised
                    // on is gone. Anything else is a copy of the prompt the user is still
                    // answering and is ignored, never disconnected.
                    when (
                        disconnectGrace.onDuplicate(
                            BleDisconnectGrace.ArrivalFacts(
                                claimHeld = true,
                                promptAnswered =
                                    pendingResponses.holdsAnswerFor(
                                        challengeKey,
                                        gatt.device.address,
                                    ),
                                releasedForRetry =
                                    authRequestGate.wasReleasedForRetry(challengeBytes),
                            ),
                        )
                    ) {
                        BleDisconnectGrace.Outcome.AnswerOnLiveHandle -> {
                            redeliverPendingResponse(
                                challengeKey,
                                challengeBytes,
                                gatt,
                                matchedDevice,
                            )
                            return
                        }
                        BleDisconnectGrace.Outcome.Retry -> {
                            retryingReleasedChallenge = true
                            Log.i(
                                TAG,
                                "BLE challenge was released for a retry after a disconnect; re-offering it to the user",
                            )
                            // Falls through to the shared rate limiter and the prompt below,
                            // exactly like the Process outcome. The release mark is consumed there,
                            // once the retry is really being raised.
                        }
                        else -> return
                    }
                }
                BleAuthRequestGate.Decision.Replay -> {
                    Log.w(TAG, "BLE replay attack detected, rejecting request")
                    // Silently disconnect - don't help attacker with denial message
                    if (
                        ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT,
                        ) == PackageManager.PERMISSION_GRANTED
                    ) {
                        gatt.disconnect()
                    }
                    return
                }
                BleAuthRequestGate.Decision.Process -> Unit
            }

            // Post-authentication rate limiting, on the one limiter and the one schedule the UDP
            // path uses (RequestRateLimiter.getInstance(), keyed on the paired Client's public
            // key): without it this path is a bypass of that limiter, and a Client that keeps
            // sending fresh requests is throttled on one transport and not on the other. It runs
            // here for both outcomes that raise a prompt — Process, and a Retry of a claim the
            // grace released (a retry arrives long after the limiter's 2 s de-duplication window,
            // so it really spends a burst slot) — while Claimed, Duplicate and Replay return above
            // it and never spend the allowance.
            if (
                !requestRateLimiter.shouldAcceptAuthenticatedRequest(
                    matchedDevice.publicKey,
                    wrapperMessageBytes,
                )
            ) {
                Log.w(
                    TAG,
                    "Rate limiting BLE auth request from device: ${matchedDevice.displayName}",
                )
                // No prompt, so nothing on this link has an answer coming: drop it rather than let
                // the Client wait on a request that will never be answered.
                disconnectGatt(gatt)
                return
            }

            // The signature was already verified by parseAndVerifyAuthRequest above, which also
            // covers the v2 signed WrapperMessage (no reconstruction of the signed bytes here).
            Log.d(
                TAG,
                "BLE signature verified for device: ${matchedDevice.displayName} (${matchedDevice.deviceId})",
            )

            // A retry consumes its release only here, where the limiter has admitted it and the
            // prompt is about to be registered: consumed up in the arm, a rate-limited or throwing
            // retry would leave the challenge with no prompt, no mark and no disconnect, and every
            // later copy of it would be a silent duplicate.
            if (retryingReleasedChallenge) {
                authRequestGate.retryStarted(challengeBytes)
            }

            // Step 8: Request biometric authentication via AuthRequestManager
            val authRequestManager = dev.rourunisen.tapauth.service.AuthRequestManager.getInstance()
            authRequestManager.submitRequest(
                context = this,
                deviceId = matchedDevice.deviceId,
                deviceName = matchedDevice.displayName,
                username = authRequest.username,
                hostname = authRequest.hostname,
                challenge = challengeBytes,
                // AuthRequestManager measures elapsed time against System.currentTimeMillis(),
                // so the wire value (epoch seconds) has to be converted to millis here exactly as
                // the UDP call site does; passing seconds made the prompt timeout evaluate to 0.
                timestamp = authRequest.timestampUnixSeconds * 1000,
                transportType = dev.rourunisen.tapauth.data.TransportType.BLE,
                bleDeviceAddress = gatt.device.address,
                pamService = authRequest.pamService,
                processName = authRequest.processName,
                commandPreview = authRequest.commandPreview,
                ttyPresent = authRequest.ttyPresent,
            ) { approved, challenge, explicitDenial ->
                // Create and send encrypted grant/denial
                if (approved && challenge != null) {
                    Log.d(TAG, "BLE auth request approved, creating encrypted grant")
                    try {
                        // Get server private key for signing
                        val privateKey = keypairRepository.getPrivateKey()

                        // Rust signs the grant's WrapperMessage and encrypts it into the finished
                        // EncryptedPacket, using the algorithms this pairing negotiated (the AAD
                        // binds the algorithm and the temporal identifier).
                        val encryptedPacket =
                            createGrantWrapperMessage(
                                challenge,
                                privateKey,
                                matchedDevice.csk,
                                matchedDevice.symmetricAlgorithm,
                                matchedDevice.hashAlgorithm,
                            )

                        sendResponseToClient(gatt, encryptedPacket, challengeBytes, matchedDevice)
                        Log.d(TAG, "Sent encrypted grant via BLE (${encryptedPacket.size} bytes)")

                        // Release transport lock after successful grant
                        transportLockManager.releaseLock(challengeBytes)
                        // The gate's claim is deliberately kept here: the Client retransmits
                        // this request until it has the grant, and a released claim would send
                        // those retransmissions to the replay cache, which answers "replay" and
                        // disconnects. BleAuthRequestGate documents the full reasoning.
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send BLE grant", e)
                        // Ensure disconnection on error
                        disconnectGatt(gatt)
                    }
                } else if (explicitDenial) {
                    // Only send denial if user explicitly denied (not timeout/error)
                    Log.d(TAG, "BLE auth request explicitly denied by user")
                    try {
                        // Get server private key for signing
                        val privateKey = keypairRepository.getPrivateKey()

                        // Rust signs the denial's WrapperMessage and encrypts it into the finished
                        // EncryptedPacket, bound to the challenge and the negotiated algorithms.
                        val encryptedPacket =
                            createDenialWrapperMessage(
                                challengeBytes,
                                DENIAL_REASON_USER_DENIED,
                                privateKey,
                                matchedDevice.csk,
                                matchedDevice.symmetricAlgorithm,
                                matchedDevice.hashAlgorithm,
                            )

                        sendResponseToClient(gatt, encryptedPacket, challengeBytes, matchedDevice)
                        Log.d(TAG, "Sent encrypted denial via BLE (${encryptedPacket.size} bytes)")

                        // Release transport lock after denial
                        transportLockManager.releaseLock(challengeBytes)
                        // Gate claim intentionally retained, as on the grant path above: the
                        // Client keeps retransmitting until it has the denial, and those copies
                        // arrive while the link is still up.
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to create or send BLE denial", e)
                        // Ensure disconnection on error
                        disconnectGatt(gatt)
                    }
                } else {
                    // Timeout or error - silently disconnect, don't send denial
                    Log.d(TAG, "BLE auth request timed out or failed - disconnecting silently")
                    disconnectGatt(gatt)
                    // Release transport lock even on timeout
                    transportLockManager.releaseLock(challengeBytes)
                    // The gate's claim is not released here: this path disconnects the link, and
                    // the peer is released only once the reconnection grace has passed without a
                    // reconnect.
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling BLE authentication request", e)
            // Ensure disconnection on unexpected error
            disconnectGatt(gatt)
        }
    }

    /**
     * Send response to client with retransmission (per spec: 500ms interval) If challenge is
     * provided, will retransmit until GrantConfirmation is received
     *
     * IMPORTANT: This function ensures the GATT connection is always disconnected after processing
     * completes, regardless of success or failure.
     */
    private fun sendResponseToClient(
        gatt: BluetoothGatt,
        response: ByteArray,
        challenge: ByteArray?,
        device: dev.rourunisen.tapauth.data.PairedDevice,
    ) {
        // The answer is recorded before the first write and stays recorded until the Client
        // confirms it: a Client that loses this link retransmits the same request on the next one,
        // and those bytes then have to be written there instead of on the dead handle
        // ([redeliverPendingResponse]).
        //
        // [gatt] is the handle this request arrived on, but the prompt can outlive it: the user may
        // answer after the Client dropped that link and reconnected on another handle. The handle
        // the challenge is tracked on now is therefore passed as the live one, so the answer is
        // aimed at the link that exists; the captured handle is only the fallback for an answer
        // built while no live handle is known, where the reconnect's duplicate re-delivers the
        // bytes.
        val delivery = challenge?.let {
            val challengeKey = it.toHex()
            pendingResponses.record(
                challengeKey,
                gatt.device.address,
                gatt,
                liveHandleFor(challengeKey, gatt.device.address),
                response,
            )
        }
        deliverResponse(delivery?.handle ?: gatt, response, challenge, device, delivery)
    }

    /**
     * The handle [challengeKey] may still be written on for [peerAddress], or null when there is
     * none.
     *
     * The challenge-tracked handle survives a drop only until the `STATE_DISCONNECTED` handler
     * removes it, and the Client's reconnect re-registers its own handle as the duplicate arrives:
     * so this is exactly the live side of a reconnection — null while the link is down, the new
     * handle afterwards. A closed handle is the tombstone of a torn-down link and is never
     * returned, and a handle another device registered for the same challenge is not this peer's
     * link to write an answer to.
     */
    private fun liveHandleFor(challengeKey: String, peerAddress: String): BluetoothGatt? =
        activeConnectionsByChallenge[challengeKey]?.takeIf { handle ->
            handle.device.address == peerAddress && !gattConnections.isTornDown(handle)
        }

    /**
     * Hand the answer already built for [challengeKey] to the handle the Client reconnected on.
     *
     * A duplicate of an in-flight challenge on a different handle means the Client lost the link
     * before the answer reached it. The bytes are still held by [pendingResponses], so they are
     * written again on the live handle; the loop that was writing the dead one is stopped first so
     * the two never both retire the same challenge. Nothing happens when no answer has been built
     * yet (the prompt is still open) or when the bytes are already going to this very handle.
     */
    private fun redeliverPendingResponse(
        challengeKey: String,
        challenge: ByteArray,
        gatt: BluetoothGatt,
        device: dev.rourunisen.tapauth.data.PairedDevice,
    ) {
        val redelivery =
            pendingResponses.redeliverOn(challengeKey, gatt.device.address, gatt) ?: return
        Log.i(
            TAG,
            "Re-delivering in-flight BLE response on the reconnected link to ${gatt.device.address}",
        )
        redelivery.cancelPrevious?.invoke()
        deliverResponse(
            gatt,
            redelivery.delivery.response,
            challenge,
            device,
            redelivery.delivery,
        )
    }

    /**
     * Write [response] on [gatt] and retransmit it until the Client confirms it or the window
     * closes.
     *
     * [delivery] is the [BleResponseHandoff] record holding these bytes; a re-delivery on a
     * reconnected handle calls this again with the same bytes and its own record.
     */
    private fun deliverResponse(
        gatt: BluetoothGatt,
        response: ByteArray,
        challenge: ByteArray?,
        device: dev.rourunisen.tapauth.data.PairedDevice,
        delivery: BleResponseHandoff.Delivery<BluetoothGatt>?,
    ) {
        if (
            ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) !=
                PackageManager.PERMISSION_GRANTED
        ) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            // Still disconnect even if permission is missing
            disconnectGatt(gatt)
            return
        }

        // Write to the server response characteristic on the client's GATT server
        val service = gatt.getService(SERVICE_UUID)
        val responseChar = service?.getCharacteristic(SERVER_RESPONSE_CHAR_UUID)
        val confirmationChar = service?.getCharacteristic(CLIENT_CONFIRMATION_CHAR_UUID)

        if (responseChar == null) {
            Log.e(TAG, "Server response characteristic not found on client")
            disconnectGatt(gatt)
            return
        }

        // The write is a queued GATT op, so it must run in a coroutine rather than on the caller.
        // It starts lazily so the stop handle is registered before the loop can take a step: a
        // re-delivery that races the start cancels it instead of letting it write a dead handle.
        val job =
            serviceScope.launch(start = CoroutineStart.LAZY) {
                if (delivery != null && delivery.superseded) {
                    return@launch
                }

                val connection = connectionState(gatt)
                val awaitingConfirmation = challenge != null && confirmationChar != null
                var confirmed = false

                // Arm the confirmation waiter BEFORE the response write: the Client notifies its
                // GrantConfirmation as soon as the write is acknowledged, so a waiter armed
                // afterwards would drop that first notification and the phone would retransmit for
                // the full 10 s. The retransmission loop below clears it in its `finally`.
                if (awaitingConfirmation) {
                    connection?.confirmationNotification = CompletableDeferred()
                }

                try {
                    if (!writeCharacteristicQueued(gatt, responseChar, response)) {
                        Log.w(TAG, "Failed to write response to ${gatt.device.address}")
                        // Disconnect immediately on write failure
                        connection?.confirmationNotification = null
                        disconnectGatt(gatt)
                        return@launch
                    }
                    Log.d(TAG, "Wrote response: ${response.size} bytes to ${gatt.device.address}")

                    // If challenge provided, start retransmission with confirmation checking
                    // The retransmission coroutine will ensure disconnection when done
                    if (challenge != null && confirmationChar != null) {
                        try {
                            confirmed =
                                retransmitWithConfirmationCheck(
                                    gatt,
                                    responseChar,
                                    confirmationChar,
                                    response,
                                    challenge,
                                    device,
                                )
                        } finally {
                            // ALWAYS disconnect after retransmission completes (success or failure)
                            Log.d(TAG, "Retransmission complete, disconnecting GATT")
                            connection?.confirmationNotification = null
                            disconnectGatt(gatt)
                        }
                    } else {
                        // No retransmission needed, disconnect immediately after write
                        Log.d(TAG, "No retransmission needed, disconnecting GATT")
                        disconnectGatt(gatt)
                    }
                } finally {
                    // Only a confirmed delivery retires the answer, and [BleResponseHandoff.finish]
                    // is what enforces it. A loop that ended because the link died (or was replaced
                    // by a re-delivery) leaves the bytes held, so the Client's reconnect can still
                    // be answered; the grace-expiry release is what drops an answer nobody is left
                    // to receive.
                    if (delivery != null) {
                        pendingResponses.finish(delivery, confirmed)
                    }
                }
            }
        delivery?.onRetransmission { job.cancel() }
        job.start()
    }

    /**
     * Retransmit response every 500ms until a verified GrantConfirmation arrives or the bound
     * expires.
     *
     * The Client notifies its confirmation over the CCCD; the read below is only the fallback for a
     * missed notification. Neither path may stop retransmission until the confirmation has been
     * signature-verified against the paired Client key.
     *
     * @return true when the loop stopped because that verified confirmation arrived, false when it
     *   merely ran out of time, lost the link or was cancelled. Only true retires the answer.
     */
    private suspend fun retransmitWithConfirmationCheck(
        gatt: BluetoothGatt,
        responseChar: BluetoothGattCharacteristic,
        confirmationChar: BluetoothGattCharacteristic,
        response: ByteArray,
        challenge: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice,
    ): Boolean {
        val startTime = android.os.SystemClock.elapsedRealtime()
        val maxDuration = 10_000L // 10 seconds max retransmission
        var attempt = 0
        var delivered = false

        // The waiter was armed by [deliverResponse] before the first response write; this loop
        // re-arms it per round and clears it when retransmission ends.
        val connection = connectionState(gatt)

        try {
            withContext(Dispatchers.IO) {
                while (
                    android.os.SystemClock.elapsedRealtime() - startTime < maxDuration && isActive
                ) {
                    // Re-arm per round: a completed waiter keeps returning its value, so a
                    // confirmation for another challenge would shadow the read fallback for the
                    // rest of the window. The awaited value is still checked against the in-flight
                    // challenge below, so a stale answer is never accepted.
                    val waiter = connection?.confirmationNotification
                    if (connection != null && (waiter == null || waiter.isCompleted)) {
                        connection.confirmationNotification = CompletableDeferred()
                    }

                    delay(500) // 500ms interval per spec
                    attempt++

                    if (
                        ActivityCompat.checkSelfPermission(
                            this@BleGattService,
                            Manifest.permission.BLUETOOTH_CONNECT,
                        ) != PackageManager.PERMISSION_GRANTED
                    ) {
                        break
                    }

                    try {
                        val notified = awaitConfirmationNotification(gatt)
                        if (notified != null) {
                            if (notified.contentEquals(challenge)) {
                                Log.d(
                                    TAG,
                                    "Received verified confirmation notification, stopping retransmission",
                                )
                                delivered = true
                                break
                            }
                            Log.w(
                                TAG,
                                "Confirmation notification is for another challenge, ignoring",
                            )
                        } else {
                            // Fallback: one read through the serialized queue.
                            val confirmationBytes = readCharacteristicQueued(gatt, confirmationChar)
                            if (confirmationBytes != null && confirmationBytes.isNotEmpty()) {
                                val confirmed = verifyConfirmationPacket(confirmationBytes, device)
                                if (confirmed != null && confirmed.contentEquals(challenge)) {
                                    Log.d(
                                        TAG,
                                        "Received verified confirmation (read), stopping retransmission",
                                    )
                                    delivered = true
                                    break
                                }
                                Log.w(
                                    TAG,
                                    "Confirmation read failed verification, continuing retransmission",
                                )
                            }
                        }

                        if (!writeCharacteristicQueued(gatt, responseChar, response)) {
                            Log.w(TAG, "Failed to retransmit BLE response - channel may be closing")
                            break
                        }
                        Log.d(TAG, "Retransmitted BLE response (attempt $attempt)")
                    } catch (e: Exception) {
                        Log.w(TAG, "BLE retransmission interrupted: ${e.message}")
                        break
                    }
                }

                Log.d(TAG, "BLE retransmission ended after $attempt attempts")
            }
        } finally {
            connection?.confirmationNotification = null
        }
        return delivered
    }

    /**
     * Wait briefly for the CCCD notification carrying the in-flight challenge's confirmation.
     *
     * The deferred is completed only after [onConfirmationNotification] has verified the packet, so
     * a returned value is always a signature-valid confirmation.
     */
    private suspend fun awaitConfirmationNotification(gatt: BluetoothGatt): ByteArray? {
        val waiter = gattConnections.stateFor(gatt)?.confirmationNotification ?: return null
        return withTimeoutOrNull(CONFIRMATION_NOTIFICATION_WAIT_MS) { waiter.await() }
    }

    /**
     * Verify a GrantConfirmation packet from the Client and return the challenge it confirms.
     *
     * Returns null when the packet does not decrypt, is not a GrantConfirmation, or its
     * WrapperMessage signature does not verify under the paired Client's Ed25519 key. Callers must
     * not act on a null result.
     */
    private fun verifyConfirmationPacket(
        packetBytes: ByteArray,
        device: dev.rourunisen.tapauth.data.PairedDevice,
    ): ByteArray? {
        return try {
            val wrapperMessageBytes =
                decryptEncryptedPacket(
                    packetBytes,
                    device.csk,
                    device.symmetricAlgorithm,
                )
            parseAndVerifyGrantConfirmation(
                wrapperMessageBytes,
                device.publicKey,
                device.protocolVersion,
                device.signatureAlgorithm,
            )
        } catch (e: TapauthException.Security) {
            Log.w(
                TAG,
                "GrantConfirmation failed verification for device ${device.deviceId}: ${e.rawMessage()}",
            )
            null
        } catch (e: Exception) {
            Log.w(
                TAG,
                "Failed to parse GrantConfirmation for device ${device.deviceId}: ${(e as? TapauthException)?.rawMessage() ?: e.message}",
            )
            null
        }
    }

    /**
     * Handle a notification on the confirmation characteristic: verify it and only then release the
     * retransmission waiter. An unverified confirmation is dropped and retransmission continues.
     */
    private fun onConfirmationNotification(gatt: BluetoothGatt, value: ByteArray) {
        Log.d(
            TAG,
            "Confirmation notification: ${value.size} bytes from ${gatt.device.address}",
        )
        serviceScope.launch {
            val device = connectionDevices[gatt]
            if (device == null) {
                Log.w(TAG, "No paired device for ${gatt.device.address}, ignoring confirmation")
                return@launch
            }
            val confirmedChallenge = verifyConfirmationPacket(value, device)
            if (confirmedChallenge == null) {
                Log.w(TAG, "Ignoring unverified GrantConfirmation notification")
                return@launch
            }
            val waiter = gattConnections.stateFor(gatt)?.confirmationNotification
            if (waiter != null && !waiter.isCompleted) {
                waiter.complete(confirmedChallenge)
            } else {
                Log.d(TAG, "No confirmation waiter for ${gatt.device.address}, dropping")
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_SCAN_RESULT) {
            handleScanResultIntent(intent)
        }
        return START_STICKY
    }

    private fun handleScanResultIntent(intent: Intent) {
        val errorCode =
            intent.getIntExtra(android.bluetooth.le.BluetoothLeScanner.EXTRA_ERROR_CODE, -1)
        if (errorCode != -1) {
            Log.e(TAG, "BLE scan failed with error: $errorCode")
            return
        }

        val scanResults: List<android.bluetooth.le.ScanResult>? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableArrayListExtra(
                    android.bluetooth.le.BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT,
                    android.bluetooth.le.ScanResult::class.java,
                )
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableArrayListExtra(
                    android.bluetooth.le.BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT,
                )
            }

        scanResults?.forEach { result ->
            val serviceData = result.scanRecord?.getServiceData(ParcelUuid(SERVICE_UUID))
            if (serviceData != null && serviceData.size == 10) {
                handleScanResult(result.device, serviceData, result.rssi)
            }
        }
    }

    private fun handleScanResult(device: BluetoothDevice, temporalId: ByteArray, rssi: Int) {
        val temporalIdHex = temporalId.toHex()
        Log.i(TAG, "Scan result: temporal ID ${temporalIdHex.take(20)}... (RSSI: ${rssi}dBm)")

        serviceScope.launch {
            // One map read: the index already holds the current and previous window's identifiers.
            val matchedDevice = temporalIdIndex.lookupAdvertisement(temporalIdHex)
            if (matchedDevice != null) {
                Log.i(TAG, "Temporal ID matches paired device, connecting...")
                withContext(Dispatchers.Main) { connectToClient(device, matchedDevice.csk.toHex()) }
            } else {
                Log.d(TAG, "Temporal ID does not match any paired device")
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()

        // Unregister broadcast receiver
        try {
            unregisterReceiver(cancelReceiver)
            Log.d(TAG, "Unregistered cancel broadcast receiver")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister cancel receiver: ${e.message}")
        }

        stopScanning()

        // Disconnect all active connections
        activeConnectionsByChallenge.values.forEach { gatt ->
            try {
                if (
                    ActivityCompat.checkSelfPermission(
                        this,
                        Manifest.permission.BLUETOOTH_CONNECT,
                    ) == PackageManager.PERMISSION_GRANTED
                ) {
                    gatt.disconnect()
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to disconnect GATT: ${e.message}")
            }
        }
        activeConnectionsByChallenge.clear()
        connectingOrConnectedDevices.clear()
        // Closed-handle tombstones live here too; the service is going away, so drop them.
        gattConnections.clear()
        connectionDevices.clear()
        authRequestGate.clear()
        pendingResponses.clear()
        // The registry is process-wide: leaving this observer behind would keep a dead service's
        // index alive for every later device change.
        DeviceRepository.removeOnDevicesChangedListener(deviceChangeObserver)

        try {
            dev.rourunisen.tapauth.service.ServiceStatusManager.setBleRunning({ this }, false)
            updateNotification()
        } catch (_: Exception) {}
        serviceScope.cancel()
        Log.i(TAG, "BLE GATT Service destroyed")
    }

    /** Handle cancellation request by disconnecting GATT connection for the given challenge */
    private fun handleCancelConnection(challengeBytes: ByteArray) {
        val challengeKey = challengeBytes.toHex()
        val gatt = activeConnectionsByChallenge.remove(challengeKey)
        // The request is no longer in flight, so its challenge must reach the replay cache again.
        authRequestGate.conclude(challengeBytes)

        if (gatt != null) {
            Log.d(TAG, "Disconnecting BLE connection for cancelled challenge: $challengeKey")
            disconnectGatt(gatt)
        } else {
            Log.d(TAG, "No active BLE connection found for challenge: $challengeKey")
        }
    }

    /**
     * Safely disconnect a GATT connection with proper permission checks. This ensures connections
     * are always cleaned up properly.
     */
    private fun disconnectGatt(gatt: BluetoothGatt) {
        try {
            if (
                ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) ==
                    PackageManager.PERMISSION_GRANTED
            ) {
                gatt.disconnect()
                Log.d(TAG, "Disconnected GATT connection: ${gatt.device.address}")
            } else {
                Log.w(TAG, "Cannot disconnect GATT - BLUETOOTH_CONNECT permission not granted")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Exception while disconnecting GATT: ${e.message}")
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun ByteArray.toHexPreview(maxBytes: Int = 8): String {
        val take = kotlin.math.min(this.size, maxBytes)
        return this.take(take).joinToString("") { "%02x".format(it) } +
            if (this.size > take) "…" else ""
    }
}

/**
 * Per-handle GATT state, plus the tombstones of the handles that have been torn down.
 *
 * The service keeps one state per `BluetoothGatt` because the stack allows only one asynchronous
 * operation in flight per connection, and it must never hand a state to a caller for a handle it
 * has already seen torn down: that caller would park on a lock nothing releases any more.
 *
 * [forget] drops the entry of a handle whose disconnect grace has passed. The handle is dead by
 * then and the stack reports nothing more on it, so holding its state would leave one entry behind
 * per reconnection for the life of the service. The handle still has to be recognised as torn down
 * afterwards — nothing else stops a late coroutine from creating a live-looking entry for it —
 * which is what [markTornDown] is for: those keys are held weakly, so the record flies away with
 * the last reference to the handle that could ask, instead of accumulating.
 */
internal class BleGattConnectionRegistry<K : Any, V : Any>(private val createState: () -> V) {

    private val states = java.util.concurrent.ConcurrentHashMap<K, V>()

    private val tornDownHandles: MutableSet<K> =
        java.util.Collections.synchronizedSet(
            java.util.Collections.newSetFromMap(java.util.WeakHashMap<K, Boolean>()),
        )

    /** The state [key] was given, or null when it has none right now. Never creates one. */
    fun stateFor(key: K): V? = states[key]

    /**
     * The state for [key], created on first use, or null once [key] has been torn down.
     *
     * `computeIfAbsent` is atomic per key, so a state created here is always the one teardown marks
     * closed: a caller racing the teardown can never hand the service a fresh entry the teardown
     * will not reach.
     */
    fun liveOrCreate(key: K): V? =
        if (isTornDown(key)) null else states.computeIfAbsent(key) { createState() }

    /** Record that [key] is torn down, and hand back its state so the caller can mark it closed. */
    fun markTornDown(key: K): V {
        tornDownHandles.add(key)
        return states.computeIfAbsent(key) { createState() }
    }

    /** Whether [key] has been torn down, whether its state is still held or already forgotten. */
    fun isTornDown(key: K): Boolean = tornDownHandles.contains(key)

    /** Drop the state of [key]; a key that has none is a no-op, and it stays torn down. */
    fun forget(key: K) {
        states.remove(key)
    }

    /** Drop every state and every tombstone: the service that owned them is going away. */
    fun clear() {
        states.clear()
        tornDownHandles.clear()
    }
}
