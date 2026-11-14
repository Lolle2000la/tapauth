package dev.rourunisen.tapauth.network

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import androidx.core.content.ContextCompat
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * BLE GATT central transport for protocol v2 pairing.
 *
 * The Android device is the pairing **Server** (`PairingInit` carries the `server_*` keys), so it
 * scans for the Client's pairing advertisement, connects as the GATT *central*, subscribes to
 * notifications on [PAIRING_CHAR_UUID], writes its `PairingInit` there, and receives the Client's
 * `PairingResponse`, `PairingConfirmClient` and `PairingAbort` as notifications on the same
 * characteristic (see `docs/design-documents/protocol/ble-gatt-specification.md` §1–§3).
 *
 * Discovery matches the 10-byte `pairing_adv_id` in `ServiceData(SERVICE_UUID)` through a hardware
 * `ScanFilter` with an all-`0xFF` service-data mask: only a phone that just scanned the QR code
 * knows that token and can find the Client. Every GATT operation is serialized — Android's
 * `BluetoothGatt` drops concurrent operations — by awaiting the matching callback (`onMtuChanged`,
 * `onServicesDiscovered`, `onDescriptorWrite`, `onCharacteristicWrite`) under a [Mutex].
 *
 * Runtime permissions (`BLUETOOTH_SCAN`/`BLUETOOTH_CONNECT`) are the app's responsibility; when the
 * adapter is off, missing, or a `SecurityException` is raised, the affected call reports failure
 * (`false`/`null`) instead of throwing.
 */
class BlePairingClient(private val context: Context) {

    companion object {
        private const val TAG = "BlePairingClient"

        /** Mirrors `ble/BleGattService.kt`; the daemon's single static TapAuth service. */
        val SERVICE_UUID: UUID = UUID.fromString("b4ad84c0-2adb-4876-8315-b39d983b2bde")

        /** The daemon's unified pairing channel characteristic. */
        val PAIRING_CHAR_UUID: UUID = UUID.fromString("d9e8f1a2-3b4c-4d5e-8f60-7a8b9c0d1e2f")

        private val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        /** MTU to request before service discovery so pairing frames fit one PDU. */
        private const val TARGET_MTU = 517

        /** `pairing_adv_id` length (`SHA-256("tapauth-ble-pair-v2" || sid || X_C)[..10]`). */
        private const val ADV_ID_BYTES = 10

        /** Bound on a single GATT write, since a lost callback must not wedge the caller. */
        private const val WRITE_TIMEOUT_MS = 5_000L
    }

    private val gattMutex = Mutex()

    /** Incoming pairing frames, in arrival order, drained by [awaitPacket]/[setListener]. */
    private val packets = Channel<ByteArray>(Channel.UNLIMITED)

    @Volatile private var onPacket: ((ByteArray) -> Unit)? = null

    @Volatile private var gatt: BluetoothGatt? = null

    @Volatile private var characteristic: BluetoothGattCharacteristic? = null

    @Volatile private var closed = false

    // One deferred per in-flight GATT operation; the callback completes it.
    @Volatile private var connectedDeferred: CompletableDeferred<Boolean>? = null
    @Volatile private var mtuDeferred: CompletableDeferred<Boolean>? = null
    @Volatile private var servicesDeferred: CompletableDeferred<Boolean>? = null
    @Volatile private var descriptorDeferred: CompletableDeferred<Boolean>? = null
    @Volatile private var writeDeferred: CompletableDeferred<Boolean>? = null

    /** Completed by [scanCallback] with the first advertisement matching the pairing filter. */
    @Volatile private var scanResult: CompletableDeferred<ScanResult>? = null

    private val scanCallback =
        object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val serviceData = result.scanRecord?.getServiceData(ParcelUuid(SERVICE_UUID))
                Log.d(
                    TAG,
                    "Matched ${runCatching { result.device.address }.getOrElse { "?" }} " +
                        "RSSI ${result.rssi} serviceData " +
                        (serviceData?.joinToString("") { "%02x".format(it) } ?: "none"),
                )
                scanResult?.complete(result)
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                results.firstOrNull()?.let { scanResult?.complete(it) }
            }

            override fun onScanFailed(errorCode: Int) {
                Log.w(TAG, "BLE scan failed with error code $errorCode")
                scanResult?.completeExceptionally(
                    IllegalStateException("BLE scan failed: $errorCode"),
                )
            }
        }

    private val gattCallback =
        object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            Log.i(TAG, "Connected to ${gatt.device.address}")
                            connectedDeferred?.complete(true)
                        } else {
                            Log.w(TAG, "Connection to ${gatt.device.address} failed: $status")
                            connectedDeferred?.complete(false)
                        }
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        Log.i(TAG, "Disconnected from ${gatt.device.address}")
                        failPendingOperations()
                    }
                }
            }

            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                Log.d(TAG, "MTU is now $mtu (status $status)")
                mtuDeferred?.complete(status == BluetoothGatt.GATT_SUCCESS)
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                Log.d(TAG, "Service discovery finished with status $status")
                servicesDeferred?.complete(status == BluetoothGatt.GATT_SUCCESS)
            }

            override fun onDescriptorWrite(
                gatt: BluetoothGatt,
                descriptor: BluetoothGattDescriptor,
                status: Int,
            ) {
                Log.d(TAG, "Descriptor ${descriptor.uuid} write status $status")
                descriptorDeferred?.complete(status == BluetoothGatt.GATT_SUCCESS)
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                Log.d(TAG, "Characteristic ${characteristic.uuid} write status $status")
                writeDeferred?.complete(status == BluetoothGatt.GATT_SUCCESS)
            }

            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
            ) {
                deliver(characteristic, value)
            }

            @Deprecated("Deprecated in Java")
            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
            ) {
                @Suppress("DEPRECATION") val value = characteristic.value ?: return
                deliver(characteristic, value)
            }
        }

    /**
     * Scan for the Client advertising [advertisementId] and prepare the GATT link for pairing.
     *
     * Performs, in order: hardware-filtered scan → `connectGatt(..., TRANSPORT_LE)` →
     * `requestMtu(517)` → `discoverServices()` → `setCharacteristicNotification` + CCCD write. On
     * success the link is ready for [send] and [awaitPacket].
     *
     * @param advertisementId 10-byte `pairing_adv_id` derived from the QR's `sid` and `pk`
     * @return true when the pairing characteristic is subscribed; false on any failure (no adapter,
     *   adapter off, no match within [timeoutMs], missing service/characteristic,
     *   `SecurityException`)
     */
    suspend fun connect(advertisementId: ByteArray, timeoutMs: Long): Boolean =
        withContext(Dispatchers.IO) {
            if (advertisementId.size != ADV_ID_BYTES) {
                Log.e(
                    TAG,
                    "Advertisement id must be $ADV_ID_BYTES bytes, got ${advertisementId.size}",
                )
                return@withContext false
            }
            if (closed) return@withContext false
            val adapter = bluetoothAdapter() ?: return@withContext false
            if (!adapter.isEnabled) {
                Log.w(TAG, "Bluetooth is off, cannot pair over BLE")
                return@withContext false
            }
            val scanner = adapter.bluetoothLeScanner ?: return@withContext false
            if (!hasPermissions()) return@withContext false

            val prepared = withTimeoutOrNull(timeoutMs) { prepare(scanner, advertisementId) }
            if (prepared != true) {
                Log.w(TAG, "BLE pairing link not established")
                releaseTransport()
                return@withContext false
            }
            true
        }

    /**
     * Write one serialized `PairingPacket` to [PAIRING_CHAR_UUID] with `WRITE_TYPE_DEFAULT`.
     *
     * @return true when the write was acknowledged; false when the link is gone, the write could
     *   not be started, it failed, or it timed out
     */
    suspend fun send(initPacketBytes: ByteArray): Boolean =
        withContext(Dispatchers.IO) {
            val activeGatt = gatt ?: return@withContext false
            val activeCharacteristic = characteristic ?: return@withContext false
            if (closed) return@withContext false
            gattMutex.withLock {
                val deferred = CompletableDeferred<Boolean>()
                writeDeferred = deferred
                try {
                    val started =
                        try {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                activeGatt.writeCharacteristic(
                                    activeCharacteristic,
                                    initPacketBytes,
                                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                                ) == BluetoothStatusCodes.SUCCESS
                            } else {
                                @Suppress("DEPRECATION")
                                activeCharacteristic.value = initPacketBytes
                                @Suppress("DEPRECATION")
                                activeGatt.writeCharacteristic(activeCharacteristic)
                            }
                        } catch (e: SecurityException) {
                            Log.w(TAG, "GATT write denied: ${e.message}")
                            false
                        }
                    if (!started) return@withLock false
                    withTimeoutOrNull(WRITE_TIMEOUT_MS) { deferred.await() } == true
                } finally {
                    writeDeferred = null
                }
            }
        }

    /**
     * Register a callback invoked for every incoming pairing frame, in addition to [awaitPacket].
     */
    fun setListener(onPacket: (ByteArray) -> Unit) {
        this.onPacket = onPacket
    }

    /**
     * Wait up to [timeoutMs] for the next incoming pairing frame.
     *
     * @return the frame, or null on timeout or after [close]
     */
    suspend fun awaitPacket(timeoutMs: Long): ByteArray? =
        withTimeoutOrNull(timeoutMs) {
            try {
                packets.receive()
            } catch (e: ClosedReceiveChannelException) {
                null
            }
        }

    /** Stop scanning, tear down the GATT link, drop pending operations. Idempotent. */
    fun close() {
        if (closed) return
        closed = true
        // `scanForDevice`'s `finally` only runs when its own await finishes; a `close()` that races
        // the scan must not leave the radio scanning for the rest of the timeout.
        stopActiveScan()
        releaseTransport()
        packets.close()
        Log.d(TAG, "BLE pairing transport closed")
    }

    /**
     * Stop an in-flight scan, if there is one.
     *
     * Guarded on [scanResult] so an already-stopped scanner is never touched, and `stopScan`
     * swallows a revoked-permission `SecurityException`. The deferred is left for `scanForDevice`'s
     * `finally` to clear, so this cannot leave its awaiter hanging without a result.
     */
    private fun stopActiveScan() {
        if (scanResult == null) return
        val scanner = bluetoothAdapter()?.bluetoothLeScanner ?: return
        stopScan(scanner)
    }

    private suspend fun prepare(scanner: BluetoothLeScanner, advertisementId: ByteArray): Boolean {
        val device = scanForDevice(scanner, advertisementId) ?: return false
        if (closed) return false

        val connected = CompletableDeferred<Boolean>()
        connectedDeferred = connected
        val activeGatt =
            try {
                @Suppress("DEPRECATION")
                device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
            } catch (e: SecurityException) {
                Log.w(TAG, "connectGatt denied: ${e.message}")
                null
            }
        if (activeGatt == null) {
            connectedDeferred = null
            return false
        }
        gatt = activeGatt

        // Clear the completer once the link is settled, so a later disconnection cannot complete a
        // deferred that belongs to this finished operation.
        val isConnected =
            try {
                connected.await()
            } finally {
                connectedDeferred = null
            }
        if (isConnected != true) return false

        // Everything after the link is up is one serialized GATT sequence: Android drops
        // concurrent BluetoothGatt operations, and a [send] racing this sequence must wait.
        return gattMutex.withLock {
            // MTU first, then discovery: a 517-byte MTU keeps every PairingPacket inside one PDU.
            if (!requestMtu(activeGatt)) {
                Log.w(TAG, "MTU negotiation failed, continuing at the default MTU")
            }
            if (!discoverServices(activeGatt)) return@withLock false

            val service = activeGatt.getService(SERVICE_UUID)
            val pairingCharacteristic = service?.getCharacteristic(PAIRING_CHAR_UUID)
            if (pairingCharacteristic == null) {
                Log.e(TAG, "Pairing characteristic not found on ${activeGatt.device.address}")
                return@withLock false
            }
            characteristic = pairingCharacteristic
            enableNotifications(activeGatt, pairingCharacteristic)
        }
    }

    private suspend fun scanForDevice(
        scanner: BluetoothLeScanner,
        advertisementId: ByteArray,
    ): BluetoothDevice? {
        // Match the 10-byte value in ServiceData(SERVICE_UUID) with an all-0xFF mask, and nothing
        // else. The daemon's advertisement is exactly 31 bytes (the legacy maximum), so it carries
        // SERVICE_UUID only inside its Service Data AD structure (type 0x21), never as a
        // service-UUID list (types 0x02/0x03/0x06/0x07) — ble-gatt-specification.md §1:
        // "service_uuids must NOT be set". Android ANDs every field of a ScanFilter, and
        // setServiceUuid() is matched only against the advertised UUID list, which is empty here:
        // adding it makes the filter reject every packet for the whole scan window. Do not re-add
        // it.
        val filter =
            ScanFilter.Builder()
                .setServiceData(
                    ParcelUuid(SERVICE_UUID),
                    advertisementId,
                    ByteArray(ADV_ID_BYTES) { 0xFF.toByte() },
                )
                .build()
        val settings =
            ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .build()

        val found = CompletableDeferred<ScanResult>()
        scanResult = found
        try {
            scanner.startScan(listOf(filter), settings, scanCallback)
        } catch (e: SecurityException) {
            Log.w(TAG, "startScan denied: ${e.message}")
            scanResult = null
            return null
        }
        Log.d(TAG, "Scanning for pairing advertisement")
        Log.d(
            TAG,
            "Scanning for pairing adv_id ${advertisementId.joinToString("") { "%02x".format(it) }}",
        )
        val result =
            try {
                found.await()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "No pairing advertisement matched: ${e.message}")
                null
            } finally {
                stopScan(scanner)
                scanResult = null
            }
        return result?.device
    }

    private fun stopScan(scanner: BluetoothLeScanner) {
        try {
            scanner.stopScan(scanCallback)
        } catch (e: SecurityException) {
            Log.d(TAG, "stopScan denied: ${e.message}")
        }
    }

    private suspend fun requestMtu(activeGatt: BluetoothGatt): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        mtuDeferred = deferred
        try {
            val started =
                try {
                    activeGatt.requestMtu(TARGET_MTU)
                } catch (e: SecurityException) {
                    false
                }
            if (!started) return false
            return deferred.await()
        } finally {
            mtuDeferred = null
        }
    }

    private suspend fun discoverServices(activeGatt: BluetoothGatt): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        servicesDeferred = deferred
        try {
            val started =
                try {
                    activeGatt.discoverServices()
                } catch (e: SecurityException) {
                    false
                }
            if (!started) return false
            return deferred.await()
        } finally {
            servicesDeferred = null
        }
    }

    private suspend fun enableNotifications(
        activeGatt: BluetoothGatt,
        pairingCharacteristic: BluetoothGattCharacteristic,
    ): Boolean {
        val descriptor = pairingCharacteristic.getDescriptor(CCCD_UUID)
        if (descriptor == null) {
            Log.e(TAG, "Pairing characteristic has no CCCD descriptor")
            return false
        }
        val subscribed =
            try {
                activeGatt.setCharacteristicNotification(pairingCharacteristic, true)
            } catch (e: SecurityException) {
                false
            }
        if (!subscribed) {
            Log.e(TAG, "Cannot enable notifications on the pairing characteristic")
            return false
        }
        val deferred = CompletableDeferred<Boolean>()
        descriptorDeferred = deferred
        try {
            val started =
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        activeGatt.writeDescriptor(
                            descriptor,
                            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE,
                        ) == BluetoothStatusCodes.SUCCESS
                    } else {
                        @Suppress("DEPRECATION")
                        descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                        @Suppress("DEPRECATION") activeGatt.writeDescriptor(descriptor)
                    }
                } catch (e: SecurityException) {
                    false
                }
            if (!started) return false
            return deferred.await()
        } finally {
            descriptorDeferred = null
        }
    }

    private fun deliver(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        if (characteristic.uuid != PAIRING_CHAR_UUID) return
        Log.d(TAG, "Received ${value.size} B pairing frame")
        packets.trySend(value)
        onPacket?.invoke(value)
    }

    private fun failPendingOperations() {
        connectedDeferred?.complete(false)
        mtuDeferred?.complete(false)
        servicesDeferred?.complete(false)
        descriptorDeferred?.complete(false)
        writeDeferred?.complete(false)
    }

    private fun releaseTransport() {
        failPendingOperations()
        gatt?.let { activeGatt ->
            try {
                activeGatt.disconnect()
            } catch (e: SecurityException) {
                Log.d(TAG, "disconnect denied: ${e.message}")
            }
            try {
                activeGatt.close()
            } catch (e: SecurityException) {
                Log.d(TAG, "gatt.close denied: ${e.message}")
            }
        }
        gatt = null
        characteristic = null
    }

    private fun bluetoothAdapter(): BluetoothAdapter? {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        return manager?.adapter
    }

    private fun hasPermissions(): Boolean {
        // BLUETOOTH_SCAN/BLUETOOTH_CONNECT only exist (and are only enforced) from API 31; below
        // that the legacy BLUETOOTH permission the manifest already declares is enough.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        val connect =
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
                PackageManager.PERMISSION_GRANTED
        if (!connect) {
            Log.w(TAG, "BLUETOOTH_CONNECT is not granted")
            return false
        }
        val scan =
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) ==
                PackageManager.PERMISSION_GRANTED
        if (!scan) Log.w(TAG, "BLUETOOTH_SCAN is not granted")
        return scan
    }
}
