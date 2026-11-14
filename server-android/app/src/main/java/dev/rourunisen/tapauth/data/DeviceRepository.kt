package dev.rourunisen.tapauth.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Repository for managing paired devices Stores device information in encrypted SharedPreferences
 */
class DeviceRepository(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("tapauth_devices", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_DEVICES = "paired_devices"

        /**
         * Observers told about every paired-device mutation, used by the temporal-ID caches of the
         * UDP and BLE transports to refresh immediately after pairing/un-pairing.
         *
         * More than one observer is expected (one per transport), and an observer registered while
         * another notification is being dispatched must still receive the next one, so the registry
         * is a [DeviceChangeListeners] rather than a single slot.
         */
        private val deviceChangeListeners = DeviceChangeListeners()

        /**
         * Register [listener] for paired-device changes. Registering the same instance is a no-op.
         */
        fun addOnDevicesChangedListener(listener: () -> Unit) {
            deviceChangeListeners.add(listener)
        }

        /** Unregister [listener]; unregistering one that was never added is a no-op. */
        fun removeOnDevicesChangedListener(listener: () -> Unit) {
            deviceChangeListeners.remove(listener)
        }

        private fun notifyListeners() {
            deviceChangeListeners.dispatch()
        }
    }

    suspend fun savePairedDevice(device: PairedDevice) =
        withContext(Dispatchers.IO) {
            val devices = getAllPairedDevices().toMutableList()
            devices.removeAll { it.deviceId == device.deviceId }
            devices.add(device)

            val json = JSONArray()
            devices.forEach { json.put(deviceToJson(it)) }

            prefs.edit().putString(KEY_DEVICES, json.toString()).commit()
            notifyListeners()
        }

    fun getAllPairedDevicesSync(): List<PairedDevice> {
        val devicesJson = prefs.getString(KEY_DEVICES, null) ?: return emptyList()

        val jsonArray = JSONArray(devicesJson)
        val devices = mutableListOf<PairedDevice>()

        for (i in 0 until jsonArray.length()) {
            val json = jsonArray.getJSONObject(i)
            devices.add(jsonToDevice(json))
        }

        return devices
    }

    suspend fun getAllPairedDevices(): List<PairedDevice> =
        withContext(Dispatchers.IO) {
            getAllPairedDevicesSync()
        }

    suspend fun getPairedDevice(deviceId: String): PairedDevice? =
        withContext(Dispatchers.IO) { getAllPairedDevices().find { it.deviceId == deviceId } }

    suspend fun removePairedDevice(deviceId: String) =
        withContext(Dispatchers.IO) {
            val devices = getAllPairedDevices().filter { it.deviceId != deviceId }

            val json = JSONArray()
            devices.forEach { json.put(deviceToJson(it)) }

            prefs.edit().putString(KEY_DEVICES, json.toString()).commit()
            notifyListeners()
        }

    /**
     * Remove a specific user from a device's allowed users list If this is the last user, removes
     * the entire device
     *
     * @return true if entire device was removed, false if only user was removed
     */
    suspend fun removeUserFromDevice(deviceId: String, username: String): Boolean =
        withContext(Dispatchers.IO) {
            val devices = getAllPairedDevices().toMutableList()
            val deviceIndex = devices.indexOfFirst { it.deviceId == deviceId }

            if (deviceIndex == -1) {
                return@withContext true // Device not found, consider it "removed"
            }

            val device = devices[deviceIndex]
            val updatedUsers = device.allowedUsers.filter { it != username }

            val entirelyRemoved = updatedUsers.isEmpty()
            if (entirelyRemoved) {
                // No users left, remove entire device
                devices.removeAt(deviceIndex)
            } else {
                // Update device with new user list
                devices[deviceIndex] = device.copy(allowedUsers = updatedUsers)
            }

            // Save updated list
            val json = JSONArray()
            devices.forEach { json.put(deviceToJson(it)) }

            prefs.edit().putString(KEY_DEVICES, json.toString()).commit()
            notifyListeners()

            return@withContext entirelyRemoved
        }

    private fun deviceToJson(device: PairedDevice): JSONObject {
        return JSONObject().apply {
            put("deviceId", device.deviceId)
            put("publicKey", Base64.encodeToString(device.publicKey, Base64.NO_WRAP))
            put("csk", Base64.encodeToString(device.csk, Base64.NO_WRAP))
            put("displayName", device.displayName)
            put("pairedAt", device.pairedAt)
            // Store allowed users list
            put("allowedUsers", JSONArray(device.allowedUsers))
            // Store the negotiated algorithm suite and protocol version
            put("symmetricAlgorithm", device.symmetricAlgorithm)
            put("hashAlgorithm", device.hashAlgorithm)
            put("signatureAlgorithm", device.signatureAlgorithm)
            put("protocolVersion", device.protocolVersion)
        }
    }

    /**
     * Read one persisted device.
     *
     * Records written before protocol v2 have none of the algorithm/version fields, so they load
     * with `protocolVersion = 1` and the AES-256-GCM/SHA-256/Ed25519 defaults. Such a legacy record
     * cannot authenticate over the v2 wire format and must be re-paired; there is deliberately no
     * compatibility path that would let it silently fall back to v1 crypto.
     */
    private fun jsonToDevice(json: JSONObject): PairedDevice {
        // Parse allowed users list (with backwards compatibility)
        val allowedUsers =
            if (json.has("allowedUsers")) {
                val jsonArray = json.getJSONArray("allowedUsers")
                List(jsonArray.length()) { jsonArray.getString(it) }
            } else {
                emptyList() // Backwards compatibility: old pairings allow all users
            }

        return PairedDevice(
            deviceId = json.getString("deviceId"),
            publicKey = Base64.decode(json.getString("publicKey"), Base64.NO_WRAP),
            csk = Base64.decode(json.getString("csk"), Base64.NO_WRAP),
            displayName = json.getString("displayName"),
            pairedAt = json.getLong("pairedAt"),
            allowedUsers = allowedUsers,
            symmetricAlgorithm = json.optInt("symmetricAlgorithm", 1),
            hashAlgorithm = json.optInt("hashAlgorithm", 1),
            signatureAlgorithm = json.optInt("signatureAlgorithm", 1),
            protocolVersion = json.optInt("protocolVersion", 1),
        )
    }
}

/**
 * Thread-safe set of paired-device change observers.
 *
 * Registration and removal are allowed at any time, including from inside a dispatch: a
 * [java.util.concurrent.CopyOnWriteArraySet] iterates a snapshot, so an observer that unregisters
 * itself while it runs neither breaks the loop nor starves the observers after it. Registration is
 * idempotent, and a removed observer is never invoked again.
 */
internal class DeviceChangeListeners {

    private val listeners = java.util.concurrent.CopyOnWriteArraySet<() -> Unit>()

    /** Register [listener]; returns false when it was already registered. */
    fun add(listener: () -> Unit): Boolean = listeners.add(listener)

    /** Unregister [listener]; returns false when it was not registered. */
    fun remove(listener: () -> Unit): Boolean = listeners.remove(listener)

    /** Drop every observer. */
    fun clear() {
        listeners.clear()
    }

    /** Number of registered observers (tests and diagnostics). */
    val size: Int
        get() = listeners.size

    /** Invoke every observer registered at the time of the call. */
    fun dispatch() {
        for (listener in listeners) {
            listener()
        }
    }
}
