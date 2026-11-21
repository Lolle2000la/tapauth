package dev.rourunisen.tapauth.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Repository for managing paired devices.
 *
 * The store is a `MODE_PRIVATE` `SharedPreferences` file (`tapauth_devices`) holding the paired
 * devices, CSK included, as plain JSON. It is not encrypted: what keeps it from other apps is the
 * app sandbox (`MODE_PRIVATE` means only this UID can open the file), not the Keystore, so anything
 * that can read the app's data directory reads the CSKs.
 */
class DeviceRepository(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("tapauth_devices", Context.MODE_PRIVATE)

    /**
     * The one durable write of the paired-device list.
     *
     * `commit()` and not `apply()`: the synchronous call is the one that answers *whether* the data
     * reached the disk, and that answer is what a pairing has to know before it tells the desktop
     * it succeeded. [PairedDeviceWrite] turns a rejected write into an error instead of a silent
     * no-op.
     */
    private val write: PairedDeviceWrite = PairedDeviceWrite { json ->
        prefs.edit().putString(KEY_DEVICES, json).commit()
    }

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

    /**
     * Persist [device], or fail.
     *
     * The write is durable before this returns, and a write that did **not** become durable is an
     * error rather than a silent success: this used to call `commit()` and drop its answer, so a
     * rejected write left no device row on the phone while the desktop went on to persist its
     * `PairedServer`. That split is the worst of the two states — the desktop believes it is
     * paired, every authentication it sends fails on the phone, and the user was told the pairing
     * succeeded. A throw reaches `PairingSession.runSession`, which reports it as
     * [dev.rourunisen.tapauth.network.PairingUpdate.Failed] with
     * [PairedDeviceWrite.UNSAVED_MESSAGE], before any `PairingConfirmServer` is sent.
     *
     * @throws IOException when the write was rejected, so nothing was persisted
     */
    suspend fun savePairedDevice(device: PairedDevice) =
        withContext(Dispatchers.IO) {
            val devices = getAllPairedDevices().toMutableList()
            devices.removeAll { it.deviceId == device.deviceId }
            devices.add(device)

            val json = JSONArray()
            devices.forEach { json.put(deviceToJson(it)) }

            write.write(json.toString())
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
 * One durable write of the paired-device list, with the failure made explicit.
 *
 * `SharedPreferences.commit()` returns whether the data reached the disk; `apply()` cannot answer
 * that, and neither can a `commit()` whose result is dropped. [DeviceRepository.savePairedDevice]
 * used to do the latter, which is how a failed write produced no device row while `PairingSession`
 * went on to confirm the pairing to the desktop — a phone the desktop believes is paired and a CSK
 * the phone does not have. The write is therefore a class with one job, and the `(String) ->
 * Boolean` it takes is the commit itself, so the answer cannot be discarded at the call site: an
 * `apply()` cannot be passed here at all.
 *
 * The commit is injected rather than reached through Android's `SharedPreferences`, which is a stub
 * in the JVM unit tests (`unitTests.isReturnDefaultValues`): this is the one decision of the
 * persist path that is worth a test, and it is the one that was missing.
 */
internal class PairedDeviceWrite(private val commit: (String) -> Boolean) {

    companion object {
        /**
         * What the user is told when the pairing could not be saved.
         *
         * Rendered by the pairing screen itself: the throw reaches `PairingSession.runSession`,
         * which emits `PairingUpdate.Failed(message)`, and `PairingScreen`'s failure view draws
         * that message. (The host's `onPairingFailed` callback is a no-op today, so the rendering
         * is the whole of the delivery — do not count on the callback.) It is written as a sentence
         * and a next step, not as a code, for that reason.
         */
        const val UNSAVED_MESSAGE =
            "Could not save the paired device on this phone. Nothing was paired — try again."
    }

    /**
     * Write [json], or fail.
     *
     * @throws IOException when the write did not become durable; nothing is persisted in that case
     */
    fun write(json: String) {
        if (!commit(json)) throw IOException(UNSAVED_MESSAGE)
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

    companion object {
        private const val TAG = "DeviceChangeListeners"
    }

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

    /**
     * Invoke every observer registered at the time of the call.
     *
     * Each observer is isolated: a throw is logged and dispatch moves on to the rest. Nothing here
     * can fail the caller, because `notifyListeners()` runs *after* the paired-device record is
     * committed — a throw would otherwise travel back through `savePairedDevice` into
     * `PairingSession.persistDevice`, abort the confirm burst in `PairingCompletion.confirm`, and
     * report a failed pairing for a device that is on disk.
     *
     * `Throwable` rather than `Exception`: the caller has no failure channel left to act on, and a
     * `LinkageError` from one transport's observer must not strand the other transport's.
     */
    fun dispatch() {
        for (listener in listeners) {
            try {
                listener()
            } catch (t: Throwable) {
                Log.w(TAG, "Paired-device observer failed; notifying the remaining observers", t)
            }
        }
    }
}
