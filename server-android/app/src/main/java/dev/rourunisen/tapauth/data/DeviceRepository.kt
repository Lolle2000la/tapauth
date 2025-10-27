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

    suspend fun savePairedDevice(device: PairedDevice) =
        withContext(Dispatchers.IO) {
            val devices = getAllPairedDevices().toMutableList()
            devices.removeAll { it.deviceId == device.deviceId }
            devices.add(device)

            val json = JSONArray()
            devices.forEach { json.put(deviceToJson(it)) }

            prefs.edit().putString(KEY_DEVICES, json.toString()).apply()
        }

    suspend fun getAllPairedDevices(): List<PairedDevice> =
        withContext(Dispatchers.IO) {
            val devicesJson = prefs.getString(KEY_DEVICES, null) ?: return@withContext emptyList()

            val jsonArray = JSONArray(devicesJson)
            val devices = mutableListOf<PairedDevice>()

            for (i in 0 until jsonArray.length()) {
                val json = jsonArray.getJSONObject(i)
                devices.add(jsonToDevice(json))
            }

            devices
        }

    suspend fun getPairedDevice(deviceId: String): PairedDevice? =
        withContext(Dispatchers.IO) { getAllPairedDevices().find { it.deviceId == deviceId } }

    suspend fun removePairedDevice(deviceId: String) =
        withContext(Dispatchers.IO) {
            val devices = getAllPairedDevices().filter { it.deviceId != deviceId }

            val json = JSONArray()
            devices.forEach { json.put(deviceToJson(it)) }

            prefs.edit().putString(KEY_DEVICES, json.toString()).apply()
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

            if (updatedUsers.isEmpty()) {
                // No users left, remove entire device
                devices.removeAt(deviceIndex)
                true
            } else {
                // Update device with new user list
                devices[deviceIndex] = device.copy(allowedUsers = updatedUsers)
                false
            }

            // Save updated list
            val json = JSONArray()
            devices.forEach { json.put(deviceToJson(it)) }

            prefs.edit().putString(KEY_DEVICES, json.toString()).apply()

            return@withContext updatedUsers.isEmpty()
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
        }
    }

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
        )
    }

    companion object {
        private const val KEY_DEVICES = "paired_devices"
    }
}
