package dev.rourunisen.tapauth.data

import android.content.Context
import android.content.SharedPreferences

/**
 * Application configuration manager using SharedPreferences.
 * Provides user-configurable settings per specification requirements.
 */
class AppConfiguration private constructor(context: Context) {
    
    private val prefs: SharedPreferences = context.getSharedPreferences(
        PREFS_NAME,
        Context.MODE_PRIVATE
    )
    
    companion object {
        private const val PREFS_NAME = "tapauth_config"
        private const val KEY_UDP_PORT = "udp_port"
        private const val KEY_SESSION_TIMEOUT = "session_timeout_seconds"
        private const val KEY_BLE_ENABLED = "ble_enabled"
    private const val KEY_UDP_ENABLED = "udp_enabled"
    private const val KEY_UDP_LAST_START = "udp_last_start_millis"
    private const val KEY_BLE_LAST_START = "ble_last_start_millis"
    private const val KEY_UDP_RUNNING = "udp_running"
    private const val KEY_BLE_RUNNING = "ble_running"
        
        // Default values per specification
        private const val DEFAULT_UDP_PORT = 36692
        private const val DEFAULT_SESSION_TIMEOUT = 120L // 120 seconds per spec
        private const val DEFAULT_BLE_ENABLED = true
    private const val DEFAULT_UDP_ENABLED = true
    private const val DEFAULT_LAST_START = 0L
        
        @Volatile
        private var instance: AppConfiguration? = null
        
        fun getInstance(context: Context): AppConfiguration {
            return instance ?: synchronized(this) {
                instance ?: AppConfiguration(context.applicationContext).also { instance = it }
            }
        }
    }
    
    /**
     * UDP port for authentication requests.
     * Default: 36692 (specification-defined)
     * Must be user-configurable per specification requirements.
     */
    var udpPort: Int
        get() = prefs.getInt(KEY_UDP_PORT, DEFAULT_UDP_PORT)
        set(value) {
            require(value in 1024..65535) { "UDP port must be between 1024 and 65535" }
            prefs.edit().putInt(KEY_UDP_PORT, value).apply()
        }
    
    /**
     * Session timeout in seconds.
     * Default: 120 seconds per specification
     */
    var sessionTimeoutSeconds: Long
        get() = prefs.getLong(KEY_SESSION_TIMEOUT, DEFAULT_SESSION_TIMEOUT)
        set(value) {
            require(value > 0) { "Session timeout must be positive" }
            prefs.edit().putLong(KEY_SESSION_TIMEOUT, value).apply()
        }
    
    /**
     * Whether BLE GATT service is enabled.
     * Default: true
     */
    var bleEnabled: Boolean
        get() = prefs.getBoolean(KEY_BLE_ENABLED, DEFAULT_BLE_ENABLED)
        set(value) {
            prefs.edit().putBoolean(KEY_BLE_ENABLED, value).apply()
        }

    /**
     * Whether UDP server is enabled.
     * Default: true
     */
    var udpEnabled: Boolean
        get() = prefs.getBoolean(KEY_UDP_ENABLED, DEFAULT_UDP_ENABLED)
        set(value) {
            prefs.edit().putBoolean(KEY_UDP_ENABLED, value).apply()
        }

    /**
     * Last time the UDP authentication service was started (epoch millis). 0 = never
     */
    var udpLastStartMillis: Long
        get() = prefs.getLong(KEY_UDP_LAST_START, DEFAULT_LAST_START)
        set(value) {
            prefs.edit().putLong(KEY_UDP_LAST_START, value).apply()
        }

    /**
     * Last time the BLE GATT service was started (epoch millis). 0 = never
     */
    var bleLastStartMillis: Long
        get() = prefs.getLong(KEY_BLE_LAST_START, DEFAULT_LAST_START)
        set(value) {
            prefs.edit().putLong(KEY_BLE_LAST_START, value).apply()
        }

    /**
     * Whether UDP service is currently running.
     */
    var udpRunning: Boolean
        get() = prefs.getBoolean(KEY_UDP_RUNNING, false)
        set(value) { prefs.edit().putBoolean(KEY_UDP_RUNNING, value).apply() }

    /**
     * Whether BLE GATT service is currently running.
     */
    var bleRunning: Boolean
        get() = prefs.getBoolean(KEY_BLE_RUNNING, false)
        set(value) { prefs.edit().putBoolean(KEY_BLE_RUNNING, value).apply() }
    
    /**
     * Reset all settings to defaults.
     */
    fun resetToDefaults() {
        prefs.edit().clear().apply()
    }
}
