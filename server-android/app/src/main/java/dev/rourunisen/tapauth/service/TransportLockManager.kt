package dev.rourunisen.tapauth.service

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log

/**
 * Owns the Wi-Fi [WifiManager.MulticastLock] required by the UDP multicast listener.
 *
 * Holding this lock forces the Wi-Fi baseband to disable its hardware multicast filter (APF), so
 * the lock must only be held while the UDP socket is actually bound — i.e. while the screen is on.
 * See [AuthenticationService] for the screen-driven lifecycle.
 *
 * Deliberately does **not** use a [WifiManager.WifiLock] (`WIFI_MODE_FULL_HIGH_PERF` /
 * `WIFI_MODE_FULL_LOW_LATENCY`): those keep the Wi-Fi chip awake for the whole screen-on period and
 * are not needed because kernel network interrupts wake the SoC for socket traffic on their own.
 */
class TransportLockManager(context: Context) {

    private val wifiManager =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager

    private val multicastLock: WifiManager.MulticastLock? =
        try {
            wifiManager?.createMulticastLock(MULTICAST_LOCK_TAG)?.apply {
                // Non-reference-counted so repeated acquire/release across screen and network
                // transitions can never leak the lock.
                setReferenceCounted(false)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to create Wi-Fi multicast lock: ${e.message}")
            null
        }

    /** Whether the Wi-Fi multicast lock is currently held (diagnostic / test use). */
    val isMulticastHeld: Boolean
        get() = multicastLock?.isHeld == true

    @Synchronized
    fun acquireMulticastLock() {
        val lock = multicastLock ?: return
        if (!lock.isHeld) {
            lock.acquire()
            Log.d(TAG, "MulticastLock acquired")
        }
    }

    @Synchronized
    fun releaseMulticastLock() {
        val lock = multicastLock ?: return
        if (lock.isHeld) {
            lock.release()
            Log.d(TAG, "MulticastLock released")
        }
    }

    companion object {
        private const val TAG = "TransportLockManager"

        /**
         * Exact tag reported by `adb shell dumpsys wifi | grep tapauth:multicast_lock`. Keep in
         * sync with documentation/tests; the acceptance check depends on this string.
         */
        const val MULTICAST_LOCK_TAG = "tapauth:multicast_lock"
    }
}
