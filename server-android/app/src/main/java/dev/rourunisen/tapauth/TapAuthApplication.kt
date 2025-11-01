package dev.rourunisen.tapauth

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.core.app.NotificationManagerCompat
import dev.rourunisen.tapauth.service.AuthenticationService

class TapAuthApplication : Application() {

    companion object {
        const val CHANNEL_ID = "tapauth_service_channel"
        const val AUTH_CHANNEL_ID = "tapauth_auth_channel"

        // Bump this when notification ID/tag scheme changes to force a one-time cleanup
        private const val NOTIFICATION_SCHEME_VERSION = 2
        private const val PREFS_NAME = "tapauth_prefs"
        private const val KEY_NOTIF_SCHEME_VER = "notification_scheme_version"
    }

    override fun onCreate() {
        super.onCreate()

        // Create notification channel for foreground service
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel =
                NotificationChannel(
                        CHANNEL_ID,
                        "TapAuth Service",
                        NotificationManager.IMPORTANCE_LOW,
                    )
                    .apply { description = "Authentication service notification" }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
            // High-priority channel for user approval notifications (heads-up)
            val authChannel =
                NotificationChannel(
                        AUTH_CHANNEL_ID,
                        "TapAuth Requests",
                        NotificationManager.IMPORTANCE_HIGH,
                    )
                    .apply {
                        description = "Authentication requests (tap to approve)"
                        enableVibration(true)
                        enableLights(true)
                    }
            notificationManager.createNotificationChannel(authChannel)
        }

        // One-time migration: clear any legacy notifications that used a different ID scheme
        try {
            val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            val current = prefs.getInt(KEY_NOTIF_SCHEME_VER, 0)
            if (current < NOTIFICATION_SCHEME_VERSION) {
                // This runs once after upgrade; safe to clear to avoid undismissable legacy items
                NotificationManagerCompat.from(this).cancelAll()
                android.util.Log.i(
                    "TapAuthApplication",
                    "Cleared legacy notifications (scheme $current -> $NOTIFICATION_SCHEME_VERSION)",
                )
                prefs.edit().putInt(KEY_NOTIF_SCHEME_VER, NOTIFICATION_SCHEME_VERSION).apply()
            }
        } catch (e: Exception) {
            android.util.Log.w("TapAuthApplication", "Failed to run notification migration: ${e.message}")
        }

        // Start core background services so UDP listener and BLE GATT are active
        // even when the app UI is not open. Services are idempotent and safe to
        // call repeatedly.
        try {
            AuthenticationService.start(this)

            // Start BLE GATT service as a foreground service (service will
            // call startForeground itself). Use startForegroundService on O+.
            val bleIntent =
                android.content.Intent(this, dev.rourunisen.tapauth.ble.BleGattService::class.java)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                startForegroundService(bleIntent)
            } else {
                startService(bleIntent)
            }
        } catch (e: Exception) {
            // Don't crash the app if services can't be started (e.g., missing
            // permissions on older devices). We log the failure for telemetry.
            android.util.Log.w(
                "TapAuthApplication",
                "Failed to start background services: ${e.message}",
            )
        }
    }

}
