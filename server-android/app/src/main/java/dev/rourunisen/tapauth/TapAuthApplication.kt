package dev.rourunisen.tapauth

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import dev.rourunisen.tapauth.service.AuthenticationService

class TapAuthApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // Create notification channel for foreground service
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TapAuth Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Authentication service notification"
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }

        // Start core background services so UDP listener and BLE GATT are active
        // even when the app UI is not open. Services are idempotent and safe to
        // call repeatedly.
        try {
            AuthenticationService.start(this)

            // Start BLE GATT service as a foreground service (service will
            // call startForeground itself). Use startForegroundService on O+.
            val bleIntent = android.content.Intent(this, dev.rourunisen.tapauth.ble.BleGattService::class.java)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                startForegroundService(bleIntent)
            } else {
                startService(bleIntent)
            }
        } catch (e: Exception) {
            // Don't crash the app if services can't be started (e.g., missing
            // permissions on older devices). We log the failure for telemetry.
            android.util.Log.w("TapAuthApplication", "Failed to start background services: ${e.message}")
        }
    }
    
    companion object {
        const val CHANNEL_ID = "tapauth_service_channel"
    }
}
