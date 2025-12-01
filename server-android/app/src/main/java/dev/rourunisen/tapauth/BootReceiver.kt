package dev.rourunisen.tapauth

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.ActivityCompat
import dev.rourunisen.tapauth.service.AuthenticationService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.d("BootReceiver", "Device boot completed")

            // Check for POST_NOTIFICATIONS permission on Android 13+
            val hasNotificationPermission =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ActivityCompat.checkSelfPermission(
                        context,
                        android.Manifest.permission.POST_NOTIFICATIONS,
                    ) == PackageManager.PERMISSION_GRANTED
                } else {
                    // Not required on older versions
                    true
                }

            if (!hasNotificationPermission) {
                Log.w(
                    "BootReceiver",
                    "Skipping service start - POST_NOTIFICATIONS permission not granted",
                )
                return
            }

            Log.d("BootReceiver", "Starting TapAuth background services")
            try {
                // Get configuration to check enabled preferences
                val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)

                // Only start UDP service if user has it enabled
                if (config.udpEnabled) {
                    Log.d("BootReceiver", "UDP service enabled, starting...")
                    AuthenticationService.start(context)
                } else {
                    Log.d("BootReceiver", "UDP service disabled by user preference, skipping")
                }

                // Only start BLE service if user has it enabled
                if (config.bleEnabled) {
                    Log.d("BootReceiver", "BLE service enabled, starting...")
                    val bleIntent =
                        Intent(context, dev.rourunisen.tapauth.ble.BleGattService::class.java)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(bleIntent)
                    } else {
                        context.startService(bleIntent)
                    }
                } else {
                    Log.d("BootReceiver", "BLE service disabled by user preference, skipping")
                }
            } catch (e: Exception) {
                Log.w("BootReceiver", "Failed to start services on boot: ${e.message}")
            }
        }
    }
}
