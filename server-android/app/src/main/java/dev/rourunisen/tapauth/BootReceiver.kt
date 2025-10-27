package dev.rourunisen.tapauth

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import dev.rourunisen.tapauth.service.AuthenticationService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.d("BootReceiver", "Device boot completed, starting TapAuth background services")
            try {
                AuthenticationService.start(context)
                val bleIntent =
                    Intent(context, dev.rourunisen.tapauth.ble.BleGattService::class.java)
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    context.startForegroundService(bleIntent)
                } else {
                    context.startService(bleIntent)
                }
            } catch (e: Exception) {
                Log.w("BootReceiver", "Failed to start services on boot: ${e.message}")
            }
        }
    }
}
