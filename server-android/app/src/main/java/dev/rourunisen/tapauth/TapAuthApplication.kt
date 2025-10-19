package dev.rourunisen.tapauth

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

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
    }
    
    companion object {
        const val CHANNEL_ID = "tapauth_service_channel"
    }
}
