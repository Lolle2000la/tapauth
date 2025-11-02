package dev.rourunisen.tapauth.crypto

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

/**
 * Test-specific Application class that skips service startup. This prevents
 * ForegroundServiceStartNotAllowedException during tests.
 */
class TestTapAuthApplication : Application() {

    companion object {
        const val CHANNEL_ID = "tapauth_service_channel"
        const val AUTH_CHANNEL_ID = "tapauth_auth_channel"
    }

    override fun onCreate() {
        super.onCreate()

        // Only create notification channels for tests that need them
        // Skip starting any foreground services
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
    }
}
