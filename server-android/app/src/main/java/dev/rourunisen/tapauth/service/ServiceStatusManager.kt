package dev.rourunisen.tapauth.service

import dev.rourunisen.tapauth.data.AppConfiguration
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Singleton that holds live service status using StateFlow so UI can collect updates in a
 * lifecycle-aware manner. Services should call update methods when their real runtime state
 * changes. State is also persisted to AppConfiguration.
 */
object ServiceStatusManager {
    private val _udpRunning = MutableStateFlow(false)
    val udpRunning: StateFlow<Boolean> = _udpRunning

    private val _bleRunning = MutableStateFlow(false)
    val bleRunning: StateFlow<Boolean> = _bleRunning

    fun setUdpRunning(contextProvider: (() -> android.content.Context?)?, running: Boolean) {
        _udpRunning.value = running
        // persist if we have a context
        try {
            val ctx = contextProvider?.invoke()
            if (ctx != null) {
                val cfg = AppConfiguration.getInstance(ctx)
                cfg.udpRunning = running
            }
        } catch (_: Exception) {}
    }

    fun setBleRunning(contextProvider: (() -> android.content.Context?)?, running: Boolean) {
        _bleRunning.value = running
        try {
            val ctx = contextProvider?.invoke()
            if (ctx != null) {
                val cfg = AppConfiguration.getInstance(ctx)
                cfg.bleRunning = running
            }
        } catch (_: Exception) {}
    }
}
