package dev.rourunisen.tapauth.data

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * Represents an authentication request that needs biometric approval
 *
 * The four context fields carry the Client's signed caller context (protocol v2: `pam_service`,
 * `process_name`, `command_preview`, `tty_present`). They are untrusted input: render them only
 * after [ContextSanitizer.sanitize], never raw.
 */
@Parcelize
data class AuthRequest(
    val requestId: String,
    val deviceId: String,
    val deviceName: String,
    val username: String,
    val hostname: String,
    val challenge: ByteArray,
    val timestamp: Long,
    val transportType: TransportType,
    val pamService: String = "",
    val processName: String = "",
    val commandPreview: String = "",
    val ttyPresent: Boolean = false,
) : Parcelable {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthRequest

        if (requestId != other.requestId) return false
        if (deviceId != other.deviceId) return false
        if (deviceName != other.deviceName) return false
        if (username != other.username) return false
        if (hostname != other.hostname) return false
        if (!challenge.contentEquals(other.challenge)) return false
        if (timestamp != other.timestamp) return false
        if (transportType != other.transportType) return false
        if (pamService != other.pamService) return false
        if (processName != other.processName) return false
        if (commandPreview != other.commandPreview) return false
        if (ttyPresent != other.ttyPresent) return false

        return true
    }

    override fun hashCode(): Int {
        var result = requestId.hashCode()
        result = 31 * result + deviceId.hashCode()
        result = 31 * result + deviceName.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + hostname.hashCode()
        result = 31 * result + challenge.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + transportType.hashCode()
        result = 31 * result + pamService.hashCode()
        result = 31 * result + processName.hashCode()
        result = 31 * result + commandPreview.hashCode()
        result = 31 * result + ttyPresent.hashCode()
        return result
    }
}

enum class TransportType(val displayName: String) {
    UDP("Local Network"),
    BLE("Bluetooth"),
}
