package dev.rourunisen.tapauth.data

/**
 * Represents a pairing URL scanned from QR code
 * Format: tapauth://pair?v=1&pk={hex}&p={port}&ip4={ipv4}&ip6={ipv6}
 */
data class PairingUrl(
    val version: Int,
    val publicKey: String, // hex encoded
    val port: Int,
    val ipv4: String?,
    val ipv6: String?
) {
    companion object {
        fun parse(url: String): PairingUrl? {
            if (!url.startsWith("tapauth://pair?")) return null
            
            val params = url.substringAfter("?")
                .split("&")
                .associate {
                    val (key, value) = it.split("=", limit = 2)
                    key to value
                }
            
            val version = params["v"]?.toIntOrNull() ?: return null
            val publicKey = params["pk"] ?: return null
            val port = params["p"]?.toIntOrNull() ?: return null
            val ipv4 = params["ip4"]
            val ipv6 = params["ip6"]
            
            return PairingUrl(version, publicKey, port, ipv4, ipv6)
        }
    }
}

/**
 * Represents a paired client device (desktop)
 * 
 * Each client generates ONE CSK (Client Symmetric Key) that it shares with all its paired servers.
 * During pairing, the client sends its CSK encrypted with the temporary PSK.
 * This CSK is then used for all future authenticated communication.
 */
data class PairedDevice(
    val deviceId: String,
    val publicKey: ByteArray,  // Client's Ed25519 public key from QR code
    val csk: ByteArray,         // Client Symmetric Key (32 bytes) - received during pairing
    val displayName: String,
    val pairedAt: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as PairedDevice
        
        if (deviceId != other.deviceId) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!csk.contentEquals(other.csk)) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = deviceId.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + csk.contentHashCode()
        return result
    }
}

/**
 * Authentication request from a device
 */
data class AuthRequest(
    val deviceId: String,
    val timestamp: Long,
    val challenge: ByteArray
)
