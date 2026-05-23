package dev.rourunisen.tapauth.data

/**
 * Represents a pairing URL scanned from QR code Format:
 * tapauth://pair?v=1&pk={hex}&p={port}&ip4={ipv4}&ip6={ipv6}
 */
data class PairingUrl(
    val version: Int,
    val publicKey: String, // hex encoded
    val port: Int,
    val ipv4: String?,
    val ipv6: String?,
) {
    companion object {
        fun parse(url: String): PairingUrl? {
            if (!url.startsWith("tapauth://pair?")) return null

            val params =
                url.substringAfter("?").split("&").associate {
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
 * During pairing, the client sends its CSK encrypted with the temporary PSK. This CSK is then used
 * for all future authenticated communication.
 *
 * SECURITY: The allowedUsers list controls which users can authenticate with this pairing. When a
 * user pairs their desktop, their username is added to this list. If multiple users on the same
 * desktop pair, they are all added to the list.
 */
data class PairedDevice(
    val deviceId: String,
    val publicKey: ByteArray, // Client's Ed25519 public key from QR code
    val csk: ByteArray, // Client Symmetric Key (32 bytes) - received during pairing
    val displayName: String,
    val pairedAt: Long,
    val allowedUsers: List<String> =
        emptyList(), // Username(s) this pairing can authenticate (MUST NOT be empty for security)
) {
    /**
     * Check if this pairing is allowed to authenticate the given username
     *
     * @param username The username from the authentication request
     * @return true if this pairing can authenticate the user
     *
     * SECURITY: Empty list means NO users allowed (prevents privilege escalation) The username must
     * be explicitly added during pairing.
     */
    fun isUserAllowed(username: String): Boolean {
        return allowedUsers.contains(username)
    }

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
