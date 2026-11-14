package dev.rourunisen.tapauth.data

/**
 * Represents a v2 pairing URL scanned from a QR code.
 *
 * Format: `tapauth://pair?v=2&sid={16B hex}&pk={32B X25519 hex}&p={port}&ip4={ipv4}&ip6={ipv6}`.
 * `p`, `ip4` and `ip6` are optional: a QR with no UDP endpoint describes a BLE-only pairing.
 */
data class PairingUrl(
    val version: Int,
    val sessionId: String, // 32 hex chars (16 bytes) from `sid`
    val publicKey: String, // 64 hex chars (32 bytes) from `pk` = client ephemeral X25519
    val port: Int?, // from `p`; null when the QR carries no UDP endpoint
    val ipv4: String?, // from `ip4`
    val ipv6: String?, // from `ip6`
) {
    /** Decode [sessionId] to the 16-byte pairing session id. */
    fun sessionIdBytes(): ByteArray = hexToBytes(sessionId)

    /** Decode [publicKey] to the 32-byte client ephemeral X25519 public key. */
    fun publicKeyBytes(): ByteArray = hexToBytes(publicKey)

    companion object {
        private const val PREFIX = "tapauth://pair?"
        private const val REQUIRED_VERSION = 2
        private const val SESSION_ID_HEX_LENGTH = 32
        private const val PUBLIC_KEY_HEX_LENGTH = 64
        private const val MIN_PORT = 1
        private const val MAX_PORT = 65535

        /**
         * Parse a scanned URL, returning null for anything that is not a well-formed v2 pairing URL
         * (wrong scheme, `v != 2`, malformed `sid`/`pk`, an all-zero `pk`, or an out-of-range `p`).
         */
        fun parse(url: String): PairingUrl? {
            if (!url.startsWith(PREFIX)) return null

            val params = LinkedHashMap<String, String>()
            for (pair in url.substringAfter('?').split('&')) {
                if (pair.isEmpty()) continue
                val key = percentDecode(pair.substringBefore('='))
                val value = percentDecode(pair.substringAfter('=', ""))
                // First occurrence wins, so a trailing duplicate cannot override `pk`.
                if (!params.containsKey(key)) params[key] = value
            }

            val version = params["v"]?.toIntOrNull() ?: return null
            if (version != REQUIRED_VERSION) return null

            val sessionId = params["sid"] ?: return null
            if (!isHex(sessionId, SESSION_ID_HEX_LENGTH)) return null

            val publicKey = params["pk"] ?: return null
            if (!isHex(publicKey, PUBLIC_KEY_HEX_LENGTH)) return null
            // Rust always compares the QR `pk` in constant time, so an all-zero value would be a
            // legitimate pin only for a peer that really published a zero ephemeral key — which no
            // Client does. Rejecting it here keeps a hostile sticker from pinning a predictable
            // key.
            if (publicKey.all { it == '0' }) return null

            val port =
                if (params.containsKey("p")) {
                    val parsedPort = params["p"]?.toIntOrNull() ?: return null
                    if (parsedPort !in MIN_PORT..MAX_PORT) return null
                    parsedPort
                } else {
                    null
                }

            return PairingUrl(
                version = version,
                sessionId = sessionId,
                publicKey = publicKey,
                port = port,
                ipv4 = params["ip4"]?.takeIf { it.isNotEmpty() },
                ipv6 = params["ip6"]?.takeIf { it.isNotEmpty() },
            )
        }

        private fun isHex(value: String, length: Int): Boolean {
            if (value.length != length) return false
            return value.all { it.digitToIntOrNull(16) != null }
        }

        /**
         * Decode `%XX` escapes. Plain string splitting keeps this usable from JVM unit tests (no
         * `android.net.Uri`), and a `+` is left alone because no field of the URL uses it as a
         * space.
         */
        private fun percentDecode(value: String): String {
            if ('%' !in value) return value
            val out = StringBuilder(value.length)
            var i = 0
            while (i < value.length) {
                if (value[i] == '%' && i + 2 < value.length) {
                    val high = value[i + 1].digitToIntOrNull(16)
                    val low = value[i + 2].digitToIntOrNull(16)
                    if (high != null && low != null) {
                        out.append((high * 16 + low).toChar())
                        i += 3
                        continue
                    }
                }
                out.append(value[i])
                i++
            }
            return out.toString()
        }
    }
}

/** Decode a hex string (already validated by [PairingUrl.parse]) to bytes. */
private fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "Hex string must have an even length" }
    return ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}

/**
 * Represents a paired client device (desktop)
 *
 * Each client generates ONE CSK (Client Symmetric Key) that it shares with all its paired servers.
 * During pairing, the client sends its CSK to the server inside the AEAD-encrypted provision
 * payload. This CSK is then used for all future authenticated communication.
 *
 * The algorithm and protocol fields record what this pairing negotiated, so every later packet is
 * encrypted, hashed and signed with the same primitives. Records migrated from v1 JSON default to
 * SHA-256/AES-256-GCM/Ed25519 with `protocolVersion = 1`.
 *
 * SECURITY: The allowedUsers list controls which users can authenticate with this pairing. When a
 * user pairs their desktop, their username is added to this list. If multiple users on the same
 * desktop pair, they are all added to the list.
 */
data class PairedDevice(
    val deviceId: String,
    val publicKey: ByteArray, // Client's Ed25519 public key (32 bytes)
    val csk: ByteArray, // Client Symmetric Key (32 bytes) - received during pairing
    val displayName: String,
    val pairedAt: Long,
    val allowedUsers: List<String> =
        emptyList(), // Username(s) this pairing can authenticate (MUST NOT be empty for security)
    val symmetricAlgorithm: Int = 1,
    val hashAlgorithm: Int = 1,
    val signatureAlgorithm: Int = 1,
    val protocolVersion: Int = 2,
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
        if (displayName != other.displayName) return false
        if (pairedAt != other.pairedAt) return false
        if (allowedUsers != other.allowedUsers) return false
        if (symmetricAlgorithm != other.symmetricAlgorithm) return false
        if (hashAlgorithm != other.hashAlgorithm) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (protocolVersion != other.protocolVersion) return false

        return true
    }

    override fun hashCode(): Int {
        var result = deviceId.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + csk.contentHashCode()
        result = 31 * result + displayName.hashCode()
        result = 31 * result + pairedAt.hashCode()
        result = 31 * result + allowedUsers.hashCode()
        result = 31 * result + symmetricAlgorithm
        result = 31 * result + hashAlgorithm
        result = 31 * result + signatureAlgorithm
        result = 31 * result + protocolVersion
        return result
    }
}
