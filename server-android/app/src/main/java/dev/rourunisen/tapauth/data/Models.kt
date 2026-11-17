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
         * Longest accepted URL, in UTF-8 bytes, mirroring `MAX_PAIRING_URL_LEN` in
         * `shared/src/models.rs`. Measured in bytes rather than in `String.length` because that is
         * what Rust's `url.len()` counts, so a multi-byte character cannot sit inside the cap on
         * one side of the wire and outside it on the other.
         */
        private const val MAX_URL_LENGTH = 512

        /**
         * Parse a scanned URL, returning null for anything that is not a well-formed v2 pairing URL
         * (wrong scheme, an over-long URL, `v != 2`, a malformed or repeated query key, a malformed
         * `sid`/`pk`, an all-zero `pk`, or an out-of-range `p`).
         *
         * The mirror of `PairingInfo::parse` in `shared/src/models.rs`; the two are pinned together
         * by `shared/testdata/pairing_url_vectors.json`, which both suites read.
         */
        fun parse(url: String): PairingUrl? {
            if (url.toByteArray(Charsets.UTF_8).size > MAX_URL_LENGTH) return null
            if (!url.startsWith(PREFIX)) return null

            val params = LinkedHashMap<String, String>()
            for (pair in url.substringAfter('?').split('&')) {
                // Every pair is `key=value`. An empty pair (a trailing `&`) has no `=`, and a
                // value that carries a second `=` is malformed: `=` has to be percent-encoded.
                val separator = pair.indexOf('=')
                if (separator < 0) return null
                val rawValue = pair.substring(separator + 1)
                if (rawValue.contains('=')) return null
                val key = percentDecode(pair.substring(0, separator)) ?: return null
                val value = percentDecode(rawValue) ?: return null
                // At most one of each key, known or not. `PairingInfo::parse` refuses a repeated
                // key rather than picking a first or a last value, so picking one here would let
                // one sticker pin a different `pk` on the phone than on the desktop.
                if (params.containsKey(key)) return null
                params[key] = value
            }

            val version = params["v"]?.let { asciiToInt(it) } ?: return null
            if (version != REQUIRED_VERSION) return null

            val sessionId = params["sid"] ?: return null
            if (!isHex(sessionId, SESSION_ID_HEX_LENGTH)) return null

            val publicKey = params["pk"] ?: return null
            if (!isHex(publicKey, PUBLIC_KEY_HEX_LENGTH)) return null
            // Rust rejects this value too (`validate_public_key` in `shared/src/models.rs`): an
            // all-zero `pk` is the "skip the QR comparison" sentinel `pairingVerifyResponse`
            // understands, so a scanned QR must not be able to request it, and no Client
            // publishes a zero ephemeral key.
            if (publicKey.all { it == '0' }) return null

            val port =
                if (params.containsKey("p")) {
                    val parsedPort = params["p"]?.let { asciiToInt(it) } ?: return null
                    if (parsedPort !in MIN_PORT..MAX_PORT) return null
                    parsedPort
                } else {
                    null
                }

            // An empty `ip4`/`ip6` is malformed, not absent: `PairingInfo::parse` cannot parse
            // an empty address, so accepting one would be a QR that is valid only here.
            val ipv4 = params["ip4"]
            if (ipv4 != null && ipv4.isEmpty()) return null
            val ipv6 = params["ip6"]
            if (ipv6 != null && ipv6.isEmpty()) return null

            return PairingUrl(
                version = version,
                sessionId = sessionId,
                publicKey = publicKey,
                port = port,
                ipv4 = ipv4,
                ipv6 = ipv6,
            )
        }

        /**
         * Parse a decimal number written only in ASCII digits.
         *
         * `toIntOrNull` goes through `Integer.parseInt`, which accepts any Unicode digit (`٤٢` is
         * 42 to it) while Rust's `parse` refuses them, so the character set has to be checked here
         * for the two sides to accept the same ports and versions.
         */
        private fun asciiToInt(value: String): Int? {
            if (value.isEmpty()) return null
            if (!value.all { it in '0'..'9' }) return null
            return value.toIntOrNull()
        }

        /**
         * Whether [value] is exactly [length] ASCII hex digits.
         *
         * ASCII only: `digitToIntOrNull(16)` accepts every Unicode digit (`０` is 0 to it) while
         * `toInt(16)` in [hexToBytes] refuses them, so the non-ASCII form used to reach an
         * exception instead of a clean rejection — and disagreed with `is_ascii_hexdigit`.
         */
        private fun isHex(value: String, length: Int): Boolean {
            if (value.length != length) return false
            return value.all { asciiHexDigit(it) != null }
        }

        /** The value of one ASCII hex digit, or null for anything else. */
        private fun asciiHexDigit(char: Char): Int? =
            when (char) {
                in '0'..'9' -> char - '0'
                in 'a'..'f' -> char - 'a' + 10
                in 'A'..'F' -> char - 'A' + 10
                else -> null
            }

        /**
         * Decode `%XX` escapes, returning null for anything malformed or non-ASCII.
         *
         * The same rules as `percent_decode` in `shared/src/models.rs`, applied to keys as well as
         * values: a `%` that does not introduce two ASCII hex digits, and an escape whose byte is
         * not ASCII, make the URL invalid. Passing a broken escape through as a literal `%` (the
         * old behaviour) or decoding `%FF` to `ÿ` is exactly how this parser and the Rust one came
         * to disagree about which QRs are valid. A `+` is left alone because no field of the URL
         * uses it as a space.
         */
        private fun percentDecode(value: String): String? {
            if ('%' !in value) return value
            val out = StringBuilder(value.length)
            var i = 0
            while (i < value.length) {
                if (value[i] != '%') {
                    out.append(value[i])
                    i++
                    continue
                }
                if (i + 2 >= value.length) return null
                val high = asciiHexDigit(value[i + 1]) ?: return null
                val low = asciiHexDigit(value[i + 2]) ?: return null
                val decoded = high * 16 + low
                // Every field of this grammar is ASCII, so a byte >= 0x80 cannot belong to a
                // valid value and there is no UTF-8 question to answer.
                if (decoded >= 0x80) return null
                out.append(decoded.toChar())
                i += 3
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
