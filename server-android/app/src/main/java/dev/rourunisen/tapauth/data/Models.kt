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

        /** The largest value of one IPv4 octet, and the range one octet spans. */
        private const val OCTET_MAX = 0xff
        private const val OCTET_RANGE = 0x100

        /** The eight 16-bit groups of an IPv6 address. */
        private const val IPV6_GROUP_COUNT = 8

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

            // `ip4`/`ip6` must be the IP literals `PairingInfo::parse` reads them as: it hands
            // each value to `std::net::Ipv4Addr`/`Ipv6Addr`, which accept exactly one textual
            // grammar and refuse a hostname, a zone id (`fe80::1%eth0`) and a bracketed form
            // (`[::1]`). An empty value fails the same parse, so it cannot stand for an absent
            // address. The value kept is the canonical text Rust's `Display` renders, because the
            // two sides must agree on the address, not only on the verdict.
            val ipv4 = params["ip4"]?.let { canonicalIpv4(it) ?: return null }
            val ipv6 = params["ip6"]?.let { canonicalIpv6(it) ?: return null }

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

        /**
         * The canonical text of [value] read as an IPv4 literal, or null for anything
         * `std::net::Ipv4Addr` refuses.
         *
         * One grammar: four decimal octets in `0..=255` separated by `.`, nothing else — no
         * hostname, no bare `1.2.3`, no surrounding whitespace. A multi-digit octet with a leading
         * zero (`01`) is refused too, because Rust refuses it, so `01.2.3.4` is not an IPv4 literal
         * on either side.
         */
        private fun canonicalIpv4(value: String): String? {
            val octets = readIpv4Octets(value) ?: return null
            return octets.joinToString(".")
        }

        /** The four octets of [value] as an IPv4 literal, or null if it is not one. */
        private fun readIpv4Octets(value: String): List<Int>? {
            val parts = value.split('.')
            if (parts.size != 4) return null
            val octets = ArrayList<Int>(4)
            for (part in parts) {
                if (part.isEmpty()) return null
                if (!part.all { it in '0'..'9' }) return null
                if (part.length > 1 && part[0] == '0') return null
                val octet = part.toIntOrNull() ?: return null
                if (octet > OCTET_MAX) return null
                octets.add(octet)
            }
            return octets
        }

        /**
         * The canonical text of [value] read as an IPv6 literal, or null for anything
         * `std::net::Ipv6Addr` refuses.
         *
         * The accepted grammar is Rust's: eight 16-bit groups of one to four hex digits, at most
         * one `::` standing for one or more zero groups, and — only as the final component — an
         * IPv4 dotted quad filling the last two groups. A zone id (`fe80::1%eth0`), a bracketed
         * form (`[::1]`) and a bare hostname are all outside that grammar. The text rendered is
         * `Display`'s: lower case, no leading zeros, the longest run of two or more zero groups
         * compressed (the leftmost on a tie), and the IPv4-mapped form written with dotted octets —
         * so `2001:0db8:0000:0000:0000:0000:0000:0001` and `2001:db8::1` yield one value.
         */
        private fun canonicalIpv6(value: String): String? {
            val groups = readIpv6Groups(value) ?: return null
            return formatIpv6(groups)
        }

        /**
         * Read [value] into the eight 16-bit groups of an IPv6 address, or null if it is not one.
         *
         * The two sides of the single `::` — and, without one, the whole address — are read as
         * colon-separated components, each one to four hex digits, whose last may be an IPv4 tail.
         * A second `::`, an empty component and a dotted quad that is not the final component are
         * refused, and `::` must stand for at least one zero group, so `1::2:3:4:5:6:7:8` and
         * `1:2:3:4:5:6:7:8::` are both outside the grammar.
         */
        private fun readIpv6Groups(value: String): IntArray? {
            if (value.isEmpty()) return null
            val ellipsis = value.indexOf("::")
            if (ellipsis >= 0 && value.indexOf("::", ellipsis + 1) >= 0) return null

            val head: List<Int>
            val tail: List<Int>
            if (ellipsis < 0) {
                head = readIpv6Side(value, allowIpv4Tail = true) ?: return null
                tail = emptyList()
                if (head.size != IPV6_GROUP_COUNT) return null
            } else {
                head =
                    readIpv6Side(value.substring(0, ellipsis), allowIpv4Tail = false) ?: return null
                tail =
                    readIpv6Side(value.substring(ellipsis + 2), allowIpv4Tail = true) ?: return null
                if (head.size + tail.size >= IPV6_GROUP_COUNT) return null
            }

            val groups = IntArray(IPV6_GROUP_COUNT)
            for (index in head.indices) groups[index] = head[index]
            for (index in tail.indices) groups[IPV6_GROUP_COUNT - tail.size + index] = tail[index]
            return groups
        }

        /**
         * The groups written on one side of the `::` (or the whole address), in order.
         *
         * [allowIpv4Tail] admits an IPv4 dotted quad as the last component, which fills the last
         * two groups; the side before a `::` never has one, as Rust rejects `1.2.3.4::`.
         */
        private fun readIpv6Side(text: String, allowIpv4Tail: Boolean): List<Int>? {
            if (text.isEmpty()) return emptyList()
            val parts = text.split(':')
            val groups = ArrayList<Int>(IPV6_GROUP_COUNT)
            for (index in parts.indices) {
                val part = parts[index]
                if (allowIpv4Tail && index == parts.size - 1 && part.contains('.')) {
                    val octets = readIpv4Octets(part) ?: return null
                    groups.add(octets[0] * OCTET_RANGE + octets[1])
                    groups.add(octets[2] * OCTET_RANGE + octets[3])
                    continue
                }
                if (part.isEmpty()) return null
                if (part.length > 4) return null
                var group = 0
                for (char in part) {
                    val digit = asciiHexDigit(char) ?: return null
                    group = group * 0x10 + digit
                }
                groups.add(group)
            }
            return groups
        }

        /** Render [groups] the way `Ipv6Addr`'s `Display` does. */
        private fun formatIpv6(groups: IntArray): String {
            // An IPv4-mapped address (`::ffff:a.b.c.d`) is written with dotted octets; every
            // other address — including the deprecated IPv4-compatible form, which Rust renders
            // as hex groups — is written group by group.
            if (
                groups[0] == 0 &&
                    groups[1] == 0 &&
                    groups[2] == 0 &&
                    groups[3] == 0 &&
                    groups[4] == 0 &&
                    groups[5] == 0xffff
            ) {
                val high = groups[6]
                val low = groups[7]
                return "::ffff:${high shr 8}.${high and 0xff}.${low shr 8}.${low and 0xff}"
            }

            // The longest run of zero groups, the leftmost on a tie. A lone zero group stays
            // written out, as RFC 5952 and `Display` require.
            var longestStart = -1
            var longestLength = 1
            var runStart = -1
            for (index in 0..IPV6_GROUP_COUNT) {
                if (index < IPV6_GROUP_COUNT && groups[index] == 0) {
                    if (runStart < 0) runStart = index
                } else if (runStart >= 0) {
                    if (index - runStart > longestLength) {
                        longestLength = index - runStart
                        longestStart = runStart
                    }
                    runStart = -1
                }
            }

            if (longestStart < 0)
                return (0 until IPV6_GROUP_COUNT).joinToString(":") {
                    groups[it].toString(16)
                }
            val head = (0 until longestStart).joinToString(":") { groups[it].toString(16) }
            val end = longestStart + longestLength
            val tail = (end until IPV6_GROUP_COUNT).joinToString(":") { groups[it].toString(16) }
            return "$head::$tail"
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
 * The first [bytes] bytes of a key as lower-case hex.
 *
 * Used by [PairedDevice.toString] for the identity of a device: enough to tell two pairings apart
 * in a log line, and nothing that would print a whole key by accident.
 */
private fun ByteArray.identityHex(bytes: Int = 8): String =
    take(bytes).joinToString("") { byte ->
        ((byte.toInt() and 0xff) + 0x100).toString(16).substring(1)
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
 *
 * SECURITY: [toString] is hand-written and redacts [csk]. The compiler's derived form renders a
 * `ByteArray` field through `java.util.Arrays.toString`, so any log line, exception message or
 * `PairingUpdate.Complete` rendering would have printed the key itself as `csk=[12, 255, …]`.
 * Nothing logs this record today, which is why the leak was latent, but a `toString()` that prints
 * a key is a loaded gun: keep the override, and do not "simplify" it back to the derived one.
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

    /**
     * Identify the device without printing its secret.
     *
     * [csk] is redacted in every form a `ByteArray` is normally rendered in — the `Arrays.toString`
     * form the derived `toString()` would have used, hex and base64 — because a key that reaches a
     * log line, a crash report or a `PairingUpdate` rendering is a key that has left the process.
     * The identity comes from [deviceId] and a short prefix of [publicKey], which is public by
     * definition (it is the desktop's Ed25519 signing key).
     *
     * The remaining fields are rendered verbatim, exactly as the derived form did: they are not
     * secret, and this is the string a developer reads in logcat.
     */
    override fun toString(): String =
        "PairedDevice(deviceId=$deviceId, publicKey=${publicKey.identityHex()}, csk=<redacted>, " +
            "displayName=$displayName, pairedAt=$pairedAt, allowedUsers=$allowedUsers, " +
            "symmetricAlgorithm=$symmetricAlgorithm, hashAlgorithm=$hashAlgorithm, " +
            "signatureAlgorithm=$signatureAlgorithm, protocolVersion=$protocolVersion)"

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
