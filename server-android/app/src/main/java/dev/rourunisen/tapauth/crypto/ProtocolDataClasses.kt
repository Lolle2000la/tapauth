package dev.rourunisen.tapauth.crypto

/**
 * Data transfer objects for TapAuth protocol messages. These classes provide type-safe access to
 * parsed protobuf data from the Rust JNI layer.
 */

/**
 * Parsed AuthenticationRequest message.
 *
 * Note: In protocol v2+, signatures are stored in WrapperMessage, not in individual messages. The
 * JNI layer extracts wrapper.signature_algorithm and wrapper.signature for compatibility.
 *
 * @property challenge 32-byte authentication challenge
 * @property username Username requesting authentication
 * @property hostname Hostname where authentication is requested
 * @property timestampUnixSeconds Unix timestamp when request was created
 * @property signatureAlgorithm Signature algorithm from WrapperMessage (e.g., Ed25519 = 1)
 * @property signature Digital signature from WrapperMessage (signs entire WrapperMessage)
 */
data class AuthRequest(
    val challenge: ByteArray,
    val username: String,
    val hostname: String,
    val timestampUnixSeconds: Long,
    val signatureAlgorithm: Int,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthRequest

        if (!challenge.contentEquals(other.challenge)) return false
        if (username != other.username) return false
        if (hostname != other.hostname) return false
        if (timestampUnixSeconds != other.timestampUnixSeconds) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = challenge.contentHashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + hostname.hashCode()
        result = 31 * result + timestampUnixSeconds.hashCode()
        result = 31 * result + signatureAlgorithm
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

/**
 * Parsed GrantConfirmation message.
 *
 * Note: In protocol v2+, signatures are stored in WrapperMessage, not in individual messages. The
 * JNI layer extracts wrapper.signature_algorithm and wrapper.signature for compatibility.
 *
 * @property challenge 32-byte challenge that was signed
 * @property signatureAlgorithm Signature algorithm from WrapperMessage
 * @property signature Digital signature from WrapperMessage (signs entire WrapperMessage)
 */
data class GrantConfirmation(
    val challenge: ByteArray,
    val signatureAlgorithm: Int,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as GrantConfirmation

        if (!challenge.contentEquals(other.challenge)) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = challenge.contentHashCode()
        result = 31 * result + signatureAlgorithm
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

/**
 * Parsed AuthenticationCancel message.
 *
 * Note: In protocol v2+, signatures are stored in WrapperMessage, not in individual messages. The
 * JNI layer extracts wrapper.signature_algorithm and wrapper.signature for compatibility.
 *
 * @property challenge 32-byte challenge of the request being cancelled
 * @property signatureAlgorithm Signature algorithm from WrapperMessage
 * @property signature Digital signature from WrapperMessage (signs entire WrapperMessage)
 */
data class AuthenticationCancel(
    val challenge: ByteArray,
    val signatureAlgorithm: Int,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticationCancel

        if (!challenge.contentEquals(other.challenge)) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = challenge.contentHashCode()
        result = 31 * result + signatureAlgorithm
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

/**
 * Parsed EncryptedPacket metadata (structure without decryption).
 *
 * @property temporalIdentifier Temporal identifier for DoS mitigation
 * @property encryptionAlgorithm Encryption algorithm used
 * @property ciphertext Encrypted payload
 */
data class EncryptedPacketInfo(
    val temporalIdentifier: ByteArray,
    val encryptionAlgorithm: Int,
    val ciphertext: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedPacketInfo

        if (!temporalIdentifier.contentEquals(other.temporalIdentifier)) return false
        if (encryptionAlgorithm != other.encryptionAlgorithm) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = temporalIdentifier.contentHashCode()
        result = 31 * result + encryptionAlgorithm
        result = 31 * result + ciphertext.contentHashCode()
        return result
    }
}

/**
 * Parsed PairingResponse message.
 *
 * @property version Protocol version
 * @property x25519PublicKey Server's X25519 public key for key exchange
 * @property ed25519PublicKey Server's Ed25519 public key for signing
 * @property deviceName Server device name
 */
data class PairingResponse(
    val version: Int,
    val x25519PublicKey: ByteArray,
    val ed25519PublicKey: ByteArray,
    val deviceName: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as PairingResponse

        if (version != other.version) return false
        if (!x25519PublicKey.contentEquals(other.x25519PublicKey)) return false
        if (!ed25519PublicKey.contentEquals(other.ed25519PublicKey)) return false
        if (deviceName != other.deviceName) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + x25519PublicKey.contentHashCode()
        result = 31 * result + ed25519PublicKey.contentHashCode()
        result = 31 * result + deviceName.hashCode()
        return result
    }
}

/**
 * Parsed PairingComplete message.
 *
 * @property success Whether pairing completed successfully
 * @property hashAlgorithm Hash algorithm used for the CSK hash
 * @property encryptedCskHash CSK SHA-256 hash encrypted with the ephemeral PSK
 */
data class PairingComplete(
    val success: Boolean,
    val hashAlgorithm: Int,
    val encryptedCskHash: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PairingComplete

        if (success != other.success) return false
        if (hashAlgorithm != other.hashAlgorithm) return false
        if (!encryptedCskHash.contentEquals(other.encryptedCskHash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = success.hashCode()
        result = 31 * result + hashAlgorithm
        result = 31 * result + encryptedCskHash.contentHashCode()
        return result
    }
}
