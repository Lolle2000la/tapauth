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
 * @property pamService PAM service name (e.g. "sudo"); empty when the Client did not send it
 * @property processName Calling process name; empty when the Client did not send it
 * @property commandPreview Sanitized command line preview; empty when the Client did not send it
 * @property ttyPresent Whether the caller had a controlling terminal
 */
data class AuthRequest(
    val challenge: ByteArray,
    val username: String,
    val hostname: String,
    val timestampUnixSeconds: Long,
    val signatureAlgorithm: Int,
    val signature: ByteArray,
    val pamService: String = "",
    val processName: String = "",
    val commandPreview: String = "",
    val ttyPresent: Boolean = false,
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
        if (pamService != other.pamService) return false
        if (processName != other.processName) return false
        if (commandPreview != other.commandPreview) return false
        if (ttyPresent != other.ttyPresent) return false

        return true
    }

    override fun hashCode(): Int {
        var result = challenge.contentHashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + hostname.hashCode()
        result = 31 * result + timestampUnixSeconds.hashCode()
        result = 31 * result + signatureAlgorithm
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + pamService.hashCode()
        result = 31 * result + processName.hashCode()
        result = 31 * result + commandPreview.hashCode()
        result = 31 * result + ttyPresent.hashCode()
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
