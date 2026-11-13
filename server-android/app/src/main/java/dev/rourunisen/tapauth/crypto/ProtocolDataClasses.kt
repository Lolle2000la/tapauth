package dev.rourunisen.tapauth.crypto

/**
 * Data transfer objects the Rust JNI layer builds with `NewObject`.
 *
 * Rust is the canonical side: it verifies the `WrapperMessage` signature and parses the inner
 * protobuf before constructing one of these, so a returned object is always signature-valid for the
 * paired Client key. Kotlin must not reorder, rename, retype or give a field a default value — the
 * shapes below are a wire contract with `shared/src/jni/objects.rs`, and `crypto/JniDescriptorTest`
 * pins the exact JVM constructor descriptors:
 *
 * - [ParsedAuthRequest]:
 *   `([BLjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V`
 * - [ParsedPairingProvision]: `([BLjava/lang/String;Ljava/lang/String;)V`
 * - [ParsedPairingResponse]: `(Ljava/lang/String;[BIII)V`
 *
 * A default value would add a synthetic constructor, and a field Kotlin declares but Rust does not
 * pass makes the JNI `NewObject` throw at runtime on the device only.
 */

/**
 * Parsed AuthenticationRequest message.
 *
 * The wrapper signature is verified inside Rust and is deliberately not returned: a
 * [ParsedAuthRequest] that exists at all is authentic for the Client key it was verified against.
 *
 * @property challenge 32-byte authentication challenge
 * @property username Username requesting authentication
 * @property hostname Hostname where authentication is requested
 * @property timestampUnixSeconds Unix timestamp when request was created
 * @property pamService PAM service name (e.g. "sudo"); empty when the Client did not send it
 * @property processName Calling process name; empty when the Client did not send it
 * @property commandPreview Sanitized command line preview; empty when the Client did not send it
 * @property ttyPresent Whether the caller had a controlling terminal
 */
data class ParsedAuthRequest(
    val challenge: ByteArray,
    val username: String,
    val hostname: String,
    val timestampUnixSeconds: Long,
    val pamService: String,
    val processName: String,
    val commandPreview: String,
    val ttyPresent: Boolean,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as ParsedAuthRequest

        if (!challenge.contentEquals(other.challenge)) return false
        if (username != other.username) return false
        if (hostname != other.hostname) return false
        if (timestampUnixSeconds != other.timestampUnixSeconds) return false
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
        result = 31 * result + pamService.hashCode()
        result = 31 * result + processName.hashCode()
        result = 31 * result + commandPreview.hashCode()
        result = 31 * result + ttyPresent.hashCode()
        return result
    }
}

/**
 * Decrypted `PairingProvisionPayload` from the desktop's `PairingConfirmClient`.
 *
 * @property csk 32-byte Client Symmetric Key the desktop provisioned; persist it as-is
 * @property username The desktop user authorizing this pairing
 * @property clientHostname The desktop's hostname (peer-supplied, sanitize before display)
 */
data class ParsedPairingProvision(
    val csk: ByteArray,
    val username: String,
    val clientHostname: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as ParsedPairingProvision

        if (!csk.contentEquals(other.csk)) return false
        if (username != other.username) return false
        if (clientHostname != other.clientHostname) return false

        return true
    }

    override fun hashCode(): Int {
        var result = csk.contentHashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + clientHostname.hashCode()
        return result
    }
}

/**
 * Verified `PairingResponse`, with the session keys already derived inside Rust.
 *
 * @property sas The short authentication string (`"123-456"`) the user compares with the desktop
 * @property clientEd25519PublicKey The Client's static Ed25519 public key, i.e. the device identity
 * @property symmetricAlgorithm The `SymmetricAlgorithm` the Client selected for the CSK
 * @property hashAlgorithm The `HashAlgorithm` the Client selected for temporal identifiers
 * @property signatureAlgorithm The `SignatureAlgorithm` the Client selected for wrapper signatures
 */
data class ParsedPairingResponse(
    val sas: String,
    val clientEd25519PublicKey: ByteArray,
    val symmetricAlgorithm: Int,
    val hashAlgorithm: Int,
    val signatureAlgorithm: Int,
) {
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (javaClass != other?.javaClass) return false

        other as ParsedPairingResponse

        if (sas != other.sas) return false
        if (!clientEd25519PublicKey.contentEquals(other.clientEd25519PublicKey)) return false
        if (symmetricAlgorithm != other.symmetricAlgorithm) return false
        if (hashAlgorithm != other.hashAlgorithm) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = sas.hashCode()
        result = 31 * result + clientEd25519PublicKey.contentHashCode()
        result = 31 * result + symmetricAlgorithm
        result = 31 * result + hashAlgorithm
        result = 31 * result + signatureAlgorithm
        return result
    }
}
