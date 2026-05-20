package dev.rourunisen.tapauth.crypto

/**
 * JNI bridge to the TapAuth shared Rust library Provides cryptographic operations via native code
 */
object TapAuthCrypto {

    init {
        try {
            System.loadLibrary("shared")
        } catch (e: UnsatisfiedLinkError) {
            // Library not found - will fail at runtime if methods are called
            // This is expected during development before the native library is built
            e.printStackTrace()
        }
    }

    /**
     * Generate a new Ed25519 keypair
     *
     * @return Array of [privateKey: ByteArray, publicKey: ByteArray]
     */
    external fun generateKeypair(): Array<ByteArray>

    /**
     * Generate a new X25519 keypair (for key exchange)
     *
     * @return Array of [privateKey: ByteArray, publicKey: ByteArray]
     */
    external fun generateX25519Keypair(): Array<ByteArray>

    /**
     * Perform X25519 key exchange
     *
     * @param ourPrivateKey Our X25519 private key (32 bytes)
     * @param theirPublicKey Their X25519 public key (32 bytes)
     * @return PSK derived from shared secret (32 bytes)
     */
    external fun keyExchange(ourPrivateKey: ByteArray, theirPublicKey: ByteArray): ByteArray

    /**
     * Generate Short Authentication String (SAS) from shared secret
     *
     * @param psk Pre-shared key / shared secret (32 bytes)
     * @return 6-digit SAS string
     */
    external fun getSas(psk: ByteArray, clientPublic: ByteArray, serverPublic: ByteArray): String

    /**
     * Decrypt data with PSK (used during pairing)
     *
     * @param psk Pairing Symmetric Key (32 bytes)
     * @param ciphertext Encrypted data
     * @return Decrypted plaintext
     */
    external fun decryptWithPsk(psk: ByteArray, ciphertext: ByteArray): ByteArray

    /**
     * Encrypt data with PSK (used during pairing)
     *
     * @param psk Pairing Symmetric Key (32 bytes)
     * @param plaintext Data to encrypt
     * @return Encrypted ciphertext
     */
    external fun encryptWithPsk(psk: ByteArray, plaintext: ByteArray): ByteArray

    /**
     * Compute SHA-256 hash
     *
     * @param data Data to hash
     * @return Hex-encoded hash
     */
    external fun sha256(data: ByteArray): String

    /**
     * Parse AuthenticationRequest from WrapperMessage protobuf bytes.
     *
     * Extracts the request payload and copies signature_algorithm/signature from the WrapperMessage
     * into the returned data class for compatibility.
     *
     * @param requestBytes Protobuf-encoded WrapperMessage containing AuthRequest
     * @return AuthRequest object with request contents and wrapper signature
     */
    external fun parseAuthRequest(requestBytes: ByteArray): AuthRequest

    /**
     * Verify Ed25519 signature
     *
     * @param publicKey Signer's public key (32 bytes)
     * @param message The message that was signed
     * @param signature The signature to verify (64 bytes)
     * @return true if signature is valid
     */
    external fun verifySignature(
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean

    /**
     * Sign data with Ed25519 private key
     *
     * @param privateKey Private key (32 bytes)
     * @param message Data to sign
     * @return Signature bytes (64 bytes)
     */
    external fun signData(privateKey: ByteArray, message: ByteArray): ByteArray

    /**
     * Serialize an AuthenticationRequest as a WrapperMessage for signature verification.
     *
     * Creates a WrapperMessage with the request payload and empty signature field. Used to
     * reconstruct the exact bytes that were signed by the client.
     *
     * @param challenge 32-byte authentication challenge
     * @param username Username requesting authentication
     * @param hostname Hostname where authentication is requested
     * @param timestampUnixSeconds Unix timestamp when request was created
     * @param signatureAlgorithm Signature algorithm (e.g., Ed25519 = 1)
     * @return Serialized WrapperMessage protobuf bytes
     */
    external fun serializeAuthRequestForVerification(
        challenge: ByteArray,
        username: String,
        hostname: String,
        timestampUnixSeconds: Long,
        signatureAlgorithm: Int,
    ): ByteArray

    /**
     * Parse GrantConfirmation from WrapperMessage protobuf bytes.
     *
     * Extracts the confirmation payload and copies signature_algorithm/signature from the
     * WrapperMessage into the returned data class for compatibility.
     *
     * @param confirmationBytes Protobuf-encoded WrapperMessage containing GrantConfirmation
     * @return GrantConfirmation object with confirmation contents and wrapper signature
     */
    external fun parseGrantConfirmation(confirmationBytes: ByteArray): GrantConfirmation

    /**
     * Parse AuthenticationCancel from WrapperMessage protobuf bytes.
     *
     * Extracts the cancel payload and copies signature_algorithm/signature from the WrapperMessage
     * into the returned data class for compatibility.
     *
     * @param cancelBytes Protobuf-encoded WrapperMessage containing AuthenticationCancel
     * @return AuthenticationCancel object with cancel contents and wrapper signature
     */
    external fun parseAuthenticationCancel(cancelBytes: ByteArray): AuthenticationCancel

    /**
     * Parse EncryptedPacket structure from protobuf bytes (without decryption)
     *
     * @param packetBytes Protobuf-encoded EncryptedPacket
     * @return EncryptedPacketInfo object with packet structure (temporal_identifier,
     *   encryption_algorithm, ciphertext)
     */
    external fun parseEncryptedPacketStructure(packetBytes: ByteArray): EncryptedPacketInfo

    /**
     * Extract temporal_identifier from EncryptedPacket protobuf bytes.
     *
     * This is used for DoS mitigation: allows checking the temporal_identifier before performing
     * expensive decryption operations.
     *
     * @param packetBytes Serialized EncryptedPacket protobuf
     * @return 16-byte temporal_identifier
     * @throws IOException if the packet cannot be parsed
     */
    external fun extractTemporalIdentifier(packetBytes: ByteArray): ByteArray

    /**
     * Determine the message type from a WrapperMessage protobuf.
     *
     * Returns a string indicating which oneof payload field is set.
     *
     * @param wrapperMessageBytes Serialized WrapperMessage protobuf
     * @return "AUTH_REQUEST", "AUTH_GRANT", "AUTH_DENIAL", "GRANT_CONFIRMATION", "AUTH_CANCEL", or
     *   "UNKNOWN"
     * @throws IOException if the message cannot be parsed
     */
    external fun determineMessageType(wrapperMessageBytes: ByteArray): String

    /**
     * Create a signed WrapperMessage containing an AuthenticationGrant.
     *
     * This is the recommended way to create grant responses. The function:
     * 1. Creates AuthenticationGrant with signed_challenge
     * 2. Wraps it in WrapperMessage
     * 3. Signs the entire wrapper with the private key
     *
     * @param signedChallenge The signed challenge bytes
     * @param privateKey Ed25519 private key (32 bytes) for signing the wrapper
     * @return Serialized WrapperMessage protobuf bytes (signed)
     */
    external fun createGrantWrapperMessage(
        signedChallenge: ByteArray,
        privateKey: ByteArray,
    ): ByteArray

    /**
     * Create a signed WrapperMessage containing an AuthenticationDenial.
     *
     * This is the recommended way to create denial responses. The function:
     * 1. Creates AuthenticationDenial with challenge
     * 2. Wraps it in WrapperMessage
     * 3. Signs the entire wrapper with the private key
     *
     * @param challenge The challenge bytes (32 bytes) from the request
     * @param privateKey Ed25519 private key (32 bytes) for signing the wrapper
     * @return Serialized WrapperMessage protobuf bytes (signed)
     */
    external fun createDenialWrapperMessage(challenge: ByteArray, privateKey: ByteArray): ByteArray

    /**
     * Create an EncryptedPacket from a WrapperMessage payload
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param wrapperMessageBytes Serialized WrapperMessage protobuf
     * @return Serialized EncryptedPacket protobuf bytes
     */
    external fun createEncryptedPacket(csk: ByteArray, wrapperMessageBytes: ByteArray): ByteArray

    /**
     * Decrypt an EncryptedPacket to get the WrapperMessage
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param encryptedPacketBytes Serialized EncryptedPacket protobuf
     * @return Serialized WrapperMessage protobuf bytes
     */
    external fun decryptEncryptedPacket(csk: ByteArray, encryptedPacketBytes: ByteArray): ByteArray

    /**
     * Generate temporal identifier for a given timestamp
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param timestampSeconds Unix timestamp in seconds
     * @return Temporal ID as byte array (16 bytes for UDP)
     */
    external fun generateTemporalId(csk: ByteArray, timestampSeconds: Long): ByteArray

    /**
     * Generate temporal identifier for BLE (10 bytes) for matching advertisements
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param timestampSeconds Unix timestamp in seconds
     * @return Temporal ID as byte array (10 bytes for BLE)
     */
    external fun generateTemporalIdBle(csk: ByteArray, timestampSeconds: Long): ByteArray

    /**
     * Verify temporal identifier matches current or previous time window
     *
     * @param id Temporal ID to verify (10 or 16 bytes)
     * @param csk Client Symmetric Key (32 bytes)
     * @return true if ID is valid
     */
    external fun verifyTemporalId(id: ByteArray, csk: ByteArray): Boolean

    /**
     * Encrypt data with CSK using challenge-derived nonce
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param challenge Challenge bytes (32 bytes)
     * @param context Context string for nonce derivation
     * @param plaintext Data to encrypt
     * @return Encrypted data
     */
    external fun encryptWithCsk(
        csk: ByteArray,
        challenge: ByteArray,
        context: String,
        plaintext: ByteArray,
    ): ByteArray

    /**
     * Decrypt data with CSK using challenge-derived nonce
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param challenge Challenge bytes (32 bytes)
     * @param context Context string for nonce derivation
     * @param ciphertext Data to decrypt
     * @return Decrypted data
     */
    external fun decryptWithCsk(
        csk: ByteArray,
        challenge: ByteArray,
        context: String,
        ciphertext: ByteArray,
    ): ByteArray

    // ========== Pairing Protocol Messages ==========

    /**
     * Create a PairingHello message (protobuf)
     *
     * @param version Protocol version (usually 1)
     * @param x25519PublicKey X25519 ephemeral public key (32 bytes)
     * @param ed25519PublicKey Ed25519 identity public key (32 bytes)
     * @param deviceName Server's device name for display purposes
     * @return Protobuf-encoded PairingHello bytes
     */
    external fun createPairingHello(
        version: Int,
        x25519PublicKey: ByteArray,
        ed25519PublicKey: ByteArray,
        deviceName: String,
    ): ByteArray

    /**
     * Parse a PairingResponse message (protobuf)
     *
     * @param responseBytes Protobuf-encoded PairingResponse
     * @return PairingResponse object with version, x25519_public_key, ed25519_public_key, and
     *   device_name
     */
    external fun parsePairingResponse(responseBytes: ByteArray): PairingResponse

    /**
     * Create a PairingCskMessage (protobuf) Note: Not used by Android server (only by clients),
     * kept for API completeness
     *
     * @param encryptedCsk CSK encrypted with PSK
     * @param username Username of the user pairing
     * @return Protobuf-encoded PairingCskMessage bytes
     */
    external fun createPairingCskMessage(encryptedCsk: ByteArray, username: String): ByteArray

    /**
     * Parse a PairingCskMessage (protobuf)
     *
     * @param messageBytes Protobuf-encoded PairingCskMessage
     * @return Array of [ByteArray (encrypted CSK), String (username)]
     */
    external fun parsePairingCskMessage(messageBytes: ByteArray): Array<Any>

    /**
     * Create a PairingComplete protobuf message.
     *
     * @param success Whether pairing was successful
     * @param hashAlgorithm Hash algorithm used for CSK hash (e.g., SHA256 = 1)
     * @param encryptedCskHash CSK hash encrypted with PSK
     * @return Protobuf-encoded PairingComplete bytes
     */
    external fun createPairingComplete(
        success: Boolean,
        hashAlgorithm: Int,
        encryptedCskHash: ByteArray,
    ): ByteArray

    /**
     * Parse a PairingComplete message (protobuf)
     *
     * @param completeBytes Protobuf-encoded PairingComplete
     * @return PairingComplete object with success, hashAlgorithm, and encryptedCskHash
     */
    external fun parsePairingComplete(completeBytes: ByteArray): PairingComplete
}

/** Kotlin wrapper for Ed25519 keypair */
data class Ed25519Keypair(val privateKey: ByteArray, val publicKey: ByteArray) {
    companion object {
        fun generate(): Ed25519Keypair {
            val result = TapAuthCrypto.generateKeypair()
            return Ed25519Keypair(privateKey = result[0], publicKey = result[1])
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Ed25519Keypair

        if (!privateKey.contentEquals(other.privateKey)) return false
        if (!publicKey.contentEquals(other.publicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}

/** X25519 keypair for ECDH key exchange */
data class X25519Keypair(val privateKey: ByteArray, val publicKey: ByteArray) {
    companion object {
        fun generate(): X25519Keypair {
            val result = TapAuthCrypto.generateX25519Keypair()
            return X25519Keypair(privateKey = result[0], publicKey = result[1])
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as X25519Keypair

        if (!privateKey.contentEquals(other.privateKey)) return false
        if (!publicKey.contentEquals(other.publicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}

/** Simple Quadruple data class to hold 4 values */
data class Quadruple<out A, out B, out C, out D>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D,
)

/** Perform X25519 Diffie-Hellman key exchange */
fun performKeyExchange(ourPrivateKey: ByteArray, theirPublicKey: ByteArray): ByteArray {
    android.util.Log.d("TapAuthCrypto", "[KOTLIN] Calling JNI keyExchange")
    android.util.Log.d("TapAuthCrypto", "[KOTLIN] Our private key: ${bytesToHex(ourPrivateKey)}")
    android.util.Log.d("TapAuthCrypto", "[KOTLIN] Their public key: ${bytesToHex(theirPublicKey)}")

    val psk = TapAuthCrypto.keyExchange(ourPrivateKey, theirPublicKey)

    android.util.Log.d(
        "TapAuthCrypto",
        "[KOTLIN] JNI returned (${psk.size} bytes): ${bytesToHex(psk)}",
    )
    return psk
}

/** Generate 6-digit Short Authentication String */
fun generateSAS(sharedSecret: ByteArray, clientPublic: ByteArray, serverPublic: ByteArray): String {
    return TapAuthCrypto.getSas(sharedSecret, clientPublic, serverPublic)
}

/** Decrypt data with PSK */
fun decryptWithPsk(psk: ByteArray, ciphertext: ByteArray): ByteArray {
    return TapAuthCrypto.decryptWithPsk(psk, ciphertext)
}

/** Encrypt data with PSK */
fun encryptWithPsk(psk: ByteArray, plaintext: ByteArray): ByteArray {
    return TapAuthCrypto.encryptWithPsk(psk, plaintext)
}

/** Compute SHA-256 hash and return as hex string */
fun sha256(data: ByteArray): String {
    return TapAuthCrypto.sha256(data)
}

/** Verify Ed25519 signature */
fun verifySignature(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    return TapAuthCrypto.verifySignature(publicKey, message, signature)
}

/** Sign data with Ed25519 private key */
fun signData(privateKey: ByteArray, message: ByteArray): ByteArray {
    return TapAuthCrypto.signData(privateKey, message)
}

/** Serialize an AuthenticationRequest for signature verification */
fun serializeAuthRequestForVerification(
    challenge: ByteArray,
    username: String,
    hostname: String,
    timestampUnixSeconds: Long,
    signatureAlgorithm: Int,
): ByteArray {
    return TapAuthCrypto.serializeAuthRequestForVerification(
        challenge,
        username,
        hostname,
        timestampUnixSeconds,
        signatureAlgorithm,
    )
}

/**
 * Generate temporal identifier for current time
 *
 * @return Temporal ID as byte array (16 bytes)
 */
fun generateTemporalId(csk: ByteArray): ByteArray {
    val timestampSeconds = System.currentTimeMillis() / 1000
    return TapAuthCrypto.generateTemporalId(csk, timestampSeconds)
}

/**
 * Generate temporal identifier for specific timestamp
 *
 * @return Temporal ID as byte array (16 bytes)
 */
fun generateTemporalId(csk: ByteArray, timestampSeconds: Long): ByteArray {
    return TapAuthCrypto.generateTemporalId(csk, timestampSeconds)
}

/**
 * Generate BLE temporal identifier (10 bytes) for current time
 *
 * @return Temporal ID as byte array (10 bytes)
 */
fun generateTemporalIdBle(csk: ByteArray): ByteArray {
    val timestampSeconds = System.currentTimeMillis() / 1000
    return TapAuthCrypto.generateTemporalIdBle(csk, timestampSeconds)
}

/**
 * Generate BLE temporal identifier (10 bytes) for specific timestamp
 *
 * @return Temporal ID as byte array (10 bytes)
 */
fun generateTemporalIdBle(csk: ByteArray, timestampSeconds: Long): ByteArray {
    return TapAuthCrypto.generateTemporalIdBle(csk, timestampSeconds)
}

/** Verify temporal identifier */
fun verifyTemporalId(id: ByteArray, csk: ByteArray): Boolean {
    return TapAuthCrypto.verifyTemporalId(id, csk)
}

/** Encrypt data with CSK */
fun encryptWithCsk(
    csk: ByteArray,
    challenge: ByteArray,
    context: String,
    plaintext: ByteArray,
): ByteArray {
    return TapAuthCrypto.encryptWithCsk(csk, challenge, context, plaintext)
}

/** Decrypt data with CSK */
fun decryptWithCsk(
    csk: ByteArray,
    challenge: ByteArray,
    context: String,
    ciphertext: ByteArray,
): ByteArray {
    return TapAuthCrypto.decryptWithCsk(csk, challenge, context, ciphertext)
}

/** Create a WrapperMessage containing an AuthenticationGrant */
fun createGrantWrapperMessage(signedChallenge: ByteArray, privateKey: ByteArray): ByteArray {
    return TapAuthCrypto.createGrantWrapperMessage(signedChallenge, privateKey)
}

/** Create a WrapperMessage containing an AuthenticationDenial */
fun createDenialWrapperMessage(challenge: ByteArray, privateKey: ByteArray): ByteArray {
    return TapAuthCrypto.createDenialWrapperMessage(challenge, privateKey)
}

/** Create an EncryptedPacket from a WrapperMessage */
fun createEncryptedPacket(csk: ByteArray, wrapperMessage: ByteArray): ByteArray {
    return TapAuthCrypto.createEncryptedPacket(csk, wrapperMessage)
}

/** Decrypt an EncryptedPacket to get the WrapperMessage */
fun decryptEncryptedPacket(csk: ByteArray, encryptedPacket: ByteArray): ByteArray {
    return TapAuthCrypto.decryptEncryptedPacket(csk, encryptedPacket)
}

// ========== Pairing Protocol Wrapper Functions ==========

/** Create a PairingHello message */
fun createPairingHello(
    version: Int,
    x25519PublicKey: ByteArray,
    ed25519PublicKey: ByteArray,
    deviceName: String,
): ByteArray {
    return TapAuthCrypto.createPairingHello(version, x25519PublicKey, ed25519PublicKey, deviceName)
}

/**
 * Parse a PairingResponse message and extract keys
 *
 * @return Quadruple of (version, x25519PublicKey, ed25519PublicKey, deviceName)
 */
fun parsePairingResponse(responseBytes: ByteArray): Quadruple<Int, ByteArray, ByteArray, String> {
    val response = TapAuthCrypto.parsePairingResponse(responseBytes)
    return Quadruple(
        response.version,
        response.x25519PublicKey,
        response.ed25519PublicKey,
        response.deviceName,
    )
}

/** Create a PairingCskMessage Note: Not used by Android server, kept for API completeness */
fun createPairingCskMessage(encryptedCsk: ByteArray, username: String): ByteArray {
    return TapAuthCrypto.createPairingCskMessage(encryptedCsk, username)
}

/**
 * Parse a PairingCskMessage and extract encrypted CSK and username
 *
 * @return Pair of (encrypted CSK bytes, username)
 */
fun parsePairingCskMessage(messageBytes: ByteArray): Pair<ByteArray, String> {
    val result = TapAuthCrypto.parsePairingCskMessage(messageBytes)
    return Pair(result[0] as ByteArray, result[1] as String)
}

/** Create a PairingComplete message */
fun createPairingComplete(
    success: Boolean,
    hashAlgorithm: Int,
    encryptedCskHash: ByteArray,
): ByteArray {
    return TapAuthCrypto.createPairingComplete(success, hashAlgorithm, encryptedCskHash)
}

/**
 * Parse a PairingComplete message
 *
 * @return PairingComplete object with success, hashAlgorithm, and encryptedCskHash
 */
fun parsePairingComplete(completeBytes: ByteArray): PairingComplete {
    return TapAuthCrypto.parsePairingComplete(completeBytes)
}

private fun hexToBytes(hex: String): ByteArray {
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

private fun bytesToHex(bytes: ByteArray): String {
    return bytes.joinToString("") { "%02x".format(it) }
}
