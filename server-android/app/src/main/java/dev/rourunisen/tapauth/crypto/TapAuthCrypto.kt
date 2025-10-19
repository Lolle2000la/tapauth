package dev.rourunisen.tapauth.crypto

/**
 * JNI bridge to the TapAuth shared Rust library
 * Provides cryptographic operations via native code
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
     * @return Keypair as "private_hex:public_hex"
     */
    external fun generateKeypair(): String
    
    /**
     * Perform X25519 key exchange
     * @param ourPrivateKeyHex Our X25519 private key (hex)
     * @param theirPublicKeyHex Their X25519 public key (hex)
     * @return Shared secret (hex)
     */
    external fun keyExchange(ourPrivateKeyHex: String, theirPublicKeyHex: String): String
    
    /**
     * Generate Short Authentication String (SAS) from shared secret
     * @param pskHex Pre-shared key / shared secret (hex)
     * @return 6-digit SAS string
     */
    external fun getSas(pskHex: String, clientPublic: ByteArray, serverPublic: ByteArray): String
    
    /**
     * Decrypt data with PSK (used during pairing)
     * @param pskHex Pairing Symmetric Key (hex)
     * @param context Context string for nonce derivation
     * @param ciphertext Encrypted data
     * @return Decrypted plaintext
     */
    external fun decryptWithPsk(pskHex: String, context: String, ciphertext: ByteArray): ByteArray
    
    /**
     * Encrypt data with PSK (used during pairing)
     * @param pskHex Pairing Symmetric Key (hex)
     * @param context Context string for nonce derivation
     * @param plaintext Data to encrypt
     * @return Encrypted ciphertext
     */
    external fun encryptWithPsk(pskHex: String, context: String, plaintext: ByteArray): ByteArray
    
    /**
     * Compute SHA-256 hash
     * @param data Data to hash
     * @return Hex-encoded hash
     */
    external fun sha256(data: ByteArray): String
    
    /**
     * Decrypt and parse an EncryptedPacket
     * @param cskHex Client Symmetric Key (hex)
     * @param packetBytes Raw packet bytes
     * @return JSON string with packet contents
     */
    external fun decryptAndParsePacket(cskHex: String, packetBytes: ByteArray): String
    
    /**
     * Parse AuthenticationRequest from protobuf bytes
     * @param requestBytes Protobuf-encoded request
     * @return JSON string with request contents
     */
    external fun parseAuthRequest(requestBytes: ByteArray): String
    
    /**
     * Create and serialize an AuthenticationGrant
     * @param signedChallenge The challenge signed by server
     * @return Protobuf-encoded grant bytes
     */
    external fun createAuthGrant(signedChallenge: ByteArray): ByteArray
    
    /**
     * Verify Ed25519 signature
     * @param publicKey Signer's public key (32 bytes)
     * @param message The message that was signed
     * @param signature The signature to verify (64 bytes)
     * @return true if signature is valid
     */
    external fun verifySignature(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
    
    /**
     * Sign data with Ed25519 private key
     * @param privateKeyHex Private key (hex)
     * @param message Data to sign
     * @return Signature bytes (64 bytes)
     */
    external fun signData(privateKeyHex: String, message: ByteArray): ByteArray
    
    /**
     * Serialize an AuthenticationRequest for signature verification
     * (with signature field empty)
     * @param requestJson JSON representation of the request
     * @return Serialized protobuf bytes
     */
    external fun serializeAuthRequestForVerification(requestJson: String): ByteArray
    
    /**
     * Parse GrantConfirmation from protobuf bytes
     * @param confirmationBytes Protobuf-encoded confirmation
     * @return JSON string with confirmation contents
     */
    external fun parseGrantConfirmation(confirmationBytes: ByteArray): String
    
    /**
     * Parse AuthenticationCancel from protobuf bytes
     * @param cancelBytes Protobuf-encoded cancel message
     * @return JSON string with cancel contents
     */
    external fun parseAuthenticationCancel(cancelBytes: ByteArray): String
    
    /**
     * Create a WrapperMessage containing an AuthenticationGrant
     * @param signedChallenge The signed challenge bytes
     * @return Serialized WrapperMessage protobuf bytes
     */
    external fun createGrantWrapperMessage(signedChallenge: ByteArray): ByteArray
    
    /**
     * Create an EncryptedPacket from a WrapperMessage payload
     * @param cskHex Client Symmetric Key (hex)
     * @param wrapperMessageBytes Serialized WrapperMessage protobuf
     * @return Serialized EncryptedPacket protobuf bytes
     */
    external fun createEncryptedPacket(cskHex: String, wrapperMessageBytes: ByteArray): ByteArray
    
    /**
     * Decrypt an EncryptedPacket to get the WrapperMessage
     * @param cskHex Client Symmetric Key (hex)
     * @param encryptedPacketBytes Serialized EncryptedPacket protobuf
     * @return Serialized WrapperMessage protobuf bytes
     */
    external fun decryptEncryptedPacket(cskHex: String, encryptedPacketBytes: ByteArray): ByteArray
    
    /**
     * Generate temporal identifier for a given timestamp
     * @param cskHex Client Symmetric Key (hex)
     * @param timestampSeconds Unix timestamp in seconds
     * @return Temporal ID as hex string (32 chars, 16 bytes)
     */
    external fun generateTemporalId(cskHex: String, timestampSeconds: Long): String
    
    /**
     * Verify temporal identifier matches current or previous time window
     * @param idHex Temporal ID to verify (hex)
     * @param cskHex Client Symmetric Key (hex)
     * @return true if ID is valid
     */
    external fun verifyTemporalId(idHex: String, cskHex: String): Boolean
    
    /**
     * Encrypt data with CSK using challenge-derived nonce
     * @param cskHex Client Symmetric Key (hex)
     * @param challenge Challenge bytes (32 bytes)
     * @param context Context string for nonce derivation
     * @param plaintext Data to encrypt
     * @return Encrypted data
     */
    external fun encryptWithCsk(cskHex: String, challenge: ByteArray, context: String, plaintext: ByteArray): ByteArray
    
    /**
     * Decrypt data with CSK using challenge-derived nonce
     * @param cskHex Client Symmetric Key (hex)
     * @param challenge Challenge bytes (32 bytes)
     * @param context Context string for nonce derivation
     * @param ciphertext Data to decrypt
     * @return Decrypted data
     */
    external fun decryptWithCsk(cskHex: String, challenge: ByteArray, context: String, ciphertext: ByteArray): ByteArray
}

/**
 * Kotlin wrapper for Ed25519 keypair
 */
data class Ed25519Keypair(
    val privateKey: ByteArray,
    val publicKey: ByteArray
) {
    companion object {
        fun generate(): Ed25519Keypair {
            val combined = TapAuthCrypto.generateKeypair()
            val parts = combined.split(":")
            return Ed25519Keypair(
                privateKey = hexToBytes(parts[0]),
                publicKey = hexToBytes(parts[1])
            )
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

/**
 * Perform X25519 Diffie-Hellman key exchange
 */
fun performKeyExchange(ourPrivateKey: ByteArray, theirPublicKey: ByteArray): ByteArray {
    val result = TapAuthCrypto.keyExchange(
        bytesToHex(ourPrivateKey),
        bytesToHex(theirPublicKey)
    )
    return hexToBytes(result)
}

/**
 * Generate 6-digit Short Authentication String
 */
fun generateSAS(sharedSecret: ByteArray, clientPublic: ByteArray, serverPublic: ByteArray): String {
    return TapAuthCrypto.getSas(bytesToHex(sharedSecret), clientPublic, serverPublic)
}

/**
 * Decrypt data with PSK
 */
fun decryptWithPsk(psk: ByteArray, context: String, ciphertext: ByteArray): ByteArray {
    return TapAuthCrypto.decryptWithPsk(bytesToHex(psk), context, ciphertext)
}

/**
 * Encrypt data with PSK
 */
fun encryptWithPsk(psk: ByteArray, context: String, plaintext: ByteArray): ByteArray {
    return TapAuthCrypto.encryptWithPsk(bytesToHex(psk), context, plaintext)
}

/**
 * Compute SHA-256 hash and return as hex string
 */
fun sha256(data: ByteArray): String {
    return TapAuthCrypto.sha256(data)
}

/**
 * Verify Ed25519 signature
 */
fun verifySignature(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    return TapAuthCrypto.verifySignature(publicKey, message, signature)
}

/**
 * Sign data with Ed25519 private key
 */
fun signData(privateKey: ByteArray, message: ByteArray): ByteArray {
    return TapAuthCrypto.signData(bytesToHex(privateKey), message)
}

/**
 * Serialize an AuthenticationRequest for signature verification
 */
fun serializeAuthRequestForVerification(requestJson: String): ByteArray {
    return TapAuthCrypto.serializeAuthRequestForVerification(requestJson)
}

/**
 * Generate temporal identifier for current time
 */
fun generateTemporalId(csk: ByteArray): String {
    val timestampSeconds = System.currentTimeMillis() / 1000
    return TapAuthCrypto.generateTemporalId(bytesToHex(csk), timestampSeconds)
}

/**
 * Generate temporal identifier for specific timestamp
 */
fun generateTemporalId(csk: ByteArray, timestampSeconds: Long): String {
    return TapAuthCrypto.generateTemporalId(bytesToHex(csk), timestampSeconds)
}

/**
 * Verify temporal identifier
 */
fun verifyTemporalId(idHex: String, csk: ByteArray): Boolean {
    return TapAuthCrypto.verifyTemporalId(idHex, bytesToHex(csk))
}

/**
 * Encrypt data with CSK
 */
fun encryptWithCsk(csk: ByteArray, challenge: ByteArray, context: String, plaintext: ByteArray): ByteArray {
    return TapAuthCrypto.encryptWithCsk(bytesToHex(csk), challenge, context, plaintext)
}

/**
 * Decrypt data with CSK
 */
fun decryptWithCsk(csk: ByteArray, challenge: ByteArray, context: String, ciphertext: ByteArray): ByteArray {
    return TapAuthCrypto.decryptWithCsk(bytesToHex(csk), challenge, context, ciphertext)
}

/**
 * Create a WrapperMessage containing an AuthenticationGrant
 */
fun createGrantWrapperMessage(signedChallenge: ByteArray): ByteArray {
    return TapAuthCrypto.createGrantWrapperMessage(signedChallenge)
}

/**
 * Create an EncryptedPacket from a WrapperMessage
 */
fun createEncryptedPacket(csk: ByteArray, wrapperMessage: ByteArray): ByteArray {
    return TapAuthCrypto.createEncryptedPacket(bytesToHex(csk), wrapperMessage)
}

/**
 * Decrypt an EncryptedPacket to get the WrapperMessage
 */
fun decryptEncryptedPacket(csk: ByteArray, encryptedPacket: ByteArray): ByteArray {
    return TapAuthCrypto.decryptEncryptedPacket(bytesToHex(csk), encryptedPacket)
}

private fun hexToBytes(hex: String): ByteArray {
    return hex.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

private fun bytesToHex(bytes: ByteArray): String {
    return bytes.joinToString("") { "%02x".format(it) }
}
