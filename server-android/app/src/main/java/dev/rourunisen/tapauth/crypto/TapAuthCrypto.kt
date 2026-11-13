package dev.rourunisen.tapauth.crypto

/**
 * JNI bridge to the TapAuth shared Rust library Provides cryptographic operations via native code
 */
object TapAuthCrypto {

    init {
        try {
            System.loadLibrary("shared")
            initLogging()
        } catch (e: UnsatisfiedLinkError) {
            // Library not found - will fail at runtime if methods are called
            // This is expected during development before the native library is built
            e.printStackTrace()
        }
    }

    /**
     * Initialize native logging to Android logcat.
     *
     * Must be called once after System.loadLibrary. Subsequent calls are no-ops.
     */
    private external fun initLogging()

    // ========== Algorithm Identifiers ==========
    //
    // Numeric values mirror `proto/auth_protocol.proto`, so persisted and wire values stay
    // unambiguous. Prefer these constants over bare integers in callers.

    /** `SymmetricAlgorithm.AES_256_GCM` */
    const val SYMMETRIC_AES_256_GCM = 1

    /** `HashAlgorithm.SHA256` */
    const val HASH_SHA256 = 1

    /** `SignatureAlgorithm.ED25519` */
    const val SIGNATURE_ED25519 = 1

    /** `PairingAbortReason.USER_REJECTED_SAS` */
    const val PAIRING_ABORT_USER_REJECTED_SAS = 1

    /** `PairingAbortReason.KEY_MISMATCH` */
    const val PAIRING_ABORT_KEY_MISMATCH = 2

    // ========== Key Generation & Signatures ==========

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
     * @return Shared secret derived from the ECDH exchange (32 bytes)
     */
    external fun keyExchange(ourPrivateKey: ByteArray, theirPublicKey: ByteArray): ByteArray

    /**
     * Compute SHA-256 hash
     *
     * @param data Data to hash
     * @return Hex-encoded hash
     */
    external fun sha256(data: ByteArray): String

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

    // ========== Encrypted Packet Layer ==========

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
     * Returns a string indicating which payload type the wrapper carries.
     *
     * @param wrapperMessageBytes Serialized WrapperMessage protobuf
     * @return "AUTH_REQUEST", "AUTH_GRANT", "AUTH_DENIAL", "GRANT_CONFIRMATION", "AUTH_CANCEL", or
     *   "UNKNOWN"
     * @throws IOException if the message cannot be parsed
     */
    external fun determineMessageType(wrapperMessageBytes: ByteArray): String

    /**
     * Create an EncryptedPacket from a WrapperMessage payload
     *
     * The AEAD associated data binds `encryption_algorithm` and `temporal_identifier`, so both
     * fields must already be final when this is called.
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param wrapperMessageBytes Serialized WrapperMessage protobuf
     * @return Serialized EncryptedPacket protobuf bytes
     */
    external fun createEncryptedPacket(csk: ByteArray, wrapperMessageBytes: ByteArray): ByteArray

    /**
     * Decrypt an EncryptedPacket to get the WrapperMessage.
     *
     * Dispatches on the packet's own `encryption_algorithm`, requires it to equal [expectedSymAlg]
     * (no algorithm downgrade), and verifies the AAD-bound AEAD tag.
     *
     * @param encryptedPacketBytes Serialized EncryptedPacket protobuf
     * @param csk Client Symmetric Key (32 bytes)
     * @param expectedSymAlg Algorithm the paired device negotiated (e.g. [SYMMETRIC_AES_256_GCM])
     * @return Serialized WrapperMessage protobuf bytes
     * @throws java.security.GeneralSecurityException if the algorithm does not match or the tag
     *   fails
     */
    external fun decryptEncryptedPacket(
        encryptedPacketBytes: ByteArray,
        csk: ByteArray,
        expectedSymAlg: Int,
    ): ByteArray

    // ========== Authenticated Wrapper Parsing ==========
    //
    // Rust verifies the Ed25519 WrapperMessage signature BEFORE parsing the inner payload, so a
    // returned data class is always signature-valid for the given Client key.

    /**
     * Verify the wrapper signature and parse the AuthenticationRequest inside it.
     *
     * @param wrapperBytes Serialized WrapperMessage protobuf
     * @param clientEd25519Pub Paired Client's Ed25519 public key (32 bytes)
     * @param protocolVersion Protocol version recorded for the paired device
     * @return The verified request, including the signed context fields
     * @throws java.security.GeneralSecurityException if the wrapper signature is invalid
     */
    external fun parseAndVerifyAuthRequest(
        wrapperBytes: ByteArray,
        clientEd25519Pub: ByteArray,
        protocolVersion: Int,
    ): AuthRequest

    /**
     * Verify the wrapper signature and parse the GrantConfirmation inside it.
     *
     * @param wrapperBytes Serialized WrapperMessage protobuf
     * @param clientEd25519Pub Paired Client's Ed25519 public key (32 bytes)
     * @param protocolVersion Protocol version recorded for the paired device
     * @return The verified confirmation
     * @throws java.security.GeneralSecurityException if the wrapper signature is invalid
     */
    external fun parseAndVerifyGrantConfirmation(
        wrapperBytes: ByteArray,
        clientEd25519Pub: ByteArray,
        protocolVersion: Int,
    ): GrantConfirmation

    /**
     * Verify the wrapper signature and parse the AuthenticationCancel inside it.
     *
     * @param wrapperBytes Serialized WrapperMessage protobuf
     * @param clientEd25519Pub Paired Client's Ed25519 public key (32 bytes)
     * @param protocolVersion Protocol version recorded for the paired device
     * @return The verified cancel
     * @throws java.security.GeneralSecurityException if the wrapper signature is invalid
     */
    external fun parseAndVerifyAuthCancel(
        wrapperBytes: ByteArray,
        clientEd25519Pub: ByteArray,
        protocolVersion: Int,
    ): AuthenticationCancel

    // ========== Server Responses ==========

    /**
     * Create a signed WrapperMessage containing an AuthenticationGrant.
     *
     * The grant carries the raw [challenge] only; the single Ed25519 signature covers the wrapper.
     *
     * @param challenge The 32-byte challenge from the request
     * @param serverPrivateKey Ed25519 private key (32 bytes) for signing the wrapper
     * @return Serialized WrapperMessage protobuf bytes (signed)
     */
    external fun createGrantWrapperMessage(
        challenge: ByteArray,
        serverPrivateKey: ByteArray,
    ): ByteArray

    /**
     * Create a signed WrapperMessage containing an AuthenticationDenial.
     *
     * The denial is bound to [challenge]; the single Ed25519 signature covers the wrapper.
     *
     * @param challenge The 32-byte challenge from the request
     * @param reason Human-readable denial reason shown/forwarded by the Client
     * @param serverPrivateKey Ed25519 private key (32 bytes) for signing the wrapper
     * @return Serialized WrapperMessage protobuf bytes (signed)
     */
    external fun createDenialWrapperMessage(
        challenge: ByteArray,
        reason: String,
        serverPrivateKey: ByteArray,
    ): ByteArray

    // ========== Temporal Identifiers ==========

    /**
     * Generate temporal identifier for a given timestamp (SHA-256 default)
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param timestampSeconds Unix timestamp in seconds
     * @return Temporal ID as byte array (16 bytes for UDP)
     */
    external fun generateTemporalId(csk: ByteArray, timestampSeconds: Long): ByteArray

    /**
     * Generate temporal identifier for BLE (10 bytes) for matching advertisements (SHA-256)
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param timestampSeconds Unix timestamp in seconds
     * @return Temporal ID as byte array (10 bytes for BLE)
     */
    external fun generateTemporalIdBle(csk: ByteArray, timestampSeconds: Long): ByteArray

    /**
     * Generate a 16-byte UDP temporal identifier with the device's negotiated hash algorithm.
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param timestampSeconds Unix timestamp in seconds
     * @param hashAlgorithm HashAlgorithm value from the paired device (e.g. [HASH_SHA256])
     * @return Temporal ID as byte array (16 bytes)
     */
    external fun generateTemporalIdWithAlg(
        csk: ByteArray,
        timestampSeconds: Long,
        hashAlgorithm: Int,
    ): ByteArray

    /**
     * Generate a 10-byte BLE temporal identifier with the device's negotiated hash algorithm.
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param timestampSeconds Unix timestamp in seconds
     * @param hashAlgorithm HashAlgorithm value from the paired device (e.g. [HASH_SHA256])
     * @return Temporal ID as byte array (10 bytes)
     */
    external fun generateTemporalIdBleWithAlg(
        csk: ByteArray,
        timestampSeconds: Long,
        hashAlgorithm: Int,
    ): ByteArray

    /**
     * Verify temporal identifier matches current or previous time window
     *
     * @param id Temporal ID to verify (10 or 16 bytes)
     * @param csk Client Symmetric Key (32 bytes)
     * @return true if ID is valid
     */
    external fun verifyTemporalId(id: ByteArray, csk: ByteArray): Boolean

    // ========== v2 Pairing ==========
    //
    // These are the JNI entries `shared/src/jni_api.rs` must provide for the unified UDP + BLE
    // pairing handshake. Android is the pairing Server (`PairingInit` carries the `server_*` keys,
    // `PairingResponse` the `client_*` keys), so it sends `PairingInit` and verifies the Client's
    // `PairingResponse` against the QR code's `pk`.
    //
    // Every packet argument and packet return is a whole serialized `PairingPacket` (Rust owns
    // protobuf); Kotlin only passes bytes and inspects the documented return slots.
    //
    // Return-slot contract — this comment is the single source of truth for slot order and is
    // mirrored by `network/PairingSession.kt`, which reads the slots positionally:
    //   pairingInit            -> one PairingPacket{init}
    //   pairingVerifyResponse  -> [0]=transcriptHash H (32B), [1]=K_c2s (32B), [2]=K_s2c (32B),
    //                             [3]=sas (UTF-8 bytes, e.g. "123-456"), [4]=client Ed25519
    //                             public key (32B), [5]=selected SymmetricAlgorithm (4-byte BE),
    //                             [6]=selected HashAlgorithm (4-byte BE),
    //                             [7]=selected SignatureAlgorithm (4-byte BE)
    //   pairingDecryptProvision-> [0]=csk (32B), [1]=username (UTF-8), [2]=clientHostname (UTF-8)
    //   pairingCreateConfirmServer -> one PairingPacket{confirm_server}
    //   pairingCreateAbort     -> one PairingPacket{abort}
    //   pairingVerifyAbort     -> PairingAbortReason value; throws GeneralSecurityException if the
    //                             auth tag does not verify

    /**
     * Derive the 10-byte BLE pairing advertisement id: `SHA-256("tapauth-ble-pair-v2" || sid ||
     * pk)[..10]`.
     *
     * @param sessionId 16-byte pairing session id from the QR code
     * @param clientX25519PublicKey Client ephemeral X25519 public key (32 bytes) from the QR code
     * @return 10-byte advertisement id to match with a hardware ScanFilter
     */
    external fun deriveBlePairingAdvId(
        sessionId: ByteArray,
        clientX25519PublicKey: ByteArray,
    ): ByteArray

    /**
     * Compute the canonical SHA-256 handshake transcript hash `H` over both handshake packets.
     *
     * @param sessionId 16-byte pairing session id
     * @param initPacketBytes Serialized `PairingPacket` carrying our `PairingInit`
     * @param responsePacketBytes Serialized `PairingPacket` carrying the Client's `PairingResponse`
     * @return 32-byte transcript hash
     */
    external fun computePairingTranscriptHash(
        sessionId: ByteArray,
        initPacketBytes: ByteArray,
        responsePacketBytes: ByteArray,
    ): ByteArray

    /**
     * Build our `PairingInit` (Server role) with the supported algorithm lists in preference order.
     *
     * @return Serialized `PairingPacket` carrying `PairingInit`
     */
    external fun pairingInit(
        sessionId: ByteArray,
        serverX25519PublicKey: ByteArray,
        serverEd25519PublicKey: ByteArray,
        serverDeviceName: String,
        supportedSymmetricAlgorithms: IntArray,
        supportedHashAlgorithms: IntArray,
        supportedSignatureAlgorithms: IntArray,
    ): ByteArray

    /**
     * Verify and accept the Client's `PairingResponse`, deriving the session keys and SAS.
     *
     * Returns eight slots, in this order (the same order documented in the section comment above,
     * which is the single source of truth):
     * - `[0]` 32-byte transcript hash `H`
     * - `[1]` `K_c2s` (32 bytes)
     * - `[2]` `K_s2c` (32 bytes)
     * - `[3]` SAS as UTF-8 bytes, already grouped (for example `"123-456"`)
     * - `[4]` the Client's Ed25519 public key (32 bytes)
     * - `[5]` the SymmetricAlgorithm the Client selected, as a 4-byte big-endian integer
     * - `[6]` the HashAlgorithm the Client selected, as a 4-byte big-endian integer
     * - `[7]` the SignatureAlgorithm the Client selected, as a 4-byte big-endian integer
     *
     * An **all-zero** [expectedClientX25519PublicKey] means "QR `pk` unavailable, skip the
     * constant-time comparison": that is the E2E harness path, where the session is configured with
     * a pairing host/port instead of a QR URL and therefore has no `pk` to pin (see
     * `PairingSession`'s "Legacy harness path"). Any non-zero expected key is always compared in
     * constant time and a mismatch throws. Every other validation — the Client's signature over the
     * transcript and a non-empty algorithm intersection — still applies on that path; only the pin
     * is skipped. `PairingUrl.parse` requires a 64-hex `pk`, so the all-zero form is unreachable
     * from a scanned QR code.
     *
     * @param sessionId 16-byte pairing session id
     * @param responsePacketBytes Serialized `PairingPacket` carrying the Client's `PairingResponse`
     * @param expectedClientX25519PublicKey The QR code's `pk` (32 bytes), or 32 zero bytes to skip
     *   the pin (E2E harness only)
     * @param serverX25519PrivateKey Our ephemeral X25519 private key (32 bytes)
     * @return `[transcriptHash(32B), K_c2s(32B), K_s2c(32B), sas(UTF-8), clientEd25519(32B),
     *   symmetricAlg(4B BE), hashAlg(4B BE), signatureAlg(4B BE)]`
     * @throws java.security.GeneralSecurityException on QR-pk mismatch, bad client signature, or an
     *   empty algorithm intersection
     */
    external fun pairingVerifyResponse(
        sessionId: ByteArray,
        responsePacketBytes: ByteArray,
        expectedClientX25519PublicKey: ByteArray,
        serverX25519PrivateKey: ByteArray,
    ): Array<ByteArray>

    /**
     * Client-role step: build the encrypted `PairingConfirmClient` provision payload.
     *
     * @return Serialized `PairingPacket` carrying `PairingConfirmClient`
     */
    external fun pairingEncryptProvision(
        kC2s: ByteArray,
        transcriptHash: ByteArray,
        csk: ByteArray,
        username: String,
        clientHostname: String,
    ): ByteArray

    /**
     * Client-role step: verify our `PairingConfirmServer` against the Server's Ed25519 key.
     *
     * @param confirmServerPacketBytes Serialized `PairingPacket` carrying `PairingConfirmServer`
     * @param serverEd25519PublicKey The Server's static Ed25519 public key (32 bytes)
     * @return The 32-byte CSK echoed inside the authenticated completion payload
     * @throws java.security.GeneralSecurityException if the tag or the server signature is invalid
     */
    external fun pairingDecryptComplete(
        kS2c: ByteArray,
        transcriptHash: ByteArray,
        confirmServerPacketBytes: ByteArray,
        serverEd25519PublicKey: ByteArray,
    ): ByteArray

    /**
     * Server-role step: decrypt the Client's provision payload.
     *
     * @param confirmClientPacketBytes Serialized `PairingPacket` carrying `PairingConfirmClient`
     * @return `[csk(32B), username(UTF-8), clientHostname(UTF-8)]`
     * @throws java.security.GeneralSecurityException if the AEAD tag fails
     */
    external fun pairingDecryptProvision(
        kC2s: ByteArray,
        transcriptHash: ByteArray,
        confirmClientPacketBytes: ByteArray,
    ): Array<ByteArray>

    /**
     * Server-role step: build the signed and encrypted `PairingConfirmServer`.
     *
     * @return Serialized `PairingPacket` carrying `PairingConfirmServer`
     */
    external fun pairingCreateConfirmServer(
        kS2c: ByteArray,
        transcriptHash: ByteArray,
        serverEd25519PrivateKey: ByteArray,
        csk: ByteArray,
    ): ByteArray

    /**
     * Build an authenticated `PairingAbort` for either direction.
     *
     * @param kDir `K_c2s` or `K_s2c`, whichever the abort travels under
     * @param transcriptHash 32-byte transcript hash `H`
     * @param reason A `PairingAbortReason` value (e.g. [PAIRING_ABORT_USER_REJECTED_SAS])
     * @return Serialized `PairingPacket` carrying `PairingAbort`
     */
    external fun pairingCreateAbort(
        kDir: ByteArray,
        transcriptHash: ByteArray,
        reason: Int,
    ): ByteArray

    /**
     * Verify an incoming `PairingAbort` auth tag and return its reason.
     *
     * @param kDir `K_c2s` or `K_s2c`, matching the direction the abort arrived on
     * @param transcriptHash 32-byte transcript hash `H`
     * @param abortPacketBytes Serialized `PairingPacket` carrying `PairingAbort`
     * @return The `PairingAbortReason` value carried by the verified abort
     * @throws java.security.GeneralSecurityException if the auth tag does not verify
     */
    external fun pairingVerifyAbort(
        kDir: ByteArray,
        transcriptHash: ByteArray,
        abortPacketBytes: ByteArray,
    ): Int
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
 * Generate temporal identifier for a specific timestamp and hash algorithm
 *
 * @return Temporal ID as byte array (16 bytes)
 */
fun generateTemporalIdWithAlg(
    csk: ByteArray,
    timestampSeconds: Long,
    hashAlgorithm: Int,
): ByteArray {
    return TapAuthCrypto.generateTemporalIdWithAlg(csk, timestampSeconds, hashAlgorithm)
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

/**
 * Generate BLE temporal identifier (10 bytes) for a specific timestamp and hash algorithm
 *
 * @return Temporal ID as byte array (10 bytes)
 */
fun generateTemporalIdBleWithAlg(
    csk: ByteArray,
    timestampSeconds: Long,
    hashAlgorithm: Int,
): ByteArray {
    return TapAuthCrypto.generateTemporalIdBleWithAlg(csk, timestampSeconds, hashAlgorithm)
}

/** Verify temporal identifier */
fun verifyTemporalId(id: ByteArray, csk: ByteArray): Boolean {
    return TapAuthCrypto.verifyTemporalId(id, csk)
}

/** Create a WrapperMessage containing an AuthenticationGrant */
fun createGrantWrapperMessage(challenge: ByteArray, serverPrivateKey: ByteArray): ByteArray {
    return TapAuthCrypto.createGrantWrapperMessage(challenge, serverPrivateKey)
}

/** Create a WrapperMessage containing an AuthenticationDenial */
fun createDenialWrapperMessage(
    challenge: ByteArray,
    reason: String,
    serverPrivateKey: ByteArray,
): ByteArray {
    return TapAuthCrypto.createDenialWrapperMessage(challenge, reason, serverPrivateKey)
}

/** Create an EncryptedPacket from a WrapperMessage */
fun createEncryptedPacket(csk: ByteArray, wrapperMessage: ByteArray): ByteArray {
    return TapAuthCrypto.createEncryptedPacket(csk, wrapperMessage)
}

/** Decrypt an EncryptedPacket to get the WrapperMessage */
fun decryptEncryptedPacket(
    encryptedPacket: ByteArray,
    csk: ByteArray,
    expectedSymAlg: Int,
): ByteArray {
    return TapAuthCrypto.decryptEncryptedPacket(encryptedPacket, csk, expectedSymAlg)
}
