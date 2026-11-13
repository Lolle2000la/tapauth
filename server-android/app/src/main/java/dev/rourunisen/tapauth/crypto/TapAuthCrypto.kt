package dev.rourunisen.tapauth.crypto

/**
 * JNI bridge to the TapAuth shared Rust library Provides cryptographic operations via native code
 *
 * Rust is the protocol: this object only moves opaque protobuf blobs and primitives across the
 * boundary. Kotlin never derives a key, builds an AAD, picks an abort MAC direction, or
 * hand-encodes a `PairingPacket` — every one of those happens behind an entry point below.
 *
 * The declaration set is frozen: a CI guard asserts exact set equality against the exported Rust
 * symbols, so adding or dropping a member here fails the build. `shared/src/jni_api.rs` documents
 * the exception contract of each entry (`IllegalArgumentException` for malformed input or an
 * unknown handle, `GeneralSecurityException` for a failed signature/AEAD/QR-pin check,
 * `IOException` for bytes that are not a decodable protobuf message, `IllegalStateException` for
 * internal failures).
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

    /** `PairingAbortReason.UNSUPPORTED_ALGORITHM` */
    const val PAIRING_ABORT_UNSUPPORTED_ALGORITHM = 3

    /** `PairingAbortReason.PROTOCOL_ERROR` */
    const val PAIRING_ABORT_PROTOCOL_ERROR = 4

    /** `PairingAbortReason.SESSION_EXPIRED` */
    const val PAIRING_ABORT_SESSION_EXPIRED = 5

    // ========== Key Generation ==========

    /**
     * Generate a new Ed25519 keypair for this phone's long-term identity (`Ed_S`).
     *
     * @return Array of [privateKey: ByteArray (32), publicKey: ByteArray (32)]
     */
    external fun generateKeypair(): Array<ByteArray>

    // ========== Encrypted Packet Layer ==========

    /**
     * Decrypt an `EncryptedPacket` to get its `WrapperMessage`.
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
     * The result is **not** authenticated: it only chooses which verifying parse entry point to
     * call next, and that entry point re-checks the signature and the payload type.
     *
     * @param wrapperMessageBytes Serialized WrapperMessage protobuf
     * @return "AUTH_REQUEST", "AUTH_GRANT", "AUTH_DENIAL", "GRANT_CONFIRMATION", "AUTH_CANCEL", or
     *   "UNKNOWN"
     * @throws IOException if the message cannot be parsed
     */
    external fun determineMessageType(wrapperMessageBytes: ByteArray): String

    // ========== Authenticated Wrapper Parsing ==========
    //
    // Rust verifies the Ed25519 WrapperMessage signature BEFORE parsing the inner payload, so a
    // returned value is always signature-valid for the given Client key.

    /**
     * Verify the wrapper signature and parse the AuthenticationRequest inside it.
     *
     * @param wrapperBytes Serialized WrapperMessage protobuf
     * @param clientEd25519Pub Paired Client's Ed25519 public key (32 bytes)
     * @param protocolVersion Protocol version recorded for the paired device. Verification is
     *   fail-closed: **any value other than 2 throws**; there is no v1 verification path. A legacy
     *   record is kept by [dev.rourunisen.tapauth.data.DeviceRepository] but simply cannot
     *   authenticate until it is re-paired; nothing purges it automatically.
     * @param expectedSignatureAlgorithm The paired Client's persisted `SignatureAlgorithm` id;
     *   never derived from the message, so an algorithm downgrade is impossible
     * @return The verified request, including the signed context fields
     * @throws java.security.GeneralSecurityException if the wrapper signature is invalid or
     *   [protocolVersion] is not 2
     */
    external fun parseAndVerifyAuthRequest(
        wrapperBytes: ByteArray,
        clientEd25519Pub: ByteArray,
        protocolVersion: Int,
        expectedSignatureAlgorithm: Int,
    ): ParsedAuthRequest

    /**
     * Verify the wrapper signature and parse the GrantConfirmation inside it.
     *
     * @param wrapperBytes Serialized WrapperMessage protobuf
     * @param clientEd25519Pub Paired Client's Ed25519 public key (32 bytes)
     * @param protocolVersion Protocol version recorded for the paired device; must be 2
     * @param expectedSignatureAlgorithm The paired Client's persisted `SignatureAlgorithm` id
     * @return The 32-byte challenge the Client confirmed
     * @throws java.security.GeneralSecurityException if the wrapper signature is invalid or
     *   [protocolVersion] is not 2
     */
    external fun parseAndVerifyGrantConfirmation(
        wrapperBytes: ByteArray,
        clientEd25519Pub: ByteArray,
        protocolVersion: Int,
        expectedSignatureAlgorithm: Int,
    ): ByteArray

    /**
     * Verify the wrapper signature and parse the AuthenticationCancel inside it.
     *
     * @param wrapperBytes Serialized WrapperMessage protobuf
     * @param clientEd25519Pub Paired Client's Ed25519 public key (32 bytes)
     * @param protocolVersion Protocol version recorded for the paired device; must be 2
     * @param expectedSignatureAlgorithm The paired Client's persisted `SignatureAlgorithm` id
     * @return The 32-byte challenge the Client cancelled
     * @throws java.security.GeneralSecurityException if the wrapper signature is invalid or
     *   [protocolVersion] is not 2
     */
    external fun parseAndVerifyAuthCancel(
        wrapperBytes: ByteArray,
        clientEd25519Pub: ByteArray,
        protocolVersion: Int,
        expectedSignatureAlgorithm: Int,
    ): ByteArray

    // ========== Server Responses ==========

    /**
     * Sign a Grant and encrypt it: the finished `EncryptedPacket` to send.
     *
     * The single Ed25519 signature covers `"tapauth-sig-v2" || be32(version) ||
     * be32(signature_algorithm) || be32(payload_type) || payload`; the packet is then
     * AEAD-encrypted under [csk] with the negotiated algorithms, and the AAD binds
     * `encryption_algorithm` and the rotating temporal identifier. Kotlin must not wrap, encrypt or
     * re-sign the result.
     *
     * @param challenge The 32-byte challenge from the request
     * @param serverPrivKey Ed25519 private key (32 bytes) for signing the wrapper
     * @param csk Client Symmetric Key (32 bytes)
     * @param symmetricAlgorithm The paired device's `SymmetricAlgorithm` (e.g.
     *   [SYMMETRIC_AES_256_GCM]); also written to `EncryptedPacket.encryption_algorithm`
     * @param hashAlgorithm The paired device's `HashAlgorithm` (e.g. [HASH_SHA256]), used to derive
     *   the temporal identifier the AAD binds
     * @return Serialized EncryptedPacket protobuf bytes, ready to send
     */
    external fun createGrantWrapperMessage(
        challenge: ByteArray,
        serverPrivKey: ByteArray,
        csk: ByteArray,
        symmetricAlgorithm: Int,
        hashAlgorithm: Int,
    ): ByteArray

    /**
     * Sign a Denial and encrypt it: the finished `EncryptedPacket` to send.
     *
     * @param challenge The 32-byte challenge from the request the denial is bound to
     * @param reason Human-readable denial reason shown/forwarded by the Client; never a secret
     * @param serverPrivKey Ed25519 private key (32 bytes) for signing the wrapper
     * @param csk Client Symmetric Key (32 bytes)
     * @param symmetricAlgorithm The paired device's `SymmetricAlgorithm`
     * @param hashAlgorithm The paired device's `HashAlgorithm`
     * @return Serialized EncryptedPacket protobuf bytes, ready to send
     */
    external fun createDenialWrapperMessage(
        challenge: ByteArray,
        reason: String,
        serverPrivKey: ByteArray,
        csk: ByteArray,
        symmetricAlgorithm: Int,
        hashAlgorithm: Int,
    ): ByteArray

    // ========== Temporal Identifiers ==========

    /**
     * Derive the 16-byte UDP/GATT temporal identifier for a 60-second window.
     *
     * **Semantic trap: [window] is the window (`unix_seconds / 60`), not a unix timestamp.** Use
     * [currentTimeWindow] to obtain it.
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param window The 60-second time window (`unix_seconds / 60`)
     * @param hashAlgorithm HashAlgorithm value from the paired device (e.g. [HASH_SHA256])
     * @return Temporal ID as byte array (16 bytes for UDP/GATT)
     */
    external fun generateTemporalIdentifier(
        csk: ByteArray,
        window: Long,
        hashAlgorithm: Int,
    ): ByteArray

    /**
     * Derive the 10-byte BLE advertisement temporal identifier for a 60-second window.
     *
     * @param csk Client Symmetric Key (32 bytes)
     * @param window The 60-second time window (`unix_seconds / 60`)
     * @param hashAlgorithm HashAlgorithm value from the paired device (e.g. [HASH_SHA256])
     * @return Temporal ID as byte array (10 bytes for BLE)
     */
    external fun generateBleTemporalIdentifier(
        csk: ByteArray,
        window: Long,
        hashAlgorithm: Int,
    ): ByteArray

    /**
     * The current 60-second time window (`unix_seconds / 60`).
     *
     * @throws java.security.GeneralSecurityException if the system clock is before the Unix epoch
     */
    external fun currentTimeWindow(): Long

    /**
     * Check a received temporal identifier against the current and previous window.
     *
     * Accepts both the 16-byte UDP/GATT form and the 10-byte BLE form.
     *
     * @param temporalIdentifier The identifier from the packet (10 or 16 bytes)
     * @param csk Client Symmetric Key (32 bytes)
     * @param hashAlgorithm HashAlgorithm value from the paired device
     * @return true if the identifier matches the current or previous window
     */
    external fun verifyTemporalIdentifier(
        temporalIdentifier: ByteArray,
        csk: ByteArray,
        hashAlgorithm: Int,
    ): Boolean

    // ========== v2 Pairing ==========
    //
    // Phone-side pairing is **stateful**: [pairingServerSessionCreate] returns an opaque handle
    // that
    // owns the ephemeral X25519 secret, `Ed_S`, the directional keys `K_c2s`/`K_s2c` and the
    // transcript hash. None of that is ever returned to Kotlin, so Kotlin cannot pick an abort MAC
    // direction or rebuild an AAD. Every packet argument and packet return is a whole serialized
    // `PairingPacket`; Rust owns the protobuf.

    /**
     * Derive the 10-byte BLE pairing advertisement id: `SHA-256("tapauth-ble-pair-v2" || sid ||
     * pk)[..10]`.
     *
     * @param sessionId 16-byte pairing session id from the QR code
     * @param clientX25519Pub Client ephemeral X25519 public key (32 bytes) from the QR code
     * @return 10-byte advertisement id to match with a hardware ScanFilter
     */
    external fun deriveBlePairingAdvId(
        sessionId: ByteArray,
        clientX25519Pub: ByteArray,
    ): ByteArray

    /**
     * Start a phone-side pairing session from the scanned QR code.
     *
     * @param sessionId 16-byte `sid` from the QR code
     * @param serverEd25519PrivKey 32-byte (or 64-byte keypair) private `Ed_S`
     * @param serverDeviceName Display name, truncated to 64 UTF-8 bytes by Rust
     * @return A positive session handle, or 0 after throwing. `0` is never a valid handle.
     */
    external fun pairingServerSessionCreate(
        sessionId: ByteArray,
        serverEd25519PrivKey: ByteArray,
        serverDeviceName: String,
    ): Long

    /**
     * Drop a pairing session and zeroize its keys.
     *
     * @throws IllegalArgumentException if the handle is unknown (already freed or never created)
     */
    external fun pairingServerSessionFree(handle: Long)

    /**
     * Build the `PairingInit` to send (serialized `PairingPacket`).
     *
     * Retransmissions must re-send the returned bytes rather than calling this again for a fresh
     * message; the cached copy is returned either way, so one session has exactly one init payload
     * and therefore exactly one SAS.
     */
    external fun pairingCreateInit(handle: Long): ByteArray

    /**
     * Verify the desktop's `PairingResponse`.
     *
     * The QR commitment (`client_x25519_public_key == expectedQrPk`) is checked first, then the
     * Client's Ed25519 signature over the transcript hash, then the keys and SAS are derived inside
     * the handle.
     *
     * @param handle Session handle from [pairingServerSessionCreate]
     * @param responsePacket Serialized `PairingPacket` carrying `PairingResponse`
     * @param expectedQrPk 32-byte `pk` from the scanned QR code; always compared
     * @return The SAS to display plus what the phone persists for the new device
     * @throws java.security.GeneralSecurityException on a QR-`pk` mismatch, a bad Client signature
     *   or an unsupported algorithm selection
     */
    external fun pairingVerifyResponse(
        handle: Long,
        responsePacket: ByteArray,
        expectedQrPk: ByteArray,
    ): ParsedPairingResponse

    /**
     * Decrypt the desktop's provisioning payload (`PairingConfirmClient`).
     *
     * @param confirmClientPacket Serialized `PairingPacket` carrying `PairingConfirmClient`
     * @return The 32-byte CSK, the authorized username and the Client hostname
     * @throws java.security.GeneralSecurityException if the AEAD tag fails
     */
    external fun pairingProcessConfirmClient(
        handle: Long,
        confirmClientPacket: ByteArray,
    ): ParsedPairingProvision

    /**
     * Build the completion proof (serialized `PairingPacket` with `PairingConfirmServer`).
     *
     * The phone signs `"tapauth-pair-server-sig-v2" || H || csk` with `Ed_S` and encrypts it under
     * `K_s2c`. Retransmissions must re-send the same bytes.
     */
    external fun pairingCreateConfirmServer(handle: Long, csk: ByteArray): ByteArray

    /**
     * Build an authenticated `PairingAbort`.
     *
     * Once the session keys exist the abort carries an HMAC tag, so a network observer cannot spoof
     * a cancellation. Rust tags it with `K_s2c`; Kotlin must not choose a direction.
     *
     * @param reason A `PairingAbortReason` value (e.g. [PAIRING_ABORT_USER_REJECTED_SAS])
     * @return Serialized `PairingPacket` carrying `PairingAbort`
     */
    external fun pairingCreateAbort(handle: Long, reason: Int): ByteArray

    /**
     * Verify an abort received from the desktop.
     *
     * @return `true` for an authenticated abort; **`false` for a tag-less abort received before any
     *   key existed, which is unauthenticated and must be ignored, never treated as an abort**
     * @throws java.security.GeneralSecurityException for a bad abort tag
     * @throws IllegalArgumentException for a packet of another session or of another type
     */
    external fun pairingVerifyAbort(handle: Long, abortPacket: ByteArray): Boolean

    /**
     * Build the `PairingKeepalive` frame that keeps an idle pairing transport alive.
     *
     * The message body is empty, but the envelope is not: Rust encodes it so Kotlin never
     * hand-writes protobuf. It is idempotent to retransmit.
     */
    external fun pairingCreateKeepalive(handle: Long): ByteArray

    /**
     * Extract the 16-byte `session_id` of a serialized `PairingPacket`.
     *
     * Lets the phone drop a frame that belongs to another pairing (the BLE characteristic and the
     * UDP port are shared) before spending any crypto on it.
     *
     * @throws IllegalArgumentException for an undecodable packet, a wrong protocol version or a
     *   session id that is not 16 bytes
     */
    external fun pairingPacketSessionId(packetBytes: ByteArray): ByteArray
}

/** Kotlin wrapper for the phone's long-term Ed25519 identity keypair (`Ed_S`). */
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
