package dev.rourunisen.tapauth.protocol

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName

/**
 * Protobuf message representations parsed from JSON
 * These match the structure of the messages in auth_protocol.proto
 */

data class EncryptedPacket(
    @SerializedName("temporal_identifier")
    val temporalIdentifier: String,  // Base64 encoded
    @SerializedName("encryption_algorithm")
    val encryptionAlgorithm: Int,
    val ciphertext: String  // Base64 encoded
)

data class AuthenticationRequest(
    val challenge: String,  // Base64 encoded
    val username: String,
    val hostname: String,
    @SerializedName("timestamp_unix_seconds")
    val timestampUnixSeconds: Long,
    @SerializedName("signature_algorithm")
    val signatureAlgorithm: Int,
    val signature: String  // Base64 encoded
)

data class AuthenticationGrant(
    @SerializedName("signed_challenge")
    val signedChallenge: String,  // Base64 encoded
    @SerializedName("signature_algorithm")
    val signatureAlgorithm: Int,
    val signature: String  // Base64 encoded
)

data class GrantConfirmation(
    val challenge: String,  // Base64 encoded
    @SerializedName("signature_algorithm")
    val signatureAlgorithm: Int,
    val signature: String  // Base64 encoded
)

data class AuthenticationCancel(
    val challenge: String,  // Base64 encoded
    @SerializedName("signature_algorithm")
    val signatureAlgorithm: Int,
    val signature: String  // Base64 encoded
)

/**
 * Helper object for parsing protobuf messages via JNI
 */
object ProtobufParser {
    private val gson = Gson()
    
    /**
     * Parse an EncryptedPacket from raw bytes using native library
     */
    fun parseEncryptedPacket(csk: ByteArray, packetBytes: ByteArray): EncryptedPacket {
        val cskHex = bytesToHex(csk)
        val json = dev.rourunisen.tapauth.crypto.TapAuthCrypto.decryptAndParsePacket(cskHex, packetBytes)
        return gson.fromJson(json, EncryptedPacket::class.java)
    }
    
    /**
     * Parse an AuthenticationRequest from protobuf bytes
     */
    fun parseAuthRequest(requestBytes: ByteArray): AuthenticationRequest {
        val json = dev.rourunisen.tapauth.crypto.TapAuthCrypto.parseAuthRequest(requestBytes)
        return gson.fromJson(json, AuthenticationRequest::class.java)
    }
    
    /**
     * Create an AuthenticationGrant protobuf message
     */
    fun createAuthGrant(signedChallenge: ByteArray): ByteArray {
        return dev.rourunisen.tapauth.crypto.TapAuthCrypto.createAuthGrant(signedChallenge)
    }
    
    /**
     * Parse GrantConfirmation from protobuf bytes
     */
    fun parseGrantConfirmation(confirmationBytes: ByteArray): GrantConfirmation {
        val json = dev.rourunisen.tapauth.crypto.TapAuthCrypto.parseGrantConfirmation(confirmationBytes)
        return gson.fromJson(json, GrantConfirmation::class.java)
    }
    
    /**
     * Parse AuthenticationCancel from protobuf bytes
     */
    fun parseAuthenticationCancel(cancelBytes: ByteArray): AuthenticationCancel {
        val json = dev.rourunisen.tapauth.crypto.TapAuthCrypto.parseAuthenticationCancel(cancelBytes)
        return gson.fromJson(json, AuthenticationCancel::class.java)
    }
    
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Algorithm enums matching the protobuf definitions
 */
enum class SignatureAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    ED25519(1)
}

enum class SymmetricAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    AES_256_GCM(1)
}

enum class HashAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    SHA256(1)
}
