package dev.rourunisen.tapauth.protocol

import com.google.gson.annotations.SerializedName

/**
 * Protobuf message representations parsed from JSON These match the structure of the messages in
 * auth_protocol.proto
 */
data class EncryptedPacket(
    @SerializedName("temporal_identifier") val temporalIdentifier: String, // Base64 encoded
    @SerializedName("encryption_algorithm") val encryptionAlgorithm: Int,
    val ciphertext: String, // Base64 encoded
)

data class AuthenticationRequest(
    val challenge: String, // Base64 encoded
    val username: String,
    val hostname: String,
    @SerializedName("timestamp_unix_seconds") val timestampUnixSeconds: Long,
    @SerializedName("signature_algorithm") val signatureAlgorithm: Int,
    val signature: String, // Base64 encoded
)

data class AuthenticationGrant(
    @SerializedName("signed_challenge") val signedChallenge: String, // Base64 encoded
    @SerializedName("signature_algorithm") val signatureAlgorithm: Int,
    val signature: String, // Base64 encoded
)

data class GrantConfirmation(
    val challenge: String, // Base64 encoded
    @SerializedName("signature_algorithm") val signatureAlgorithm: Int,
    val signature: String, // Base64 encoded
)

data class AuthenticationCancel(
    val challenge: String, // Base64 encoded
    @SerializedName("signature_algorithm") val signatureAlgorithm: Int,
    val signature: String, // Base64 encoded
)

/** Helper object for parsing protobuf messages via JNI */
object ProtobufParser {
    /** Parse an EncryptedPacket structure from raw protobuf bytes (without decryption) */
    fun parseEncryptedPacket(packetBytes: ByteArray): EncryptedPacket {
        val info =
            dev.rourunisen.tapauth.crypto.TapAuthCrypto.parseEncryptedPacketStructure(packetBytes)
        return EncryptedPacket(
            temporalIdentifier =
                android.util.Base64.encodeToString(
                    info.temporalIdentifier,
                    android.util.Base64.NO_WRAP,
                ),
            encryptionAlgorithm = info.encryptionAlgorithm,
            ciphertext =
                android.util.Base64.encodeToString(info.ciphertext, android.util.Base64.NO_WRAP),
        )
    }

    /** Parse an AuthenticationRequest from protobuf bytes */
    fun parseAuthRequest(requestBytes: ByteArray): AuthenticationRequest {
        val req = dev.rourunisen.tapauth.crypto.TapAuthCrypto.parseAuthRequest(requestBytes)
        return AuthenticationRequest(
            challenge =
                android.util.Base64.encodeToString(req.challenge, android.util.Base64.NO_WRAP),
            username = req.username,
            hostname = req.hostname,
            timestampUnixSeconds = req.timestampUnixSeconds,
            signatureAlgorithm = req.signatureAlgorithm,
            signature =
                android.util.Base64.encodeToString(req.signature, android.util.Base64.NO_WRAP),
        )
    }

    /** Create an AuthenticationGrant protobuf message */
    fun createAuthGrant(signedChallenge: ByteArray): ByteArray {
        return dev.rourunisen.tapauth.crypto.TapAuthCrypto.createAuthGrant(signedChallenge)
    }

    /** Parse GrantConfirmation from protobuf bytes */
    fun parseGrantConfirmation(confirmationBytes: ByteArray): GrantConfirmation {
        val conf =
            dev.rourunisen.tapauth.crypto.TapAuthCrypto.parseGrantConfirmation(confirmationBytes)
        return GrantConfirmation(
            challenge =
                android.util.Base64.encodeToString(conf.challenge, android.util.Base64.NO_WRAP),
            signatureAlgorithm = conf.signatureAlgorithm,
            signature =
                android.util.Base64.encodeToString(conf.signature, android.util.Base64.NO_WRAP),
        )
    }

    /** Parse AuthenticationCancel from protobuf bytes */
    fun parseAuthenticationCancel(cancelBytes: ByteArray): AuthenticationCancel {
        val cancel =
            dev.rourunisen.tapauth.crypto.TapAuthCrypto.parseAuthenticationCancel(cancelBytes)
        return AuthenticationCancel(
            challenge =
                android.util.Base64.encodeToString(cancel.challenge, android.util.Base64.NO_WRAP),
            signatureAlgorithm = cancel.signatureAlgorithm,
            signature =
                android.util.Base64.encodeToString(cancel.signature, android.util.Base64.NO_WRAP),
        )
    }
}

/** Algorithm enums matching the protobuf definitions */
enum class SignatureAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    ED25519(1),
}

enum class SymmetricAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    AES_256_GCM(1),
}

enum class HashAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    SHA256(1),
}
