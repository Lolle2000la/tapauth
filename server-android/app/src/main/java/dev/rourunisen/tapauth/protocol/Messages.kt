package dev.rourunisen.tapauth.protocol

/**
 * Algorithm enums mirroring `proto/auth_protocol.proto`.
 *
 * Values are the persisted/wire values, so they are spelled out explicitly and must never be
 * renumbered.
 */
enum class SymmetricAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    AES_256_GCM(1),
    CHACHA20_POLY1305(2),
}

enum class HashAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    SHA256(1),
    BLAKE3(2),
}

enum class SignatureAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    ED25519(1),
}
