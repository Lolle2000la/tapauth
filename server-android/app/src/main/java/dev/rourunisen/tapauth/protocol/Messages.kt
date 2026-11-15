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
    // Tag 2 is reserved: it was `CHACHA20_POLY1305` in pre-release builds and must never be
    // handed to a different algorithm. AES-256-GCM is the single active algorithm of v2; the
    // enum and the `supported_*` / `selected_*` fields stay so a future release can add one
    // without a wire change.
}

enum class HashAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    SHA256(1),
    // Tag 2 is reserved: it was `BLAKE3` in pre-release builds. SHA-256 (HMAC-SHA256) is the
    // single active algorithm of v2.
}

enum class SignatureAlgorithm(val value: Int) {
    UNSPECIFIED(0),
    ED25519(1),
}
