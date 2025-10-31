//! JNI exception throwing utilities.
//!
//! Provides consistent exception mapping for common error categories.

use jni::JNIEnv;

/// Throw `java.lang.IllegalArgumentException` with the given message.
///
/// Used for invalid input parameters (wrong sizes, invalid UTF-8, null arguments).
pub fn throw_illegal_argument(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("java/lang/IllegalArgumentException", message.into());
}

/// Throw `java.lang.IllegalStateException` with the given message.
///
/// Used for VM/JNI interop errors not related to memory exhaustion
/// (e.g., class lookup failures, array element set failures).
pub fn throw_illegal_state(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("java/lang/IllegalStateException", message.into());
}

/// Throw `java.lang.OutOfMemoryError` with the given message.
///
/// Used for allocation failures (byte arrays, strings, object arrays).
pub fn throw_out_of_memory(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("java/lang/OutOfMemoryError", message.into());
}

/// Throw `java.io.IOException` with the given message.
///
/// Used for protobuf encoding/decoding failures and JSON serialization errors.
pub fn throw_io_exception(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("java/io/IOException", message.into());
}

/// Throw `java.security.GeneralSecurityException` with the given message.
///
/// Used for general cryptographic errors (key generation, nonce failures,
/// encryption/decryption setup errors not related to authentication).
pub fn throw_security_exception(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("java/security/GeneralSecurityException", message.into());
}

/// Throw `javax.crypto.AEADBadTagException` with the given message.
///
/// Used specifically for AEAD decryption authentication tag verification failures.
pub fn throw_aead_bad_tag(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("javax/crypto/AEADBadTagException", message.into());
}

/// Throw `javax.crypto.BadPaddingException` with the given message.
///
/// Used for decryption padding/format errors.
pub fn throw_bad_padding(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("javax/crypto/BadPaddingException", message.into());
}

/// Throw `java.security.InvalidKeyException` with the given message.
///
/// Used when provided key material is malformed or invalid.
pub fn throw_invalid_key(env: &mut JNIEnv, message: impl Into<String>) {
    let _ = env.throw_new("java/security/InvalidKeyException", message.into());
}
