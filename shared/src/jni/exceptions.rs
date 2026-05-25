//! JNI exception throwing utilities.
//!
//! Provides consistent exception mapping for common error categories.

use jni::strings::JNIString;
use jni::EnvUnowned as JNIEnv;

/// Throw `java.lang.IllegalArgumentException` with the given message.
///
/// Used for invalid input parameters (wrong sizes, invalid UTF-8, null arguments).
pub fn throw_illegal_argument(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| {
            env.throw_new(
                jni::jni_str!("java/lang/IllegalArgumentException"),
                &message,
            )
        })
        .into_outcome();
}

/// Throw `java.lang.IllegalStateException` with the given message.
///
/// Used for VM/JNI interop errors not related to memory exhaustion
/// (e.g., class lookup failures, array element set failures).
pub fn throw_illegal_state(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| env.throw_new(jni::jni_str!("java/lang/IllegalStateException"), &message))
        .into_outcome();
}

/// Throw `java.lang.OutOfMemoryError` with the given message.
///
/// Used for allocation failures (byte arrays, strings, object arrays).
pub fn throw_out_of_memory(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| env.throw_new(jni::jni_str!("java/lang/OutOfMemoryError"), &message))
        .into_outcome();
}

/// Throw `java.io.IOException` with the given message.
///
/// Used for protobuf encoding/decoding failures and JSON serialization errors.
pub fn throw_io_exception(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| env.throw_new(jni::jni_str!("java/io/IOException"), &message))
        .into_outcome();
}

/// Throw `java.security.GeneralSecurityException` with the given message.
///
/// Used for general cryptographic errors (key generation, nonce failures,
/// encryption/decryption setup errors not related to authentication).
pub fn throw_security_exception(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| {
            env.throw_new(
                jni::jni_str!("java/security/GeneralSecurityException"),
                &message,
            )
        })
        .into_outcome();
}

/// Throw `javax.crypto.AEADBadTagException` with the given message.
///
/// Used specifically for AEAD decryption authentication tag verification failures.
pub fn throw_aead_bad_tag(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| env.throw_new(jni::jni_str!("javax/crypto/AEADBadTagException"), &message))
        .into_outcome();
}

/// Throw `javax.crypto.BadPaddingException` with the given message.
///
/// Used for decryption padding/format errors.
pub fn throw_bad_padding(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| env.throw_new(jni::jni_str!("javax/crypto/BadPaddingException"), &message))
        .into_outcome();
}

/// Throw `java.security.InvalidKeyException` with the given message.
///
/// Used when provided key material is malformed or invalid.
pub fn throw_invalid_key(env: &mut JNIEnv, message: impl Into<String>) {
    let message = JNIString::new(message.into());
    let _ = env
        .with_env(|env| env.throw_new(jni::jni_str!("java/security/InvalidKeyException"), &message))
        .into_outcome();
}

/// Map a `TapAuthError` to the appropriate Java exception and throw it.
///
/// Exception mapping:
/// - `InvalidInput` → `IllegalArgumentException`
/// - `Io`, `ProtoDecode` → `IOException`
/// - `AeadBadTag` → `AEADBadTagException`
/// - `Crypto` → `GeneralSecurityException`
/// - `State` → `IllegalStateException`
pub fn throw_tapauth_error(env: &mut JNIEnv, err: &crate::error::TapAuthError) {
    use crate::error::TapAuthError;
    match err {
        TapAuthError::InvalidInput(msg) => throw_illegal_argument(env, msg),
        TapAuthError::Io(err) => throw_io_exception(env, err.to_string()),
        TapAuthError::ProtoDecode(err) => throw_io_exception(env, err.to_string()),
        TapAuthError::AeadBadTag => throw_aead_bad_tag(env, "AEAD tag verification failed"),
        TapAuthError::Crypto(msg) => throw_security_exception(env, msg),
        TapAuthError::State(msg) => throw_illegal_state(env, msg),
    }
}
