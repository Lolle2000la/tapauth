//! JNI exception throwing utilities.
//!
//! Provides consistent exception mapping for common error categories.

use jni::strings::{JNIStr, JNIString};
use jni::{EnvUnowned as JNIEnv, Outcome};

fn throw_exception(env: &mut JNIEnv, class: &'static JNIStr, message: JNIString) {
    match env
        .with_env(|env| env.throw_new(class, &message))
        .into_outcome()
    {
        Outcome::Ok(()) => {}
        Outcome::Err(err) => tracing::warn!("failed to throw Java exception {class}: {err}"),
        Outcome::Panic(_) => tracing::warn!("panic while throwing Java exception {class}"),
    }
}

/// Throw `java.lang.IllegalArgumentException` with the given message.
///
/// Used for invalid input parameters (wrong sizes, invalid UTF-8, null arguments).
pub fn throw_illegal_argument(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("java/lang/IllegalArgumentException"),
        JNIString::new(message.into()),
    );
}

/// Throw `java.lang.IllegalStateException` with the given message.
///
/// Used for VM/JNI interop errors not related to memory exhaustion
/// (e.g., class lookup failures, array element set failures).
pub fn throw_illegal_state(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("java/lang/IllegalStateException"),
        JNIString::new(message.into()),
    );
}

/// Throw `java.lang.OutOfMemoryError` with the given message.
///
/// Used for allocation failures (byte arrays, strings, object arrays).
pub fn throw_out_of_memory(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("java/lang/OutOfMemoryError"),
        JNIString::new(message.into()),
    );
}

/// Throw `java.io.IOException` with the given message.
///
/// Used for protobuf encoding/decoding failures and JSON serialization errors.
pub fn throw_io_exception(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("java/io/IOException"),
        JNIString::new(message.into()),
    );
}

/// Throw `java.security.GeneralSecurityException` with the given message.
///
/// Used for general cryptographic errors (key generation, nonce failures,
/// encryption/decryption setup errors not related to authentication).
pub fn throw_security_exception(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("java/security/GeneralSecurityException"),
        JNIString::new(message.into()),
    );
}

/// Throw `javax.crypto.AEADBadTagException` with the given message.
///
/// Used specifically for AEAD decryption authentication tag verification failures.
pub fn throw_aead_bad_tag(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("javax/crypto/AEADBadTagException"),
        JNIString::new(message.into()),
    );
}

/// Throw `javax.crypto.BadPaddingException` with the given message.
///
/// Used for decryption padding/format errors.
pub fn throw_bad_padding(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("javax/crypto/BadPaddingException"),
        JNIString::new(message.into()),
    );
}

/// Throw `java.security.InvalidKeyException` with the given message.
///
/// Used when provided key material is malformed or invalid.
pub fn throw_invalid_key(env: &mut JNIEnv, message: impl Into<String>) {
    throw_exception(
        env,
        jni::jni_str!("java/security/InvalidKeyException"),
        JNIString::new(message.into()),
    );
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
