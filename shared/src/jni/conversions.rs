//! JNI type conversions between Rust and Java.
//!
//! Provides helpers for converting between JNI types (byte arrays, strings)
//! and Rust types, with automatic exception throwing on failure.

use jni::objects::{JByteArray, JIntArray, JString};
use jni::{EnvUnowned as JNIEnv, Outcome};

use super::exceptions::{throw_illegal_argument, throw_out_of_memory};

/// Convert a JNI int array to a Rust `Vec<i32>`.
///
/// ## Returns
///
/// `Some(Vec<i32>)` on success, `None` if reading fails.
///
/// ## Errors
///
/// Throws `IllegalArgumentException` and returns `None` if the array cannot be read.
pub fn jintarray_to_vec(env: &mut JNIEnv, array: JIntArray) -> Option<Vec<i32>> {
    match env
        .with_env(|env| -> jni::errors::Result<Vec<i32>> {
            let len = array.len(env)?;
            let mut vec = vec![0i32; len];
            array.get_region(env, 0, &mut vec)?;
            Ok(vec)
        })
        .into_outcome()
    {
        Outcome::Ok(vec) => Some(vec),
        Outcome::Err(err) => {
            throw_illegal_argument(env, format!("failed to get int array length: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_illegal_argument(env, "failed to read int array: panic".to_string());
            None
        }
    }
}

/// Convert a JNI byte array to a Rust `Vec<u8>`.
///
/// ## Returns
///
/// `Some(Vec<u8>)` on success, `None` if reading fails.
///
/// ## Errors
///
/// Throws `IllegalArgumentException` and returns `None` if the array cannot be read.
pub fn jbytearray_to_vec(env: &mut JNIEnv, array: JByteArray, name: &str) -> Option<Vec<u8>> {
    match env
        .with_env(|env| env.convert_byte_array(array))
        .into_outcome()
    {
        Outcome::Ok(bytes) => Some(bytes),
        Outcome::Err(err) => {
            throw_illegal_argument(env, format!("failed to read {name}: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_illegal_argument(env, format!("failed to read {name}: panic"));
            None
        }
    }
}

/// Convert a JNI byte array to a fixed-size Rust array.
///
/// ## Returns
///
/// `Some([u8; N])` on success, `None` if reading or size conversion fails.
///
/// ## Errors
///
/// Throws `IllegalArgumentException` and returns `None` if:
/// - The array cannot be read
/// - The array length does not match `N` bytes
pub fn jbytearray_to_fixed<const N: usize>(
    env: &mut JNIEnv,
    array: JByteArray,
    name: &str,
) -> Option<[u8; N]> {
    let bytes = jbytearray_to_vec(env, array, name)?;
    match bytes.try_into() {
        Ok(fixed) => Some(fixed),
        Err(_) => {
            throw_illegal_argument(env, format!("{name} must be {N} bytes"));
            None
        }
    }
}

/// Convert a JNI string to a Rust `String`.
///
/// ## Returns
///
/// `Some(String)` on success, `None` if reading or UTF-8 conversion fails.
///
/// ## Errors
///
/// Throws `IllegalArgumentException` and returns `None` if:
/// - The string cannot be read
/// - The string contains invalid UTF-8
pub fn jstring_to_rust(env: &mut JNIEnv, string: JString, name: &str) -> Option<String> {
    match env.with_env(|env| string.try_to_string(env)).into_outcome() {
        Outcome::Ok(rust_string) => Some(rust_string),
        Outcome::Err(err) => {
            throw_illegal_argument(env, format!("failed to read {name}: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_illegal_argument(env, format!("failed to read {name}: panic"));
            None
        }
    }
}

/// Convert a Rust byte slice to a JNI byte array.
///
/// ## Returns
///
/// `Some(JByteArray)` on success, `None` if allocation fails.
///
/// ## Errors
///
/// Throws `OutOfMemoryError` and returns `None` if the array cannot be allocated.
pub fn vec_to_jbytearray<'local>(
    env: &mut JNIEnv<'local>,
    bytes: &[u8],
) -> Option<JByteArray<'local>> {
    match env
        .with_env(|env| env.byte_array_from_slice(bytes))
        .into_outcome()
    {
        Outcome::Ok(array) => Some(array),
        Outcome::Err(err) => {
            throw_out_of_memory(env, format!("failed to allocate byte array: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_out_of_memory(env, "failed to allocate byte array: panic".to_string());
            None
        }
    }
}

/// Convert a Rust string to a JNI string.
///
/// ## Returns
///
/// `Some(jstring)` on success, `None` if allocation fails.
///
/// ## Errors
///
/// Throws `OutOfMemoryError` and returns `None` if the string cannot be allocated.
pub fn string_to_jstring<'local>(
    env: &mut JNIEnv<'local>,
    string: &str,
) -> Option<JString<'local>> {
    match env.with_env(|env| env.new_string(string)).into_outcome() {
        Outcome::Ok(jstr) => Some(jstr),
        Outcome::Err(err) => {
            throw_out_of_memory(env, format!("failed to allocate string: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_out_of_memory(env, "failed to allocate string: panic".to_string());
            None
        }
    }
}

/// Load an Ed25519 keypair from a JNI byte array.
///
/// Accepts either 32 bytes (signing key) or 64 bytes (full keypair).
/// When given 64 bytes, extracts the first 32 bytes as the signing key.
///
/// ## Returns
///
/// `Some(Ed25519KeyPair)` on success, `None` if loading fails.
///
/// ## Errors
///
/// Throws `IllegalArgumentException` and returns `None` if:
/// - The array cannot be read
/// - The array is not 32 or 64 bytes
/// - The key data is invalid
pub fn jbytearray_to_ed25519_keypair(
    env: &mut JNIEnv,
    array: JByteArray,
    name: &str,
) -> Option<crate::crypto::Ed25519KeyPair> {
    use crate::crypto::Ed25519KeyPair;

    let bytes = jbytearray_to_vec(env, array, name)?;

    let signing_key = match bytes.len() {
        64 => {
            let mut key = [0u8; 32];
            // Already checked length is 64, so this slice is safe
            if let Some(slice) = bytes.get(..32) {
                key.copy_from_slice(slice);
            } else {
                // Should never happen, but be defensive
                throw_illegal_argument(env, "invalid key buffer length");
                return None;
            }
            key
        }
        32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        }
        _ => {
            throw_illegal_argument(
                env,
                format!("{name} must be 32 bytes (signing key) or 64 bytes (full keypair)"),
            );
            return None;
        }
    };

    match Ed25519KeyPair::from_signing_key_bytes(&signing_key) {
        Ok(kp) => Some(kp),
        Err(err) => {
            throw_illegal_argument(env, format!("invalid Ed25519 keypair: {err}"));
            None
        }
    }
}
