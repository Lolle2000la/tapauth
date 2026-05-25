//! JNI helpers for creating Java objects.
//!
//! Provides strongly-typed wrappers for creating Java data transfer objects
//! instead of using error-prone JSON string serialization.

use jni::objects::{JObject, JValue};
use jni::signature::RuntimeMethodSignature;
use jni::strings::JNIString;
use jni::{EnvUnowned as JNIEnv, Outcome};

use super::conversions::{string_to_jstring, vec_to_jbytearray};
use super::exceptions::throw_illegal_state;

/// Create a Java object by calling its constructor with the given arguments.
///
/// ## Returns
///
/// `Some(JObject)` on success, `None` if class lookup, constructor lookup, or object creation fails.
///
/// ## Errors
///
/// Throws `IllegalStateException` and returns `None` on any failure.
fn create_object<'local>(
    env: &mut JNIEnv<'local>,
    class_name: &str,
    constructor_sig: &str,
    args: &[JValue],
) -> Option<JObject<'local>> {
    let class_name_jni = JNIString::new(class_name);
    let constructor_sig = match RuntimeMethodSignature::from_str(constructor_sig) {
        Ok(sig) => sig,
        Err(err) => {
            throw_illegal_state(
                env,
                format!("failed to parse constructor signature {constructor_sig}: {err}"),
            );
            return None;
        }
    };

    // Find the class
    let class = match env
        .with_env(|env| env.find_class(&class_name_jni))
        .into_outcome()
    {
        Outcome::Ok(cls) => cls,
        Outcome::Err(err) => {
            throw_illegal_state(env, format!("failed to find class {}: {}", class_name, err));
            return None;
        }
        Outcome::Panic(_) => {
            throw_illegal_state(env, format!("failed to find class {}: panic", class_name));
            return None;
        }
    };

    // Create the object
    match env
        .with_env(|env| env.new_object(class, constructor_sig.method_signature(), args))
        .into_outcome()
    {
        Outcome::Ok(obj) => Some(obj),
        Outcome::Err(err) => {
            throw_illegal_state(
                env,
                format!("failed to create object of type {}: {}", class_name, err),
            );
            None
        }
        Outcome::Panic(_) => {
            throw_illegal_state(
                env,
                format!("failed to create object of type {}: panic", class_name),
            );
            None
        }
    }
}

/// Create an AuthenticationRequest Java object.
///
/// Corresponds to: `dev.rourunisen.tapauth.data.AuthRequest`
///
/// ## Constructor signature
/// ```kotlin
/// data class AuthRequest(
///     val challenge: ByteArray,
///     val username: String,
///     val hostname: String,
///     val timestampUnixSeconds: Long,
///     val signatureAlgorithm: Int,
///     val signature: ByteArray
/// )
/// ```
pub fn create_auth_request<'local>(
    env: &mut JNIEnv<'local>,
    challenge: &[u8],
    username: &str,
    hostname: &str,
    timestamp_unix_seconds: i64,
    signature_algorithm: i32,
    signature: &[u8],
) -> Option<JObject<'local>> {
    let challenge_array = vec_to_jbytearray(env, challenge)?;
    let username_str = string_to_jstring(env, username)?;
    let hostname_str = string_to_jstring(env, hostname)?;
    let signature_array = vec_to_jbytearray(env, signature)?;

    let args = [
        JValue::Object(&challenge_array),
        JValue::Object(username_str.as_ref()),
        JValue::Object(hostname_str.as_ref()),
        JValue::Long(timestamp_unix_seconds),
        JValue::Int(signature_algorithm),
        JValue::Object(&signature_array),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/AuthRequest",
        "([BLjava/lang/String;Ljava/lang/String;JI[B)V",
        &args,
    )
}

/// Create a GrantConfirmation Java object.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.GrantConfirmation`
///
/// ## Constructor signature
/// ```kotlin
/// data class GrantConfirmation(
///     val challenge: ByteArray,
///     val signatureAlgorithm: Int,
///     val signature: ByteArray
/// )
/// ```
pub fn create_grant_confirmation<'local>(
    env: &mut JNIEnv<'local>,
    challenge: &[u8],
    signature_algorithm: i32,
    signature: &[u8],
) -> Option<JObject<'local>> {
    let challenge_array = vec_to_jbytearray(env, challenge)?;
    let signature_array = vec_to_jbytearray(env, signature)?;

    let args = [
        JValue::Object(&challenge_array),
        JValue::Int(signature_algorithm),
        JValue::Object(&signature_array),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/GrantConfirmation",
        "([BI[B)V",
        &args,
    )
}

/// Create an AuthenticationCancel Java object.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.AuthenticationCancel`
///
/// ## Constructor signature
/// ```kotlin
/// data class AuthenticationCancel(
///     val challenge: ByteArray,
///     val signatureAlgorithm: Int,
///     val signature: ByteArray
/// )
/// ```
pub fn create_authentication_cancel<'local>(
    env: &mut JNIEnv<'local>,
    challenge: &[u8],
    signature_algorithm: i32,
    signature: &[u8],
) -> Option<JObject<'local>> {
    let challenge_array = vec_to_jbytearray(env, challenge)?;
    let signature_array = vec_to_jbytearray(env, signature)?;

    let args = [
        JValue::Object(&challenge_array),
        JValue::Int(signature_algorithm),
        JValue::Object(&signature_array),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/AuthenticationCancel",
        "([BI[B)V",
        &args,
    )
}

/// Create a PairingResponse Java object.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.PairingResponse`
///
/// ## Constructor signature
/// ```kotlin
/// data class PairingResponse(
///     val version: Int,
///     val x25519PublicKey: ByteArray,
///     val ed25519PublicKey: ByteArray,
///     val deviceName: String,
///     val selectedSymmetricAlgorithm: Int,
///     val selectedHashAlgorithm: Int,
///     val selectedSignatureAlgorithm: Int
/// )
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_pairing_response<'local>(
    env: &mut JNIEnv<'local>,
    version: i32,
    x25519_public_key: &[u8],
    ed25519_public_key: &[u8],
    device_name: &str,
    selected_symmetric_algorithm: i32,
    selected_hash_algorithm: i32,
    selected_signature_algorithm: i32,
) -> Option<JObject<'local>> {
    let x25519_array = vec_to_jbytearray(env, x25519_public_key)?;
    let ed25519_array = vec_to_jbytearray(env, ed25519_public_key)?;
    let device_name_str = string_to_jstring(env, device_name)?;

    let args = [
        JValue::Int(version),
        JValue::Object(&x25519_array),
        JValue::Object(&ed25519_array),
        JValue::Object(device_name_str.as_ref()),
        JValue::Int(selected_symmetric_algorithm),
        JValue::Int(selected_hash_algorithm),
        JValue::Int(selected_signature_algorithm),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/PairingResponse",
        "(I[B[BLjava/lang/String;III)V",
        &args,
    )
}

/// Create a PairingComplete Java object.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.PairingComplete`
///
/// ## Constructor signature
/// ```kotlin
/// data class PairingComplete(
///     val success: Boolean,
///     val hashAlgorithm: Int,
///     val encryptedCskHash: ByteArray
/// )
/// ```
pub fn create_pairing_complete<'local>(
    env: &mut JNIEnv<'local>,
    success: bool,
    hash_algorithm: i32,
    encrypted_csk_hash: &[u8],
) -> Option<JObject<'local>> {
    let hash_array = vec_to_jbytearray(env, encrypted_csk_hash)?;

    let args = [
        JValue::Bool(success),
        JValue::Int(hash_algorithm),
        JValue::Object(&hash_array),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/PairingComplete",
        "(ZI[B)V",
        &args,
    )
}

/// Create an EncryptedPacketInfo Java object.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.EncryptedPacketInfo`
///
/// ## Constructor signature
/// ```kotlin
/// data class EncryptedPacketInfo(
///     val temporalIdentifier: ByteArray,
///     val encryptionAlgorithm: Int,
///     val ciphertext: ByteArray
/// )
/// ```
pub fn create_encrypted_packet_info<'local>(
    env: &mut JNIEnv<'local>,
    temporal_identifier: &[u8],
    encryption_algorithm: i32,
    ciphertext: &[u8],
) -> Option<JObject<'local>> {
    let temporal_id_array = vec_to_jbytearray(env, temporal_identifier)?;
    let ciphertext_array = vec_to_jbytearray(env, ciphertext)?;

    let args = [
        JValue::Object(&temporal_id_array),
        JValue::Int(encryption_algorithm),
        JValue::Object(&ciphertext_array),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/EncryptedPacketInfo",
        "([BI[B)V",
        &args,
    )
}
