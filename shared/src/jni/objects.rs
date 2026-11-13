//! JNI helpers for creating Java objects.
//!
//! Provides strongly-typed wrappers for creating Java data transfer objects
//! instead of using error-prone JSON string serialization. Only the three objects the
//! protocol v2 surface returns are built here; every other result is an opaque
//! protobuf `byte[]` or a primitive.

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

/// Create a `ParsedAuthRequest` Java object from a verified request.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.ParsedAuthRequest`
///
/// ## Constructor signature
///
/// ```kotlin
/// data class ParsedAuthRequest(
///     val challenge: ByteArray,
///     val username: String,
///     val hostname: String,
///     val timestampUnixSeconds: Long,
///     val pamService: String,
///     val processName: String,
///     val commandPreview: String,
///     val ttyPresent: Boolean
/// )
/// ```
///
/// JVM descriptor: `([BLjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V`
#[allow(clippy::too_many_arguments)]
pub fn create_parsed_auth_request<'local>(
    env: &mut JNIEnv<'local>,
    challenge: &[u8],
    username: &str,
    hostname: &str,
    timestamp_unix_seconds: i64,
    pam_service: &str,
    process_name: &str,
    command_preview: &str,
    tty_present: bool,
) -> Option<JObject<'local>> {
    let challenge_array = vec_to_jbytearray(env, challenge)?;
    let username_str = string_to_jstring(env, username)?;
    let hostname_str = string_to_jstring(env, hostname)?;
    let pam_service_str = string_to_jstring(env, pam_service)?;
    let process_name_str = string_to_jstring(env, process_name)?;
    let command_preview_str = string_to_jstring(env, command_preview)?;

    let args = [
        JValue::Object(&challenge_array),
        JValue::Object(username_str.as_ref()),
        JValue::Object(hostname_str.as_ref()),
        JValue::Long(timestamp_unix_seconds),
        JValue::Object(pam_service_str.as_ref()),
        JValue::Object(process_name_str.as_ref()),
        JValue::Object(command_preview_str.as_ref()),
        JValue::Bool(tty_present),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/ParsedAuthRequest",
        "([BLjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V",
        &args,
    )
}

/// Create a `ParsedPairingProvision` Java object from a decrypted provisioning payload.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.ParsedPairingProvision`
///
/// ## Constructor signature
///
/// ```kotlin
/// data class ParsedPairingProvision(
///     val csk: ByteArray,
///     val username: String,
///     val clientHostname: String
/// )
/// ```
///
/// JVM descriptor: `([BLjava/lang/String;Ljava/lang/String;)V`
pub fn create_parsed_pairing_provision<'local>(
    env: &mut JNIEnv<'local>,
    csk: &[u8],
    username: &str,
    client_hostname: &str,
) -> Option<JObject<'local>> {
    let csk_array = vec_to_jbytearray(env, csk)?;
    let username_str = string_to_jstring(env, username)?;
    let client_hostname_str = string_to_jstring(env, client_hostname)?;

    let args = [
        JValue::Object(&csk_array),
        JValue::Object(username_str.as_ref()),
        JValue::Object(client_hostname_str.as_ref()),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/ParsedPairingProvision",
        "([BLjava/lang/String;Ljava/lang/String;)V",
        &args,
    )
}

/// Create a `ParsedPairingResponse` Java object from a verified pairing response.
///
/// The values here are what the phone must persist for the new paired device (its
/// `Ed_C` and the negotiated algorithms) plus the SAS the user compares. The
/// directional keys, the transcript hash and the ephemeral secrets stay in Rust,
/// behind the pairing handle.
///
/// Corresponds to: `dev.rourunisen.tapauth.crypto.ParsedPairingResponse`
///
/// ## Constructor signature
///
/// ```kotlin
/// data class ParsedPairingResponse(
///     val sas: String,
///     val clientEd25519PublicKey: ByteArray,
///     val symmetricAlgorithm: Int,
///     val hashAlgorithm: Int,
///     val signatureAlgorithm: Int,
/// )
/// ```
///
/// JVM descriptor: `(Ljava/lang/String;[BIII)V`
pub fn create_parsed_pairing_response<'local>(
    env: &mut JNIEnv<'local>,
    sas: &str,
    client_ed25519_public_key: &[u8],
    symmetric_algorithm: i32,
    hash_algorithm: i32,
    signature_algorithm: i32,
) -> Option<JObject<'local>> {
    let sas_str = string_to_jstring(env, sas)?;
    let public_key_array = vec_to_jbytearray(env, client_ed25519_public_key)?;

    let args = [
        JValue::Object(sas_str.as_ref()),
        JValue::Object(&public_key_array),
        JValue::Int(symmetric_algorithm),
        JValue::Int(hash_algorithm),
        JValue::Int(signature_algorithm),
    ];

    create_object(
        env,
        "dev/rourunisen/tapauth/crypto/ParsedPairingResponse",
        "(Ljava/lang/String;[BIII)V",
        &args,
    )
}
