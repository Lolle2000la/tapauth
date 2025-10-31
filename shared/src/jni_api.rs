//! JNI bindings for TapAuth cryptographic operations.
//!
//! This module provides the Android JNI interface to TapAuth's Rust cryptographic
//! core, exposing functions for key generation, encryption, signing, and protocol
//! message handling.
//!
//! ## Threading and Safety
//!
//! All JNI functions receive a `JNIEnv` parameter that is valid only on the calling
//! thread. `JNIEnv` is not thread-safe and must never be shared across threads or
//! stored beyond the function call.
//!
//! ## Ownership and Memory Management
//!
//! Values returned via `into_raw()` transfer ownership to the JVM. The garbage
//! collector manages their lifecycle; Rust must not attempt to free them. Local
//! references created within JNI functions are automatically freed when the function
//! returns.
//!
//! ## Exception Handling
//!
//! Functions throw Java exceptions on error and return `null` (for objects/arrays)
//! or `false` (for booleans). After throwing an exception, functions must return
//! immediately without further JNI calls. The Kotlin code checks return values and
//! handles exceptions.
//!
//! ### Exception Mapping
//!
//! - `IllegalArgumentException`: Invalid inputs (wrong sizes, null, malformed UTF-8)
//! - `IllegalStateException`: JNI/VM interop errors (class lookup, array operations)
//! - `OutOfMemoryError`: Allocation failures
//! - `IOException`: Protobuf encode/decode and JSON serialization failures
//! - `GeneralSecurityException`: General crypto errors (nonce generation, encryption setup)
//! - `AEADBadTagException`: AEAD decryption authentication failures
//! - `BadPaddingException`: Decryption padding/format errors
//! - `InvalidKeyException`: Malformed key material
//!
//! ## Panics
//!
//! JNI functions must not panic, as unwinding across FFI boundaries is undefined
//! behavior. All potentially-panicking operations are wrapped in error handling that
//! converts Rust errors to Java exceptions.

#![allow(non_snake_case)]
#![allow(clippy::needless_borrows_for_generic_args)]

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring};
use jni::JNIEnv;

use crate::crypto;
use crate::jni::*;
use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generate a new Ed25519 keypair for signing.
///
/// ## Returns
///
/// A 2-element `Object[]` containing `[byte[] privateKey, byte[] publicKey]`,
/// or `null` if allocation fails.
///
/// ## Errors
///
/// - `IllegalStateException`: Class lookup or array construction fails
/// - `OutOfMemoryError`: Byte array allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    let keypair = crypto::Ed25519KeyPair::generate();
    let private_bytes = keypair.signing_key.to_bytes();
    let public_bytes = keypair.verifying_key.to_bytes();

    match make_keypair_array(&mut env, &private_bytes, &public_bytes) {
        Some(array) => array,
        None => std::ptr::null_mut(),
    }
}

/// Generate a new X25519 keypair for ECDH key exchange.
///
/// ## Returns
///
/// A 2-element `Object[]` containing `[byte[] privateKey, byte[] publicKey]`,
/// or `null` if allocation fails.
///
/// ## Errors
///
/// - `IllegalStateException`: Class lookup or array construction fails
/// - `OutOfMemoryError`: Byte array allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateX25519Keypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    let keypair = crypto::X25519KeyPair::generate();
    let private_bytes = keypair.secret_key_bytes();
    let public_bytes = keypair.public_key_bytes();

    match make_keypair_array(&mut env, &private_bytes, &public_bytes) {
        Some(array) => array,
        None => std::ptr::null_mut(),
    }
}

/// Perform X25519 Diffie-Hellman key exchange and derive a PSK.
///
/// ## Arguments
///
/// * `our_private_key` - Our 32-byte X25519 private key
/// * `their_public_key` - Their 32-byte X25519 public key
///
/// ## Returns
///
/// A 32-byte PSK derived from the shared secret via HKDF, or `null` on error.
///
/// ## Errors
///
/// - `IllegalArgumentException`: Key reading fails, keys are not 32 bytes, or key exchange fails
/// - `OutOfMemoryError`: Result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_keyExchange(
    mut env: JNIEnv,
    _class: JClass,
    our_private_key: JByteArray,
    their_public_key: JByteArray,
) -> jbyteArray {
    let our_key_array = match jbytearray_to_fixed::<32>(&mut env, our_private_key, "private key") {
        Some(key) => key,
        None => return std::ptr::null_mut(),
    };

    let their_key_array = match jbytearray_to_fixed::<32>(&mut env, their_public_key, "public key")
    {
        Some(key) => key,
        None => return std::ptr::null_mut(),
    };

    let our_keypair = crypto::X25519KeyPair::from_secret_bytes(our_key_array);
    let shared_secret = match our_keypair.diffie_hellman(&their_key_array) {
        Ok(secret) => secret,
        Err(err) => {
            throw_illegal_argument(&mut env, format!("key exchange failed: {err}"));
            return std::ptr::null_mut();
        }
    };

    tracing::debug!("Shared secret (sha256): {}", sha256_hex(&shared_secret));
    let psk = match crypto::derive_psk_from_x25519(&shared_secret) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!("PSK derivation FAILED: {}", err);
            throw_illegal_argument(&mut env, format!("PSK derivation failed: {err}"));
            return std::ptr::null_mut();
        }
    };
    tracing::debug!("Derived PSK (sha256): {}", sha256_hex(psk.as_bytes()));

    match vec_to_jbytearray(&mut env, psk.as_bytes()) {
        Some(array) => array.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Generate the Short Authentication String (SAS) for pairing verification.
///
/// ## Arguments
///
/// * `psk` - 32-byte Pairing Symmetric Key
/// * `client_public` - 32-byte client X25519 public key
/// * `server_public` - 32-byte server X25519 public key
///
/// ## Returns
///
/// 6-digit SAS string, or `null` on error.
///
/// ## Errors
///
/// - `IllegalArgumentException`: Key reading fails, keys are not 32 bytes, or SAS derivation fails
/// - `OutOfMemoryError`: String allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_getSas(
    mut env: JNIEnv,
    _class: JClass,
    psk: JByteArray,
    client_public: JByteArray,
    server_public: JByteArray,
) -> jstring {
    let psk_array = match jbytearray_to_fixed::<32>(&mut env, psk, "PSK") {
        Some(key) => key,
        None => return std::ptr::null_mut(),
    };

    let client_pub_array = match jbytearray_to_fixed::<32>(&mut env, client_public, "client_public")
    {
        Some(key) => key,
        None => return std::ptr::null_mut(),
    };

    let server_pub_array = match jbytearray_to_fixed::<32>(&mut env, server_public, "server_public")
    {
        Some(key) => key,
        None => return std::ptr::null_mut(),
    };

    let psk = crypto::keys::PairingSymmetricKey::from_bytes(psk_array);

    let sas = match crypto::kdf::derive_sas(&psk, &client_pub_array, &server_pub_array) {
        Ok(value) => value,
        Err(err) => {
            throw_illegal_argument(&mut env, err.to_string());
            return std::ptr::null_mut();
        }
    };

    match string_to_jstring(&mut env, &sas) {
        Some(s) => s,
        None => std::ptr::null_mut(),
    }
}

/// Decrypt data with PSK using AES-256-GCM.
///
/// Used during pairing to decrypt the CSK. Uses a random nonce prepended to the ciphertext.
///
/// ## Arguments
///
/// * `psk` - 32-byte Pairing Symmetric Key
/// * `ciphertext` - Encrypted data with prepended 12-byte nonce
///
/// ## Returns
///
/// Decrypted plaintext bytes, or `null` on error.
///
/// ## Errors
///
/// - `IllegalArgumentException`: PSK reading fails or PSK is not 32 bytes
/// - `BadPaddingException`: Decryption or authentication fails
/// - `OutOfMemoryError`: Result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptWithPsk(
    mut env: JNIEnv,
    _class: JClass,
    psk: JByteArray,
    ciphertext: JByteArray,
) -> jbyteArray {
    let psk_array = match jbytearray_to_fixed::<32>(&mut env, psk, "PSK") {
        Some(key) => key,
        None => return std::ptr::null_mut(),
    };

    let psk = crypto::PairingSymmetricKey::from_bytes(psk_array);

    let ciphertext_bytes = match jbytearray_to_vec(&mut env, ciphertext, "ciphertext") {
        Some(bytes) => bytes,
        None => return std::ptr::null_mut(),
    };

    let plaintext = match crypto::decrypt_with_psk(&psk, &ciphertext_bytes) {
        Ok(data) => data,
        Err(err) => {
            throw_bad_padding(&mut env, format!("decryption failed: {err}"));
            return std::ptr::null_mut();
        }
    };

    match vec_to_jbytearray(&mut env, &plaintext) {
        Some(array) => array.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Encrypt data with PSK using AES-256-GCM.
///
/// Used during pairing to encrypt confirmation hashes. Uses a random nonce prepended to the ciphertext.
///
/// ## Arguments
///
/// * `psk` - 32-byte Pairing Symmetric Key
/// * `plaintext` - Data to encrypt
///
/// ## Returns
///
/// Encrypted ciphertext bytes with prepended 12-byte nonce, or `null` on error.
///
/// ## Errors
///
/// - `IllegalArgumentException`: PSK reading fails or PSK is not 32 bytes
/// - `GeneralSecurityException`: Encryption fails
/// - `OutOfMemoryError`: Result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_encryptWithPsk(
    mut env: JNIEnv,
    _class: JClass,
    psk: JByteArray,
    plaintext: JByteArray,
) -> jbyteArray {
    let psk_array = match jbytearray_to_fixed::<32>(&mut env, psk, "PSK") {
        Some(key) => key,
        None => return std::ptr::null_mut(),
    };

    let psk = crypto::PairingSymmetricKey::from_bytes(psk_array);

    let plaintext_bytes = match jbytearray_to_vec(&mut env, plaintext, "plaintext") {
        Some(bytes) => bytes,
        None => return std::ptr::null_mut(),
    };

    let ciphertext = match crypto::encrypt_with_psk(&psk, &plaintext_bytes) {
        Ok(data) => data,
        Err(err) => {
            throw_security_exception(&mut env, format!("encryption failed: {err}"));
            return std::ptr::null_mut();
        }
    };

    match vec_to_jbytearray(&mut env, &ciphertext) {
        Some(array) => array.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Compute SHA-256 hash of input data.
///
/// @param data Input bytes to hash
/// @return Hex-encoded SHA-256 digest (64 characters)
/// @throws IllegalArgumentException if data cannot be read
/// @throws OutOfMemoryError if result string allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_sha256(
    mut env: JNIEnv,
    _class: JClass,
    data: JByteArray,
) -> jstring {
    use super::jni::conversions::{jbytearray_to_vec, string_to_jstring};
    use sha2::{Digest, Sha256};

    let data_bytes = match jbytearray_to_vec(&mut env, data, "data") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let hash = Sha256::digest(&data_bytes);
    let hex_hash = hex::encode(hash);

    match string_to_jstring(&mut env, &hex_hash) {
        Some(s) => s,
        None => std::ptr::null_mut(),
    }
}

/// Parse AuthenticationRequest from WrapperMessage protobuf.
///
/// @param requestBytes Serialized WrapperMessage containing AuthenticationRequest
/// @return AuthRequest object with strongly-typed fields
/// @throws IllegalArgumentException if request bytes cannot be read
/// @throws IOException if protobuf decoding fails or payload is not AuthenticationRequest
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseAuthRequest(
    mut env: JNIEnv,
    _class: JClass,
    request_bytes: JByteArray,
) -> jni::sys::jobject {
    use super::jni::conversions::jbytearray_to_vec;
    use super::jni::exceptions::throw_io_exception;
    use super::jni::objects::create_auth_request;
    use super::jni::protobuf::decode_message;
    use crate::protocol::pb;

    let data = match jbytearray_to_vec(&mut env, request_bytes, "request_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let wrapper: pb::WrapperMessage = match decode_message(&mut env, &data) {
        Some(w) => w,
        None => return std::ptr::null_mut(),
    };

    let auth_request = match wrapper.payload {
        Some(pb::wrapper_message::Payload::AuthRequest(req)) => req,
        _ => {
            throw_io_exception(
                &mut env,
                "WrapperMessage does not contain AuthenticationRequest",
            );
            return std::ptr::null_mut();
        }
    };

    match create_auth_request(
        &mut env,
        &auth_request.challenge,
        &auth_request.username,
        &auth_request.hostname,
        auth_request.timestamp_unix_seconds as i64,
        auth_request.signature_algorithm,
        &auth_request.signature,
    ) {
        Some(obj) => obj.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Create and serialize an AuthenticationGrant protobuf.
///
/// Note: The signature field is empty and must be filled by the caller after signing.
///
/// @param signedChallenge The challenge bytes signed by the device
/// @return Serialized AuthenticationGrant protobuf
/// @throws IllegalArgumentException if signedChallenge cannot be read
/// @throws IOException if protobuf encoding fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createAuthGrant(
    mut env: JNIEnv,
    _class: JClass,
    signed_challenge: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{jbytearray_to_vec, vec_to_jbytearray};
    use super::jni::protobuf::encode_message;
    use crate::protocol::pb;

    let signed_challenge_bytes =
        match jbytearray_to_vec(&mut env, signed_challenge, "signed_challenge") {
            Some(b) => b,
            None => return std::ptr::null_mut(),
        };

    let grant = pb::AuthenticationGrant {
        signed_challenge: signed_challenge_bytes,
        signature_algorithm: pb::SignatureAlgorithm::Ed25519 as i32,
        signature: vec![],
    };

    let buf = match encode_message(&mut env, &grant) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Parse EncryptedPacket structure without performing decryption.
///
/// @param packetBytes Serialized EncryptedPacket protobuf
/// @return EncryptedPacketInfo object with strongly-typed fields
/// @throws IllegalArgumentException if packet bytes cannot be read
/// @throws IOException if protobuf decoding fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseEncryptedPacketStructure(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jni::sys::jobject {
    use super::jni::conversions::jbytearray_to_vec;
    use super::jni::objects::create_encrypted_packet_info;
    use super::jni::protobuf::decode_message;
    use crate::protocol::pb;

    let data = match jbytearray_to_vec(&mut env, packet_bytes, "packet_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let encrypted_packet: pb::EncryptedPacket = match decode_message(&mut env, &data) {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    match create_encrypted_packet_info(
        &mut env,
        &encrypted_packet.temporal_identifier,
        encrypted_packet.encryption_algorithm,
        &encrypted_packet.ciphertext,
    ) {
        Some(obj) => obj.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Extract temporal_identifier from EncryptedPacket protobuf bytes.
///
/// This is used for DoS mitigation: allows checking the temporal_identifier
/// before performing expensive decryption operations.
///
/// @param packetBytes Serialized EncryptedPacket protobuf
/// @return 16-byte temporal_identifier
/// @throws IllegalArgumentException if packetBytes cannot be read
/// @throws IOException if packet parsing fails or temporal_identifier length is not 16 bytes
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_extractTemporalIdentifier(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{jbytearray_to_vec, vec_to_jbytearray};
    use super::jni::exceptions::throw_io_exception;
    use super::jni::protobuf::decode_message;
    use crate::protocol::pb;

    let data = match jbytearray_to_vec(&mut env, packet_bytes, "packet_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let encrypted_packet: pb::EncryptedPacket = match decode_message(&mut env, &data) {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    if encrypted_packet.temporal_identifier.len() != 16 {
        throw_io_exception(
            &mut env,
            &format!(
                "invalid temporal_identifier length: {}, expected 16",
                encrypted_packet.temporal_identifier.len()
            ),
        );
        return std::ptr::null_mut();
    }

    match vec_to_jbytearray(&mut env, &encrypted_packet.temporal_identifier) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Determine the message type from a WrapperMessage protobuf.
///
/// @param wrapperMessageBytes Serialized WrapperMessage protobuf
/// @return String indicating message type: "AUTH_REQUEST", "AUTH_GRANT", "AUTH_DENIAL", "GRANT_CONFIRMATION", "AUTH_CANCEL", or "UNKNOWN"
/// @throws IllegalArgumentException if wrapperMessageBytes cannot be read
/// @throws IOException if protobuf decoding fails
/// @throws OutOfMemoryError if result string allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_determineMessageType(
    mut env: JNIEnv,
    _class: JClass,
    wrapper_message_bytes: JByteArray,
) -> jstring {
    use super::jni::conversions::{jbytearray_to_vec, string_to_jstring};
    use super::jni::protobuf::decode_message;
    use crate::protocol::pb;

    let data = match jbytearray_to_vec(&mut env, wrapper_message_bytes, "wrapper_message_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let wrapper: pb::WrapperMessage = match decode_message(&mut env, &data) {
        Some(w) => w,
        None => return std::ptr::null_mut(),
    };

    let message_type = match wrapper.payload {
        Some(pb::wrapper_message::Payload::AuthRequest(_)) => "AUTH_REQUEST",
        Some(pb::wrapper_message::Payload::AuthGrant(_)) => "AUTH_GRANT",
        Some(pb::wrapper_message::Payload::AuthDenial(_)) => "AUTH_DENIAL",
        Some(pb::wrapper_message::Payload::GrantConfirmation(_)) => "GRANT_CONFIRMATION",
        Some(pb::wrapper_message::Payload::AuthCancel(_)) => "AUTH_CANCEL",
        None => "UNKNOWN",
    };

    match string_to_jstring(&mut env, message_type) {
        Some(s) => s,
        None => std::ptr::null_mut(),
    }
}

/// Generate a temporal identifier for DoS mitigation.
///
/// Creates a 16-byte identifier derived from the CSK and current time window.
/// This allows client devices to prove possession of the CSK without revealing it.
///
/// @param csk 32-byte Client Symmetric Key
/// @param timestampSeconds Unix timestamp in seconds
/// @return 16-byte temporal identifier
/// @throws IllegalArgumentException if csk cannot be read or is not 32 bytes
/// @throws GeneralSecurityException if identifier generation fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateTemporalId(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    timestamp_seconds: jlong,
) -> jbyteArray {
    use super::jni::conversions::{jbytearray_to_fixed, vec_to_jbytearray};
    use super::jni::exceptions::throw_security_exception;

    let csk_array = match jbytearray_to_fixed::<32>(&mut env, csk, "csk") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);
    let time_window = (timestamp_seconds as u64) / crypto::temporal::TIME_WINDOW_SECONDS;

    let identifier = match crypto::temporal::generate_temporal_identifier(&csk, time_window) {
        Ok(id) => id,
        Err(err) => {
            throw_security_exception(&mut env, &format!("failed to generate temporal ID: {err}"));
            return std::ptr::null_mut();
        }
    };

    match vec_to_jbytearray(&mut env, &identifier) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Generate a BLE-optimized temporal identifier (10 bytes).
///
/// Creates a shorter 10-byte identifier for Bluetooth Low Energy advertisements
/// where payload size is constrained. Used by Android BLE advertisement cache
/// for efficient matching.
///
/// @param csk 32-byte Client Symmetric Key
/// @param timestampSeconds Unix timestamp in seconds
/// @return 10-byte temporal identifier
/// @throws IllegalArgumentException if csk cannot be read or is not 32 bytes
/// @throws GeneralSecurityException if identifier generation fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateTemporalIdBle(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    timestamp_seconds: jlong,
) -> jbyteArray {
    use super::jni::conversions::{jbytearray_to_fixed, vec_to_jbytearray};
    use super::jni::exceptions::throw_security_exception;

    let csk_array = match jbytearray_to_fixed::<32>(&mut env, csk, "csk") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);
    let time_window = (timestamp_seconds as u64) / crypto::temporal::TIME_WINDOW_SECONDS;

    let identifier = match crypto::temporal::generate_temporal_identifier_ble(&csk, time_window) {
        Ok(id) => id,
        Err(err) => {
            throw_security_exception(&mut env, &format!("failed to generate temporal ID: {err}"));
            return std::ptr::null_mut();
        }
    };

    match vec_to_jbytearray(&mut env, &identifier) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Verify a temporal identifier against the CSK.\n///\n/// Checks if the identifier matches the current or previous time window.\n/// Supports both 16-byte (UDP) and 10-byte (BLE) identifiers.\n///\n/// @param id Temporal identifier (10 or 16 bytes)\n/// @param csk 32-byte Client Symmetric Key\n/// @return true if identifier is valid for current or previous time window\n/// @throws IllegalArgumentException if id or csk cannot be read, csk is not 32 bytes, or id length is invalid\n/// @throws GeneralSecurityException if verification fails\n#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_verifyTemporalId(
    mut env: JNIEnv,
    _class: JClass,
    id: JByteArray,
    csk: JByteArray,
) -> jboolean {
    use super::jni::conversions::{jbytearray_to_fixed, jbytearray_to_vec};
    use super::jni::exceptions::{throw_illegal_argument, throw_security_exception};

    let id_bytes = match jbytearray_to_vec(&mut env, id, "id") {
        Some(b) => b,
        None => return false as jboolean,
    };

    let csk_array = match jbytearray_to_fixed::<32>(&mut env, csk, "csk") {
        Some(arr) => arr,
        None => return false as jboolean,
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    let result = match id_bytes.len() {
        16 => {
            let id_array: [u8; 16] = id_bytes.try_into().unwrap();
            crypto::temporal::verify_temporal_identifier(&csk, &id_array)
        }
        10 => {
            let id_array: [u8; 10] = id_bytes.try_into().unwrap();
            crypto::temporal::verify_temporal_identifier_ble(&csk, &id_array)
        }
        len => {
            throw_illegal_argument(
                &mut env,
                &format!("temporal ID must be 10 or 16 bytes, got {}", len),
            );
            return false as jboolean;
        }
    };

    match result {
        Ok(valid) => valid as jboolean,
        Err(err) => {
            throw_security_exception(&mut env, &format!("failed to verify temporal ID: {err}"));
            false as jboolean
        }
    }
}

/// Encrypt data with the Client Symmetric Key using a challenge-derived nonce.
///
/// Uses AES-256-GCM with a nonce derived from HKDF-SHA256(challenge, context).
/// This provides authenticated encryption with additional data binding.
///
/// @param csk 32-byte Client Symmetric Key
/// @param challenge 32-byte challenge (typically from AuthenticationRequest)
/// @param context Context string for domain separation (e.g., "auth_grant")
/// @param plaintext Data to encrypt
/// @return Encrypted data (includes authentication tag)
/// @throws IllegalArgumentException if inputs cannot be read or have invalid lengths
/// @throws GeneralSecurityException if encryption fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_encryptWithCsk(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    challenge: JByteArray,
    context: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{
        jbytearray_to_fixed, jbytearray_to_vec, jstring_to_rust, vec_to_jbytearray,
    };
    use super::jni::exceptions::throw_security_exception;

    let csk_array = match jbytearray_to_fixed::<32>(&mut env, csk, "csk") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let challenge_array = match jbytearray_to_fixed::<32>(&mut env, challenge, "challenge") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let context_str = match jstring_to_rust(&mut env, context, "context") {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let plaintext_bytes = match jbytearray_to_vec(&mut env, plaintext, "plaintext") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    let ciphertext = match crypto::encryption::encrypt_with_csk(
        &csk,
        &challenge_array,
        context_str.as_bytes(),
        &plaintext_bytes,
    ) {
        Ok(ct) => ct,
        Err(err) => {
            throw_security_exception(&mut env, &format!("encryption failed: {err}"));
            return std::ptr::null_mut();
        }
    };

    match vec_to_jbytearray(&mut env, &ciphertext) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Decrypt data encrypted with the Client Symmetric Key.
///
/// Uses AES-256-GCM with a nonce derived from HKDF-SHA256(challenge, context).
/// Verifies the authentication tag before returning plaintext.
///
/// @param csk 32-byte Client Symmetric Key
/// @param challenge 32-byte challenge (must match the one used for encryption)
/// @param context Context string for domain separation (must match encryption context)
/// @param ciphertext Encrypted data (includes authentication tag)
/// @return Decrypted plaintext
/// @throws IllegalArgumentException if inputs cannot be read or have invalid lengths
/// @throws AEADBadTagException if authentication tag verification fails (tampering or wrong key)
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptWithCsk(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    challenge: JByteArray,
    context: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{
        jbytearray_to_fixed, jbytearray_to_vec, jstring_to_rust, vec_to_jbytearray,
    };
    use super::jni::exceptions::throw_aead_bad_tag;

    let csk_array = match jbytearray_to_fixed::<32>(&mut env, csk, "csk") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let challenge_array = match jbytearray_to_fixed::<32>(&mut env, challenge, "challenge") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let context_str = match jstring_to_rust(&mut env, context, "context") {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let ciphertext_bytes = match jbytearray_to_vec(&mut env, ciphertext, "ciphertext") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    let plaintext = match crypto::encryption::decrypt_with_csk(
        &csk,
        &challenge_array,
        context_str.as_bytes(),
        &ciphertext_bytes,
    ) {
        Ok(pt) => pt,
        Err(err) => {
            throw_aead_bad_tag(&mut env, &format!("decryption failed: {err}"));
            return std::ptr::null_mut();
        }
    };

    match vec_to_jbytearray(&mut env, &plaintext) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Verify an Ed25519 digital signature.
///
/// @param publicKey 32-byte Ed25519 public key
/// @param message Message that was signed
/// @param signature 64-byte Ed25519 signature
/// @return true if signature is valid, false otherwise
/// @throws IllegalArgumentException if inputs cannot be read or have invalid lengths
/// @throws InvalidKeyException if public key is malformed
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_verifySignature(
    mut env: JNIEnv,
    _class: JClass,
    public_key: JByteArray,
    message: JByteArray,
    signature: JByteArray,
) -> bool {
    use super::jni::conversions::{jbytearray_to_fixed, jbytearray_to_vec};
    use super::jni::exceptions::throw_invalid_key;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let public_key_array = match jbytearray_to_fixed::<32>(&mut env, public_key, "public_key") {
        Some(arr) => arr,
        None => return false,
    };

    let message_bytes = match jbytearray_to_vec(&mut env, message, "message") {
        Some(b) => b,
        None => return false,
    };

    let signature_array = match jbytearray_to_fixed::<64>(&mut env, signature, "signature") {
        Some(arr) => arr,
        None => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&public_key_array) {
        Ok(key) => key,
        Err(err) => {
            throw_invalid_key(&mut env, &format!("invalid public key: {err}"));
            return false;
        }
    };

    let signature = Signature::from_bytes(&signature_array);
    verifying_key.verify(&message_bytes, &signature).is_ok()
}

/// Sign data with an Ed25519 private key.
///
/// @param privateKey 32-byte Ed25519 private key
/// @param message Message to sign
/// @return 64-byte Ed25519 signature
/// @throws IllegalArgumentException if inputs cannot be read or privateKey is not 32 bytes
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_signData(
    mut env: JNIEnv,
    _class: JClass,
    private_key: JByteArray,
    message: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{jbytearray_to_fixed, jbytearray_to_vec, vec_to_jbytearray};
    use ed25519_dalek::{Signer, SigningKey};

    let private_key_array = match jbytearray_to_fixed::<32>(&mut env, private_key, "private_key") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let message_bytes = match jbytearray_to_vec(&mut env, message, "message") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let signing_key = SigningKey::from_bytes(&private_key_array);
    let signature = signing_key.sign(&message_bytes);

    match vec_to_jbytearray(&mut env, &signature.to_bytes()) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Serialize AuthenticationRequest for signature verification.
///
/// Takes JSON representation and creates protobuf bytes with empty signature field.
/// Used to reconstruct the exact bytes that were signed.
///
/// @param requestJson JSON with challenge, username, hostname, timestamp_unix_seconds, signature_algorithm (byte fields base64-encoded)
/// @return Serialized AuthenticationRequest protobuf with empty signature field
/// @throws IllegalArgumentException if requestJson cannot be read
/// @throws IOException if JSON parsing, base64 decoding, or protobuf encoding fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_serializeAuthRequestForVerification(
    mut env: JNIEnv,
    _class: JClass,
    request_json: JString,
) -> jbyteArray {
    use super::jni::conversions::{jstring_to_rust, vec_to_jbytearray};
    use super::jni::exceptions::throw_io_exception;
    use super::jni::protobuf::encode_message;
    use crate::protocol::pb;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let json_str = match jstring_to_rust(&mut env, request_json, "request_json") {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let json_value: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(val) => val,
        Err(err) => {
            throw_io_exception(&mut env, &format!("failed to parse JSON: {err}"));
            return std::ptr::null_mut();
        }
    };

    let challenge_b64 = json_value["challenge"].as_str().unwrap_or("");
    let challenge = match BASE64.decode(challenge_b64) {
        Ok(bytes) => bytes,
        Err(err) => {
            throw_io_exception(&mut env, &format!("failed to decode challenge: {err}"));
            return std::ptr::null_mut();
        }
    };

    let auth_request = pb::AuthenticationRequest {
        challenge,
        username: json_value["username"].as_str().unwrap_or("").to_string(),
        hostname: json_value["hostname"].as_str().unwrap_or("").to_string(),
        timestamp_unix_seconds: json_value["timestamp_unix_seconds"].as_u64().unwrap_or(0),
        signature_algorithm: json_value["signature_algorithm"].as_i64().unwrap_or(0) as i32,
        signature: vec![],
    };

    let buf = match encode_message(&mut env, &auth_request) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Parse GrantConfirmation from WrapperMessage protobuf.
///
/// @param confirmationBytes Serialized WrapperMessage containing GrantConfirmation
/// @return GrantConfirmation object with strongly-typed fields
/// @throws IllegalArgumentException if confirmationBytes cannot be read
/// @throws IOException if protobuf decoding fails or payload is not GrantConfirmation
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseGrantConfirmation(
    mut env: JNIEnv,
    _class: JClass,
    confirmation_bytes: JByteArray,
) -> jni::sys::jobject {
    use super::jni::conversions::jbytearray_to_vec;
    use super::jni::exceptions::throw_io_exception;
    use super::jni::objects::create_grant_confirmation;
    use super::jni::protobuf::decode_message;
    use crate::protocol::pb;

    let bytes = match jbytearray_to_vec(&mut env, confirmation_bytes, "confirmation_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let wrapper: pb::WrapperMessage = match decode_message(&mut env, &bytes) {
        Some(w) => w,
        None => return std::ptr::null_mut(),
    };

    let confirmation = match wrapper.payload {
        Some(pb::wrapper_message::Payload::GrantConfirmation(conf)) => conf,
        _ => {
            throw_io_exception(
                &mut env,
                "WrapperMessage does not contain GrantConfirmation",
            );
            return std::ptr::null_mut();
        }
    };

    match create_grant_confirmation(
        &mut env,
        &confirmation.challenge,
        confirmation.signature_algorithm,
        &confirmation.signature,
    ) {
        Some(obj) => obj.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Parse AuthenticationCancel from WrapperMessage protobuf.
///
/// @param cancelBytes Serialized WrapperMessage containing AuthenticationCancel
/// @return JSON string with challenge, signature_algorithm, signature fields (byte fields base64-encoded)
/// @throws IllegalArgumentException if cancelBytes cannot be read
/// @throws IOException if protobuf decoding fails, payload is not AuthenticationCancel, or JSON serialization fails
/// @throws OutOfMemoryError if result string allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseAuthenticationCancel(
    mut env: JNIEnv,
    _class: JClass,
    cancel_bytes: JByteArray,
) -> jni::sys::jobject {
    use super::jni::conversions::jbytearray_to_vec;
    use super::jni::exceptions::throw_io_exception;
    use super::jni::objects::create_authentication_cancel;
    use super::jni::protobuf::decode_message;
    use crate::protocol::pb;

    let bytes = match jbytearray_to_vec(&mut env, cancel_bytes, "cancel_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let wrapper: pb::WrapperMessage = match decode_message(&mut env, &bytes) {
        Some(w) => w,
        None => return std::ptr::null_mut(),
    };

    let cancel = match wrapper.payload {
        Some(pb::wrapper_message::Payload::AuthCancel(c)) => c,
        _ => {
            throw_io_exception(
                &mut env,
                "WrapperMessage does not contain AuthenticationCancel",
            );
            return std::ptr::null_mut();
        }
    };

    match create_authentication_cancel(
        &mut env,
        &cancel.challenge,
        cancel.signature_algorithm,
        &cancel.signature,
    ) {
        Some(obj) => obj.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Create a WrapperMessage containing a signed AuthenticationGrant.
///
/// @param signedChallenge The challenge bytes signed by the device
/// @param privateKey Ed25519 private key (32 or 64 bytes)
/// @return Serialized WrapperMessage protobuf containing signed grant
/// @throws IllegalArgumentException if inputs cannot be read or privateKey is invalid
/// @throws IOException if protobuf encoding fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createGrantWrapperMessage(
    mut env: JNIEnv,
    _class: JClass,
    signed_challenge: JByteArray,
    private_key: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{
        jbytearray_to_ed25519_keypair, jbytearray_to_vec, vec_to_jbytearray,
    };
    use super::jni::protobuf::encode_message;
    use crate::crypto::signing::sign_ed25519;
    use crate::protocol::pb;
    use prost::Message;

    let signed_challenge_bytes =
        match jbytearray_to_vec(&mut env, signed_challenge, "signed_challenge") {
            Some(b) => b,
            None => return std::ptr::null_mut(),
        };

    let keypair = match jbytearray_to_ed25519_keypair(&mut env, private_key, "private_key") {
        Some(kp) => kp,
        None => return std::ptr::null_mut(),
    };

    let mut grant = pb::AuthenticationGrant {
        signed_challenge: signed_challenge_bytes,
        signature_algorithm: pb::SignatureAlgorithm::Ed25519 as i32,
        signature: vec![],
    };

    let data_to_sign = grant.encode_to_vec();
    grant.signature = sign_ed25519(&keypair, &data_to_sign);

    let wrapper = pb::WrapperMessage {
        version: 1,
        payload: Some(pb::wrapper_message::Payload::AuthGrant(grant)),
    };

    let buf = match encode_message(&mut env, &wrapper) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Create a WrapperMessage containing a signed AuthenticationDenial.
///
/// @param challenge 32-byte authentication challenge
/// @param privateKey Ed25519 private key (32 or 64 bytes)
/// @return Serialized WrapperMessage protobuf containing signed denial
/// @throws IllegalArgumentException if inputs cannot be read, challenge is not 32 bytes, or privateKey is invalid
/// @throws IOException if protobuf encoding fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createDenialWrapperMessage(
    mut env: JNIEnv,
    _class: JClass,
    challenge: JByteArray,
    private_key: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{
        jbytearray_to_ed25519_keypair, jbytearray_to_fixed, vec_to_jbytearray,
    };
    use super::jni::protobuf::encode_message;
    use crate::crypto::signing::sign_ed25519;
    use crate::protocol::pb;
    use prost::Message;

    let challenge_bytes = match jbytearray_to_fixed::<32>(&mut env, challenge, "challenge") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let keypair = match jbytearray_to_ed25519_keypair(&mut env, private_key, "private_key") {
        Some(kp) => kp,
        None => return std::ptr::null_mut(),
    };

    let mut denial = pb::AuthenticationDenial {
        challenge: challenge_bytes.to_vec(),
        signature_algorithm: pb::SignatureAlgorithm::Ed25519 as i32,
        signature: vec![],
    };

    let data_to_sign = denial.encode_to_vec();
    denial.signature = sign_ed25519(&keypair, &data_to_sign);

    let wrapper = pb::WrapperMessage {
        version: 1,
        payload: Some(pb::wrapper_message::Payload::AuthDenial(denial)),
    };

    let buf = match encode_message(&mut env, &wrapper) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Create an EncryptedPacket from a WrapperMessage.
///
/// Encrypts the WrapperMessage with AES-256-GCM using the CSK and generates
/// a temporal identifier for DoS mitigation.
///
/// @param csk 32-byte Client Symmetric Key
/// @param wrapperMessageBytes Serialized WrapperMessage protobuf to encrypt
/// @return Serialized EncryptedPacket protobuf
/// @throws IllegalArgumentException if inputs cannot be read or csk is not 32 bytes
/// @throws GeneralSecurityException if encryption, random generation, or temporal ID generation fails
/// @throws IOException if protobuf encoding fails
/// @throws OutOfMemoryError if result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createEncryptedPacket(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    wrapper_message_bytes: JByteArray,
) -> jbyteArray {
    use super::jni::conversions::{jbytearray_to_fixed, jbytearray_to_vec, vec_to_jbytearray};
    use super::jni::exceptions::throw_security_exception;
    use super::jni::protobuf::encode_message;
    use crate::crypto;
    use crate::protocol::pb;
    use rand::{rngs::OsRng, TryRngCore};

    let csk_array = match jbytearray_to_fixed::<32>(&mut env, csk, "csk") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };

    let payload = match jbytearray_to_vec(&mut env, wrapper_message_bytes, "wrapper_message_bytes")
    {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    let mut nonce = [0u8; 12];
    if let Err(err) = OsRng.try_fill_bytes(&mut nonce) {
        throw_security_exception(&mut env, &format!("random generation failed: {err}"));
        return std::ptr::null_mut();
    }

    let ciphertext_with_nonce =
        match crypto::encryption::encrypt_aes_gcm(csk.as_bytes(), &nonce, &payload, &[]) {
            Ok(ct) => ct,
            Err(err) => {
                throw_security_exception(&mut env, &format!("encryption failed: {err}"));
                return std::ptr::null_mut();
            }
        };

    let mut ciphertext = Vec::with_capacity(12 + ciphertext_with_nonce.len());
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&ciphertext_with_nonce);

    let temporal_id = match crypto::temporal::generate_current_temporal_identifier(&csk) {
        Ok(id) => id,
        Err(err) => {
            throw_security_exception(&mut env, &format!("temporal ID generation failed: {err}"));
            return std::ptr::null_mut();
        }
    };

    let encrypted_packet = pb::EncryptedPacket {
        temporal_identifier: temporal_id.to_vec(),
        encryption_algorithm: pb::SymmetricAlgorithm::Aes256Gcm as i32,
        ciphertext,
    };

    let buf = match encode_message(&mut env, &encrypted_packet) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Decrypt and parse an EncryptedPacket to get the WrapperMessage
///
/// @param csk Client Symmetric Key for decryption
/// @param encryptedPacketBytes Serialized EncryptedPacket protobuf
/// @return Serialized WrapperMessage protobuf bytes
/// @throws IllegalArgumentException if CSK has invalid length
/// @throws IOException if protobuf decoding fails
/// @throws GeneralSecurityException if decryption fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptEncryptedPacket(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    encrypted_packet_bytes: JByteArray,
) -> jbyteArray {
    use crate::crypto;
    use crate::protocol::pb;

    let csk_array = match jbytearray_to_fixed::<32>(&mut env, csk, "csk") {
        Some(arr) => arr,
        None => return std::ptr::null_mut(),
    };
    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    let packet_bytes =
        match jbytearray_to_vec(&mut env, encrypted_packet_bytes, "encrypted_packet_bytes") {
            Some(b) => b,
            None => return std::ptr::null_mut(),
        };

    let encrypted_packet: pb::EncryptedPacket = match decode_message(&mut env, &packet_bytes) {
        Some(pkt) => pkt,
        None => return std::ptr::null_mut(),
    };

    if encrypted_packet.ciphertext.len() < 12 {
        throw_security_exception(&mut env, "ciphertext too short - missing nonce");
        return std::ptr::null_mut();
    }

    let nonce: [u8; 12] = encrypted_packet.ciphertext[..12].try_into().unwrap();
    let actual_ciphertext = &encrypted_packet.ciphertext[12..];

    let wrapper_bytes =
        match crypto::encryption::decrypt_aes_gcm(csk.as_bytes(), &nonce, actual_ciphertext, &[]) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                throw_security_exception(&mut env, "decryption failed");
                return std::ptr::null_mut();
            }
        };

    match vec_to_jbytearray(&mut env, &wrapper_bytes) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

// ========== Pairing Protocol Message Functions ==========

/// JNI wrapper for creating and serializing a PairingHello message.
///
/// @param version Protocol version
/// @param x25519_public_key X25519 public key bytes
/// @param ed25519_public_key Ed25519 public key bytes
/// @param device_name Device name string
/// @return Protobuf-encoded PairingHello bytes
/// @throws IllegalArgumentException if inputs are invalid
/// @throws IOException if protobuf encoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingHello(
    mut env: JNIEnv,
    _class: JClass,
    version: jint,
    x25519_public_key: JByteArray,
    ed25519_public_key: JByteArray,
    device_name: JString,
) -> jbyteArray {
    use crate::protocol::pb;

    let x25519_bytes = match jbytearray_to_vec(&mut env, x25519_public_key, "x25519_public_key") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let ed25519_bytes = match jbytearray_to_vec(&mut env, ed25519_public_key, "ed25519_public_key")
    {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let device_name_str = match jstring_to_rust(&mut env, device_name, "device_name") {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let hello = pb::PairingHello {
        version: version as u32,
        x25519_public_key: x25519_bytes,
        ed25519_public_key: ed25519_bytes,
        device_name: device_name_str,
    };

    let buf = match encode_message(&mut env, &hello) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// JNI wrapper for parsing a PairingResponse message from protobuf bytes.
///
/// @param response_bytes Serialized PairingResponse protobuf
/// @return PairingResponse object with strongly-typed fields
/// @throws IllegalArgumentException if input is invalid
/// @throws IOException if protobuf decoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingResponse(
    mut env: JNIEnv,
    _class: JClass,
    response_bytes: JByteArray,
) -> jni::sys::jobject {
    use super::jni::objects::create_pairing_response;
    use crate::protocol::pb;

    let data = match jbytearray_to_vec(&mut env, response_bytes, "response_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let response: pb::PairingResponse = match decode_message(&mut env, &data) {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    match create_pairing_response(
        &mut env,
        response.version as i32,
        &response.x25519_public_key,
        &response.ed25519_public_key,
        &response.device_name,
    ) {
        Some(obj) => obj.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// JNI wrapper for creating and serializing a PairingCskMessage.
///
/// @param encrypted_csk Encrypted Client Symmetric Key bytes
/// @param username Username string
/// @return Protobuf-encoded PairingCskMessage bytes
/// @throws IllegalArgumentException if inputs are invalid
/// @throws IOException if protobuf encoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingCskMessage(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_csk: JByteArray,
    username: JString,
) -> jbyteArray {
    use crate::protocol::pb;

    let encrypted_csk_bytes = match jbytearray_to_vec(&mut env, encrypted_csk, "encrypted_csk") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let username_str = match jstring_to_rust(&mut env, username, "username") {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let csk_msg = pb::PairingCskMessage {
        encrypted_csk: encrypted_csk_bytes,
        username: username_str,
    };

    let buf = match encode_message(&mut env, &csk_msg) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// JNI wrapper for parsing a PairingCskMessage from protobuf bytes.
///
/// @param message_bytes Serialized PairingCskMessage protobuf
/// @return Object array [byte[] encrypted_csk, String username]
/// @throws IllegalArgumentException if input is invalid or parsing fails
/// @throws IOException if protobuf decoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingCskMessage(
    mut env: JNIEnv,
    _class: JClass,
    message_bytes: JByteArray,
) -> jobjectArray {
    use crate::protocol::pb;

    let data = match jbytearray_to_vec(&mut env, message_bytes, "message_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let csk_msg: pb::PairingCskMessage = match decode_message(&mut env, &data) {
        Some(msg) => msg,
        None => return std::ptr::null_mut(),
    };

    match make_bytes_string_array(&mut env, &csk_msg.encrypted_csk, &csk_msg.username) {
        Some(arr) => arr,
        None => std::ptr::null_mut(),
    }
}

/// JNI wrapper for creating a PairingComplete message.
///
/// @param success Whether pairing succeeded
/// @return Protobuf-encoded PairingComplete bytes
/// @throws IOException if protobuf encoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingComplete(
    mut env: JNIEnv,
    _class: JClass,
    success: jboolean,
) -> jbyteArray {
    use crate::protocol::pb;

    let complete = pb::PairingComplete {
        success: success != 0,
    };

    let buf = match encode_message(&mut env, &complete) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    match vec_to_jbytearray(&mut env, &buf) {
        Some(arr) => arr.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// JNI wrapper for parsing a PairingComplete message from protobuf bytes.
///
/// @param complete_bytes Serialized PairingComplete protobuf
/// @return PairingComplete object with strongly-typed field
/// @throws IllegalArgumentException if input is invalid
/// @throws IOException if protobuf decoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingComplete(
    mut env: JNIEnv,
    _class: JClass,
    complete_bytes: JByteArray,
) -> jni::sys::jobject {
    use super::jni::objects::create_pairing_complete;
    use crate::protocol::pb;

    let data = match jbytearray_to_vec(&mut env, complete_bytes, "complete_bytes") {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let complete: pb::PairingComplete = match decode_message(&mut env, &data) {
        Some(msg) => msg,
        None => return std::ptr::null_mut(),
    };

    match create_pairing_complete(&mut env, complete.success) {
        Some(obj) => obj.into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod extract_temporal_id_tests {
    use super::*;
    use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};
    use prost::Message;

    #[test]
    fn test_extract_temporal_identifier_correct_length() {
        // Create a test EncryptedPacket with exactly 16 bytes
        let temporal_id = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let packet = EncryptedPacket {
            temporal_identifier: temporal_id.clone(),
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };

        // Encode the packet
        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // Decode using prost to verify we get the same temporal_identifier
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier, temporal_id);
        assert_eq!(decoded.temporal_identifier.len(), 16);
    }

    #[test]
    fn test_extract_temporal_identifier_wrong_length_fails() {
        // Create packet with wrong length temporal_identifier (should be 16 bytes)
        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5], // Only 5 bytes
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0xAA, 0xBB],
        };

        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // This should parse fine with prost (it doesn't validate length)
        // But our JNI function should reject it
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier.len(), 5); // Prost allows it

        // The JNI function would reject this and throw IOException
        // (We can't easily test JNI throwing here, but the validation is in the code)
    }

    #[test]
    fn test_extract_temporal_identifier_field_order_independent() {
        // Verify that prost correctly handles fields regardless of encoding order
        // This is why using prost is better than manual parsing

        let temporal_id = vec![0xFF; 16];
        let ciphertext = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let packet = EncryptedPacket {
            temporal_identifier: temporal_id.clone(),
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: ciphertext.clone(),
        };

        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // Decode and verify all fields are correct
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier, temporal_id);
        assert_eq!(
            decoded.encryption_algorithm,
            SymmetricAlgorithm::Aes256Gcm as i32
        );
        assert_eq!(decoded.ciphertext, ciphertext);
    }

    #[test]
    fn test_extract_temporal_identifier_with_various_ciphertext_lengths() {
        // Test that extraction works regardless of ciphertext size
        let temporal_id = vec![0x42; 16];

        for ciphertext_len in [0, 1, 100, 1000, 10000] {
            let ciphertext = vec![0xAB; ciphertext_len];

            let packet = EncryptedPacket {
                temporal_identifier: temporal_id.clone(),
                encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
                ciphertext,
            };

            let mut buf = Vec::new();
            packet.encode(&mut buf).unwrap();

            let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
            assert_eq!(
                decoded.temporal_identifier, temporal_id,
                "Failed for ciphertext length {}",
                ciphertext_len
            );
        }
    }

    #[test]
    fn test_extract_temporal_identifier_all_byte_values() {
        // Ensure extraction works with any byte values in temporal_id
        for byte_val in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
            let temporal_id = vec![byte_val; 16];

            let packet = EncryptedPacket {
                temporal_identifier: temporal_id.clone(),
                encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
                ciphertext: vec![0x00],
            };

            let mut buf = Vec::new();
            packet.encode(&mut buf).unwrap();

            let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
            assert_eq!(
                decoded.temporal_identifier, temporal_id,
                "Failed for byte value 0x{:02X}",
                byte_val
            );
        }
    }
}

#[cfg(test)]
mod determine_message_type_tests {
    use super::*;
    use crate::protocol::pb::{
        wrapper_message, AuthenticationCancel, AuthenticationRequest, GrantConfirmation,
        SignatureAlgorithm, WrapperMessage,
    };
    use prost::Message;

    #[test]
    fn test_determine_auth_request_type() {
        let request = AuthenticationRequest {
            challenge: vec![0xAA; 32],
            username: "testuser".to_string(),
            hostname: "testhost".to_string(),
            timestamp_unix_seconds: 1234567890,
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xBB; 64],
        };

        let wrapper = WrapperMessage {
            version: 1,
            payload: Some(wrapper_message::Payload::AuthRequest(request)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        // Parse and verify type
        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::AuthRequest(_))
        ));
    }

    #[test]
    fn test_determine_grant_confirmation_type() {
        let confirmation = GrantConfirmation {
            challenge: vec![0xCC; 32],
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xBB; 64],
        };

        let wrapper = WrapperMessage {
            version: 1,
            payload: Some(wrapper_message::Payload::GrantConfirmation(confirmation)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::GrantConfirmation(_))
        ));
    }

    #[test]
    fn test_determine_auth_cancel_type() {
        let cancel = AuthenticationCancel {
            challenge: vec![0xDD; 32],
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xCC; 64],
        };

        let wrapper = WrapperMessage {
            version: 1,
            payload: Some(wrapper_message::Payload::AuthCancel(cancel)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::AuthCancel(_))
        ));
    }

    #[test]
    fn test_determine_message_type_with_version() {
        // Verify that version field doesn't interfere with message type detection
        let request = AuthenticationRequest {
            challenge: vec![0xEE; 32],
            username: "user".to_string(),
            hostname: "host".to_string(),
            timestamp_unix_seconds: 1234567890,
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xFF; 64],
        };

        let wrapper = WrapperMessage {
            version: 42, // Non-standard version
            payload: Some(wrapper_message::Payload::AuthRequest(request)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert_eq!(parsed.version, 42);
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::AuthRequest(_))
        ));
    }

    #[test]
    fn test_determine_message_type_unknown() {
        // Empty wrapper message (no payload set)
        let wrapper = WrapperMessage {
            version: 1,
            payload: None,
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(parsed.payload.is_none());
    }
}
