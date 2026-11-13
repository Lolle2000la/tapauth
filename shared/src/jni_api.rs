//! JNI bindings for the TapAuth protocol v2 cryptographic core.
//!
//! This module is the whole Rust↔Kotlin surface used by the Android application.
//! Kotlin never parses protobuf: every `*Packet`/`*Message` argument and return value
//! is an opaque serialized protobuf blob, and every signature, AEAD operation and
//! pairing state transition happens **inside** Rust. `shared/src/jni_api/ops.rs`
//! holds the byte-level logic (and its tests); this file only converts arguments,
//! calls into `ops`, and turns failures into thrown Java exceptions.
//!
//! ## Protocol role
//!
//! Android is the protocol **Server**: it verifies `AuthenticationRequest`,
//! `GrantConfirmation` and `AuthenticationCancel` envelopes from a paired Client,
//! answers with a signed+encrypted Grant or Denial, and runs the phone half of the
//! pairing handshake. Long-term keys (CSK, `Ed_S`, and the pairing session's
//! directional keys) stay in Rust; Kotlin only receives a numeric pairing handle.
//!
//! ## Threading and Safety
//!
//! All JNI functions receive a `JNIEnv` parameter that is valid only on the calling
//! thread. `JNIEnv` is not thread-safe and must never be shared across threads or
//! stored beyond the function call. The pairing session table is the only shared
//! state and is guarded by a `Mutex`.
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
//! - `IllegalArgumentException`: malformed caller input — wrong key/challenge/session
//!   lengths, a null array, an unsupported protocol version or algorithm id, an
//!   unknown pairing handle, or a `PairingPacket` for another session.
//! - `GeneralSecurityException`: an Ed25519 signature that does not verify, an AEAD
//!   tag/AAD failure, an algorithm downgrade, a tampered temporal identifier, or a
//!   signed message of the wrong payload type.
//! - `IOException`: bytes that are not a decodable protobuf message.
//! - `IllegalStateException`: VM/JNI interop errors and internal state failures.
//!
//! After throwing, functions return `0`, `false` or `null` and must not make further
//! JNI calls. Kotlin checks the return value and handles the exception.
//!
//! ## Panics
//!
//! JNI functions must not panic, as unwinding across FFI boundaries is undefined
//! behaviour. Each entry point is wrapped in `catch_unwind`, and no code path uses
//! `unwrap`/`expect` (the crate denies them).
//!
//! ## Verification ordering
//!
//! Every parse entry point verifies the `WrapperMessage` signature **before** the
//! inner payload is decoded, and pins `payload_type` before dispatching on it. A
//! forged envelope therefore never reaches a protobuf decoder.

#![allow(non_snake_case)]

mod ops;

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobject, jobjectArray, jstring};
use jni::EnvUnowned as JNIEnv;
use zeroize::Zeroizing;

use crate::jni::arrays::make_keypair_array;
use crate::jni::conversions::{
    jbytearray_to_ed25519_keypair, jbytearray_to_fixed, jbytearray_to_vec, jstring_to_rust,
    string_to_jstring, vec_to_jbytearray,
};
use crate::jni::exceptions::{
    throw_illegal_argument, throw_illegal_state, throw_io_exception, throw_security_exception,
};
use crate::jni::objects::{create_parsed_auth_request, create_parsed_pairing_provision};

use crate::crypto::Ed25519KeyPair;
use crate::protocol::pairing::PAIRING_SESSION_ID_LEN;
use ops::JniError;

/// Length of an authentication challenge.
const CHALLENGE_LEN: usize = ops::CHALLENGE_LEN;
/// Length of the Client Symmetric Key.
const CSK_LEN: usize = ops::CSK_LEN;
/// Length of an Ed25519 public key.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

#[cfg(target_os = "android")]
use tracing_subscriber::prelude::*;

// ---------------------------------------------------------------------------
// Argument reading and result conversion
// ---------------------------------------------------------------------------

/// Throw the Java exception that `err` maps to.
fn throw(env: &mut JNIEnv, err: &JniError) {
    match err {
        JniError::Argument(message) => throw_illegal_argument(env, message.clone()),
        JniError::Security(message) => throw_security_exception(env, message.clone()),
        JniError::Io(message) => throw_io_exception(env, message.clone()),
        JniError::State(message) => throw_illegal_state(env, message.clone()),
    }
}

/// Convert an operation result into a returned `byte[]`, throwing on failure.
fn bytes_or_throw(env: &mut JNIEnv, result: Result<Vec<u8>, JniError>) -> jbyteArray {
    match result {
        Ok(bytes) => match vec_to_jbytearray(env, &bytes) {
            Some(array) => array.into_raw(),
            None => std::ptr::null_mut(),
        },
        Err(err) => {
            throw(env, &err);
            std::ptr::null_mut()
        }
    }
}

/// Convert a fixed-size operation result into a returned `byte[]`.
fn fixed_bytes_or_throw<const N: usize>(
    env: &mut JNIEnv,
    result: Result<[u8; N], JniError>,
) -> jbyteArray {
    bytes_or_throw(env, result.map(|bytes| bytes.to_vec()))
}

/// Read a 32-byte CSK argument. The Rust-side copy is zeroized on drop.
fn read_csk(env: &mut JNIEnv, csk: JByteArray) -> Option<Zeroizing<[u8; CSK_LEN]>> {
    jbytearray_to_fixed::<CSK_LEN>(env, csk, "csk").map(Zeroizing::new)
}

/// Read the 32-byte Ed25519 public key of the paired Client.
fn read_ed25519_public_key(
    env: &mut JNIEnv,
    key: JByteArray,
) -> Option<[u8; ED25519_PUBLIC_KEY_LEN]> {
    jbytearray_to_fixed::<ED25519_PUBLIC_KEY_LEN>(env, key, "clientEd25519Pub")
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 keypair for the phone's long-term identity (`Ed_S`).
///
/// ## Returns
///
/// A 2-element `Object[]` containing `[byte[] privateKey (32), byte[] publicKey (32)]`.
///
/// ## Errors
///
/// - `GeneralSecurityException`: CSPRNG failure
/// - `IllegalStateException`: class lookup or array construction fails
/// - `OutOfMemoryError`: byte array allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let keypair = match Ed25519KeyPair::generate() {
            Ok(keypair) => keypair,
            Err(err) => {
                throw_security_exception(&mut env, format!("key generation failed: {err}"));
                return std::ptr::null_mut();
            }
        };
        let private_bytes = Zeroizing::new(keypair.signing_key_bytes());
        let public_bytes = keypair.verifying_key_bytes();

        match make_keypair_array(&mut env, &*private_bytes, &public_bytes) {
            Some(array) => array,
            None => std::ptr::null_mut(),
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in generateKeypair");
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Encrypted packet (outer AEAD framing)
// ---------------------------------------------------------------------------

/// Decrypt an `EncryptedPacket` under the CSK and return the serialized
/// `WrapperMessage` bytes.
///
/// The packet's `encryption_algorithm` must equal `expectedSymAlg`; the check runs
/// before any AEAD work. The AAD is `tapauth-pkt-v2 || be32(algorithm) ||
/// be16(len) || temporal_identifier`, so a tampered identifier or a relabelled
/// algorithm fails the tag.
///
/// ## Arguments
///
/// * `encryptedPacketBytes` - serialized `EncryptedPacket`
/// * `csk` - 32-byte Client Symmetric Key
/// * `expectedSymAlg` - negotiated `SymmetricAlgorithm` id (1 = AES-256-GCM,
///   2 = ChaCha20-Poly1305)
///
/// ## Returns
///
/// The decrypted `WrapperMessage` bytes, exactly as the peer serialized them.
///
/// ## Errors
///
/// - `IllegalArgumentException`: null/short `csk`, unknown algorithm id
/// - `IOException`: `encryptedPacketBytes` is not a decodable `EncryptedPacket`
/// - `GeneralSecurityException`: algorithm mismatch, AEAD tag/AAD failure
/// - `OutOfMemoryError`: result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptEncryptedPacket(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_packet_bytes: JByteArray,
    csk: JByteArray,
    expected_symmetric_algorithm: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let csk = match read_csk(&mut env, csk) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };
        let packet_bytes =
            match jbytearray_to_vec(&mut env, encrypted_packet_bytes, "encryptedPacketBytes") {
                Some(bytes) => bytes,
                None => return std::ptr::null_mut(),
            };

        bytes_or_throw(
            &mut env,
            ops::decrypt_packet_bytes(&packet_bytes, &csk, expected_symmetric_algorithm),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in decryptEncryptedPacket");
            std::ptr::null_mut()
        }
    }
}

/// Read the 16-byte `temporal_identifier` of a serialized `EncryptedPacket`.
///
/// This is the pre-decryption filter: Kotlin can match the identifier against the
/// paired Clients' per-device CSKs before spending CPU on AEAD.
///
/// ## Errors
///
/// - `IOException`: `packetBytes` is not a decodable `EncryptedPacket`
/// - `IllegalArgumentException`: the identifier is not 16 bytes
/// - `OutOfMemoryError`: result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_extractTemporalIdentifier(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let packet_bytes = match jbytearray_to_vec(&mut env, packet_bytes, "packetBytes") {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };

        fixed_bytes_or_throw(
            &mut env,
            ops::encrypted_packet_temporal_identifier(&packet_bytes),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in extractTemporalIdentifier");
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication messages from the Client
// ---------------------------------------------------------------------------

/// Verify an `AuthenticationRequest` and return its fields.
///
/// The Ed25519 signature is verified over the raw payload bytes **before** the inner
/// protobuf is decoded, and `payload_type` must be `PAYLOAD_TYPE_AUTH_REQUEST`.
///
/// ## Arguments
///
/// * `wrapperBytes` - decrypted serialized `WrapperMessage`
/// * `clientEd25519Pub` - 32-byte public key of the paired Client
/// * `protocolVersion` - must be `2`
/// * `expectedSignatureAlgorithm` - the paired Client's persisted
///   `SignatureAlgorithm` id (`1` = ED25519); never derived from the message
///
/// ## Returns
///
/// A `ParsedAuthRequest` (challenge, username, hostname, timestampUnixSeconds,
/// pamService, processName, commandPreview, ttyPresent). The four context fields are
/// returned verbatim; Android sanitizes them for display.
///
/// ## Errors
///
/// - `IllegalArgumentException`: `protocolVersion != 2`, wrong key/challenge length
/// - `IOException`: `wrapperBytes` is not a decodable `WrapperMessage`
/// - `GeneralSecurityException`: bad signature, wrong payload type, wrong wrapper
///   version, or an `expectedSignatureAlgorithm` this build cannot verify
/// - `IllegalStateException`: `ParsedAuthRequest` cannot be constructed
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseAndVerifyAuthRequest(
    mut env: JNIEnv,
    _class: JClass,
    wrapper_bytes: JByteArray,
    client_ed25519_pub: JByteArray,
    protocol_version: jint,
    expected_signature_algorithm: jint,
) -> jobject {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let public_key = match read_ed25519_public_key(&mut env, client_ed25519_pub) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };
        let wrapper_bytes = match jbytearray_to_vec(&mut env, wrapper_bytes, "wrapperBytes") {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };

        let parsed = match ops::parse_auth_request_verified(
            &wrapper_bytes,
            &public_key,
            protocol_version,
            expected_signature_algorithm,
        ) {
            Ok(parsed) => parsed,
            Err(err) => {
                throw(&mut env, &err);
                return std::ptr::null_mut();
            }
        };

        let timestamp_unix_seconds = match i64::try_from(parsed.timestamp_unix_seconds) {
            Ok(timestamp) => timestamp,
            Err(_) => {
                throw_illegal_argument(&mut env, "timestamp is out of range");
                return std::ptr::null_mut();
            }
        };

        match create_parsed_auth_request(
            &mut env,
            &parsed.challenge,
            &parsed.username,
            &parsed.hostname,
            timestamp_unix_seconds,
            &parsed.pam_service,
            &parsed.process_name,
            &parsed.command_preview,
            parsed.tty_present,
        ) {
            Some(object) => object.into_raw(),
            None => std::ptr::null_mut(),
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in parseAndVerifyAuthRequest");
            std::ptr::null_mut()
        }
    }
}

/// Verify a `GrantConfirmation` and return the acknowledged challenge.
///
/// ## Returns
///
/// The 32-byte challenge the Client confirmed.
///
/// ## Errors
///
/// - `IllegalArgumentException`: `protocolVersion != 2`, wrong key/challenge length
/// - `IOException`: `wrapperBytes` is not a decodable `WrapperMessage`
/// - `GeneralSecurityException`: bad signature, wrong payload type, or an
///   `expectedSignatureAlgorithm` this build cannot verify
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseAndVerifyGrantConfirmation(
    mut env: JNIEnv,
    _class: JClass,
    wrapper_bytes: JByteArray,
    client_ed25519_pub: JByteArray,
    protocol_version: jint,
    expected_signature_algorithm: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let public_key = match read_ed25519_public_key(&mut env, client_ed25519_pub) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };
        let wrapper_bytes = match jbytearray_to_vec(&mut env, wrapper_bytes, "wrapperBytes") {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };

        fixed_bytes_or_throw(
            &mut env,
            ops::parse_grant_confirmation_verified(
                &wrapper_bytes,
                &public_key,
                protocol_version,
                expected_signature_algorithm,
            ),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in parseAndVerifyGrantConfirmation");
            std::ptr::null_mut()
        }
    }
}

/// Verify an `AuthenticationCancel` and return the cancelled challenge.
///
/// ## Returns
///
/// The 32-byte challenge the Client cancelled.
///
/// ## Errors
///
/// - `IllegalArgumentException`: `protocolVersion != 2`, wrong key/challenge length
/// - `IOException`: `wrapperBytes` is not a decodable `WrapperMessage`
/// - `GeneralSecurityException`: bad signature, wrong payload type, or an
///   `expectedSignatureAlgorithm` this build cannot verify
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseAndVerifyAuthCancel(
    mut env: JNIEnv,
    _class: JClass,
    wrapper_bytes: JByteArray,
    client_ed25519_pub: JByteArray,
    protocol_version: jint,
    expected_signature_algorithm: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let public_key = match read_ed25519_public_key(&mut env, client_ed25519_pub) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };
        let wrapper_bytes = match jbytearray_to_vec(&mut env, wrapper_bytes, "wrapperBytes") {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };

        fixed_bytes_or_throw(
            &mut env,
            ops::parse_auth_cancel_verified(
                &wrapper_bytes,
                &public_key,
                protocol_version,
                expected_signature_algorithm,
            ),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in parseAndVerifyAuthCancel");
            std::ptr::null_mut()
        }
    }
}

/// Name the payload type of a serialized `WrapperMessage`, for dispatch only.
///
/// The returned string is **not** authenticated; Kotlin uses it solely to choose
/// which verifying parse entry point to call next, and that entry point re-checks the
/// signature and the payload type.
///
/// ## Returns
///
/// `"AUTH_REQUEST"`, `"AUTH_GRANT"`, `"AUTH_DENIAL"`, `"GRANT_CONFIRMATION"`,
/// `"AUTH_CANCEL"` or `"UNKNOWN"`.
///
/// ## Errors
///
/// - `IOException`: `wrapperMessageBytes` is not a decodable `WrapperMessage`
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_determineMessageType(
    mut env: JNIEnv,
    _class: JClass,
    wrapper_message_bytes: JByteArray,
) -> jstring {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = match jbytearray_to_vec(&mut env, wrapper_message_bytes, "wrapperMessageBytes")
        {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };

        let message_type = match ops::message_type_name(&bytes) {
            Ok(Some(name)) => name,
            Ok(None) => "UNKNOWN",
            Err(err) => {
                throw(&mut env, &err);
                return std::ptr::null_mut();
            }
        };

        match string_to_jstring(&mut env, message_type) {
            Some(string) => string.into_raw(),
            None => std::ptr::null_mut(),
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in determineMessageType");
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Grant / Denial construction
// ---------------------------------------------------------------------------

/// Sign a Grant and return the serialized `EncryptedPacket` to send.
///
/// The single Ed25519 signature covers
/// `"tapauth-sig-v2" || be32(version) || be32(signature_algorithm) ||
/// be32(payload_type) || payload`; the packet is then AEAD-encrypted under the CSK
/// with the negotiated symmetric and hash algorithms.
///
/// ## Errors
///
/// - `IllegalArgumentException`: wrong challenge/CSK/key length, unknown algorithm id
/// - `GeneralSecurityException`: signing, temporal-identifier derivation or encryption
///   fails
/// - `IOException`: protobuf encoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createGrantWrapperMessage(
    mut env: JNIEnv,
    _class: JClass,
    challenge: JByteArray,
    server_priv_key: JByteArray,
    csk: JByteArray,
    symmetric_algorithm: jint,
    hash_algorithm: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let challenge = match jbytearray_to_fixed::<CHALLENGE_LEN>(&mut env, challenge, "challenge")
        {
            Some(challenge) => challenge,
            None => return std::ptr::null_mut(),
        };
        let keypair =
            match jbytearray_to_ed25519_keypair(&mut env, server_priv_key, "serverPrivKey") {
                Some(keypair) => keypair,
                None => return std::ptr::null_mut(),
            };
        let csk = match read_csk(&mut env, csk) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };

        bytes_or_throw(
            &mut env,
            ops::build_grant_packet(
                &challenge,
                &keypair,
                &csk,
                symmetric_algorithm,
                hash_algorithm,
            ),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in createGrantWrapperMessage");
            std::ptr::null_mut()
        }
    }
}

/// Sign a Denial and return the serialized `EncryptedPacket` to send.
///
/// `reason` travels inside the signed payload and is shown on the Client's PAM
/// prompt, so it must not contain secrets.
///
/// ## Errors
///
/// - `IllegalArgumentException`: wrong challenge/CSK/key length, unknown algorithm id
/// - `GeneralSecurityException`: signing, temporal-identifier derivation or encryption
///   fails
/// - `IOException`: protobuf encoding fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createDenialWrapperMessage(
    mut env: JNIEnv,
    _class: JClass,
    challenge: JByteArray,
    reason: JString,
    server_priv_key: JByteArray,
    csk: JByteArray,
    symmetric_algorithm: jint,
    hash_algorithm: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let challenge = match jbytearray_to_fixed::<CHALLENGE_LEN>(&mut env, challenge, "challenge")
        {
            Some(challenge) => challenge,
            None => return std::ptr::null_mut(),
        };
        let reason = match jstring_to_rust(&mut env, reason, "reason") {
            Some(reason) => reason,
            None => return std::ptr::null_mut(),
        };
        let keypair =
            match jbytearray_to_ed25519_keypair(&mut env, server_priv_key, "serverPrivKey") {
                Some(keypair) => keypair,
                None => return std::ptr::null_mut(),
            };
        let csk = match read_csk(&mut env, csk) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };

        bytes_or_throw(
            &mut env,
            ops::build_denial_packet(
                &challenge,
                &reason,
                &keypair,
                &csk,
                symmetric_algorithm,
                hash_algorithm,
            ),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in createDenialWrapperMessage");
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery: temporal identifiers
// ---------------------------------------------------------------------------

/// Derive the 16-byte UDP/GATT temporal identifier for `window`.
///
/// The identifier is `HMAC-SHA256(csk, be64(window))` (or keyed BLAKE3) truncated to
/// 16 bytes, so it proves CSK possession without revealing the key. Each paired
/// Client persists its own `hashAlgorithm`; Kotlin must pass that stored value.
///
/// ## Errors
///
/// - `IllegalArgumentException`: wrong CSK length, negative window, unknown hash
///   algorithm id
/// - `GeneralSecurityException`: derivation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateTemporalIdentifier(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    window: jlong,
    hash_algorithm: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let csk = match read_csk(&mut env, csk) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };

        fixed_bytes_or_throw(
            &mut env,
            ops::temporal_identifier(&csk, window, hash_algorithm),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in generateTemporalIdentifier");
            std::ptr::null_mut()
        }
    }
}

/// Derive the 10-byte BLE advertisement temporal identifier for `window`.
///
/// Same keyed MAC as [`Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateTemporalIdentifier`],
/// truncated to 10 bytes to fit the advertisement budget.
///
/// ## Errors
///
/// - `IllegalArgumentException`: wrong CSK length, negative window, unknown hash
///   algorithm id
/// - `GeneralSecurityException`: derivation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateBleTemporalIdentifier(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    window: jlong,
    hash_algorithm: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let csk = match read_csk(&mut env, csk) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };

        fixed_bytes_or_throw(
            &mut env,
            ops::ble_temporal_identifier(&csk, window, hash_algorithm),
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in generateBleTemporalIdentifier");
            std::ptr::null_mut()
        }
    }
}

/// The current 60-second time window (`unix_seconds / 60`).
///
/// ## Errors
///
/// - `GeneralSecurityException`: the system clock is before the Unix epoch
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_currentTimeWindow(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || match ops::time_window_now() {
            Ok(window) => window,
            Err(err) => {
                throw(&mut env, &err);
                0
            }
        },
    )) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in currentTimeWindow");
            0
        }
    }
}

/// Check a received temporal identifier against the current and previous window.
///
/// Accepts both the 16-byte UDP/GATT form and the 10-byte BLE form. Use the paired
/// Client's stored `hashAlgorithm`.
///
/// ## Returns
///
/// `true` if the identifier matches the current or previous window.
///
/// ## Errors
///
/// - `IllegalArgumentException`: wrong CSK length, identifier is neither 10 nor 16
///   bytes, unknown hash algorithm id
/// - `GeneralSecurityException`: derivation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_verifyTemporalIdentifier(
    mut env: JNIEnv,
    _class: JClass,
    temporal_identifier: JByteArray,
    csk: JByteArray,
    hash_algorithm: jint,
) -> jboolean {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let identifier =
            match jbytearray_to_vec(&mut env, temporal_identifier, "temporalIdentifier") {
                Some(bytes) => bytes,
                None => return false,
            };
        let csk = match read_csk(&mut env, csk) {
            Some(key) => key,
            None => return false,
        };

        match ops::verify_temporal_identifier(&identifier, &csk, hash_algorithm) {
            Ok(valid) => valid,
            Err(err) => {
                throw(&mut env, &err);
                false
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in verifyTemporalIdentifier");
            false
        }
    }
}

/// Derive the 10-byte BLE pairing advertisement identifier from the scanned QR code.
///
/// The value is `SHA-256("tapauth-ble-pair-v2" || sessionId || clientX25519Pub)[..10]`.
///
/// ## Arguments
///
/// * `sessionId` - 16-byte `sid` from the QR code
/// * `clientX25519Pub` - 32-byte `pk` from the QR code
///
/// ## Errors
///
/// - `IllegalArgumentException`: wrong session-id or public-key length
/// - `OutOfMemoryError`: result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_deriveBlePairingAdvId(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JByteArray,
    client_x25519_pub: JByteArray,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session_id = match jbytearray_to_vec(&mut env, session_id, "sessionId") {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };
        let public_key = match jbytearray_to_fixed::<ED25519_PUBLIC_KEY_LEN>(
            &mut env,
            client_x25519_pub,
            "clientX25519Pub",
        ) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };

        fixed_bytes_or_throw(&mut env, ops::ble_pairing_adv_id(&session_id, &public_key))
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in deriveBlePairingAdvId");
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing (phone side; stateful, keyed by an opaque handle)
// ---------------------------------------------------------------------------

/// Start a phone-side pairing session from the scanned QR code.
///
/// The session owns the ephemeral X25519 secret and the directional keys; `Ed_S` is
/// copied into Rust and never returned.
///
/// ## Arguments
///
/// * `sessionId` - 16-byte `sid` from the QR code
/// * `serverEd25519PrivKey` - 32-byte (or 64-byte keypair) private `Ed_S`
/// * `serverDeviceName` - display name, truncated to 64 UTF-8 bytes
///
/// ## Returns
///
/// A positive session handle, or `0` after throwing.
///
/// ## Errors
///
/// - `IllegalArgumentException`: wrong session-id or key length
/// - `GeneralSecurityException`: ephemeral key generation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingServerSessionCreate(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JByteArray,
    server_ed25519_priv_key: JByteArray,
    server_device_name: JString,
) -> jlong {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session_id = match jbytearray_to_fixed::<PAIRING_SESSION_ID_LEN>(
            &mut env,
            session_id,
            "sessionId",
        ) {
            Some(id) => id,
            None => return 0,
        };
        let identity = match jbytearray_to_ed25519_keypair(
            &mut env,
            server_ed25519_priv_key,
            "serverEd25519PrivKey",
        ) {
            Some(keypair) => keypair,
            None => return 0,
        };
        let device_name = match jstring_to_rust(&mut env, server_device_name, "serverDeviceName") {
            Some(name) => name,
            None => return 0,
        };

        match ops::pairing_session_create(session_id, identity, &device_name) {
            Ok(handle) => handle,
            Err(err) => {
                throw(&mut env, &err);
                0
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingServerSessionCreate");
            0
        }
    }
}

/// Drop a pairing session and zeroize its keys.
///
/// ## Errors
///
/// - `IllegalArgumentException`: the handle is unknown (already freed or never
///   created)
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingServerSessionFree(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Err(err) = ops::pairing_session_free(handle) {
            throw(&mut env, &err);
        }
    }));
}

/// Build the `PairingInit` to send (serialized `PairingPacket`).
///
/// Retransmissions must re-send these exact bytes rather than calling this again for
/// a fresh message; the cached copy is returned either way.
///
/// ## Errors
///
/// - `IllegalArgumentException`: unknown handle
/// - `IllegalStateException`: the packet cannot be encoded
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingCreateInit(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bytes_or_throw(&mut env, ops::pairing_create_init(handle))
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingCreateInit");
            std::ptr::null_mut()
        }
    }
}

/// Verify the desktop's `PairingResponse` and return the SAS to display.
///
/// The QR commitment (`client_x25519_public_key == pk`) is checked first, then the
/// Client's Ed25519 signature over the transcript hash, then the keys and SAS are
/// derived.
///
/// ## Arguments
///
/// * `responsePacket` - serialized `PairingPacket` carrying `PairingResponse`
/// * `expectedQrPk` - 32-byte `pk` from the scanned QR code
///
/// ## Returns
///
/// The SAS (for example `"123-456"`), shown to the user for comparison.
///
/// ## Errors
///
/// - `IllegalArgumentException`: unknown handle, undecodable or foreign-session
///   packet, wrong packet type or key length
/// - `GeneralSecurityException`: QR key mismatch, bad client signature, unsupported
///   algorithm selection, key derivation failure
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingVerifyResponse(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    response_packet: JByteArray,
    expected_qr_pk: JByteArray,
) -> jstring {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let packet_bytes = match jbytearray_to_vec(&mut env, response_packet, "responsePacket") {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };
        let qr_public_key = match jbytearray_to_fixed::<ED25519_PUBLIC_KEY_LEN>(
            &mut env,
            expected_qr_pk,
            "expectedQrPk",
        ) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };

        match ops::pairing_verify_response(handle, &packet_bytes, &qr_public_key) {
            Ok(sas) => match string_to_jstring(&mut env, &sas) {
                Some(string) => string.into_raw(),
                None => std::ptr::null_mut(),
            },
            Err(err) => {
                throw(&mut env, &err);
                std::ptr::null_mut()
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingVerifyResponse");
            std::ptr::null_mut()
        }
    }
}

/// Decrypt the desktop's provisioning payload (`PairingConfirmClient`).
///
/// ## Returns
///
/// A `ParsedPairingProvision` with the 32-byte CSK, the authorized username and the
/// Client hostname. The CSK must be persisted by the caller.
///
/// ## Errors
///
/// - `IllegalArgumentException`: unknown handle, undecodable or foreign-session
///   packet, wrong packet type
/// - `GeneralSecurityException`: AEAD failure, or a provisioning payload whose CSK is
///   not 32 bytes
/// - `IllegalStateException`: `ParsedPairingProvision` cannot be constructed
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingProcessConfirmClient(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    confirm_client_packet: JByteArray,
) -> jobject {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let packet_bytes =
            match jbytearray_to_vec(&mut env, confirm_client_packet, "confirmClientPacket") {
                Some(bytes) => bytes,
                None => return std::ptr::null_mut(),
            };

        let provision = match ops::pairing_process_confirm_client(handle, &packet_bytes) {
            Ok(provision) => provision,
            Err(err) => {
                throw(&mut env, &err);
                return std::ptr::null_mut();
            }
        };

        match create_parsed_pairing_provision(
            &mut env,
            &*provision.csk,
            &provision.username,
            &provision.client_hostname,
        ) {
            Some(object) => object.into_raw(),
            None => std::ptr::null_mut(),
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingProcessConfirmClient");
            std::ptr::null_mut()
        }
    }
}

/// Build the completion proof (serialized `PairingPacket` with `PairingConfirmServer`).
///
/// The phone signs `"tapauth-pair-server-sig-v2" || H || csk` with `Ed_S` and encrypts
/// it under `K_s2c`. Retransmissions must re-send the same bytes.
///
/// ## Errors
///
/// - `IllegalArgumentException`: unknown handle, wrong CSK length
/// - `GeneralSecurityException`: the session is not keyed yet, signing or encryption
///   fails
/// - `IllegalStateException`: the packet cannot be encoded
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingCreateConfirmServer(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    csk: JByteArray,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let csk = match read_csk(&mut env, csk) {
            Some(key) => key,
            None => return std::ptr::null_mut(),
        };

        bytes_or_throw(&mut env, ops::pairing_create_confirm_server(handle, &csk))
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingCreateConfirmServer");
            std::ptr::null_mut()
        }
    }
}

/// Build an abort (serialized `PairingPacket` with `PairingAbort`).
///
/// Once the session keys exist the abort carries an HMAC tag, so a network observer
/// cannot spoof a cancellation.
///
/// ## Arguments
///
/// * `reason` - `PairingAbortReason` id (1 = USER_REJECTED_SAS, 2 = KEY_MISMATCH,
///   3 = UNSUPPORTED_ALGORITHM, 4 = PROTOCOL_ERROR, 5 = SESSION_EXPIRED)
///
/// ## Errors
///
/// - `IllegalArgumentException`: unknown handle or unknown reason id
/// - `IllegalStateException`: the packet cannot be encoded
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingCreateAbort(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    reason: jint,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bytes_or_throw(&mut env, ops::pairing_create_abort(handle, reason))
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingCreateAbort");
            std::ptr::null_mut()
        }
    }
}

/// Verify an abort received from the desktop.
///
/// ## Returns
///
/// `true` for an authenticated abort, `false` for a tag-less abort received before
/// any key exists (unauthenticated by construction).
///
/// ## Errors
///
/// - `IllegalArgumentException`: unknown handle, undecodable or foreign-session
///   packet, wrong packet type
/// - `GeneralSecurityException`: bad abort tag
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingVerifyAbort(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    abort_packet: JByteArray,
) -> jboolean {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let packet_bytes = match jbytearray_to_vec(&mut env, abort_packet, "abortPacket") {
            Some(bytes) => bytes,
            None => return false,
        };

        match ops::pairing_verify_abort(handle, &packet_bytes) {
            Ok(valid) => valid,
            Err(err) => {
                throw(&mut env, &err);
                false
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingVerifyAbort");
            false
        }
    }
}

/// Extract the 16-byte `session_id` of a serialized `PairingPacket`.
///
/// Used to filter frames for the session currently pairing before spending any crypto
/// on them. A frame with a foreign protocol version or a session id that is not 16
/// bytes is rejected.
///
/// ## Errors
///
/// - `IllegalArgumentException`: undecodable packet, wrong version, wrong session-id
///   length
/// - `OutOfMemoryError`: result allocation fails
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_pairingPacketSessionId(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let packet_bytes = match jbytearray_to_vec(&mut env, packet_bytes, "packetBytes") {
            Some(bytes) => bytes,
            None => return std::ptr::null_mut(),
        };

        fixed_bytes_or_throw(&mut env, ops::pairing_packet_session_id(&packet_bytes))
    })) {
        Ok(result) => result,
        Err(_) => {
            throw_illegal_state(&mut env, "panic caught in pairingPacketSessionId");
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Logging initialization
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
static INIT_LOGGING: std::sync::Once = std::sync::Once::new();

/// Initialize native Android logcat forwarding for tracing events.
///
/// Configures a global tracing subscriber with API 30 structured log support.
/// Automatically hooks file strings, line counts, and thread naming metadata.
///
/// Must be called once after `System.loadLibrary`. Subsequent calls are no-ops
/// thanks to `std::sync::Once`.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_initLogging(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        INIT_LOGGING.call_once(|| {
            let android_layer = paranoid_android::layer("TapAuthNative")
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                .with_thread_names(true)
                .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG);

            tracing_subscriber::registry().with(android_layer).init();
        });
    }));
}
