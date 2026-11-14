//! Byte-level protocol operations behind the Android JNI exports.
//!
//! Every decision the JNI surface makes — protobuf decoding, algorithm pinning,
//! "verify the signature before decoding the inner message", AEAD framing, and the
//! pairing-session handle table — lives here, so it can be exercised by
//! `cargo test --features jni` without a JVM. [`super`] (the `jni_api` module) only
//! converts arguments, calls into this module, and translates [`JniError`] into a
//! thrown Java exception.
//!
//! None of these functions `unwrap`, `expect` or panic: every failure is a
//! [`JniError`] carrying the exception class it must surface as.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};

use prost::Message as ProstMessage;
use zeroize::Zeroizing;

use crate::crypto::{
    current_time_window, decrypt_with_csk_and_prepended_nonce, encrypted_packet_aad,
    generate_ble_temporal_id_with_alg, generate_temporal_id_with_alg,
    verify_ble_temporal_identifier_with_alg, verify_temporal_identifier_with_alg,
    ClientSymmetricKey, CryptoError, Ed25519KeyPair,
};
use crate::protocol::messages::{
    create_signed_auth_denial, create_signed_auth_grant, verify_and_decode_payload, DecodedPayload,
    ProtocolError, PROTOCOL_VERSION_V2,
};
use crate::protocol::packet::create_encrypted_packet_with_csk_nonce;
use crate::protocol::pairing::{
    decode_pairing_packet, encode_pairing_packet, pairing_session_id, ClientPairingSession,
    PAIRING_SESSION_ID_LEN,
};
use crate::protocol::pb::{
    pairing_packet, EncryptedPacket, HashAlgorithm, PairingAbortReason, PairingKeepalive,
    PairingPacket, PayloadType, SignatureAlgorithm, SymmetricAlgorithm, WrapperMessage,
};

/// Length of an authentication challenge (`AuthenticationRequest.challenge`).
pub(crate) const CHALLENGE_LEN: usize = 32;

/// Length of the Client Symmetric Key.
pub(crate) const CSK_LEN: usize = 32;

/// Length of the UDP/GATT temporal identifier.
///
/// Taken from the packet layer so the Kotlin-facing path and
/// `decrypt_encrypted_packet_with_csk_nonce` cannot disagree on the rule.
pub(crate) const TEMPORAL_ID_LEN: usize = crate::protocol::packet::TEMPORAL_IDENTIFIER_LEN;

/// Length of the BLE advertisement temporal identifier.
pub(crate) const BLE_TEMPORAL_ID_LEN: usize = 10;

/// A failure that must be reported to Kotlin as an exception.
///
/// The variant fixes the Java exception class: `Argument` →
/// `java.lang.IllegalArgumentException`, `Security` →
/// `java.security.GeneralSecurityException`, `Io` → `java.io.IOException`,
/// `State` → `java.lang.IllegalStateException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JniError {
    /// Malformed caller input: wrong lengths, an unsupported caller-chosen
    /// negotiation algorithm id, or an unknown handle.
    Argument(String),
    /// Signature, AEAD, algorithm-binding or protocol-integrity failure.
    Security(String),
    /// A protobuf blob that cannot be decoded.
    Io(String),
    /// A JNI/VM or internal-state failure.
    State(String),
}

impl From<CryptoError> for JniError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidSignature => Self::Security("invalid signature".to_string()),
            other => Self::Security(format!("cryptographic failure: {other}")),
        }
    }
}

impl From<ProtocolError> for JniError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::Serialization(inner) => {
                Self::Io(format!("protobuf encode failed: {inner}"))
            }
            ProtocolError::Deserialization(inner) => {
                Self::Io(format!("protobuf decode failed: {inner}"))
            }
            ProtocolError::Io(inner) => Self::Io(format!("io failure: {inner}")),
            ProtocolError::InvalidSignature => Self::Security("invalid signature".to_string()),
            ProtocolError::Crypto(inner) => inner.into(),
            ProtocolError::AlgorithmMismatch => {
                Self::Security("algorithm mismatch between peer and local policy".to_string())
            }
            ProtocolError::UnsupportedAlgorithm => {
                Self::Security("peer selected an unsupported algorithm".to_string())
            }
            ProtocolError::ChallengeMismatch => {
                Self::Security("challenge does not match the session".to_string())
            }
            ProtocolError::MissingField(field) => {
                Self::Security(format!("signed message is missing required field {field}"))
            }
            ProtocolError::InvalidMessageFormat => {
                Self::Security("malformed or unexpected protocol message".to_string())
            }
        }
    }
}

/// An `AuthenticationRequest` whose Ed25519 signature has already been verified.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedAuthRequest {
    /// 32-byte challenge the Server (phone) must answer with a Grant or Denial.
    pub(crate) challenge: [u8; CHALLENGE_LEN],
    /// Target Linux account.
    pub(crate) username: String,
    /// Client hostname.
    pub(crate) hostname: String,
    /// Client wall-clock time, Unix seconds.
    pub(crate) timestamp_unix_seconds: u64,
    /// PAM service that triggered the request (verbatim, already sanitized by the Client).
    pub(crate) pam_service: String,
    /// Process name that triggered the request (verbatim).
    pub(crate) process_name: String,
    /// Truncated command line for display (verbatim).
    pub(crate) command_preview: String,
    /// Whether the requesting session has a terminal.
    pub(crate) tty_present: bool,
}

/// The provisioning payload of `PairingConfirmClient`, after AEAD decryption.
#[derive(Debug, Clone)]
pub(crate) struct ProvisionedClient {
    /// The CSK the desktop provisioned; must be persisted by the phone.
    pub(crate) csk: Zeroizing<[u8; CSK_LEN]>,
    /// Linux account this pairing authorizes.
    pub(crate) username: String,
    /// Authenticated Client hostname.
    pub(crate) client_hostname: String,
}

/// A `PairingResponse` whose QR commitment, signature and algorithm selection all
/// verified on the phone.
///
/// These are exactly the values the phone persists for the new paired device (its
/// static `Ed_C` and the three negotiated algorithms) plus the SAS the two users
/// compare out of band. `H`, `K_c2s`, `K_s2c` and the ephemeral secrets are
/// deliberately absent: they stay behind the pairing handle, in Rust.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedPairingResponse {
    /// The SAS to display, for example `"123-456"`.
    pub(crate) sas: String,
    /// The desktop's static `Ed_C`, persisted as the paired device's public key.
    pub(crate) client_ed25519_public_key: [u8; 32],
    /// Negotiated AEAD algorithm (client-wide, bound to the CSK).
    pub(crate) symmetric_algorithm: i32,
    /// Negotiated hash algorithm (client-wide, bound to the CSK).
    pub(crate) hash_algorithm: i32,
    /// Negotiated signature algorithm (per-server).
    pub(crate) signature_algorithm: i32,
}

// ---------------------------------------------------------------------------
// Post-pairing authentication messages (Android is the protocol Server)
// ---------------------------------------------------------------------------

/// Require the caller's pinned protocol version to be v2.
///
/// `protocol_version` is the paired Client's **persisted** `protocolVersion`, the
/// same record field [`signature_algorithm`] is drawn from, so an unsupported value
/// is reported as a security failure rather than a caller-argument error: the stored
/// pairing cannot be used, and Kotlin must reject the request instead of treating it
/// as a programming mistake on its own side.
fn check_protocol_version(protocol_version: i32) -> Result<(), JniError> {
    if protocol_version != PROTOCOL_VERSION_V2 as i32 {
        return Err(JniError::Security(format!(
            "unsupported protocol version {protocol_version} (this build speaks only v{PROTOCOL_VERSION_V2})"
        )));
    }
    Ok(())
}

/// Decode `EncryptedPacket` bytes.
fn decode_encrypted_packet(packet_bytes: &[u8]) -> Result<EncryptedPacket, JniError> {
    EncryptedPacket::decode(packet_bytes)
        .map_err(|err| JniError::Io(format!("invalid EncryptedPacket: {err}")))
}

/// Decode `WrapperMessage` bytes.
fn decode_wrapper(wrapper_bytes: &[u8]) -> Result<WrapperMessage, JniError> {
    WrapperMessage::decode(wrapper_bytes)
        .map_err(|err| JniError::Io(format!("invalid WrapperMessage: {err}")))
}

/// Reject a signed envelope that does not declare the v2 framing.
///
/// `version` is part of the signing transcript, so a non-v2 value is either a
/// misbehaving peer or a replayed v1 frame; both are refused before any decode.
fn check_wrapper_version(wrapper: &WrapperMessage) -> Result<(), JniError> {
    if wrapper.version != PROTOCOL_VERSION_V2 {
        return Err(JniError::Security(format!(
            "unexpected wrapper version {} (this build speaks only v{PROTOCOL_VERSION_V2})",
            wrapper.version
        )));
    }
    Ok(())
}

/// Require `wrapper.payload_type` to name the message the caller is waiting for.
///
/// `payload_type` is covered by the signature; checking it first keeps the parse
/// entry points from dispatching on an attacker-chosen tag.
fn require_payload_type(wrapper: &WrapperMessage, expected: PayloadType) -> Result<(), JniError> {
    if wrapper.payload_type != expected as i32 {
        return Err(JniError::Security(format!(
            "unexpected payload type {} (expected {})",
            wrapper.payload_type, expected as i32
        )));
    }
    Ok(())
}

/// Convert a decoded `challenge` field into its fixed 32-byte form.
fn challenge_32(challenge: &[u8]) -> Result<[u8; CHALLENGE_LEN], JniError> {
    challenge.try_into().map_err(|_| {
        JniError::Argument(format!(
            "challenge must be {CHALLENGE_LEN} bytes, got {}",
            challenge.len()
        ))
    })
}

/// Decrypt an `EncryptedPacket` under the CSK and return the raw `WrapperMessage` bytes.
///
/// The packet's `encryption_algorithm` must equal the caller's pinned algorithm; the
/// check runs **before** any AEAD work so a downgrade is reported as such. A
/// `temporal_identifier` that is not [`TEMPORAL_ID_LEN`] bytes is a malformed
/// envelope and is rejected as an argument error before decryption, matching
/// [`decrypt_encrypted_packet_with_csk_nonce`] (the BLE GATT specification fixes the
/// on-air identifier at the full 16 bytes). The AAD binds the cleartext header, so a
/// tampered `temporal_identifier` fails the tag instead of being accepted. The
/// returned bytes are the decrypted plaintext exactly as the peer serialized it —
/// nothing is re-encoded.
pub(crate) fn decrypt_packet_bytes(
    packet_bytes: &[u8],
    csk: &[u8; CSK_LEN],
    expected_symmetric_algorithm: i32,
) -> Result<Vec<u8>, JniError> {
    let expected = symmetric_algorithm(expected_symmetric_algorithm)?;
    let packet = decode_encrypted_packet(packet_bytes)?;

    // Malformed envelope, not a security event: refuse it before the algorithm
    // check and before any AEAD work.
    if packet.temporal_identifier.len() != TEMPORAL_ID_LEN {
        return Err(JniError::Argument(format!(
            "temporal identifier must be {TEMPORAL_ID_LEN} bytes, got {}",
            packet.temporal_identifier.len()
        )));
    }

    if packet.encryption_algorithm != expected as i32 {
        return Err(JniError::Security(format!(
            "packet encryption algorithm {} does not match the negotiated algorithm {}",
            packet.encryption_algorithm, expected as i32
        )));
    }

    let key = ClientSymmetricKey::from_bytes(*csk);
    let aad = encrypted_packet_aad(packet.encryption_algorithm, &packet.temporal_identifier);
    decrypt_with_csk_and_prepended_nonce(&key, expected, &packet.ciphertext, &aad)
        .map_err(|err| JniError::Security(format!("packet decryption failed: {err}")))
}

/// Verify and decode an `AuthenticationRequest`.
///
/// The Ed25519 signature is checked over the raw `payload` bytes **before** the inner
/// protobuf is decoded, so a forged envelope never reaches a decoder.
///
/// `expected_signature_algorithm` is the paired Client's **persisted**
/// `signature_algorithm` (security-hardening.md §2.1), not a constant: a value this
/// build does not implement is refused before any verification runs.
pub(crate) fn parse_auth_request_verified(
    wrapper_bytes: &[u8],
    client_ed25519_public_key: &[u8; 32],
    protocol_version: i32,
    expected_signature_algorithm: i32,
) -> Result<VerifiedAuthRequest, JniError> {
    check_protocol_version(protocol_version)?;
    let expected_signature_algorithm = signature_algorithm(expected_signature_algorithm)?;
    let wrapper = decode_wrapper(wrapper_bytes)?;
    check_wrapper_version(&wrapper)?;
    require_payload_type(&wrapper, PayloadType::AuthRequest)?;

    let decoded = verify_and_decode_payload(
        &wrapper,
        client_ed25519_public_key,
        expected_signature_algorithm,
    )?;

    match decoded {
        DecodedPayload::AuthRequest(request) => Ok(VerifiedAuthRequest {
            challenge: challenge_32(&request.challenge)?,
            username: request.username,
            hostname: request.hostname,
            timestamp_unix_seconds: request.timestamp_unix_seconds,
            pam_service: request.pam_service,
            process_name: request.process_name,
            command_preview: request.command_preview,
            tty_present: request.tty_present,
        }),
        _ => Err(JniError::Security(
            "payload is not an AuthenticationRequest".to_string(),
        )),
    }
}

/// Verify a `GrantConfirmation` or `AuthenticationCancel` and return its challenge.
fn verified_challenge(
    wrapper_bytes: &[u8],
    client_ed25519_public_key: &[u8; 32],
    protocol_version: i32,
    expected: PayloadType,
    expected_signature_algorithm: i32,
) -> Result<[u8; CHALLENGE_LEN], JniError> {
    check_protocol_version(protocol_version)?;
    let expected_signature_algorithm = signature_algorithm(expected_signature_algorithm)?;
    let wrapper = decode_wrapper(wrapper_bytes)?;
    check_wrapper_version(&wrapper)?;
    require_payload_type(&wrapper, expected)?;

    let decoded = verify_and_decode_payload(
        &wrapper,
        client_ed25519_public_key,
        expected_signature_algorithm,
    )?;

    let challenge = match decoded {
        DecodedPayload::GrantConfirmation(message) => message.challenge,
        DecodedPayload::AuthCancel(message) => message.challenge,
        DecodedPayload::AuthRequest(message) => message.challenge,
        DecodedPayload::AuthGrant(message) => message.challenge,
        DecodedPayload::AuthDenial(message) => message.challenge,
    };
    challenge_32(&challenge)
}

/// Verify a `GrantConfirmation` and return the acknowledged challenge.
pub(crate) fn parse_grant_confirmation_verified(
    wrapper_bytes: &[u8],
    client_ed25519_public_key: &[u8; 32],
    protocol_version: i32,
    expected_signature_algorithm: i32,
) -> Result<[u8; CHALLENGE_LEN], JniError> {
    verified_challenge(
        wrapper_bytes,
        client_ed25519_public_key,
        protocol_version,
        PayloadType::GrantConfirmation,
        expected_signature_algorithm,
    )
}

/// Verify an `AuthenticationCancel` and return the cancelled challenge.
pub(crate) fn parse_auth_cancel_verified(
    wrapper_bytes: &[u8],
    client_ed25519_public_key: &[u8; 32],
    protocol_version: i32,
    expected_signature_algorithm: i32,
) -> Result<[u8; CHALLENGE_LEN], JniError> {
    verified_challenge(
        wrapper_bytes,
        client_ed25519_public_key,
        protocol_version,
        PayloadType::AuthCancel,
        expected_signature_algorithm,
    )
}

/// Sign a Grant and package it into a serialized `EncryptedPacket`.
///
/// One Ed25519 signature covers `"tapauth-sig-v2" || be32(version) ||
/// be32(signature_algorithm) || be32(payload_type) || payload`, and the packet is
/// encrypted under the CSK with the negotiated pair of algorithms.
pub(crate) fn build_grant_packet(
    challenge: &[u8; CHALLENGE_LEN],
    server_signing_key: &Ed25519KeyPair,
    csk: &[u8; CSK_LEN],
    symmetric_algorithm_id: i32,
    hash_algorithm_id: i32,
) -> Result<Vec<u8>, JniError> {
    let symmetric = symmetric_algorithm(symmetric_algorithm_id)?;
    let hash = hash_algorithm(hash_algorithm_id)?;

    let wrapper = create_signed_auth_grant(*challenge, server_signing_key)?;
    let key = ClientSymmetricKey::from_bytes(*csk);
    let packet = create_encrypted_packet_with_csk_nonce(&key, symmetric, hash, &wrapper)?;
    Ok(packet.encode_to_vec())
}

/// Sign a Denial and package it into a serialized `EncryptedPacket`.
pub(crate) fn build_denial_packet(
    challenge: &[u8; CHALLENGE_LEN],
    reason: &str,
    server_signing_key: &Ed25519KeyPair,
    csk: &[u8; CSK_LEN],
    symmetric_algorithm_id: i32,
    hash_algorithm_id: i32,
) -> Result<Vec<u8>, JniError> {
    let symmetric = symmetric_algorithm(symmetric_algorithm_id)?;
    let hash = hash_algorithm(hash_algorithm_id)?;

    let wrapper = create_signed_auth_denial(*challenge, reason, server_signing_key)?;
    let key = ClientSymmetricKey::from_bytes(*csk);
    let packet = create_encrypted_packet_with_csk_nonce(&key, symmetric, hash, &wrapper)?;
    Ok(packet.encode_to_vec())
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Resolve a caller-supplied `SymmetricAlgorithm` id, rejecting `UNSPECIFIED` and
/// any value this build cannot implement.
fn symmetric_algorithm(value: i32) -> Result<SymmetricAlgorithm, JniError> {
    match SymmetricAlgorithm::try_from(value) {
        Ok(SymmetricAlgorithm::Aes256Gcm) => Ok(SymmetricAlgorithm::Aes256Gcm),
        Ok(SymmetricAlgorithm::Chacha20Poly1305) => Ok(SymmetricAlgorithm::Chacha20Poly1305),
        _ => Err(JniError::Argument(format!(
            "unsupported symmetric algorithm id {value}"
        ))),
    }
}

/// Resolve a caller-supplied `HashAlgorithm` id, rejecting `UNSPECIFIED` and any
/// value this build cannot implement.
fn hash_algorithm(value: i32) -> Result<HashAlgorithm, JniError> {
    match HashAlgorithm::try_from(value) {
        Ok(HashAlgorithm::Sha256) => Ok(HashAlgorithm::Sha256),
        Ok(HashAlgorithm::Blake3) => Ok(HashAlgorithm::Blake3),
        _ => Err(JniError::Argument(format!(
            "unsupported hash algorithm id {value}"
        ))),
    }
}

/// Resolve the paired Client's persisted `SignatureAlgorithm` id and return it as
/// the id to pin verification to.
///
/// `UNSPECIFIED` (0) and any value this build does not implement are refused: the
/// signature algorithm is a per-server persisted property
/// (security-hardening.md §2.1), so accepting "whatever the wrapper claims" would
/// hand the choice of verification algorithm back to the peer. This is reported as
/// a security failure, not a caller-argument error, because the value comes from
/// persisted per-Client state and a wrong one means the stored pairing is unusable.
fn signature_algorithm(value: i32) -> Result<i32, JniError> {
    match SignatureAlgorithm::try_from(value) {
        Ok(SignatureAlgorithm::Ed25519) => Ok(SignatureAlgorithm::Ed25519 as i32),
        _ => Err(JniError::Security(format!(
            "unsupported signature algorithm id {value} for this paired client"
        ))),
    }
}

/// 16-byte UDP/GATT temporal identifier for `window` under `hash_algorithm_id`.
pub(crate) fn temporal_identifier(
    csk: &[u8; CSK_LEN],
    window: i64,
    hash_algorithm_id: i32,
) -> Result<[u8; TEMPORAL_ID_LEN], JniError> {
    let hash = hash_algorithm(hash_algorithm_id)?;
    let window = u64::try_from(window).map_err(|_| {
        JniError::Argument(format!("time window must be non-negative, got {window}"))
    })?;
    let key = ClientSymmetricKey::from_bytes(*csk);
    generate_temporal_id_with_alg(&key, window, hash).map_err(Into::into)
}

/// 10-byte BLE advertisement temporal identifier for `window` under `hash_algorithm_id`.
pub(crate) fn ble_temporal_identifier(
    csk: &[u8; CSK_LEN],
    window: i64,
    hash_algorithm_id: i32,
) -> Result<[u8; BLE_TEMPORAL_ID_LEN], JniError> {
    let hash = hash_algorithm(hash_algorithm_id)?;
    let window = u64::try_from(window).map_err(|_| {
        JniError::Argument(format!("time window must be non-negative, got {window}"))
    })?;
    let key = ClientSymmetricKey::from_bytes(*csk);
    generate_ble_temporal_id_with_alg(&key, window, hash).map_err(Into::into)
}

/// The current 60-second time window.
pub(crate) fn time_window_now() -> Result<i64, JniError> {
    let window = current_time_window()?;
    i64::try_from(window).map_err(|_| JniError::State("system clock is out of range".to_string()))
}

/// Check a received temporal identifier (`10` or `16` bytes) against the current and
/// previous window for `hash_algorithm_id`.
pub(crate) fn verify_temporal_identifier(
    temporal_identifier: &[u8],
    csk: &[u8; CSK_LEN],
    hash_algorithm_id: i32,
) -> Result<bool, JniError> {
    let hash = hash_algorithm(hash_algorithm_id)?;
    let key = ClientSymmetricKey::from_bytes(*csk);

    match temporal_identifier.len() {
        TEMPORAL_ID_LEN => {
            let mut identifier = [0u8; TEMPORAL_ID_LEN];
            identifier.copy_from_slice(temporal_identifier);
            verify_temporal_identifier_with_alg(&key, &identifier, hash).map_err(Into::into)
        }
        BLE_TEMPORAL_ID_LEN => {
            let mut identifier = [0u8; BLE_TEMPORAL_ID_LEN];
            identifier.copy_from_slice(temporal_identifier);
            verify_ble_temporal_identifier_with_alg(&key, &identifier, hash).map_err(Into::into)
        }
        len => Err(JniError::Argument(format!(
            "temporal identifier must be {TEMPORAL_ID_LEN} or {BLE_TEMPORAL_ID_LEN} bytes, got {len}"
        ))),
    }
}

/// The 10-byte BLE pairing advertisement identifier for a scanned QR code.
pub(crate) fn ble_pairing_adv_id(
    session_id: &[u8],
    client_x25519_public_key: &[u8; 32],
) -> Result<[u8; BLE_TEMPORAL_ID_LEN], JniError> {
    if session_id.len() != PAIRING_SESSION_ID_LEN {
        return Err(JniError::Argument(format!(
            "session id must be {PAIRING_SESSION_ID_LEN} bytes, got {}",
            session_id.len()
        )));
    }
    Ok(crate::crypto::derive_ble_pairing_adv_id(
        session_id,
        client_x25519_public_key,
    ))
}

// ---------------------------------------------------------------------------
// Pairing (Android is the protocol Server)
// ---------------------------------------------------------------------------

/// Live pairing sessions, keyed by the handle handed to Kotlin.
///
/// Directional keys (`K_c2s`, `K_s2c`, the ephemeral X25519 secret and `Ed_S`) never
/// leave Rust: Kotlin only ever holds the numeric handle.
static SESSIONS: OnceLock<Mutex<HashMap<i64, ClientPairingSession>>> = OnceLock::new();

/// Monotonic handle allocator. Handles start at 1 so `0` is never valid.
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

fn sessions() -> &'static Mutex<HashMap<i64, ClientPairingSession>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_sessions(
) -> Result<std::sync::MutexGuard<'static, HashMap<i64, ClientPairingSession>>, JniError> {
    sessions()
        .lock()
        .map_err(|_| JniError::State("pairing session table is poisoned".to_string()))
}

/// Run `f` against the session behind `handle`.
fn with_session<T>(
    handle: i64,
    f: impl FnOnce(&mut ClientPairingSession) -> Result<T, JniError>,
) -> Result<T, JniError> {
    let mut guard = lock_sessions()?;
    let session = guard
        .get_mut(&handle)
        .ok_or_else(|| JniError::Argument(format!("unknown pairing session handle {handle}")))?;
    f(session)
}

/// Register a new phone-side pairing session and return its handle.
pub(crate) fn pairing_session_create(
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    server_identity: Ed25519KeyPair,
    server_device_name: &str,
) -> Result<i64, JniError> {
    let session = ClientPairingSession::new(session_id, server_identity, server_device_name)?;
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let previous = lock_sessions()?.insert(handle, session);
    drop(previous);
    Ok(handle)
}

/// Drop the session behind `handle` (zeroizing its keys on drop).
pub(crate) fn pairing_session_free(handle: i64) -> Result<(), JniError> {
    let removed = lock_sessions()?.remove(&handle);
    match removed {
        Some(session) => {
            drop(session);
            Ok(())
        }
        None => Err(JniError::Argument(format!(
            "unknown pairing session handle {handle}"
        ))),
    }
}

/// Decode a `PairingPacket` and require it to belong to `session`.
fn decode_session_packet(
    session: &ClientPairingSession,
    packet_bytes: &[u8],
) -> Result<PairingPacket, JniError> {
    let packet = decode_pairing_packet(packet_bytes)
        .map_err(|err| JniError::Argument(format!("invalid PairingPacket: {err}")))?;

    if packet.session_id.as_slice() != session.session_id().as_slice() {
        return Err(JniError::Argument(
            "PairingPacket session id does not match this pairing session".to_string(),
        ));
    }
    Ok(packet)
}

/// Wrap a pairing message in its `PairingPacket` envelope and serialize it.
fn encode_session_packet(
    session: &ClientPairingSession,
    message: pairing_packet::Msg,
) -> Result<Vec<u8>, JniError> {
    let packet = PairingPacket {
        version: PROTOCOL_VERSION_V2,
        session_id: session.session_id().to_vec(),
        msg: Some(message),
    };
    encode_pairing_packet(&packet)
        .map_err(|err| JniError::State(format!("failed to encode PairingPacket: {err}")))
}

/// Build the `PairingInit` to send (serialized `PairingPacket`).
pub(crate) fn pairing_create_init(handle: i64) -> Result<Vec<u8>, JniError> {
    with_session(handle, |session| {
        let init = session.create_init()?;
        encode_session_packet(session, pairing_packet::Msg::Init(init))
    })
}

/// Verify the desktop's `PairingResponse` and return what the phone persists and shows.
///
/// The QR commitment (`client_x25519_public_key == expected_qr_public_key`) is the
/// whole point of the pin: it is checked inside
/// [`ClientPairingSession::verify_response`] in constant time, first, and there is no
/// sentinel that skips it. Nothing is cached until every check passed, so a response
/// that fails here leaves the session unkeyed and a later genuine one still verifies.
pub(crate) fn pairing_verify_response(
    handle: i64,
    response_packet: &[u8],
    expected_qr_public_key: &[u8; 32],
) -> Result<VerifiedPairingResponse, JniError> {
    with_session(handle, |session| {
        let packet = decode_session_packet(session, response_packet)?;
        match packet.msg {
            Some(pairing_packet::Msg::Response(response)) => {
                session.verify_response(&response, expected_qr_public_key)?;

                let client_ed25519_public_key: [u8; 32] = response
                    .client_ed25519_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| {
                        JniError::Argument(format!(
                            "PairingResponse client Ed25519 key must be 32 bytes, got {}",
                            response.client_ed25519_public_key.len()
                        ))
                    })?;

                let sas = session
                    .sas()
                    .ok_or_else(|| {
                        JniError::State("SAS unavailable after a verified response".to_string())
                    })?
                    .to_string();
                let negotiated = session.negotiated().ok_or_else(|| {
                    JniError::State("algorithms unavailable after a verified response".to_string())
                })?;

                Ok(VerifiedPairingResponse {
                    sas,
                    client_ed25519_public_key,
                    symmetric_algorithm: negotiated.symmetric_algorithm as i32,
                    hash_algorithm: negotiated.hash_algorithm as i32,
                    signature_algorithm: negotiated.signature_algorithm as i32,
                })
            }
            _ => Err(JniError::Argument(
                "PairingPacket does not carry a PairingResponse".to_string(),
            )),
        }
    })
}

/// Decrypt the desktop's provisioning payload.
pub(crate) fn pairing_process_confirm_client(
    handle: i64,
    confirm_client_packet: &[u8],
) -> Result<ProvisionedClient, JniError> {
    with_session(handle, |session| {
        let packet = decode_session_packet(session, confirm_client_packet)?;
        match packet.msg {
            Some(pairing_packet::Msg::ConfirmClient(confirm)) => {
                let payload = session.process_confirm_client(&confirm)?;
                let csk: [u8; CSK_LEN] = payload.csk.as_slice().try_into().map_err(|_| {
                    JniError::Argument(format!(
                        "provisioned CSK must be {CSK_LEN} bytes, got {}",
                        payload.csk.len()
                    ))
                })?;
                Ok(ProvisionedClient {
                    csk: Zeroizing::new(csk),
                    username: payload.username,
                    client_hostname: payload.client_hostname,
                })
            }
            _ => Err(JniError::Argument(
                "PairingPacket does not carry a PairingConfirmClient".to_string(),
            )),
        }
    })
}

/// Build the completion proof (serialized `PairingPacket` with `PairingConfirmServer`).
pub(crate) fn pairing_create_confirm_server(
    handle: i64,
    csk: &[u8; CSK_LEN],
) -> Result<Vec<u8>, JniError> {
    with_session(handle, |session| {
        let confirm = session.create_confirm_server(csk)?;
        encode_session_packet(session, pairing_packet::Msg::ConfirmServer(confirm))
    })
}

/// Build a keepalive frame (serialized `PairingPacket` with `PairingKeepalive`).
///
/// The frame carries no key material and no state transition: it only keeps a NAT
/// or BLE link alive while the two users compare the SAS. Kotlin must not hand-build
/// the wire format, so the empty message is encoded here.
pub(crate) fn pairing_create_keepalive(handle: i64) -> Result<Vec<u8>, JniError> {
    with_session(handle, |session| {
        encode_session_packet(session, pairing_packet::Msg::Keepalive(PairingKeepalive {}))
    })
}

/// Resolve a caller-supplied `PairingAbortReason` id.
fn pairing_abort_reason(value: i32) -> Result<PairingAbortReason, JniError> {
    PairingAbortReason::try_from(value)
        .map_err(|_| JniError::Argument(format!("unknown pairing abort reason id {value}")))
}

/// Build an abort (serialized `PairingPacket` with `PairingAbort`).
pub(crate) fn pairing_create_abort(handle: i64, reason: i32) -> Result<Vec<u8>, JniError> {
    let reason = pairing_abort_reason(reason)?;
    with_session(handle, |session| {
        let abort = session.create_abort(reason)?;
        encode_session_packet(session, pairing_packet::Msg::Abort(abort))
    })
}

/// Verify an abort received from the desktop.
pub(crate) fn pairing_verify_abort(handle: i64, abort_packet: &[u8]) -> Result<bool, JniError> {
    with_session(handle, |session| {
        let packet = decode_session_packet(session, abort_packet)?;
        match packet.msg {
            Some(pairing_packet::Msg::Abort(abort)) => {
                session.verify_abort(&abort).map_err(Into::into)
            }
            _ => Err(JniError::Argument(
                "PairingPacket does not carry a PairingAbort".to_string(),
            )),
        }
    })
}

/// Extract the validated 16-byte `session_id` of a serialized `PairingPacket`.
pub(crate) fn pairing_packet_session_id(
    packet_bytes: &[u8],
) -> Result<[u8; PAIRING_SESSION_ID_LEN], JniError> {
    let packet = decode_pairing_packet(packet_bytes)
        .map_err(|err| JniError::Argument(format!("invalid PairingPacket: {err}")))?;
    pairing_session_id(&packet)
        .map_err(|err| JniError::Argument(format!("invalid PairingPacket session id: {err}")))
}

/// Name the payload type of a `WrapperMessage`.
///
/// This is a dispatch hint only: `payload_type` is reported **before** verification,
/// and every parse entry point re-checks it against the signed transcript.
pub(crate) fn payload_type_name(wrapper: &WrapperMessage) -> Option<&'static str> {
    match PayloadType::try_from(wrapper.payload_type).ok()? {
        PayloadType::AuthRequest => Some("AUTH_REQUEST"),
        PayloadType::AuthGrant => Some("AUTH_GRANT"),
        PayloadType::AuthDenial => Some("AUTH_DENIAL"),
        PayloadType::GrantConfirmation => Some("GRANT_CONFIRMATION"),
        PayloadType::AuthCancel => Some("AUTH_CANCEL"),
        PayloadType::Unspecified => None,
    }
}

/// Name the payload type of serialized `WrapperMessage` bytes.
///
/// A dispatch hint only — see [`payload_type_name`].
pub(crate) fn message_type_name(wrapper_bytes: &[u8]) -> Result<Option<&'static str>, JniError> {
    let wrapper = decode_wrapper(wrapper_bytes)?;
    Ok(payload_type_name(&wrapper))
}

/// Read the validated `temporal_identifier` of a serialized `EncryptedPacket`.
pub(crate) fn encrypted_packet_temporal_identifier(
    packet_bytes: &[u8],
) -> Result<[u8; TEMPORAL_ID_LEN], JniError> {
    let packet = decode_encrypted_packet(packet_bytes)?;
    packet
        .temporal_identifier
        .as_slice()
        .try_into()
        .map_err(|_| {
            JniError::Argument(format!(
                "temporal identifier must be {TEMPORAL_ID_LEN} bytes, got {}",
                packet.temporal_identifier.len()
            ))
        })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::protocol::messages::create_auth_request_with_context;
    use crate::protocol::packet::{wrap_auth_cancel, wrap_auth_request, wrap_grant_confirmation};
    use crate::protocol::pairing::{PinnedAlgorithms, ServerPairingState};
    use crate::protocol::pb::{
        AuthenticationCancel, AuthenticationRequest, GrantConfirmation, PairingAbort,
        WrapperMessage,
    };

    const AES: i32 = SymmetricAlgorithm::Aes256Gcm as i32;
    const CHACHA: i32 = SymmetricAlgorithm::Chacha20Poly1305 as i32;
    const SHA256: i32 = HashAlgorithm::Sha256 as i32;
    const BLAKE3: i32 = HashAlgorithm::Blake3 as i32;
    const ED25519: i32 = SignatureAlgorithm::Ed25519 as i32;

    fn context_request(challenge: [u8; 32]) -> AuthenticationRequest {
        create_auth_request_with_context(
            "luca",
            "thinkpad",
            &challenge,
            "sudo",
            "sudo",
            "apt upgrade",
            true,
        )
        .unwrap()
    }

    /// Sign a request wrapper with `keypair` and return its wire bytes.
    fn signed_request(keypair: &Ed25519KeyPair, request: AuthenticationRequest) -> Vec<u8> {
        let mut wrapper = wrap_auth_request(request);
        crate::protocol::messages::sign_wrapper_message(&mut wrapper, keypair).unwrap();
        wrapper.encode_to_vec()
    }

    /// An `EncryptedPacket` carrying a signed grant, serialized.
    fn grant_packet(
        csk: &[u8; 32],
        signer: &Ed25519KeyPair,
        symmetric: i32,
        challenge: [u8; 32],
    ) -> Vec<u8> {
        build_grant_packet(&challenge, signer, csk, symmetric, SHA256).unwrap()
    }

    // ---------------------------------------------------------------
    // decryptEncryptedPacket
    // ---------------------------------------------------------------

    /// A genuine packet decrypts to the exact serialized `WrapperMessage` bytes for
    /// both AEAD algorithms, byte for byte — including protobuf fields this build does
    /// not know, which a decode/re-encode round trip would silently drop.
    /// The defect this catches: a decrypt path that ignores the caller's pinned
    /// algorithm, rebuilds the plaintext from a decoded struct instead of returning the
    /// peer's bytes, or only implements one of the two negotiated algorithms.
    #[test]
    fn decrypt_packet_accepts_genuine_packets_for_both_algorithms() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();

        for symmetric in [AES, CHACHA] {
            let algorithm = SymmetricAlgorithm::try_from(symmetric).unwrap();
            let mut wrapper = wrap_auth_request(context_request([0x21; 32]));
            crate::protocol::messages::sign_wrapper_message(&mut wrapper, &keypair).unwrap();

            let packet = create_encrypted_packet_with_csk_nonce(
                &csk,
                algorithm,
                HashAlgorithm::Sha256,
                &wrapper,
            )
            .unwrap();
            let plaintext =
                decrypt_packet_bytes(&packet.encode_to_vec(), &csk_bytes, symmetric).unwrap();
            assert_eq!(plaintext, wrapper.encode_to_vec());

            // Hand-build the packet so the plaintext carries an unknown field
            // (field 99, wire type 2: key 0x031A -> [0x9a, 0x06], len 3, "xyz").
            // A decrypt that re-encodes a decoded `WrapperMessage` loses those bytes.
            let mut wire = wrapper.encode_to_vec();
            wire.extend_from_slice(&[0x9a, 0x06, 0x03, b'x', b'y', b'z']);
            let temporal_identifier = crate::crypto::generate_temporal_id_with_alg(
                &csk,
                time_window_now().unwrap() as u64,
                HashAlgorithm::Sha256,
            )
            .unwrap();
            let aad = encrypted_packet_aad(symmetric, &temporal_identifier);
            let ciphertext =
                crate::crypto::encrypt_with_csk_and_random_nonce(&csk, algorithm, &wire, &aad)
                    .unwrap();
            let raw_packet = EncryptedPacket {
                temporal_identifier: temporal_identifier.to_vec(),
                encryption_algorithm: symmetric,
                ciphertext,
            };

            let plaintext =
                decrypt_packet_bytes(&raw_packet.encode_to_vec(), &csk_bytes, symmetric).unwrap();
            assert_eq!(
                plaintext, wire,
                "the peer's plaintext bytes are returned verbatim"
            );

            // The decrypted bytes still verify, so the pipeline is intact end to end.
            let verified =
                parse_auth_request_verified(&plaintext, &keypair.verifying_key_bytes(), 2, ED25519)
                    .unwrap();
            assert_eq!(verified.challenge, [0x21; 32]);
        }
    }

    /// A packet whose header names a different algorithm than the caller pinned is
    /// rejected before any AEAD work.
    /// The defect this catches: a downgrade accepted by decrypting under the packet's
    /// self-declared algorithm instead of the negotiated one.
    #[test]
    fn decrypt_packet_rejects_algorithm_mismatch_before_decrypting() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();

        let mut packet =
            EncryptedPacket::decode(grant_packet(&csk_bytes, &keypair, AES, [0x31; 32]).as_slice())
                .unwrap();
        assert_eq!(packet.encryption_algorithm, AES);

        // Unusable ciphertext: only a pre-decryption check can report a mismatch here.
        packet.ciphertext = vec![0x00];
        let bytes = packet.encode_to_vec();

        match decrypt_packet_bytes(&bytes, &csk_bytes, CHACHA) {
            Err(JniError::Security(message)) => {
                assert!(
                    message.contains("algorithm"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected an algorithm mismatch, got {other:?}"),
        }

        // Control: with the matching algorithm the same packet is a crypto failure,
        // not an algorithm mismatch.
        assert!(matches!(
            decrypt_packet_bytes(&bytes, &csk_bytes, AES),
            Err(JniError::Security(message)) if message.contains("decryption failed")
        ));

        // An unknown/unspecified algorithm id is a caller error, not a security event.
        assert!(matches!(
            decrypt_packet_bytes(&bytes, &csk_bytes, 0),
            Err(JniError::Argument(_))
        ));
    }

    /// A flipped ciphertext bit and a flipped temporal-identifier bit both fail the tag.
    /// The defect this catches: a missing AAD binding (temporal identifier tampering
    /// silently accepted) or a decrypt path that returns empty bytes instead of
    /// raising.
    #[test]
    fn decrypt_packet_rejects_tampered_tag_and_temporal_identifier() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();
        let genuine = grant_packet(&csk_bytes, &keypair, AES, [0x41; 32]);

        let packet = EncryptedPacket::decode(genuine.as_slice()).unwrap();

        // Tampered tag (last byte of the AEAD tag).
        let mut tampered_tag = packet.clone();
        let last = tampered_tag.ciphertext.len() - 1;
        tampered_tag.ciphertext[last] ^= 0x01;
        assert_eq!(tampered_tag.ciphertext.len(), packet.ciphertext.len());
        match decrypt_packet_bytes(&tampered_tag.encode_to_vec(), &csk_bytes, AES) {
            Err(JniError::Security(message)) => {
                assert!(
                    message.contains("decryption failed"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected an AEAD failure, got {other:?}"),
        }

        // Tampered temporal identifier (bound into the AAD).
        let mut tampered_id = packet.clone();
        tampered_id.temporal_identifier[0] ^= 0x01;
        assert_eq!(tampered_id.ciphertext, packet.ciphertext);
        assert!(matches!(
            decrypt_packet_bytes(&tampered_id.encode_to_vec(), &csk_bytes, AES),
            Err(JniError::Security(_))
        ));

        // The untouched packet still decrypts, so the tampering above was the cause.
        assert!(decrypt_packet_bytes(&genuine, &csk_bytes, AES).is_ok());
    }

    /// Bytes that are not a decodable `EncryptedPacket` are an I/O failure, not a panic.
    #[test]
    fn decrypt_packet_rejects_undecodable_packet() {
        let csk = [0x11u8; 32];
        assert!(matches!(
            decrypt_packet_bytes(&[0xFF, 0xFF, 0xFF], &csk, AES),
            Err(JniError::Io(_))
        ));
    }

    /// A `temporal_identifier` that is not 16 bytes is a malformed envelope on the
    /// path Android actually uses, so it must be an *argument* failure raised before
    /// any decryption.
    /// The defect this catches: `decrypt_packet_bytes` skipping the length rule that
    /// `decrypt_encrypted_packet_with_csk_nonce` enforces, so a short identifier is
    /// either accepted as a valid frame or reported only as an AEAD failure (which
    /// makes a malformed envelope indistinguishable from a forged one).
    #[test]
    fn decrypt_packet_rejects_non_16_byte_temporal_identifier() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();
        let genuine = grant_packet(&csk_bytes, &keypair, AES, [0x42; 32]);

        // The genuine 16-byte packet still decrypts, and to the genuine signed
        // grant, so the rejections below are caused by the identifier length and
        // nothing else.
        let decrypted = decrypt_packet_bytes(&genuine, &csk_bytes, AES).unwrap();
        let wrapper = WrapperMessage::decode(decrypted.as_slice()).unwrap();
        match crate::protocol::messages::verify_and_decode_payload(
            &wrapper,
            &keypair.verifying_key_bytes(),
            ED25519,
        )
        .unwrap()
        {
            DecodedPayload::AuthGrant(grant) => assert_eq!(grant.challenge, vec![0x42; 32]),
            other => panic!("expected the genuine AuthGrant, got {other:?}"),
        }

        let packet = EncryptedPacket::decode(genuine.as_slice()).unwrap();
        assert_eq!(packet.temporal_identifier.len(), TEMPORAL_ID_LEN);

        for len in [5usize, 17] {
            let mut resized = packet.clone();
            resized.temporal_identifier = vec![0xAB; len];
            match decrypt_packet_bytes(&resized.encode_to_vec(), &csk_bytes, AES) {
                Err(JniError::Argument(message)) => {
                    assert!(
                        message.contains("temporal identifier"),
                        "unexpected message: {message}"
                    );
                }
                other => panic!(
                    "a {len}-byte temporal identifier must be an argument error, got {other:?}"
                ),
            }
        }
    }

    // ---------------------------------------------------------------
    // parseAndVerifyAuthRequest
    // ---------------------------------------------------------------

    /// A validly signed request yields every field verbatim, including all four
    /// context fields.
    /// The defect this catches: dropped/renamed context fields, a re-sanitized
    /// username or hostname, or a timestamp truncated by a wrong width.
    #[test]
    fn parse_auth_request_accepts_signed_request_with_context() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let request = AuthenticationRequest {
            challenge: vec![0x51; 32],
            username: "luca".to_string(),
            hostname: "thinkpad".to_string(),
            timestamp_unix_seconds: 1_700_000_123,
            pam_service: "sudo".to_string(),
            process_name: "sudo".to_string(),
            command_preview: "apt  upgrade".to_string(),
            tty_present: true,
        };
        let bytes = signed_request(&keypair, request);

        let parsed =
            parse_auth_request_verified(&bytes, &keypair.verifying_key_bytes(), 2, ED25519)
                .unwrap();
        assert_eq!(parsed.challenge, [0x51; 32]);
        assert_eq!(parsed.username, "luca");
        assert_eq!(parsed.hostname, "thinkpad");
        assert_eq!(parsed.timestamp_unix_seconds, 1_700_000_123);
        assert_eq!(parsed.pam_service, "sudo");
        assert_eq!(parsed.process_name, "sudo");
        // Verbatim as signed: no second sanitization pass collapses the double space.
        assert_eq!(parsed.command_preview, "apt  upgrade");
        assert!(parsed.tty_present);
    }

    /// A request signed by another key is refused.
    /// The defect this catches: a parse path that decodes the payload without
    /// checking the signature against the paired Client's key.
    #[test]
    fn parse_auth_request_rejects_wrong_signer() {
        let signer = Ed25519KeyPair::generate().unwrap();
        let other = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&signer, context_request([0x61; 32]));

        assert!(matches!(
            parse_auth_request_verified(&bytes, &other.verifying_key_bytes(), 2, ED25519),
            Err(JniError::Security(message)) if message.contains("signature")
        ));
    }

    /// Re-encoding a signed payload with one byte changed breaks the signature.
    /// The defect this catches: verification over a re-serialized struct instead of
    /// the raw wire bytes, which would let the tampered field through.
    #[test]
    fn parse_auth_request_rejects_tampered_payload() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&keypair, context_request([0x62; 32]));

        let mut wrapper = WrapperMessage::decode(bytes.as_slice()).unwrap();
        let index = wrapper.payload.len() / 2;
        wrapper.payload[index] ^= 0x01;

        assert!(matches!(
            parse_auth_request_verified(
                &wrapper.encode_to_vec(),
                &keypair.verifying_key_bytes(),
                2,
                ED25519
            ),
            Err(JniError::Security(_))
        ));
    }

    /// `payload_type` is covered by the signature, so relabelling a signed message is
    /// refused instead of being decoded as the new type.
    /// The defect this catches: dispatch on an unauthenticated `payload_type`, which
    /// lets a signed Grant be replayed as an AuthRequest.
    #[test]
    fn parse_auth_request_rejects_relabelled_payload_type() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&keypair, context_request([0x63; 32]));

        let mut wrapper = WrapperMessage::decode(bytes.as_slice()).unwrap();
        assert_eq!(wrapper.payload_type, PayloadType::AuthRequest as i32);
        wrapper.payload_type = PayloadType::AuthGrant as i32;

        match parse_auth_request_verified(
            &wrapper.encode_to_vec(),
            &keypair.verifying_key_bytes(),
            2,
            ED25519,
        ) {
            Err(JniError::Security(message)) => {
                assert!(
                    message.contains("payload type"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected a payload-type rejection, got {other:?}"),
        }
    }

    /// A well-signed request whose challenge is not 32 bytes is rejected.
    /// The defect this catches: a challenge length accepted by truncation or padding,
    /// which would let the peer shrink the answer space.
    #[test]
    fn parse_auth_request_rejects_non_32_byte_challenge() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let mut request = context_request([0x64; 32]);
        request.challenge = vec![0x64; 31];
        let bytes = signed_request(&keypair, request);

        match parse_auth_request_verified(&bytes, &keypair.verifying_key_bytes(), 2, ED25519) {
            Err(JniError::Argument(message)) => {
                assert!(
                    message.contains("challenge"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected a challenge-length rejection, got {other:?}"),
        }
    }

    /// The caller's protocol version is pinned to v2.
    /// The defect this catches: a v1 (or future) frame accepted because the version
    /// argument is ignored, i.e. a compatibility branch sneaking back in.
    /// It is a `Security` failure, not an `Argument` one: the value is the paired
    /// Client's persisted `protocolVersion`, so a value this build cannot speak means
    /// the stored pairing is unusable.
    #[test]
    fn parse_auth_request_rejects_other_protocol_versions() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&keypair, context_request([0x65; 32]));

        for version in [0, 1, 3] {
            assert!(
                matches!(
                    parse_auth_request_verified(
                        &bytes,
                        &keypair.verifying_key_bytes(),
                        version,
                        ED25519
                    ),
                    Err(JniError::Security(message)) if message.contains("protocol version")
                ),
                "protocol version {version} must be refused"
            );
        }

        // The wrapper's own version field is signed and pinned too.
        let mut wrapper = WrapperMessage::decode(bytes.as_slice()).unwrap();
        wrapper.version = 1;
        assert!(matches!(
            parse_auth_request_verified(
                &wrapper.encode_to_vec(),
                &keypair.verifying_key_bytes(),
                2,
                ED25519
            ),
            Err(JniError::Security(_))
        ));
    }

    /// With an invalid signature *and* an undecodable payload, the reported failure is
    /// the signature, not the decode.
    /// The defect this catches: decoding before verifying, which hands attacker-chosen
    /// bytes to the protobuf decoder and reports a parse error where an authentication
    /// failure belongs.
    #[test]
    fn parse_auth_request_fails_on_signature_before_decoding() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let wrapper = WrapperMessage {
            version: PROTOCOL_VERSION_V2,
            signature_algorithm: ED25519,
            payload_type: PayloadType::AuthRequest as i32,
            payload: vec![0xFF, 0xFF, 0xFF],
            signature: vec![0x00; 64],
        };
        assert!(AuthenticationRequest::decode([0xFFu8, 0xFF, 0xFF].as_slice()).is_err());

        match parse_auth_request_verified(
            &wrapper.encode_to_vec(),
            &keypair.verifying_key_bytes(),
            2,
            ED25519,
        ) {
            Err(JniError::Security(message)) => {
                assert!(
                    message.contains("signature"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected a signature failure, got {other:?}"),
        }
    }

    /// The three parse entry points must verify against the caller-supplied,
    /// per-Client `signature_algorithm`, and refuse an id this build cannot verify.
    /// The defect this catches: verification pinned to a hard-coded `ED25519`
    /// constant, so the persisted per-server algorithm is never consulted and any
    /// value Kotlin passes (including `UNSPECIFIED`) is silently accepted as ED25519.
    #[test]
    fn parse_entry_points_pin_the_caller_supplied_signature_algorithm() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.verifying_key_bytes();
        let challenge = [0x73u8; 32];
        let request_bytes = signed_request(&keypair, context_request(challenge));

        let mut confirmation = wrap_grant_confirmation(GrantConfirmation {
            challenge: challenge.to_vec(),
        });
        crate::protocol::messages::sign_wrapper_message(&mut confirmation, &keypair).unwrap();
        let confirmation_bytes = confirmation.encode_to_vec();

        let mut cancel = wrap_auth_cancel(AuthenticationCancel {
            challenge: challenge.to_vec(),
        });
        crate::protocol::messages::sign_wrapper_message(&mut cancel, &keypair).unwrap();
        let cancel_bytes = cancel.encode_to_vec();

        // The persisted value (ED25519) succeeds on all three entry points.
        assert_eq!(
            parse_auth_request_verified(&request_bytes, &public_key, 2, ED25519)
                .unwrap()
                .challenge,
            challenge
        );
        assert_eq!(
            parse_grant_confirmation_verified(&confirmation_bytes, &public_key, 2, ED25519)
                .unwrap(),
            challenge
        );
        assert_eq!(
            parse_auth_cancel_verified(&cancel_bytes, &public_key, 2, ED25519).unwrap(),
            challenge
        );

        // `UNSPECIFIED` (0) and an unknown id (99) are refused on every entry
        // point, before any signature check.
        for algorithm in [0, 99] {
            assert!(
                matches!(
                    parse_auth_request_verified(&request_bytes, &public_key, 2, algorithm),
                    Err(JniError::Security(message)) if message.contains("signature algorithm")
                ),
                "signature algorithm {algorithm} must be refused for AuthRequest"
            );
            assert!(
                matches!(
                    parse_grant_confirmation_verified(
                        &confirmation_bytes,
                        &public_key,
                        2,
                        algorithm
                    ),
                    Err(JniError::Security(message)) if message.contains("signature algorithm")
                ),
                "signature algorithm {algorithm} must be refused for GrantConfirmation"
            );
            assert!(
                matches!(
                    parse_auth_cancel_verified(&cancel_bytes, &public_key, 2, algorithm),
                    Err(JniError::Security(message)) if message.contains("signature algorithm")
                ),
                "signature algorithm {algorithm} must be refused for AuthCancel"
            );
        }
    }

    // ---------------------------------------------------------------
    // parseAndVerifyGrantConfirmation / parseAndVerifyAuthCancel
    // ---------------------------------------------------------------

    /// Both acknowledgement messages verify and return their challenge, and each is
    /// refused where the other one is expected.
    /// The defect this catches: a shared parse path that returns the challenge without
    /// pinning `payload_type`, so a Cancel satisfies a Grant wait (or vice versa).
    #[test]
    fn grant_confirmation_and_cancel_verify_before_returning_the_challenge() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.verifying_key_bytes();
        let challenge = [0x71u8; 32];

        let mut confirmation = wrap_grant_confirmation(GrantConfirmation {
            challenge: challenge.to_vec(),
        });
        crate::protocol::messages::sign_wrapper_message(&mut confirmation, &keypair).unwrap();
        let confirmation_bytes = confirmation.encode_to_vec();

        let mut cancel = wrap_auth_cancel(AuthenticationCancel {
            challenge: challenge.to_vec(),
        });
        crate::protocol::messages::sign_wrapper_message(&mut cancel, &keypair).unwrap();
        let cancel_bytes = cancel.encode_to_vec();

        assert_eq!(
            parse_grant_confirmation_verified(&confirmation_bytes, &public_key, 2, ED25519)
                .unwrap(),
            challenge
        );
        assert_eq!(
            parse_auth_cancel_verified(&cancel_bytes, &public_key, 2, ED25519).unwrap(),
            challenge
        );

        assert!(matches!(
            parse_grant_confirmation_verified(&cancel_bytes, &public_key, 2, ED25519),
            Err(JniError::Security(message)) if message.contains("payload type")
        ));
        assert!(matches!(
            parse_auth_cancel_verified(&confirmation_bytes, &public_key, 2, ED25519),
            Err(JniError::Security(message)) if message.contains("payload type")
        ));

        // Wrong signer is refused on both paths.
        let other = Ed25519KeyPair::generate().unwrap();
        assert!(matches!(
            parse_grant_confirmation_verified(
                &confirmation_bytes,
                &other.verifying_key_bytes(),
                2,
                ED25519,
            ),
            Err(JniError::Security(_))
        ));
        assert!(matches!(
            parse_auth_cancel_verified(&cancel_bytes, &other.verifying_key_bytes(), 2, ED25519,),
            Err(JniError::Security(_))
        ));
    }

    // ---------------------------------------------------------------
    // createGrantWrapperMessage / createDenialWrapperMessage
    // ---------------------------------------------------------------

    /// Both builders produce an `EncryptedPacket` that decrypts back to the right
    /// payload type and challenge under the negotiated algorithms.
    /// The defect this catches: a grant/denial that is signed but not encrypted, one
    /// built with the wrong payload type, or one whose challenge is not the answered
    /// challenge.
    #[test]
    fn grant_and_denial_builders_round_trip_through_the_csk() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let csk_bytes = *csk.as_bytes();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [0x81u8; 32];

        for symmetric in [AES, CHACHA] {
            let grant_bytes =
                build_grant_packet(&challenge, &keypair, &csk_bytes, symmetric, SHA256)
                    .expect("grant packet");
            let signature_algorithm = ED25519;
            let grant = crate::protocol::packet::decrypt_encrypted_packet_with_csk_nonce(
                &csk,
                SymmetricAlgorithm::try_from(symmetric).unwrap(),
                &EncryptedPacket::decode(grant_bytes.as_slice()).unwrap(),
            )
            .unwrap();
            assert_eq!(grant.payload_type, PayloadType::AuthGrant as i32);
            assert_eq!(grant.signature.len(), 64);
            crate::protocol::messages::verify_and_decode_payload(
                &grant,
                &keypair.verifying_key_bytes(),
                signature_algorithm,
            )
            .unwrap();
            assert_eq!(
                crate::protocol::packet::extract_challenge(&grant).unwrap(),
                challenge.to_vec()
            );

            let denial_bytes = build_denial_packet(
                &challenge,
                "user rejected",
                &keypair,
                &csk_bytes,
                symmetric,
                SHA256,
            )
            .expect("denial packet");
            let denial = crate::protocol::packet::decrypt_encrypted_packet_with_csk_nonce(
                &csk,
                SymmetricAlgorithm::try_from(symmetric).unwrap(),
                &EncryptedPacket::decode(denial_bytes.as_slice()).unwrap(),
            )
            .unwrap();
            assert_eq!(denial.payload_type, PayloadType::AuthDenial as i32);
            match crate::protocol::messages::verify_and_decode_payload(
                &denial,
                &keypair.verifying_key_bytes(),
                signature_algorithm,
            )
            .unwrap()
            {
                DecodedPayload::AuthDenial(message) => {
                    assert_eq!(message.challenge, challenge.to_vec());
                    assert_eq!(message.reason, "user rejected");
                }
                other => panic!("expected an AuthDenial, got {other:?}"),
            }
        }
    }

    /// An unsupported algorithm id supplied by the caller is refused, not defaulted.
    /// The defect this catches: `UNSPECIFIED` silently selecting AES-256-GCM or SHA-256.
    #[test]
    fn builders_reject_unsupported_algorithm_ids() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk = [0x91u8; 32];
        let challenge = [0x92u8; 32];

        assert!(matches!(
            build_grant_packet(&challenge, &keypair, &csk, 0, SHA256),
            Err(JniError::Argument(_))
        ));
        assert!(matches!(
            build_grant_packet(&challenge, &keypair, &csk, AES, 0),
            Err(JniError::Argument(_))
        ));
        assert!(matches!(
            build_denial_packet(&challenge, "no", &keypair, &csk, 99, SHA256),
            Err(JniError::Argument(_))
        ));
    }

    // ---------------------------------------------------------------
    // Discovery
    // ---------------------------------------------------------------

    /// Temporal identifiers are keyed, window-bound and algorithm-dispatched, and the
    /// verifier accepts only the current/previous window.
    /// The defect this catches: a per-device algorithm dispatch that ignores the
    /// stored `hashAlgorithm` (a BLAKE3 client's packets would never match).
    #[test]
    fn temporal_identifiers_dispatch_on_the_persisted_algorithm() {
        let csk = [0xA1u8; 32];
        let window = time_window_now().unwrap();

        let sha16 = temporal_identifier(&csk, window, SHA256).unwrap();
        let blake16 = temporal_identifier(&csk, window, 2).unwrap();
        assert_eq!(sha16.len(), TEMPORAL_ID_LEN);
        assert_ne!(sha16, blake16, "the hash algorithm must be dispatched on");

        let sha10 = ble_temporal_identifier(&csk, window, SHA256).unwrap();
        assert_eq!(sha10.len(), BLE_TEMPORAL_ID_LEN);
        assert_eq!(&sha10[..], &sha16[..BLE_TEMPORAL_ID_LEN]);

        assert!(verify_temporal_identifier(&sha16, &csk, SHA256).unwrap());
        assert!(verify_temporal_identifier(&sha10, &csk, SHA256).unwrap());
        assert!(verify_temporal_identifier(&blake16, &csk, 2).unwrap());

        // The wrong algorithm never matches.
        assert!(!verify_temporal_identifier(&blake16, &csk, SHA256).unwrap());
        // A window two periods old is stale.
        let stale = temporal_identifier(&csk, window - 2, SHA256).unwrap();
        assert!(!verify_temporal_identifier(&stale, &csk, SHA256).unwrap());

        // Caller errors are refused rather than defaulted.
        assert!(matches!(
            temporal_identifier(&csk, -1, SHA256),
            Err(JniError::Argument(_))
        ));
        assert!(matches!(
            temporal_identifier(&csk, window, 0),
            Err(JniError::Argument(_))
        ));
        assert!(matches!(
            verify_temporal_identifier(&[0u8; 8], &csk, SHA256),
            Err(JniError::Argument(_))
        ));
    }

    /// The BLE pairing advertisement id is 10 bytes and rejects a malformed session id.
    #[test]
    fn ble_pairing_adv_id_rejects_wrong_length_session_ids() {
        let session_id = [0xB1u8; PAIRING_SESSION_ID_LEN];
        let public_key = [0xB2u8; 32];

        let id = ble_pairing_adv_id(&session_id, &public_key).unwrap();
        assert_eq!(
            id,
            crate::crypto::derive_ble_pairing_adv_id(&session_id, &public_key)
        );
        assert_eq!(id.len(), BLE_TEMPORAL_ID_LEN);

        assert!(matches!(
            ble_pairing_adv_id(&session_id[..15], &public_key),
            Err(JniError::Argument(_))
        ));
    }

    // ---------------------------------------------------------------
    // Pairing (phone side, behind the handle table)
    // ---------------------------------------------------------------

    fn session_packet(
        session_id: &[u8; PAIRING_SESSION_ID_LEN],
        msg: pairing_packet::Msg,
    ) -> Vec<u8> {
        encode_pairing_packet(&PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: session_id.to_vec(),
            msg: Some(msg),
        })
        .unwrap()
    }

    fn init_of(packet_bytes: &[u8]) -> crate::protocol::pb::PairingInit {
        match decode_pairing_packet(packet_bytes).unwrap().msg {
            Some(pairing_packet::Msg::Init(init)) => init,
            other => panic!("expected PairingInit, got {other:?}"),
        }
    }

    fn confirm_server_of(packet_bytes: &[u8]) -> crate::protocol::pb::PairingConfirmServer {
        match decode_pairing_packet(packet_bytes).unwrap().msg {
            Some(pairing_packet::Msg::ConfirmServer(confirm)) => confirm,
            other => panic!("expected PairingConfirmServer, got {other:?}"),
        }
    }

    /// The whole phone-side pairing path, driven from a real desktop
    /// `ServerPairingState`: init → verify response (correct and wrong QR key) →
    /// provision → confirm server, which the desktop then verifies.
    /// The defect this catches: a wrong QR `pk` accepted (a substituted `X_C` would
    /// silently pair), a provisioning payload that never reaches Kotlin, or a
    /// completion proof the desktop rejects because the directional keys or the
    /// transcript were wrong.
    #[test]
    fn pairing_handle_path_matches_the_desktop_state_machine() {
        let (mut desktop, started) = ServerPairingState::start(
            Ed25519KeyPair::generate().unwrap(),
            "thinkpad",
            36_692,
            None,
            None,
            None,
        )
        .unwrap();
        // The session id comes from the QR code the desktop generated.
        let session_id = started.session_id;

        let identity = Ed25519KeyPair::generate().unwrap();
        let identity_public = identity.verifying_key_bytes();
        let handle = pairing_session_create(session_id, identity, "pixel").unwrap();
        assert!(handle > 0);

        // Step 1: the phone builds its PairingInit.
        let init = init_of(&pairing_create_init(handle).unwrap());
        assert_eq!(init.server_ed25519_public_key, identity_public.to_vec());
        assert_eq!(init.server_device_name, "pixel");

        // Step 2: the desktop answers.
        let response = desktop.handle_init(&init).unwrap().clone();
        let response_bytes =
            session_packet(&started.session_id, pairing_packet::Msg::Response(response));

        // A response carrying another session id never reaches the session.
        let foreign = session_packet(
            &[0xC2u8; PAIRING_SESSION_ID_LEN],
            match decode_pairing_packet(&response_bytes).unwrap().msg {
                Some(msg) => msg,
                None => panic!("response packet has no message"),
            },
        );
        assert!(matches!(
            pairing_verify_response(handle, &foreign, &started.client_x25519_public_key),
            Err(JniError::Argument(message)) if message.contains("session id")
        ));

        // A substituted X_C is refused.
        assert!(matches!(
            pairing_verify_response(handle, &response_bytes, &[0x00u8; 32]),
            Err(JniError::Security(_))
        ));

        // The genuine response verifies and both sides derive the same SAS.
        let verified =
            pairing_verify_response(handle, &response_bytes, &started.client_x25519_public_key)
                .unwrap();
        let sas = verified.sas;
        assert_eq!(sas, desktop.sas().unwrap());
        assert_eq!(sas.len(), 7, "SAS is 6 digits plus the dash");
        assert!(sas.as_bytes()[3] == b'-');

        // Step 3: the desktop provisions the CSK and the phone decrypts it.
        let csk = [0xC3u8; 32];
        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        let provision = pairing_process_confirm_client(
            handle,
            &session_packet(
                &started.session_id,
                pairing_packet::Msg::ConfirmClient(confirm_client),
            ),
        )
        .unwrap();
        assert_eq!(*provision.csk, csk);
        assert_eq!(provision.username, "luca");
        assert_eq!(provision.client_hostname, "thinkpad");

        // Step 4: the phone's completion proof satisfies the desktop.
        let confirm = confirm_server_of(&pairing_create_confirm_server(handle, &csk).unwrap());
        desktop.verify_confirm_server(&confirm, &csk).unwrap();

        // The same proof for a different CSK is refused by the desktop, which proves
        // the phone signed the provisioned key and not something else.
        assert!(desktop
            .verify_confirm_server(&confirm, &[0xC4u8; 32])
            .is_err());

        // Aborts authenticate in both directions once the keys exist.
        let abort = desktop
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();
        let abort_bytes = session_packet(&started.session_id, pairing_packet::Msg::Abort(abort));
        assert!(pairing_verify_abort(handle, &abort_bytes).unwrap());

        let mut tampered_abort = decode_pairing_packet(&abort_bytes).unwrap();
        match tampered_abort.msg.as_mut() {
            Some(pairing_packet::Msg::Abort(abort)) => {
                abort.reason = PairingAbortReason::KeyMismatch as i32
            }
            other => panic!("expected PairingAbort, got {other:?}"),
        }
        assert!(matches!(
            pairing_verify_abort(handle, &encode_pairing_packet(&tampered_abort).unwrap()),
            Err(JniError::Security(_))
        ));

        // A phone-side abort is encodable and carries the requested reason.
        match decode_pairing_packet(&pairing_create_abort(handle, 2).unwrap())
            .unwrap()
            .msg
        {
            Some(pairing_packet::Msg::Abort(abort)) => {
                assert_eq!(abort.reason, PairingAbortReason::KeyMismatch as i32);
                assert_eq!(abort.auth_tag.len(), 32);
            }
            other => panic!("expected PairingAbort, got {other:?}"),
        }
        assert!(matches!(
            pairing_create_abort(handle, 99),
            Err(JniError::Argument(_))
        ));

        // Freeing removes the handle; every later use is an error, never a panic.
        pairing_session_free(handle).unwrap();
        assert!(matches!(
            pairing_session_free(handle),
            Err(JniError::Argument(_))
        ));
        assert!(matches!(
            pairing_create_init(handle),
            Err(JniError::Argument(_))
        ));

        // A packet of the wrong type for the call is refused.
        let other_handle = pairing_session_create(
            [0xC5u8; PAIRING_SESSION_ID_LEN],
            Ed25519KeyPair::generate().unwrap(),
            "pixel",
        )
        .unwrap();
        assert!(matches!(
            pairing_verify_response(
                other_handle,
                &session_packet(
                    &[0xC5u8; PAIRING_SESSION_ID_LEN],
                    pairing_packet::Msg::Keepalive(Default::default())
                ),
                &[0u8; 32]
            ),
            Err(JniError::Argument(_))
        ));
        pairing_session_free(other_handle).unwrap();
    }

    /// A phone session behind a handle, plus the desktop's `PairingResponse` as a wire
    /// frame the phone has not verified yet. This is the state
    /// `pairingVerifyResponse` is called from.
    ///
    /// The desktop is started with client-wide pins for a **non-baseline** algorithm
    /// pair, so the negotiated triple differs from the AES-256-GCM/SHA-256/Ed25519
    /// default: a caller that hard-codes the baseline instead of reporting
    /// `session.negotiated()` fails here. The phone advertises both algorithms, so
    /// negotiation picks up the pins.
    fn pending_handle_session() -> (
        ServerPairingState,
        i64,
        [u8; PAIRING_SESSION_ID_LEN],
        [u8; 32],
        Vec<u8>,
    ) {
        let (mut desktop, started) = ServerPairingState::start(
            Ed25519KeyPair::generate().unwrap(),
            "thinkpad",
            36_692,
            None,
            None,
            Some(PinnedAlgorithms {
                symmetric_algorithm: SymmetricAlgorithm::Chacha20Poly1305,
                hash_algorithm: HashAlgorithm::Blake3,
            }),
        )
        .unwrap();
        let handle = pairing_session_create(
            started.session_id,
            Ed25519KeyPair::generate().unwrap(),
            "pixel",
        )
        .unwrap();

        let init = match decode_pairing_packet(&pairing_create_init(handle).unwrap())
            .unwrap()
            .msg
        {
            Some(pairing_packet::Msg::Init(init)) => init,
            other => panic!("expected PairingInit, got {other:?}"),
        };
        let response = desktop.handle_init(&init).unwrap().clone();
        let response_bytes =
            session_packet(&started.session_id, pairing_packet::Msg::Response(response));
        (
            desktop,
            handle,
            started.session_id,
            started.client_x25519_public_key,
            response_bytes,
        )
    }

    /// `pairingVerifyResponse` returns exactly what the phone persists — the SAS, the
    /// desktop's `Ed_C` and the negotiated algorithm triple — and the desktop derives
    /// the same SAS and transcript hash from the very same wire frame.
    /// The defect this catches: a result that drops the device key or the algorithms
    /// (leaving `PairedDevice` unverifiable), one that carries the ephemeral `X_C` or
    /// the phone's own `Ed_S` instead of `Ed_C`, or one that reports a fixed triple —
    /// the AES-256-GCM/SHA-256/Ed25519 baseline — rather than the pinned algorithms
    /// the session actually negotiated.
    #[test]
    fn pairing_verify_response_returns_the_persistable_fields() {
        let (desktop, handle, session_id, qr_pk, response_bytes) = pending_handle_session();

        let verified = pairing_verify_response(handle, &response_bytes, &qr_pk).unwrap();

        // The SAS is the one both sides derived; the desktop's is the out-of-band
        // reference, and it is shaped `ddd-ddd`.
        assert_eq!(verified.sas, desktop.sas().unwrap());
        assert_eq!(verified.sas.len(), 7, "SAS is 6 digits plus the dash");
        assert_eq!(verified.sas.as_bytes()[3], b'-');

        // The persisted key is the desktop's static `Ed_C`, not the ephemeral `X_C`
        // committed in the QR code and not anything else.
        assert_eq!(
            verified.client_ed25519_public_key,
            desktop.client_ed25519_public_key()
        );
        assert_ne!(verified.client_ed25519_public_key, qr_pk);
        assert_ne!(verified.client_ed25519_public_key, [0u8; 32]);

        // The triple is what negotiation selected — the pinned, non-baseline pair, so
        // a hard-coded (AES-256-GCM, SHA-256, Ed25519) fails here — and the desktop's
        // own answer agrees with it. (`Chacha20Poly1305` and `Blake3` are both id 2,
        // so the wire numbers alone cannot tell the two fields apart; the
        // `desktop.negotiated()` comparisons below are what pin the mapping.)
        assert_eq!(verified.symmetric_algorithm, CHACHA);
        assert_eq!(verified.hash_algorithm, BLAKE3);
        assert_eq!(verified.signature_algorithm, ED25519);
        let negotiated = desktop.negotiated().unwrap();
        assert_eq!(
            negotiated.symmetric_algorithm,
            SymmetricAlgorithm::Chacha20Poly1305
        );
        assert_eq!(negotiated.hash_algorithm, HashAlgorithm::Blake3);
        assert_eq!(
            verified.symmetric_algorithm,
            negotiated.symmetric_algorithm as i32
        );
        assert_eq!(verified.hash_algorithm, negotiated.hash_algorithm as i32);
        assert_eq!(
            verified.signature_algorithm,
            negotiated.signature_algorithm as i32
        );

        // The frame the handle read is the one the desktop answered, so the phone's
        // transcript hash is the desktop's.
        let phone_transcript_hash =
            with_session(handle, |session| Ok(session.transcript_hash().copied())).unwrap();
        assert_eq!(phone_transcript_hash, desktop.transcript_hash().copied());
        assert_eq!(&session_id, desktop.session_id());
    }

    /// The QR pin is mandatory: a response checked against the wrong `pk` — including
    /// the all-zero sentinel — is a security failure that caches nothing, so the
    /// genuine response still verifies afterwards.
    /// The defect this catches: a "no QR key available, skip the comparison" path
    /// (which lets a substituted `X_C` pair silently), or a failed attempt that leaves
    /// the session poisoned or already keyed.
    #[test]
    fn pairing_verify_response_rejects_a_wrong_qr_pin_and_stays_usable() {
        let (desktop, handle, _session_id, qr_pk, response_bytes) = pending_handle_session();

        let mut wrong_pin = qr_pk;
        wrong_pin[0] ^= 0x01;
        for pin in [wrong_pin, [0x00u8; 32]] {
            assert!(matches!(
                pairing_verify_response(handle, &response_bytes, &pin),
                Err(JniError::Security(message)) if message.contains("challenge")
            ));
            // Nothing was cached: no SAS, no transcript hash, no keys.
            let state = with_session(handle, |session| {
                Ok((
                    session.sas().map(str::to_string),
                    session.transcript_hash().is_some(),
                    session.negotiated().is_some(),
                ))
            })
            .unwrap();
            assert_eq!(state, (None, false, false));
        }

        // The session is still usable: the genuine response now verifies.
        let verified = pairing_verify_response(handle, &response_bytes, &qr_pk).unwrap();
        assert_eq!(verified.sas, desktop.sas().unwrap());
        assert_eq!(
            verified.client_ed25519_public_key,
            desktop.client_ed25519_public_key()
        );
    }

    /// Aborts authenticate in the right direction through the ops layer: a phone-built
    /// abort (from `pairingCreateAbort`) verifies on the desktop, a desktop-built abort
    /// verifies on the phone, a flipped tag byte fails, and a tag-less abort once the
    /// keys exist is refused rather than reported as the "unauthenticated" `false`.
    /// The defect this catches: `pairingVerifyAbort` checking the wrong directional key
    /// (`K_s2c` instead of `K_c2s`), or accepting an empty tag after the keys exist, so
    /// any observer on the path can cancel a pairing.
    #[test]
    fn pairing_aborts_authenticate_in_both_directions() {
        let (desktop, handle, session_id, qr_pk, response_bytes) = pending_handle_session();
        pairing_verify_response(handle, &response_bytes, &qr_pk).unwrap();

        // Phone → desktop: built here, verified by the desktop state machine.
        let phone_abort = match decode_pairing_packet(
            &pairing_create_abort(handle, PairingAbortReason::UserRejectedSas as i32).unwrap(),
        )
        .unwrap()
        .msg
        {
            Some(pairing_packet::Msg::Abort(abort)) => abort,
            other => panic!("expected PairingAbort, got {other:?}"),
        };
        assert_eq!(
            phone_abort.reason,
            PairingAbortReason::UserRejectedSas as i32
        );
        assert_eq!(phone_abort.auth_tag.len(), 32);
        assert!(desktop.verify_abort(&phone_abort).unwrap());

        // Desktop → phone: verified here, with the `K_c2s` direction the desktop does
        // not use, so the desktop itself must reject its own frame.
        let desktop_abort = desktop
            .create_abort(PairingAbortReason::KeyMismatch)
            .unwrap();
        let desktop_abort_bytes = session_packet(
            &session_id,
            pairing_packet::Msg::Abort(desktop_abort.clone()),
        );
        assert!(pairing_verify_abort(handle, &desktop_abort_bytes).unwrap());
        assert!(desktop.verify_abort(&desktop_abort).is_err());

        // One flipped tag byte fails the direction check.
        let mut flipped = desktop_abort.clone();
        flipped.auth_tag[0] ^= 0xFF;
        assert!(matches!(
            pairing_verify_abort(
                handle,
                &session_packet(&session_id, pairing_packet::Msg::Abort(flipped))
            ),
            Err(JniError::Security(message)) if message.contains("signature")
        ));

        // Keys exist, so a tag-less abort is spoofable: it must be an error, not the
        // `false` that means "unauthenticated abort before any key existed".
        let untagged = PairingAbort {
            reason: PairingAbortReason::ProtocolError as i32,
            auth_tag: Vec::new(),
        };
        assert!(matches!(
            pairing_verify_abort(
                handle,
                &session_packet(&session_id, pairing_packet::Msg::Abort(untagged))
            ),
            Err(JniError::Security(message)) if message.contains("signature")
        ));
    }

    /// `pairingCreateKeepalive` emits a real, decodable `PairingPacket` for the
    /// session: v2, its 16-byte session id and an empty `PairingKeepalive`.
    /// The defect this catches: a frame Kotlin hand-built to another version or with
    /// the wrong session id (which the peer's envelope filter drops), or an envelope
    /// carrying the wrong `msg` variant.
    #[test]
    fn pairing_create_keepalive_emits_a_decodable_v2_frame() {
        let session_id = [0xF1u8; PAIRING_SESSION_ID_LEN];
        let handle =
            pairing_session_create(session_id, Ed25519KeyPair::generate().unwrap(), "pixel")
                .unwrap();

        let bytes = pairing_create_keepalive(handle).unwrap();
        let packet = decode_pairing_packet(&bytes).unwrap();
        assert_eq!(packet.version, PROTOCOL_VERSION_V2);
        assert_eq!(packet.session_id, session_id.to_vec());
        assert_eq!(packet.session_id.len(), PAIRING_SESSION_ID_LEN);
        assert_eq!(
            packet.msg,
            Some(pairing_packet::Msg::Keepalive(PairingKeepalive {}))
        );

        // An unknown handle is a caller error, never a silently empty frame.
        pairing_session_free(handle).unwrap();
        assert!(matches!(
            pairing_create_keepalive(handle),
            Err(JniError::Argument(message)) if message.contains("unknown pairing session handle")
        ));
    }

    /// `pairingPacketSessionId` validates the envelope and returns the 16-byte id.
    /// The defect this catches: a transport filter accepting a v1 frame or a
    /// truncated/padded session id.
    #[test]
    fn pairing_packet_session_id_validates_the_envelope() {
        let session_id = [0xD1u8; PAIRING_SESSION_ID_LEN];
        let bytes = session_packet(
            &session_id,
            pairing_packet::Msg::Keepalive(Default::default()),
        );
        assert_eq!(pairing_packet_session_id(&bytes).unwrap(), session_id);

        // Wrong version.
        let wrong_version = PairingPacket {
            version: 1,
            session_id: session_id.to_vec(),
            msg: Some(pairing_packet::Msg::Keepalive(Default::default())),
        }
        .encode_to_vec();
        assert!(matches!(
            pairing_packet_session_id(&wrong_version),
            Err(JniError::Argument(_))
        ));

        // Truncated session id.
        let short = PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: session_id[..15].to_vec(),
            msg: Some(pairing_packet::Msg::Keepalive(Default::default())),
        }
        .encode_to_vec();
        assert!(matches!(
            pairing_packet_session_id(&short),
            Err(JniError::Argument(_))
        ));

        assert!(matches!(
            pairing_packet_session_id(&[0xFF, 0xFF]),
            Err(JniError::Argument(_))
        ));
    }

    /// The pre-decryption temporal-identifier read requires the 16-byte UDP/GATT form.
    #[test]
    fn encrypted_packet_temporal_identifier_requires_16_bytes() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = grant_packet(csk.as_bytes(), &keypair, AES, [0xE1; 32]);

        let identifier = encrypted_packet_temporal_identifier(&bytes).unwrap();
        assert_eq!(identifier.len(), TEMPORAL_ID_LEN);

        let mut short = EncryptedPacket::decode(bytes.as_slice()).unwrap();
        short.temporal_identifier.truncate(5);
        assert!(matches!(
            encrypted_packet_temporal_identifier(&short.encode_to_vec()),
            Err(JniError::Argument(_))
        ));
    }
}
