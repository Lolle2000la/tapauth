//! Byte-level protocol operations behind the Android (UniFFI) surface.
//!
//! Every decision the Rust↔Kotlin surface makes — protobuf decoding, algorithm
//! pinning, "verify the signature before decoding the inner message", AEAD framing,
//! and every pairing-session state transition — lives here, so it can be exercised
//! by `cargo test --features jni` without a JVM or a Kotlin toolchain. [`super`] (the
//! `ffi` module) only converts arguments, calls into this module, and lets
//! [`TapauthError`] surface as a Kotlin `TapauthException`.
//!
//! None of these functions `unwrap`, `expect` or panic: every failure is a
//! [`TapauthError`] carrying the exception type it must surface as.

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
    decode_pairing_packet, encode_pairing_packet, pairing_session_id, ServerPairingSession,
    PAIRING_SESSION_ID_LEN,
};
use crate::protocol::pb::{
    pairing_packet, EncryptedPacket, HashAlgorithm, PairingAbortReason, PairingPacket, PayloadType,
    SignatureAlgorithm, SymmetricAlgorithm, WrapperMessage,
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
/// The variant fixes the Kotlin exception type: `Argument` →
/// `TapauthException.Argument`, `Security` → `TapauthException.Security`,
/// `Io` → `TapauthException.Io`, `State` → `TapauthException.State`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TapauthError {
    /// Malformed caller input: wrong lengths, an unsupported caller-chosen
    /// negotiation algorithm id, or a packet for another pairing session.
    #[error("{detail}")]
    Argument {
        /// The detail handed to Kotlin verbatim, prefixed with the argument name
        /// where the failure names one.
        detail: String,
    },
    /// Signature, AEAD, algorithm-binding or protocol-integrity failure.
    #[error("{detail}")]
    Security {
        /// The detail handed to Kotlin verbatim.
        detail: String,
    },
    /// A protobuf blob that cannot be decoded.
    #[error("{detail}")]
    Io {
        /// The detail handed to Kotlin verbatim.
        detail: String,
    },
    /// An FFI-object or internal-state failure.
    #[error("{detail}")]
    State {
        /// The detail handed to Kotlin verbatim.
        detail: String,
    },
}

impl From<CryptoError> for TapauthError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidSignature => Self::Security {
                detail: "invalid signature".to_string(),
            },
            other => Self::Security {
                detail: format!("cryptographic failure: {other}"),
            },
        }
    }
}

impl From<ProtocolError> for TapauthError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::Serialization(inner) => Self::Io {
                detail: format!("protobuf encode failed: {inner}"),
            },
            ProtocolError::Deserialization(inner) => Self::Io {
                detail: format!("protobuf decode failed: {inner}"),
            },
            ProtocolError::Io(inner) => Self::Io {
                detail: format!("io failure: {inner}"),
            },
            ProtocolError::InvalidSignature => Self::Security {
                detail: "invalid signature".to_string(),
            },
            ProtocolError::Crypto(inner) => inner.into(),
            ProtocolError::AlgorithmMismatch => Self::Security {
                detail: "algorithm mismatch between peer and local policy".to_string(),
            },
            ProtocolError::UnsupportedAlgorithm => Self::Security {
                detail: "peer selected an unsupported algorithm".to_string(),
            },
            ProtocolError::ChallengeMismatch => Self::Security {
                detail: "challenge does not match the session".to_string(),
            },
            ProtocolError::MissingField(field) => Self::Security {
                detail: format!("signed message is missing required field {field}"),
            },
            ProtocolError::InvalidMessageFormat => Self::Security {
                detail: "malformed or unexpected protocol message".to_string(),
            },
            ProtocolError::SessionConcluded => Self::State {
                detail: "pairing session already concluded".to_string(),
            },
            ProtocolError::ConfirmationAlreadySent => Self::State {
                detail: "pairing confirmation already sent; the handshake has moved past \
                         this step"
                    .to_string(),
            },
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
fn check_protocol_version(protocol_version: i32) -> Result<(), TapauthError> {
    if protocol_version != PROTOCOL_VERSION_V2 as i32 {
        return Err(TapauthError::Security { detail: format!(
            "unsupported protocol version {protocol_version} (this build speaks only v{PROTOCOL_VERSION_V2})"
        ) });
    }
    Ok(())
}

/// Decode `EncryptedPacket` bytes.
fn decode_encrypted_packet(packet_bytes: &[u8]) -> Result<EncryptedPacket, TapauthError> {
    EncryptedPacket::decode(packet_bytes).map_err(|err| TapauthError::Io {
        detail: format!("invalid EncryptedPacket: {err}"),
    })
}

/// Decode `WrapperMessage` bytes.
fn decode_wrapper(wrapper_bytes: &[u8]) -> Result<WrapperMessage, TapauthError> {
    WrapperMessage::decode(wrapper_bytes).map_err(|err| TapauthError::Io {
        detail: format!("invalid WrapperMessage: {err}"),
    })
}

/// Reject a signed envelope that does not declare the v2 framing.
///
/// `version` is part of the signing transcript, so a non-v2 value is either a
/// misbehaving peer or a replayed v1 frame; both are refused before any decode.
fn check_wrapper_version(wrapper: &WrapperMessage) -> Result<(), TapauthError> {
    if wrapper.version != PROTOCOL_VERSION_V2 {
        return Err(TapauthError::Security {
            detail: format!(
                "unexpected wrapper version {} (this build speaks only v{PROTOCOL_VERSION_V2})",
                wrapper.version
            ),
        });
    }
    Ok(())
}

/// Require `wrapper.payload_type` to name the message the caller is waiting for.
///
/// `payload_type` is covered by the signature; checking it first keeps the parse
/// entry points from dispatching on an attacker-chosen tag.
fn require_payload_type(
    wrapper: &WrapperMessage,
    expected: PayloadType,
) -> Result<(), TapauthError> {
    if wrapper.payload_type != expected as i32 {
        return Err(TapauthError::Security {
            detail: format!(
                "unexpected payload type {} (expected {})",
                wrapper.payload_type, expected as i32
            ),
        });
    }
    Ok(())
}

/// Convert a decoded `challenge` field into its fixed 32-byte form.
fn challenge_32(challenge: &[u8]) -> Result<[u8; CHALLENGE_LEN], TapauthError> {
    challenge.try_into().map_err(|_| TapauthError::Argument {
        detail: format!(
            "challenge must be {CHALLENGE_LEN} bytes, got {}",
            challenge.len()
        ),
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
) -> Result<Vec<u8>, TapauthError> {
    let expected = symmetric_algorithm(expected_symmetric_algorithm)?;
    let packet = decode_encrypted_packet(packet_bytes)?;

    // Malformed envelope, not a security event: refuse it before the algorithm
    // check and before any AEAD work.
    if packet.temporal_identifier.len() != TEMPORAL_ID_LEN {
        return Err(TapauthError::Argument {
            detail: format!(
                "temporal identifier must be {TEMPORAL_ID_LEN} bytes, got {}",
                packet.temporal_identifier.len()
            ),
        });
    }

    if packet.encryption_algorithm != expected as i32 {
        return Err(TapauthError::Security {
            detail: format!(
                "packet encryption algorithm {} does not match the negotiated algorithm {}",
                packet.encryption_algorithm, expected as i32
            ),
        });
    }

    let key = ClientSymmetricKey::from_bytes(*csk);
    let aad = encrypted_packet_aad(packet.encryption_algorithm, &packet.temporal_identifier);
    decrypt_with_csk_and_prepended_nonce(&key, expected, &packet.ciphertext, &aad).map_err(|err| {
        TapauthError::Security {
            detail: format!("packet decryption failed: {err}"),
        }
    })
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
) -> Result<VerifiedAuthRequest, TapauthError> {
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
        _ => Err(TapauthError::Security {
            detail: "payload is not an AuthenticationRequest".to_string(),
        }),
    }
}

/// Verify a `GrantConfirmation` or `AuthenticationCancel` and return its challenge.
fn verified_challenge(
    wrapper_bytes: &[u8],
    client_ed25519_public_key: &[u8; 32],
    protocol_version: i32,
    expected: PayloadType,
    expected_signature_algorithm: i32,
) -> Result<[u8; CHALLENGE_LEN], TapauthError> {
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
) -> Result<[u8; CHALLENGE_LEN], TapauthError> {
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
) -> Result<[u8; CHALLENGE_LEN], TapauthError> {
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
) -> Result<Vec<u8>, TapauthError> {
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
) -> Result<Vec<u8>, TapauthError> {
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
///
/// `AES_256_GCM` (1) is the only id this build implements; `0`, the reserved
/// tag `2` and any other id are caller errors rather than a default.
fn symmetric_algorithm(value: i32) -> Result<SymmetricAlgorithm, TapauthError> {
    match SymmetricAlgorithm::try_from(value) {
        Ok(SymmetricAlgorithm::Aes256Gcm) => Ok(SymmetricAlgorithm::Aes256Gcm),
        _ => Err(TapauthError::Argument {
            detail: format!("unsupported symmetric algorithm id {value}"),
        }),
    }
}

/// Resolve a caller-supplied `HashAlgorithm` id, rejecting `UNSPECIFIED` and any
/// value this build cannot implement.
///
/// `SHA256` (1) is the only id this build implements; `0`, the reserved tag `2`
/// and any other id are caller errors rather than a default.
fn hash_algorithm(value: i32) -> Result<HashAlgorithm, TapauthError> {
    match HashAlgorithm::try_from(value) {
        Ok(HashAlgorithm::Sha256) => Ok(HashAlgorithm::Sha256),
        _ => Err(TapauthError::Argument {
            detail: format!("unsupported hash algorithm id {value}"),
        }),
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
fn signature_algorithm(value: i32) -> Result<i32, TapauthError> {
    match SignatureAlgorithm::try_from(value) {
        Ok(SignatureAlgorithm::Ed25519) => Ok(SignatureAlgorithm::Ed25519 as i32),
        _ => Err(TapauthError::Security {
            detail: format!("unsupported signature algorithm id {value} for this paired client"),
        }),
    }
}

/// 16-byte UDP/GATT temporal identifier for `window` under `hash_algorithm_id`.
pub(crate) fn temporal_identifier(
    csk: &[u8; CSK_LEN],
    window: i64,
    hash_algorithm_id: i32,
) -> Result<[u8; TEMPORAL_ID_LEN], TapauthError> {
    let hash = hash_algorithm(hash_algorithm_id)?;
    let window = u64::try_from(window).map_err(|_| TapauthError::Argument {
        detail: format!("time window must be non-negative, got {window}"),
    })?;
    let key = ClientSymmetricKey::from_bytes(*csk);
    generate_temporal_id_with_alg(&key, window, hash).map_err(Into::into)
}

/// 10-byte BLE advertisement temporal identifier for `window` under `hash_algorithm_id`.
pub(crate) fn ble_temporal_identifier(
    csk: &[u8; CSK_LEN],
    window: i64,
    hash_algorithm_id: i32,
) -> Result<[u8; BLE_TEMPORAL_ID_LEN], TapauthError> {
    let hash = hash_algorithm(hash_algorithm_id)?;
    let window = u64::try_from(window).map_err(|_| TapauthError::Argument {
        detail: format!("time window must be non-negative, got {window}"),
    })?;
    let key = ClientSymmetricKey::from_bytes(*csk);
    generate_ble_temporal_id_with_alg(&key, window, hash).map_err(Into::into)
}

/// The current 60-second time window.
pub(crate) fn time_window_now() -> Result<i64, TapauthError> {
    let window = current_time_window()?;
    i64::try_from(window).map_err(|_| TapauthError::State {
        detail: "system clock is out of range".to_string(),
    })
}

/// Check a received temporal identifier (`10` or `16` bytes) against the current and
/// previous window for `hash_algorithm_id`.
pub(crate) fn verify_temporal_identifier(
    temporal_identifier: &[u8],
    csk: &[u8; CSK_LEN],
    hash_algorithm_id: i32,
) -> Result<bool, TapauthError> {
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
        len => Err(TapauthError::Argument { detail: format!(
            "temporal identifier must be {TEMPORAL_ID_LEN} or {BLE_TEMPORAL_ID_LEN} bytes, got {len}"
        ) }),
    }
}

/// The 10-byte BLE pairing advertisement identifier for a scanned QR code.
pub(crate) fn ble_pairing_adv_id(
    session_id: &[u8],
    client_x25519_public_key: &[u8; 32],
) -> Result<[u8; BLE_TEMPORAL_ID_LEN], TapauthError> {
    if session_id.len() != PAIRING_SESSION_ID_LEN {
        return Err(TapauthError::Argument {
            detail: format!(
                "session id must be {PAIRING_SESSION_ID_LEN} bytes, got {}",
                session_id.len()
            ),
        });
    }
    Ok(crate::crypto::derive_ble_pairing_adv_id(
        session_id,
        client_x25519_public_key,
    ))
}

// ---------------------------------------------------------------------------
// Pairing (Android is the protocol Server)
// ---------------------------------------------------------------------------

/// Decode a `PairingPacket` and require it to belong to `session`.
fn decode_session_packet(
    session: &ServerPairingSession,
    packet_bytes: &[u8],
) -> Result<PairingPacket, TapauthError> {
    let packet = decode_pairing_packet(packet_bytes).map_err(|err| TapauthError::Argument {
        detail: format!("invalid PairingPacket: {err}"),
    })?;

    if packet.session_id.as_slice() != session.session_id().as_slice() {
        return Err(TapauthError::Argument {
            detail: "PairingPacket session id does not match this pairing session".to_string(),
        });
    }
    Ok(packet)
}

/// Wrap a pairing message in its `PairingPacket` envelope and serialize it.
fn encode_session_packet(
    session: &ServerPairingSession,
    message: pairing_packet::Msg,
) -> Result<Vec<u8>, TapauthError> {
    let packet = PairingPacket {
        version: PROTOCOL_VERSION_V2,
        session_id: session.session_id().to_vec(),
        msg: Some(message),
    };
    encode_pairing_packet(&packet).map_err(|err| TapauthError::State {
        detail: format!("failed to encode PairingPacket: {err}"),
    })
}

/// Build the `PairingInit` to send (serialized `PairingPacket`).
pub(crate) fn pairing_create_init(
    session: &mut ServerPairingSession,
) -> Result<Vec<u8>, TapauthError> {
    let init = session.create_init()?;
    encode_session_packet(session, pairing_packet::Msg::Init(init))
}

/// Verify the desktop's `PairingResponse` and return what the phone persists and shows.
///
/// The QR commitment (`client_x25519_public_key == expected_qr_public_key`) is the
/// whole point of the pin: it is checked inside
/// [`ServerPairingSession::verify_response`] in constant time, first, and there is no
/// sentinel that skips it. Nothing is cached until every check passed, so a response
/// that fails here leaves the session unkeyed and a later genuine one still verifies.
pub(crate) fn pairing_verify_response(
    session: &mut ServerPairingSession,
    response_packet: &[u8],
    expected_qr_public_key: &[u8; 32],
) -> Result<VerifiedPairingResponse, TapauthError> {
    let packet = decode_session_packet(session, response_packet)?;
    match packet.msg {
        Some(pairing_packet::Msg::Response(response)) => {
            session.verify_response(&response, expected_qr_public_key)?;

            let client_ed25519_public_key: [u8; 32] = response
                .client_ed25519_public_key
                .as_slice()
                .try_into()
                .map_err(|_| TapauthError::Argument {
                    detail: format!(
                        "PairingResponse client Ed25519 key must be 32 bytes, got {}",
                        response.client_ed25519_public_key.len()
                    ),
                })?;

            let sas = session
                .sas()
                .ok_or_else(|| TapauthError::State {
                    detail: "SAS unavailable after a verified response".to_string(),
                })?
                .to_string();
            let negotiated = session.negotiated().ok_or_else(|| TapauthError::State {
                detail: "algorithms unavailable after a verified response".to_string(),
            })?;

            Ok(VerifiedPairingResponse {
                sas,
                client_ed25519_public_key,
                symmetric_algorithm: negotiated.symmetric_algorithm as i32,
                hash_algorithm: negotiated.hash_algorithm as i32,
                signature_algorithm: negotiated.signature_algorithm as i32,
            })
        }
        _ => Err(TapauthError::Argument {
            detail: "PairingPacket does not carry a PairingResponse".to_string(),
        }),
    }
}

/// Decrypt the desktop's provisioning payload.
pub(crate) fn pairing_process_confirm_client(
    session: &ServerPairingSession,
    confirm_client_packet: &[u8],
) -> Result<ProvisionedClient, TapauthError> {
    let packet = decode_session_packet(session, confirm_client_packet)?;
    match packet.msg {
        Some(pairing_packet::Msg::ConfirmClient(confirm)) => {
            let payload = session.process_confirm_client(&confirm)?;
            let csk: [u8; CSK_LEN] =
                payload
                    .csk
                    .as_slice()
                    .try_into()
                    .map_err(|_| TapauthError::Argument {
                        detail: format!(
                            "provisioned CSK must be {CSK_LEN} bytes, got {}",
                            payload.csk.len()
                        ),
                    })?;
            Ok(ProvisionedClient {
                csk: Zeroizing::new(csk),
                username: payload.username,
                client_hostname: payload.client_hostname,
            })
        }
        _ => Err(TapauthError::Argument {
            detail: "PairingPacket does not carry a PairingConfirmClient".to_string(),
        }),
    }
}

/// Build the completion proof (serialized `PairingPacket` with `PairingConfirmServer`).
///
/// Marks the session's confirmation as sent; the session stays live so
/// `pairing_process_confirm_client` can keep answering retransmissions.
pub(crate) fn pairing_create_confirm_server(
    session: &mut ServerPairingSession,
    csk: &[u8; CSK_LEN],
) -> Result<Vec<u8>, TapauthError> {
    let confirm = session.create_confirm_server(csk)?;
    encode_session_packet(session, pairing_packet::Msg::ConfirmServer(confirm))
}

/// Build a keepalive frame (serialized `PairingPacket` with `PairingKeepalive`).
///
/// The frame carries no key material and no state transition: it only keeps a NAT
/// or BLE link alive while the two users compare the SAS. Kotlin must not hand-build
/// the wire format, so the empty message is encoded here. A concluded session refuses
/// it (`State`), like every other entry point: the frame would keep a path open for a
/// `PairingConfirmClient` retransmission that `process_confirm_client` also refuses.
pub(crate) fn pairing_create_keepalive(
    session: &ServerPairingSession,
) -> Result<Vec<u8>, TapauthError> {
    let keepalive = session.create_keepalive()?;
    encode_session_packet(session, pairing_packet::Msg::Keepalive(keepalive))
}

/// Resolve a caller-supplied `PairingAbortReason` id.
fn pairing_abort_reason(value: i32) -> Result<PairingAbortReason, TapauthError> {
    PairingAbortReason::try_from(value).map_err(|_| TapauthError::Argument {
        detail: format!("unknown pairing abort reason id {value}"),
    })
}

/// Build an abort (serialized `PairingPacket` with `PairingAbort`).
pub(crate) fn pairing_create_abort(
    session: &ServerPairingSession,
    reason: i32,
) -> Result<Vec<u8>, TapauthError> {
    let reason = pairing_abort_reason(reason)?;
    let abort = session.create_abort(reason)?;
    encode_session_packet(session, pairing_packet::Msg::Abort(abort))
}

/// Verify an abort received from the desktop.
///
/// `Ok(false)` means a tag-less abort arrived before any key existed, i.e. it is
/// unauthenticated by construction; a tag-less or wrong-tag abort once the keys do
/// exist is a [`TapauthError::Security`] failure, never `Ok(false)`.
pub(crate) fn pairing_verify_abort(
    session: &ServerPairingSession,
    abort_packet: &[u8],
) -> Result<bool, TapauthError> {
    let packet = decode_session_packet(session, abort_packet)?;
    match packet.msg {
        Some(pairing_packet::Msg::Abort(abort)) => session.verify_abort(&abort).map_err(Into::into),
        _ => Err(TapauthError::Argument {
            detail: "PairingPacket does not carry a PairingAbort".to_string(),
        }),
    }
}

/// Extract the validated 16-byte `session_id` of a serialized `PairingPacket`.
pub(crate) fn pairing_packet_session_id(
    packet_bytes: &[u8],
) -> Result<[u8; PAIRING_SESSION_ID_LEN], TapauthError> {
    let packet = decode_pairing_packet(packet_bytes).map_err(|err| TapauthError::Argument {
        detail: format!("invalid PairingPacket: {err}"),
    })?;
    pairing_session_id(&packet).map_err(|err| TapauthError::Argument {
        detail: format!("invalid PairingPacket session id: {err}"),
    })
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
pub(crate) fn message_type_name(
    wrapper_bytes: &[u8],
) -> Result<Option<&'static str>, TapauthError> {
    let wrapper = decode_wrapper(wrapper_bytes)?;
    Ok(payload_type_name(&wrapper))
}

/// Read the validated `temporal_identifier` of a serialized `EncryptedPacket`.
pub(crate) fn encrypted_packet_temporal_identifier(
    packet_bytes: &[u8],
) -> Result<[u8; TEMPORAL_ID_LEN], TapauthError> {
    let packet = decode_encrypted_packet(packet_bytes)?;
    packet
        .temporal_identifier
        .as_slice()
        .try_into()
        .map_err(|_| TapauthError::Argument {
            detail: format!(
                "temporal identifier must be {TEMPORAL_ID_LEN} bytes, got {}",
                packet.temporal_identifier.len()
            ),
        })
}
