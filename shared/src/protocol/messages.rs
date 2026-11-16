//! Protocol message creation, signing and verification.
//!
//! v2 signs the **raw** inner protobuf bytes carried in `WrapperMessage.payload`
//! (see `cryptography-specification.md` §2.3). Verification therefore runs over the
//! exact wire bytes of `payload` instead of re-serializing a decoded struct, so
//! unknown fields written by a newer peer survive signature verification and are
//! ignored by the inner decode that follows.
//!
//! The caller context those messages carry — its byte budgets and the sanitizer that
//! makes it safe to display — lives in the `context` submodule.

use prost::Message as ProstMessage;
use subtle::ConstantTimeEq;

use crate::crypto::{sign_ed25519, verify_ed25519, CryptoError, Ed25519KeyPair};
use crate::protocol::packet::{wrap_auth_denial, wrap_auth_grant};
use crate::protocol::pb::*;

mod context;

pub use context::*;

/// Protocol version stored in `WrapperMessage.version` for the v2 framing.
pub const PROTOCOL_VERSION_V2: u32 = 2;

/// Domain separation tag prepended to every `WrapperMessage` signing transcript.
const WRAPPER_SIGNING_DOMAIN: &[u8] = b"tapauth-sig-v2";

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] prost::EncodeError),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] prost::DecodeError),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("Invalid message format")]
    InvalidMessageFormat,
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Algorithm mismatch")]
    AlgorithmMismatch,
    #[error("Challenge mismatch")]
    ChallengeMismatch,
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    /// The pairing session reached its terminal state: `conclude()` already
    /// dropped every key, so no further protocol operation may run on it.
    #[error("Pairing session has already concluded")]
    SessionConcluded,
    /// The phone already sent its completion proof: the handshake has moved past
    /// the step the caller is trying to run again, so a second
    /// `create_confirm_server` (or a `create_init` after it) is refused. Distinct
    /// from [`ProtocolError::SessionConcluded`]: the session is not over, it still
    /// answers `process_confirm_client` retransmissions.
    #[error("Pairing confirmation already sent")]
    ConfirmationAlreadySent,
}

/// Build the v2 `WrapperMessage` signing transcript:
///
/// `b"tapauth-sig-v2" || be32(version) || be32(signature_algorithm)
///  || be32(payload_type) || raw_payload`
pub fn wrapper_signing_transcript(
    version: u32,
    signature_algorithm: i32,
    payload_type: i32,
    raw_payload: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        WRAPPER_SIGNING_DOMAIN.len() + 3 * std::mem::size_of::<u32>() + raw_payload.len(),
    );
    transcript.extend_from_slice(WRAPPER_SIGNING_DOMAIN);
    transcript.extend_from_slice(&version.to_be_bytes());
    transcript.extend_from_slice(&signature_algorithm.to_be_bytes());
    transcript.extend_from_slice(&payload_type.to_be_bytes());
    transcript.extend_from_slice(raw_payload);
    transcript
}

/// Sign a `WrapperMessage` over its raw payload bytes.
///
/// Sets `signature_algorithm` to `ED25519` and clears `signature` before computing the
/// transcript. The inner protobuf is never re-serialized: the signature covers exactly
/// the bytes already sitting in `wrapper.payload`.
pub fn sign_wrapper_message(
    wrapper: &mut WrapperMessage,
    keypair: &Ed25519KeyPair,
) -> Result<(), ProtocolError> {
    wrapper.signature_algorithm = SignatureAlgorithm::Ed25519 as i32;
    wrapper.signature = Vec::new();

    let transcript = wrapper_signing_transcript(
        wrapper.version,
        wrapper.signature_algorithm,
        wrapper.payload_type,
        &wrapper.payload,
    );

    wrapper.signature = sign_ed25519(keypair, &transcript);
    Ok(())
}

/// Verify a `WrapperMessage` signature over its raw payload bytes.
///
/// The declared algorithm must equal the algorithm the caller expects (no silent
/// downgrade to `UNSPECIFIED` or to an algorithm the caller cannot validate), and only
/// `ED25519` is implemented. Verification happens over the raw payload bytes, so no
/// inner decode is performed here or implied.
///
/// The declared framing version must be [`PROTOCOL_VERSION_V2`]. The version is inside
/// the signed transcript, so a well-signed v1 frame cannot be forged, but the
/// verifiers below (`verify_auth_grant`, `verify_auth_denial`,
/// `verify_and_decode_payload`) are reached from `tapauthd` and the FFI surface without
/// any other version gate, and a v1 payload must never reach the v2 decoder. Checking
/// it here is defence in depth and costs one comparison.
pub fn verify_wrapper_signature(
    wrapper: &WrapperMessage,
    public_key: &[u8; 32],
    expected_signature_algorithm: i32,
) -> Result<(), ProtocolError> {
    if wrapper.version != PROTOCOL_VERSION_V2 {
        return Err(ProtocolError::InvalidMessageFormat);
    }
    if wrapper.signature_algorithm != expected_signature_algorithm {
        return Err(ProtocolError::AlgorithmMismatch);
    }
    if wrapper.signature_algorithm != SignatureAlgorithm::Ed25519 as i32 {
        return Err(ProtocolError::UnsupportedAlgorithm);
    }
    if wrapper.signature.is_empty() {
        return Err(ProtocolError::InvalidSignature);
    }

    let transcript = wrapper_signing_transcript(
        wrapper.version,
        wrapper.signature_algorithm,
        wrapper.payload_type,
        &wrapper.payload,
    );

    verify_ed25519(public_key, &transcript, &wrapper.signature)?;
    Ok(())
}

/// An inner payload decoded according to `WrapperMessage.payload_type`.
#[derive(Debug, Clone)]
pub enum DecodedPayload {
    AuthRequest(AuthenticationRequest),
    AuthGrant(AuthenticationGrant),
    AuthDenial(AuthenticationDenial),
    GrantConfirmation(GrantConfirmation),
    AuthCancel(AuthenticationCancel),
}

/// Decode `wrapper.payload` according to `wrapper.payload_type`.
///
/// Does **not** verify anything, which is why it is crate-private: the only
/// public entry point is [`verify_and_decode_payload`], which verifies the wrapper
/// signature before the inner decode.
pub(crate) fn decode_payload(wrapper: &WrapperMessage) -> Result<DecodedPayload, ProtocolError> {
    let payload = wrapper.payload.as_slice();
    let payload_type = wrapper.payload_type;

    if payload_type == PayloadType::AuthRequest as i32 {
        Ok(DecodedPayload::AuthRequest(AuthenticationRequest::decode(
            payload,
        )?))
    } else if payload_type == PayloadType::AuthGrant as i32 {
        Ok(DecodedPayload::AuthGrant(AuthenticationGrant::decode(
            payload,
        )?))
    } else if payload_type == PayloadType::AuthDenial as i32 {
        Ok(DecodedPayload::AuthDenial(AuthenticationDenial::decode(
            payload,
        )?))
    } else if payload_type == PayloadType::GrantConfirmation as i32 {
        Ok(DecodedPayload::GrantConfirmation(
            GrantConfirmation::decode(payload)?,
        ))
    } else if payload_type == PayloadType::AuthCancel as i32 {
        Ok(DecodedPayload::AuthCancel(AuthenticationCancel::decode(
            payload,
        )?))
    } else {
        Err(ProtocolError::InvalidMessageFormat)
    }
}

/// Verify the wrapper signature, then decode the inner payload.
///
/// This is the only ordering callers may use: an unauthenticated `payload` must never
/// reach a protobuf decoder.
pub fn verify_and_decode_payload(
    wrapper: &WrapperMessage,
    public_key: &[u8; 32],
    expected_signature_algorithm: i32,
) -> Result<DecodedPayload, ProtocolError> {
    verify_wrapper_signature(wrapper, public_key, expected_signature_algorithm)?;
    decode_payload(wrapper)
}

/// Create a signed `AuthenticationGrant` for `challenge`.
///
/// The challenge is bound by the single wrapper signature; the grant carries no
/// second signature of its own.
pub fn create_signed_auth_grant(
    challenge: [u8; 32],
    keypair: &Ed25519KeyPair,
) -> Result<WrapperMessage, ProtocolError> {
    let grant = AuthenticationGrant {
        challenge: challenge.to_vec(),
    };
    let mut wrapper = wrap_auth_grant(grant);
    sign_wrapper_message(&mut wrapper, keypair)?;
    Ok(wrapper)
}

/// Create a signed `AuthenticationDenial` for `challenge` with a human-readable reason.
pub fn create_signed_auth_denial(
    challenge: [u8; 32],
    reason: &str,
    keypair: &Ed25519KeyPair,
) -> Result<WrapperMessage, ProtocolError> {
    let denial = AuthenticationDenial {
        challenge: challenge.to_vec(),
        reason: reason.to_string(),
    };
    let mut wrapper = wrap_auth_denial(denial);
    sign_wrapper_message(&mut wrapper, keypair)?;
    Ok(wrapper)
}

/// Verify a signed `AuthenticationGrant` against the challenge it must answer.
pub fn verify_auth_grant(
    wrapper: &WrapperMessage,
    challenge: &[u8; 32],
    server_public_key: &[u8; 32],
    expected_signature_algorithm: i32,
) -> Result<(), ProtocolError> {
    match verify_and_decode_payload(wrapper, server_public_key, expected_signature_algorithm)? {
        DecodedPayload::AuthGrant(grant) => verify_challenge_field(&grant.challenge, challenge),
        _ => Err(ProtocolError::InvalidMessageFormat),
    }
}

/// Verify a signed `AuthenticationDenial` against the challenge it must answer.
pub fn verify_auth_denial(
    wrapper: &WrapperMessage,
    challenge: &[u8; 32],
    server_public_key: &[u8; 32],
    expected_signature_algorithm: i32,
) -> Result<(), ProtocolError> {
    match verify_and_decode_payload(wrapper, server_public_key, expected_signature_algorithm)? {
        DecodedPayload::AuthDenial(denial) => verify_challenge_field(&denial.challenge, challenge),
        _ => Err(ProtocolError::InvalidMessageFormat),
    }
}

/// Require the inner `challenge` field to be exactly 32 bytes and equal `expected`.
///
/// The length check comes first because `ct_eq` only compares equal-length
/// slices; the length itself is not secret (both sides are fixed-length 32-byte
/// challenges on the paths that use it).
fn verify_challenge_field(field: &[u8], expected: &[u8; 32]) -> Result<(), ProtocolError> {
    if field.len() != expected.len() {
        return Err(ProtocolError::ChallengeMismatch);
    }
    if bool::from(field.ct_eq(expected.as_slice())) {
        Ok(())
    } else {
        Err(ProtocolError::ChallengeMismatch)
    }
}

/// Create an AuthenticationRequest message (without signature)
/// The signature will be added when wrapping in WrapperMessage
pub fn create_auth_request(
    username: &str,
    hostname: &str,
) -> Result<AuthenticationRequest, ProtocolError> {
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge)
        .map_err(|_| ProtocolError::Crypto(CryptoError::RandomGenerationFailed))?;

    create_auth_request_with_challenge(username, hostname, &challenge)
}

/// Create an AuthenticationRequest with an externally supplied 32-byte challenge
pub fn create_auth_request_with_challenge(
    username: &str,
    hostname: &str,
    challenge: &[u8],
) -> Result<AuthenticationRequest, ProtocolError> {
    create_auth_request_with_context(
        challenge,
        ContextFields {
            username,
            hostname,
            pam_service: "",
            process_name: "",
            command_preview: "",
        },
        false,
    )
}

/// The five caller-context strings an [`AuthenticationRequest`] carries, named.
///
/// The struct exists so the values cannot be transposed: five of the builder's
/// parameters were exactly these five strings, which made a wrong order compile.
/// A named field has no position to get wrong.
pub struct ContextFields<'a> {
    pub username: &'a str,
    pub hostname: &'a str,
    pub pam_service: &'a str,
    pub process_name: &'a str,
    pub command_preview: &'a str,
}

/// Create an AuthenticationRequest carrying sanitized call-site context.
///
/// Every bounded field takes its budget and its over-budget behaviour from its row of
/// the per-field table (`ContextField::policy`, whose rows are `FieldPolicy`) rather
/// than from a check written here: every field but the username is sanitized and
/// truncated, so the signed payload stays inside the BLE GATT budget
/// ([`crate::models::ble::MAX_GATT_PAYLOAD_BYTES`]), while `username` is **rejected**
/// with [`ProtocolError::InvalidMessageFormat`] when it exceeds its budget. That
/// distinction is a column of the table, not a branch to notice: the username is the
/// account the Server (phone) shows and the one the Client authorizes, so a truncated
/// value would name a different account than the one being authenticated, while a
/// long hostname is only display text.
///
/// The five bounded values arrive as [`ContextFields`], so their order cannot be
/// transposed: the function takes the challenge, the fields and `tty_present`, and
/// nothing else.
pub fn create_auth_request_with_context(
    challenge: &[u8],
    fields: ContextFields<'_>,
    tty_present: bool,
) -> Result<AuthenticationRequest, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    // One row per field. A field is bounded only by appearing here, so the table above
    // is the whole list of what *this builder* asks `sanitize_context_string` to cut —
    // `tapauthd/src/caller_context.rs` cuts the same three fields on its own, and a row
    // edited here does not reach it.
    let username = bound_context_value(ContextField::Username, fields.username)?;
    let hostname = bound_context_value(ContextField::Hostname, fields.hostname)?;
    let pam_service = bound_context_value(ContextField::PamService, fields.pam_service)?;
    let process_name = bound_context_value(ContextField::ProcessName, fields.process_name)?;
    let command_preview =
        bound_context_value(ContextField::CommandPreview, fields.command_preview)?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProtocolError::Crypto(CryptoError::SystemTimeError))?
        .as_secs();

    Ok(AuthenticationRequest {
        challenge: challenge.to_vec(),
        username,
        hostname,
        timestamp_unix_seconds: timestamp,
        pam_service,
        process_name,
        command_preview,
        tty_present,
    })
}

/// Validate timestamp in AuthenticationRequest (within ±60 seconds)
pub fn is_request_timestamp_valid(request: &AuthenticationRequest) -> bool {
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return false,
    };

    let timestamp = request.timestamp_unix_seconds;
    const MAX_CLOCK_SKEW: u64 = 60; // 60-second validity window per auth spec

    timestamp <= now + MAX_CLOCK_SKEW && timestamp >= now.saturating_sub(MAX_CLOCK_SKEW)
}

/// Create a GrantConfirmation message
pub fn create_grant_confirmation(challenge: &[u8]) -> Result<GrantConfirmation, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    Ok(GrantConfirmation {
        challenge: challenge.to_vec(),
    })
}

/// Create an AuthenticationCancel message
pub fn create_auth_cancel(challenge: &[u8]) -> Result<AuthenticationCancel, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    Ok(AuthenticationCancel {
        challenge: challenge.to_vec(),
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
    use crate::protocol::packet::*;

    const ED25519: i32 = SignatureAlgorithm::Ed25519 as i32;

    fn sample_request() -> AuthenticationRequest {
        AuthenticationRequest {
            challenge: vec![0x11; 32],
            username: "user".to_string(),
            hostname: "host".to_string(),
            timestamp_unix_seconds: 1_700_000_000,
            pam_service: "sudo".to_string(),
            process_name: "sudo".to_string(),
            command_preview: "apt upgrade".to_string(),
            tty_present: true,
        }
    }

    #[test]
    fn test_wrapper_signing_transcript_layout() {
        let transcript = wrapper_signing_transcript(2, ED25519, 4, b"abc");

        let mut expected = b"tapauth-sig-v2".to_vec();
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // be32(version)
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // be32(signature_algorithm)
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // be32(payload_type)
        expected.extend_from_slice(b"abc");

        assert_eq!(transcript, expected);
        assert_eq!(
            transcript.get(..WRAPPER_SIGNING_DOMAIN.len()),
            Some(WRAPPER_SIGNING_DOMAIN)
        );
        // "tapauth-sig-v2" is 14 bytes; + 3 be32 words + the raw payload.
        assert_eq!(WRAPPER_SIGNING_DOMAIN.len(), 14);
        assert_eq!(transcript.len(), 14 + 12 + 3);
    }

    #[test]
    fn test_wrapper_signature_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();

        let mut wrapper = wrap_auth_request(sample_request());
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        assert_eq!(wrapper.signature.len(), 64); // Ed25519 signatures are 64 bytes
        assert_eq!(wrapper.signature_algorithm, ED25519);

        // Verify with correct key
        assert!(
            verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes(), ED25519).is_ok()
        );

        // Verify with wrong key should fail
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(
            verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes(), ED25519)
                .is_err()
        );
    }

    #[test]
    fn test_tampered_signature_detection() {
        let keypair = Ed25519KeyPair::generate().unwrap();

        let mut wrapper = wrap_auth_request(sample_request());
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Tamper with the signature
        if let Some(byte) = wrapper.signature.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }

        assert!(
            verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes(), ED25519).is_err()
        );
    }

    #[test]
    fn test_unknown_protobuf_field_is_signed_and_ignored_on_decode() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let request = sample_request();

        // Append a hand-encoded unknown field 99, wire type 2 (length delimited):
        // key = (99 << 3) | 2 = 794 = 0x031A -> varint [0x9a, 0x06]; len 3; "xyz".
        let mut payload = request.encode_to_vec();
        payload.extend_from_slice(&[0x9a, 0x06, 0x03, b'x', b'y', b'z']);

        let mut wrapper = WrapperMessage {
            version: PROTOCOL_VERSION_V2,
            signature_algorithm: ED25519,
            payload_type: PayloadType::AuthRequest as i32,
            payload: payload.clone(),
            signature: Vec::new(),
        };
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Signing must not re-serialize (and therefore not drop) the raw bytes.
        assert_eq!(wrapper.payload, payload);

        // The unknown field is inside the signed transcript.
        let mut tampered = wrapper.clone();
        tampered.payload = request.encode_to_vec(); // same message without field 99
        assert!(
            verify_wrapper_signature(&tampered, &keypair.verifying_key_bytes(), ED25519).is_err()
        );

        // Verification happens over the raw bytes and prost ignores field 99 on decode.
        match verify_and_decode_payload(&wrapper, &keypair.verifying_key_bytes(), ED25519).unwrap()
        {
            DecodedPayload::AuthRequest(decoded) => {
                assert_eq!(decoded.challenge, request.challenge);
                assert_eq!(decoded.username, "user");
                assert_eq!(decoded.hostname, "host");
                assert_eq!(decoded.timestamp_unix_seconds, 1_700_000_000);
                assert_eq!(decoded.pam_service, "sudo");
                assert_eq!(decoded.process_name, "sudo");
                assert_eq!(decoded.command_preview, "apt upgrade");
                assert!(decoded.tty_present);
            }
            other => panic!("expected AuthRequest, got {other:?}"),
        }

        // The same raw bytes decode directly too (unknown field ignored).
        let direct = AuthenticationRequest::decode(payload.as_slice()).unwrap();
        assert_eq!(direct, request);
    }

    #[test]
    fn test_verify_and_decode_verifies_before_decoding() {
        let keypair = Ed25519KeyPair::generate().unwrap();

        // The payload is not a decodable AuthenticationRequest and the signature is
        // garbage; only the ordering of verify-vs-decode decides which error surfaces.
        let wrapper = WrapperMessage {
            version: PROTOCOL_VERSION_V2,
            signature_algorithm: ED25519,
            payload_type: PayloadType::AuthRequest as i32,
            payload: vec![0xFF, 0xFF, 0xFF],
            signature: vec![0u8; 64],
        };
        assert!(AuthenticationRequest::decode([0xFFu8, 0xFF, 0xFF].as_slice()).is_err());

        match verify_and_decode_payload(&wrapper, &keypair.verifying_key_bytes(), ED25519) {
            Err(ProtocolError::Crypto(CryptoError::InvalidSignature)) => {}
            other => panic!("expected signature failure before decode, got {other:?}"),
        }
    }

    #[test]
    fn test_wrapper_signature_rejects_algorithm_downgrade() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let wrapper = create_signed_auth_grant([7u8; 32], &keypair).unwrap();
        assert_eq!(wrapper.signature_algorithm, ED25519);

        // Caller expects only ED25519 while the wrapper claims UNSPECIFIED (0).
        let mut downgraded = wrapper.clone();
        downgraded.signature_algorithm = SignatureAlgorithm::Unspecified as i32;
        assert!(matches!(
            verify_wrapper_signature(&downgraded, &keypair.verifying_key_bytes(), ED25519),
            Err(ProtocolError::AlgorithmMismatch)
        ));

        // Caller pinned to UNSPECIFIED while the wrapper is ED25519: still a mismatch,
        // so a peer cannot pick the algorithm the verifier dispatches on.
        assert!(matches!(
            verify_wrapper_signature(
                &wrapper,
                &keypair.verifying_key_bytes(),
                SignatureAlgorithm::Unspecified as i32
            ),
            Err(ProtocolError::AlgorithmMismatch)
        ));
    }

    /// A v1-versioned wrapper is refused by `verify_wrapper_signature` even when it
    /// carries a valid signature over its own (v1) transcript and a payload that would
    /// otherwise decode and answer the challenge.
    ///
    /// The defect this catches: `verify_wrapper_signature` checking only the signature
    /// algorithm and the signature, so `tapauthd` — which reaches the shared verifiers
    /// and never the FFI's own version gate — would accept a v1 frame and hand its
    /// payload to the v2 decoder.
    #[test]
    fn test_wrapper_signature_rejects_non_v2_version_before_payload_handling() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [0x44u8; 32];

        let mut wrapper = wrap_auth_grant(AuthenticationGrant {
            challenge: challenge.to_vec(),
        });
        // Downgrade to the v1 framing and sign *that* transcript: the signature is
        // valid, so only the version gate can reject it.
        wrapper.version = 1;
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        assert!(matches!(
            verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes(), ED25519),
            Err(ProtocolError::InvalidMessageFormat)
        ));
        // `verify_auth_grant` is the entry point tapauthd calls: a matching challenge
        // must not rescue the frame.
        assert!(matches!(
            verify_auth_grant(
                &wrapper,
                &challenge,
                &keypair.verifying_key_bytes(),
                ED25519
            ),
            Err(ProtocolError::InvalidMessageFormat)
        ));

        // Control: the same message at v2 verifies, so the gate is the version alone.
        let mut v2 = wrap_auth_grant(AuthenticationGrant {
            challenge: challenge.to_vec(),
        });
        sign_wrapper_message(&mut v2, &keypair).unwrap();
        assert_eq!(v2.version, PROTOCOL_VERSION_V2);
        assert!(
            verify_auth_grant(&v2, &challenge, &keypair.verifying_key_bytes(), ED25519).is_ok()
        );
    }

    #[test]
    fn test_payload_type_is_covered_by_signature() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let mut wrapper = create_signed_auth_grant([9u8; 32], &keypair).unwrap();
        assert_eq!(wrapper.payload_type, PayloadType::AuthGrant as i32);

        // Re-label the signed grant as a request without re-signing.
        wrapper.payload_type = PayloadType::AuthRequest as i32;
        assert!(
            verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes(), ED25519).is_err()
        );
    }

    #[test]
    fn test_auth_grant_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [3u8; 32];

        let wrapper = create_signed_auth_grant(challenge, &keypair).unwrap();
        assert_eq!(wrapper.version, PROTOCOL_VERSION_V2);
        assert_eq!(wrapper.payload_type, PayloadType::AuthGrant as i32);

        verify_auth_grant(
            &wrapper,
            &challenge,
            &keypair.verifying_key_bytes(),
            ED25519,
        )
        .unwrap();

        // A grant for a different challenge must not verify.
        assert!(matches!(
            verify_auth_grant(
                &wrapper,
                &[4u8; 32],
                &keypair.verifying_key_bytes(),
                ED25519
            ),
            Err(ProtocolError::ChallengeMismatch)
        ));

        // Wrong signer must not verify.
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(verify_auth_grant(
            &wrapper,
            &challenge,
            &other_keypair.verifying_key_bytes(),
            ED25519
        )
        .is_err());
    }

    #[test]
    fn test_auth_grant_with_wrong_length_challenge_field_is_rejected() {
        let keypair = Ed25519KeyPair::generate().unwrap();

        // A well-signed grant whose inner challenge is the wrong length (16 bytes).
        let mut wrapper = wrap_auth_grant(AuthenticationGrant {
            challenge: vec![0x33; 16],
        });
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        assert!(matches!(
            verify_auth_grant(
                &wrapper,
                &[0x33; 32],
                &keypair.verifying_key_bytes(),
                ED25519
            ),
            Err(ProtocolError::ChallengeMismatch)
        ));
    }

    #[test]
    fn test_auth_grant_rejects_wrong_payload_type() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [6u8; 32];

        // A signed denial is not an acceptable answer where a grant is required.
        let wrapper = create_signed_auth_denial(challenge, "user rejected", &keypair).unwrap();
        assert!(matches!(
            verify_auth_grant(
                &wrapper,
                &challenge,
                &keypair.verifying_key_bytes(),
                ED25519
            ),
            Err(ProtocolError::InvalidMessageFormat)
        ));
    }

    #[test]
    fn test_auth_denial_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [5u8; 32];

        let wrapper = create_signed_auth_denial(challenge, "user rejected", &keypair).unwrap();
        assert_eq!(wrapper.payload_type, PayloadType::AuthDenial as i32);

        verify_auth_denial(
            &wrapper,
            &challenge,
            &keypair.verifying_key_bytes(),
            ED25519,
        )
        .unwrap();

        match decode_payload(&wrapper).unwrap() {
            DecodedPayload::AuthDenial(denial) => {
                assert_eq!(denial.reason, "user rejected");
                assert_eq!(denial.challenge, challenge.to_vec());
            }
            other => panic!("expected AuthDenial, got {other:?}"),
        }

        assert!(matches!(
            verify_auth_denial(
                &wrapper,
                &[8u8; 32],
                &keypair.verifying_key_bytes(),
                ED25519
            ),
            Err(ProtocolError::ChallengeMismatch)
        ));
    }

    #[test]
    fn test_grant_confirmation_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [7u8; 32];

        let confirmation = create_grant_confirmation(&challenge).unwrap();
        assert_eq!(confirmation.challenge.len(), 32);

        let mut wrapper = wrap_grant_confirmation(confirmation);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        assert!(
            verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes(), ED25519).is_ok()
        );

        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(
            verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes(), ED25519)
                .is_err()
        );
    }

    #[test]
    fn test_auth_cancel_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [9u8; 32];

        let cancel = create_auth_cancel(&challenge).unwrap();
        assert_eq!(cancel.challenge.len(), 32);

        let mut wrapper = wrap_auth_cancel(cancel);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        assert!(
            verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes(), ED25519).is_ok()
        );

        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(
            verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes(), ED25519)
                .is_err()
        );
    }

    #[test]
    fn test_unknown_payload_type_is_rejected() {
        let wrapper = WrapperMessage {
            version: PROTOCOL_VERSION_V2,
            signature_algorithm: ED25519,
            payload_type: PayloadType::Unspecified as i32,
            payload: vec![0x00],
            signature: vec![0xAA; 64],
        };

        assert!(matches!(
            decode_payload(&wrapper),
            Err(ProtocolError::InvalidMessageFormat)
        ));
    }

    #[test]
    fn test_invalid_challenge_length() {
        assert!(create_auth_request_with_challenge("user", "host", &[1u8; 16]).is_err());
        assert!(create_grant_confirmation(&[1u8; 16]).is_err());
        assert!(create_auth_cancel(&[1u8; 16]).is_err());
    }

    #[test]
    fn test_create_auth_request_with_context_fills_sanitized_fields() {
        let long_preview = "y".repeat(400);

        let request = create_auth_request_with_context(
            &[1u8; 32],
            ContextFields {
                username: "user",
                hostname: "host",
                pam_service: "  sudo\u{0} ",
                process_name: "sudo",
                command_preview: &long_preview,
            },
            true,
        )
        .unwrap();

        assert_eq!(request.challenge, vec![1u8; 32]);
        assert_eq!(request.pam_service, "sudo"); // trimmed and control-stripped
        assert_eq!(request.process_name, "sudo");
        assert_eq!(request.command_preview.len(), COMMAND_PREVIEW_MAX_BYTES);
        assert!(request.command_preview.ends_with('\u{2026}'));
        assert!(request.tty_present);

        // The minimal builder keeps fields 5-8 at their defaults.
        let minimal = create_auth_request_with_challenge("user", "host", &[1u8; 32]).unwrap();
        assert!(minimal.pam_service.is_empty());
        assert!(minimal.process_name.is_empty());
        assert!(minimal.command_preview.is_empty());
        assert!(!minimal.tty_present);
    }

    /// Every field the module bounds owns exactly one row of the per-field table, with
    /// the budget of its own constant and the overflow policy the protocol documents.
    ///
    /// The defect this catches: a bounded field whose row was never written (so its
    /// budget and its reject/truncate answer are whatever its call site happens to do),
    /// two rows sharing one field's budget, and a policy flipped from `Reject` to
    /// `Truncate` — which would let the phone display, and the client authorize, an
    /// account that was cut to fit.
    #[test]
    fn every_context_field_has_exactly_one_policy_row() {
        // Exhaustive destructuring of the message: a bounded field *added* to
        // `AuthenticationRequest` cannot compile past this test without someone
        // deciding whether it needs a row. `policy`'s exhaustive `match` is the other
        // half — a `ContextField` variant without a row does not compile at all.
        let AuthenticationRequest {
            challenge: _,
            username,
            hostname,
            timestamp_unix_seconds: _,
            pam_service,
            process_name,
            command_preview,
            tty_present: _,
        } = sample_request();
        let bounded_fields = [
            username,
            hostname,
            pam_service,
            process_name,
            command_preview,
        ];

        assert_eq!(
            ContextField::ALL.len(),
            bounded_fields.len(),
            "the table must hold one row per bounded field of AuthenticationRequest, \
             found {} rows for {} fields",
            ContextField::ALL.len(),
            bounded_fields.len()
        );

        // Each field owns a row of its own: a duplicate would leave another field
        // without one while the count above still matched.
        let mut names: Vec<&str> = ContextField::ALL
            .iter()
            .map(|field| field.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names,
            [
                "command_preview",
                "hostname",
                "pam_service",
                "process_name",
                "username"
            ],
            "the table must name every bounded field of the message"
        );

        // The rows themselves: each budget is the field's named constant (the table
        // never inlines a number), and the overflow policy is the documented one.
        let expected = [
            (ContextField::Username, USERNAME_MAX_BYTES, Overflow::Reject),
            (
                ContextField::Hostname,
                HOSTNAME_MAX_BYTES,
                Overflow::Truncate,
            ),
            (
                ContextField::PamService,
                PAM_SERVICE_MAX_BYTES,
                Overflow::Truncate,
            ),
            (
                ContextField::ProcessName,
                PROCESS_NAME_MAX_BYTES,
                Overflow::Truncate,
            ),
            (
                ContextField::CommandPreview,
                COMMAND_PREVIEW_MAX_BYTES,
                Overflow::Truncate,
            ),
        ];
        assert_eq!(expected.len(), ContextField::ALL.len());
        for (field, max_bytes, on_overflow) in expected {
            assert!(
                ContextField::ALL.contains(&field),
                "{} is missing from the table",
                field.as_str()
            );
            assert_eq!(
                field.policy(),
                FieldPolicy {
                    max_bytes,
                    on_overflow
                },
                "row {}",
                field.as_str()
            );
        }
    }

    /// Build a request with `field` over budget and every other bounded field short.
    ///
    /// The `match` is exhaustive, so a field added to the enum needs its own
    /// over-budget call here before the test compiles.
    fn request_with_over_budget(
        field: ContextField,
        value: &str,
    ) -> Result<AuthenticationRequest, ProtocolError> {
        let challenge = [0x2Au8; 32];
        match field {
            ContextField::Username => create_auth_request_with_context(
                &challenge,
                ContextFields {
                    username: value,
                    hostname: "host",
                    pam_service: "sudo",
                    process_name: "sudo",
                    command_preview: "apt",
                },
                false,
            ),
            ContextField::Hostname => create_auth_request_with_context(
                &challenge,
                ContextFields {
                    username: "luca",
                    hostname: value,
                    pam_service: "sudo",
                    process_name: "sudo",
                    command_preview: "apt",
                },
                false,
            ),
            ContextField::PamService => create_auth_request_with_context(
                &challenge,
                ContextFields {
                    username: "luca",
                    hostname: "host",
                    pam_service: value,
                    process_name: "sudo",
                    command_preview: "apt",
                },
                false,
            ),
            ContextField::ProcessName => create_auth_request_with_context(
                &challenge,
                ContextFields {
                    username: "luca",
                    hostname: "host",
                    pam_service: "sudo",
                    process_name: value,
                    command_preview: "apt",
                },
                false,
            ),
            ContextField::CommandPreview => create_auth_request_with_context(
                &challenge,
                ContextFields {
                    username: "luca",
                    hostname: "host",
                    pam_service: "sudo",
                    process_name: "sudo",
                    command_preview: value,
                },
                false,
            ),
        }
    }

    /// Each row is what the builder actually does to that field: a `Reject` row fails
    /// the request at one byte over its budget (an error, not a shorter `Ok`), and a
    /// `Truncate` row cuts to exactly its budget and marks the cut — while the same
    /// field exactly *at* its budget is kept verbatim under either policy.
    ///
    /// The defect this catches: a call site that bounds a field some other way than its
    /// row says (a `Reject` field truncated, a `Truncate` field rejected, or a budget
    /// read from the wrong constant), i.e. the table describing one policy while the
    /// builder applies another. The vectors in
    /// `testdata/context_sanitizer_vectors.json` pin how a cut is made; these pin which
    /// fields get one.
    #[test]
    fn each_context_field_row_is_applied_by_the_builder() {
        for field in ContextField::ALL.iter().copied() {
            let policy = field.policy();
            let name = field.as_str();
            let at_cap = "x".repeat(policy.max_bytes);
            let over = "x".repeat(policy.max_bytes + 1);

            match policy.on_overflow {
                Overflow::Reject => {
                    assert!(
                        matches!(
                            request_with_over_budget(field, &over),
                            Err(ProtocolError::InvalidMessageFormat)
                        ),
                        "{name} must be rejected one byte over its {} byte budget, \
                         not shortened",
                        policy.max_bytes
                    );
                    let request = request_with_over_budget(field, &at_cap).unwrap();
                    assert_eq!(
                        field.read(&request),
                        at_cap,
                        "{name} at its budget must be kept verbatim"
                    );
                }
                Overflow::Truncate => {
                    let request = request_with_over_budget(field, &over).unwrap();
                    let bounded = field.read(&request);
                    assert_eq!(
                        bounded.len(),
                        policy.max_bytes,
                        "{name} must use the whole budget, ellipsis included"
                    );
                    assert!(
                        bounded.ends_with(ELLIPSIS),
                        "{name} must mark the cut, got {bounded:?}"
                    );
                    assert!(
                        bounded.trim_end_matches(ELLIPSIS).chars().all(|c| c == 'x'),
                        "{name} must keep the input's own bytes, got {bounded:?}"
                    );

                    // At the budget nothing is cut and no ellipsis is added.
                    let request = request_with_over_budget(field, &at_cap).unwrap();
                    assert_eq!(
                        field.read(&request),
                        at_cap,
                        "{name} at its budget must be kept verbatim"
                    );
                }
            }
        }
    }

    #[test]
    fn test_username_and_hostname_budget() {
        // A username that cannot fit is refused, never truncated: the defect this
        // catches is a 200-byte username silently cut to 32 bytes, i.e. the phone
        // authorizing (and displaying) a different account than the one asking.
        let long_username = "u".repeat(200);
        assert!(matches!(
            create_auth_request_with_context(
                &[1u8; 32],
                ContextFields {
                    username: &long_username,
                    hostname: "host",
                    pam_service: "",
                    process_name: "",
                    command_preview: "",
                },
                false,
            ),
            Err(ProtocolError::InvalidMessageFormat)
        ));
        // Just over the cap is already refused; exactly at the cap is accepted.
        assert!(matches!(
            create_auth_request_with_challenge(
                &"u".repeat(USERNAME_MAX_BYTES + 1),
                "host",
                &[1u8; 32]
            ),
            Err(ProtocolError::InvalidMessageFormat)
        ));
        let at_cap = "u".repeat(USERNAME_MAX_BYTES);
        let request = create_auth_request_with_challenge(&at_cap, "host", &[1u8; 32]).unwrap();
        assert_eq!(request.username, at_cap);
        assert_eq!(request.username.len(), USERNAME_MAX_BYTES);

        // A multi-byte username is measured in UTF-8 bytes, not characters: 16
        // three-byte characters are 48 bytes and must be refused.
        let multibyte = "\u{20ac}".repeat(16);
        assert_eq!(multibyte.chars().count(), 16);
        assert!(multibyte.len() > USERNAME_MAX_BYTES);
        assert!(matches!(
            create_auth_request_with_challenge(&multibyte, "host", &[1u8; 32]),
            Err(ProtocolError::InvalidMessageFormat)
        ));

        // A 200-byte hostname is display-only: it is sanitized and truncated to the
        // budget, and the signed packet still fits the BLE GATT attribute.
        let long_hostname = "h".repeat(200);
        let request = create_auth_request_with_context(
            &[0x5Au8; 32],
            ContextFields {
                username: "luca",
                hostname: &long_hostname,
                pam_service: "sudo",
                process_name: "sudo",
                command_preview: &"c".repeat(COMMAND_PREVIEW_MAX_BYTES),
            },
            true,
        )
        .unwrap();
        assert!(request.hostname.len() <= HOSTNAME_MAX_BYTES);
        assert_eq!(
            request.hostname.len(),
            HOSTNAME_MAX_BYTES,
            "the hostname must use the whole budget, ellipsis included"
        );
        // The ellipsis marks the cut instead of pretending the name is complete.
        assert!(request.hostname.ends_with(ELLIPSIS));
        assert!(long_hostname.starts_with(request.hostname.trim_end_matches(ELLIPSIS)));

        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk = crate::crypto::ClientSymmetricKey::generate().unwrap();
        let mut wrapper = crate::protocol::packet::wrap_auth_request(request);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();
        let packet = crate::protocol::packet::create_encrypted_packet_with_csk_nonce(
            &csk,
            SymmetricAlgorithm::Aes256Gcm,
            HashAlgorithm::Sha256,
            &wrapper,
        )
        .unwrap();
        let measured = packet.encode_to_vec().len();
        assert!(
            measured <= crate::models::ble::MAX_GATT_PAYLOAD_BYTES,
            "an over-long hostname must not push the packet past the GATT budget: {measured}"
        );
    }

    #[test]
    fn test_timestamp_validation() {
        let challenge = [1u8; 32];
        let mut request = create_auth_request_with_challenge("user", "host", &challenge).unwrap();

        // Current timestamp should be valid
        assert!(is_request_timestamp_valid(&request));

        // Old timestamp should be invalid
        request.timestamp_unix_seconds = 1000;
        assert!(!is_request_timestamp_valid(&request));
    }

    #[test]
    fn test_timestamp_validation_at_boundary() {
        let challenge = [1u8; 32];
        let request = create_auth_request_with_challenge("user", "host", &challenge).unwrap();

        // Exactly at the +60s boundary (future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut req_plus_60 = request.clone();
        req_plus_60.timestamp_unix_seconds = now + 60;
        assert!(is_request_timestamp_valid(&req_plus_60));

        // Just beyond the +60s boundary
        let mut req_plus_61 = request.clone();
        req_plus_61.timestamp_unix_seconds = now + 61;
        assert!(!is_request_timestamp_valid(&req_plus_61));

        // Exactly at the -60s boundary (past)
        let mut req_minus_60 = request.clone();
        req_minus_60.timestamp_unix_seconds = now.saturating_sub(60);
        assert!(is_request_timestamp_valid(&req_minus_60));

        // Just beyond the -60s boundary
        let mut req_minus_61 = request.clone();
        req_minus_61.timestamp_unix_seconds = now.saturating_sub(61);
        assert!(!is_request_timestamp_valid(&req_minus_61));
    }
}
