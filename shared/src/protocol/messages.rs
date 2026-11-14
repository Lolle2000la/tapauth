//! Protocol message creation, signing and verification.
//!
//! v2 signs the **raw** inner protobuf bytes carried in `WrapperMessage.payload`
//! (see `cryptography-specification.md` §2.3). Verification therefore runs over the
//! exact wire bytes of `payload` instead of re-serializing a decoded struct, so
//! unknown fields written by a newer peer survive signature verification and are
//! ignored by the inner decode that follows.

use prost::Message as ProstMessage;
use subtle::ConstantTimeEq;

use crate::crypto::{sign_ed25519, verify_ed25519, CryptoError, Ed25519KeyPair};
use crate::protocol::packet::{wrap_auth_denial, wrap_auth_grant};
use crate::protocol::pb::*;

/// Protocol version stored in `WrapperMessage.version` for the v2 framing.
pub const PROTOCOL_VERSION_V2: u32 = 2;

/// Domain separation tag prepended to every `WrapperMessage` signing transcript.
const WRAPPER_SIGNING_DOMAIN: &[u8] = b"tapauth-sig-v2";

/// Maximum byte length of `AuthenticationRequest.username`.
///
/// A username that exceeds this is **rejected**, never truncated: the phone would
/// otherwise display (and the PAM module would otherwise authorize) an account
/// that is not the one being authenticated.
pub const USERNAME_MAX_BYTES: usize = 32;
/// Maximum byte length of `AuthenticationRequest.hostname`.
///
/// A hostname is display-only, so an over-long one is sanitized and truncated
/// instead of rejected — see [`create_auth_request_with_context`].
pub const HOSTNAME_MAX_BYTES: usize = 64;
/// Maximum byte length of `AuthenticationRequest.pam_service`.
pub const PAM_SERVICE_MAX_BYTES: usize = 32;
/// Maximum byte length of `AuthenticationRequest.process_name`.
pub const PROCESS_NAME_MAX_BYTES: usize = 32;
/// Maximum byte length of `AuthenticationRequest.command_preview`.
pub const COMMAND_PREVIEW_MAX_BYTES: usize = 128;

/// Truncation marker appended inside the byte budget when a context string is cut.
const ELLIPSIS: char = '\u{2026}';

/// `ESC`, which opens every ANSI escape sequence stripped from a context string.
const ESC_BYTE: u8 = 0x1B;

/// `BEL`, the short terminator of an OSC sequence.
const BEL_BYTE: u8 = 0x07;

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

/// Sanitize untrusted contextual metadata for display on the Server prompt.
///
/// The Kotlin mirror (`ContextSanitizer` in `server-android`) must implement exactly
/// this, so both sides are driven by the same vectors in
/// `shared/testdata/context_sanitizer_vectors.json`:
///
/// 1. ANSI escape sequences are removed as a unit, first. A CSI (`ESC '['`, parameter
///    bytes `0x30..=0x3F`, intermediate bytes `0x20..=0x2F`, one final byte
///    `0x40..=0x7E`) and an OSC (`ESC ']'` up to `BEL` or `ESC '\'`, terminator
///    included) are deleted whole — deleting only the `ESC` would leave `[31m` in the
///    prompt. An unterminated sequence is deleted to end of input. A lone `ESC` is a
///    forbidden character and is dropped, and the byte after it is filtered normally.
/// 2. Then, per code point: a whitespace code point (see
///    [`is_context_whitespace`]) becomes one space, runs collapse to one space and
///    both ends are trimmed; otherwise a forbidden code point (see
///    [`is_forbidden_context_char`]) is dropped; everything else is kept. The
///    whitespace test comes *first*, so `\t`, `\n` and U+0085 separate words instead
///    of vanishing (`sudo\tapt` must not become `sudoapt`).
/// 3. The result is truncated to at most `max_bytes` bytes on a UTF-8 char boundary;
///    when truncation happens a single `…` is appended *inside* that budget, so a
///    budget of 3 bytes or less truncates without an ellipsis.
pub fn sanitize_context_string(input: &str, max_bytes: usize) -> String {
    let collapsed = normalize_context_string(input);

    if max_bytes == 0 {
        return String::new();
    }

    let sanitized = collapsed.as_str();
    if sanitized.len() <= max_bytes {
        return sanitized.to_string();
    }

    let ellipsis_len = ELLIPSIS.len_utf8();
    // The ellipsis itself costs 3 bytes and must leave room for at least one content
    // byte, so budgets below 4 truncate without one.
    let with_ellipsis = max_bytes > ellipsis_len;
    let budget = if with_ellipsis {
        max_bytes - ellipsis_len
    } else {
        max_bytes
    };

    let mut truncated = String::with_capacity(max_bytes);
    for ch in sanitized.chars() {
        if truncated.len() + ch.len_utf8() > budget {
            break;
        }
        truncated.push(ch);
    }
    if with_ellipsis {
        truncated.push(ELLIPSIS);
    }
    truncated
}

/// Delete ANSI escape sequences and every forbidden code point, and collapse
/// whitespace runs to one ASCII space (see [`sanitize_context_string`]).
///
/// Byte- and char-addressed at once: the escape scanner walks the byte slice (every
/// byte of an escape sequence is ASCII), and everything else is consumed one whole
/// `char` at a time, so the string is never split inside a multi-byte code point.
fn normalize_context_string(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut pending_space = false;
    let mut index = 0;

    while index < bytes.len() {
        if bytes.get(index).copied() == Some(ESC_BYTE) {
            match ansi_sequence_len(bytes, index) {
                Some(len) => index = index.saturating_add(len),
                // A lone `ESC` (end of input, or followed by anything but `[`/`]`) is
                // just a forbidden character: drop it and filter the next byte normally.
                None => index = index.saturating_add(1),
            }
            continue;
        }

        // `index` is on a char boundary: every advance above covers ASCII bytes only.
        let next_char = input.get(index..).and_then(|rest| rest.chars().next());
        let Some(ch) = next_char else {
            break;
        };
        index = index.saturating_add(ch.len_utf8());

        // Whitespace before the forbidden set: `U+0009..=U+000D` and `U+0085` are both.
        if is_context_whitespace(ch) {
            pending_space = !out.is_empty();
            continue;
        }
        if is_forbidden_context_char(ch) {
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }

    out
}

/// Length in bytes of the ANSI escape sequence starting at `start`, terminator included.
///
/// `None` when `bytes[start]` is an `ESC` that does not begin a CSI or OSC, which the
/// caller treats as a forbidden character. An unterminated CSI/OSC reports the rest of
/// the input, so a truncated escape cannot leak its parameter bytes into the prompt.
fn ansi_sequence_len(bytes: &[u8], start: usize) -> Option<usize> {
    match bytes.get(start.checked_add(1)?).copied() {
        // CSI: ESC '[' params intermediates final
        Some(b'[') => {
            let mut cursor = start.saturating_add(2);
            while bytes.get(cursor).copied().is_some_and(is_csi_parameter) {
                cursor = cursor.saturating_add(1);
            }
            while bytes.get(cursor).copied().is_some_and(is_csi_intermediate) {
                cursor = cursor.saturating_add(1);
            }
            if bytes.get(cursor).copied().is_some_and(is_csi_final) {
                Some(cursor.saturating_add(1).saturating_sub(start))
            } else {
                Some(bytes.len().saturating_sub(start))
            }
        }
        // OSC: ESC ']' ... (BEL | ESC '\')
        Some(b']') => {
            let mut cursor = start.saturating_add(2);
            while cursor < bytes.len() {
                if bytes.get(cursor).copied() == Some(BEL_BYTE) {
                    return Some(cursor.saturating_add(1).saturating_sub(start));
                }
                let is_string_terminator = bytes.get(cursor).copied() == Some(ESC_BYTE)
                    && bytes.get(cursor.saturating_add(1)).copied() == Some(b'\\');
                if is_string_terminator {
                    return Some(cursor.saturating_add(2).saturating_sub(start));
                }
                cursor = cursor.saturating_add(1);
            }
            Some(bytes.len().saturating_sub(start))
        }
        _ => None,
    }
}

/// One byte of a CSI parameter string: `0x30..=0x3F` (ECMA-48 §5.4).
fn is_csi_parameter(byte: u8) -> bool {
    (0x30..=0x3F).contains(&byte)
}

/// One byte of a CSI intermediate string: `0x20..=0x2F` (ECMA-48 §5.4).
fn is_csi_intermediate(byte: u8) -> bool {
    (0x20..=0x2F).contains(&byte)
}

/// The single final byte of a CSI sequence: `0x40..=0x7E` (ECMA-48 §5.4).
fn is_csi_final(byte: u8) -> bool {
    (0x40..=0x7E).contains(&byte)
}

/// The code points that become one ASCII space, collapsed and trimmed.
///
/// Spelled out instead of `char::is_whitespace` because the set is part of the display
/// contract the Kotlin mirror implements; `char::is_whitespace` is a Unicode property
/// that changes with the Unicode version and does not include `U+200B`.
fn is_context_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// Code points that must never reach the Server prompt: controls and bidi formatters.
fn is_forbidden_context_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{0000}'..='\u{001F}'
            | '\u{007F}'..='\u{009F}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
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
    create_auth_request_with_context(username, hostname, challenge, "", "", "", false)
}

/// Create an AuthenticationRequest carrying sanitized call-site context.
///
/// `pam_service`, `process_name` and `command_preview` are sanitized and truncated to
/// [`PAM_SERVICE_MAX_BYTES`], [`PROCESS_NAME_MAX_BYTES`] and
/// [`COMMAND_PREVIEW_MAX_BYTES`] respectively, so the signed payload stays inside the
/// BLE GATT budget ([`crate::models::ble::MAX_GATT_PAYLOAD_BYTES`]).
///
/// `hostname` is bounded the same way, with [`HOSTNAME_MAX_BYTES`].
///
/// `username` is the exception: it is **rejected** with
/// [`ProtocolError::InvalidMessageFormat`] when it exceeds [`USERNAME_MAX_BYTES`]
/// instead of being sanitized or truncated. The username is the account the Server
/// (phone) shows and the one the Client authorizes, so a truncated value would name
/// a different account than the one being authenticated; a caller that cannot name
/// the account in 32 bytes has a defect, not a long hostname.
pub fn create_auth_request_with_context(
    username: &str,
    hostname: &str,
    challenge: &[u8],
    pam_service: &str,
    process_name: &str,
    command_preview: &str,
    tty_present: bool,
) -> Result<AuthenticationRequest, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }
    if username.len() > USERNAME_MAX_BYTES {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProtocolError::Crypto(CryptoError::SystemTimeError))?
        .as_secs();

    Ok(AuthenticationRequest {
        challenge: challenge.to_vec(),
        username: username.to_string(),
        hostname: sanitize_context_string(hostname, HOSTNAME_MAX_BYTES),
        timestamp_unix_seconds: timestamp,
        pam_service: sanitize_context_string(pam_service, PAM_SERVICE_MAX_BYTES),
        process_name: sanitize_context_string(process_name, PROCESS_NAME_MAX_BYTES),
        command_preview: sanitize_context_string(command_preview, COMMAND_PREVIEW_MAX_BYTES),
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
            "user",
            "host",
            &[1u8; 32],
            "  sudo\u{0} ",
            "sudo",
            &long_preview,
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

    #[test]
    fn test_sanitize_context_string_strips_control_and_bidi_characters() {
        assert_eq!(
            sanitize_context_string("a\u{0}b\u{1}c\u{7f}d", 32),
            "abcd",
            "C0 controls, NUL and DEL must be removed"
        );
        assert_eq!(
            sanitize_context_string("\u{202e}evil\u{2066}", 32),
            "evil",
            "bidi overrides/isolates removed"
        );
        assert_eq!(
            sanitize_context_string("a\u{80}b\u{9f}c", 32),
            "abc",
            "C1 controls removed"
        );
        assert_eq!(
            sanitize_context_string("a\u{61c}b\u{200b}c\u{feff}d", 32),
            "abcd",
            "Arabic letter mark, zero-width space and BOM removed"
        );
    }

    /// Whitespace is checked *before* the forbidden set, so a tab or newline separates
    /// words instead of being deleted: the defect this catches is `sudo\tapt` collapsing
    /// to `sudoapt`, which renders as one word the user never typed.
    #[test]
    fn test_sanitize_context_string_separates_words_on_whitespace() {
        assert_eq!(
            sanitize_context_string("sudo\tapt\nupdate", 128),
            "sudo apt update"
        );
        assert_eq!(sanitize_context_string("  a \t\n  b  ", 128), "a b");
        // U+0085 (NEL) is both Unicode whitespace and a C1 control: it must collapse.
        assert_eq!(sanitize_context_string("a\u{85}b", 128), "a b");
        // U+00A0 (NBSP) and U+3000 (ideographic space) are not ASCII spaces either.
        assert_eq!(
            sanitize_context_string("sudo\u{a0}apt\u{3000}update", 128),
            "sudo apt update"
        );
    }

    /// An escape sequence is deleted as a unit. The defect this catches is stripping only
    /// the `ESC`: the parameter bytes (`[31m`, `]0;…`) would survive into the prompt and
    /// render as text that was never meant to be shown.
    #[test]
    fn test_sanitize_context_string_removes_ansi_sequences() {
        assert_eq!(
            sanitize_context_string("\u{1b}[31mroot\u{1b}[0m", 128),
            "root"
        );
        // Unterminated CSI: removed to end of input, not leaked as "[31".
        assert_eq!(sanitize_context_string("x\u{1b}[31", 128), "x");
        // Parameter byte `1`, intermediate byte `0x20` and the final byte `q`: one
        // sequence, so the "b" survives and nothing of `ESC [1 q` does.
        assert_eq!(sanitize_context_string("x\u{1b}[1 qb", 128), "xb");
        // OSC terminated by BEL, and by ESC '\'.
        assert_eq!(sanitize_context_string("a\u{1b}]0;evil\u{7}b", 128), "ab");
        assert_eq!(
            sanitize_context_string("a\u{1b}]8;;http://evil.example\u{1b}\\b", 128),
            "ab"
        );
        // Unterminated OSC: removed to end of input, so the title text cannot render.
        assert_eq!(sanitize_context_string("a\u{1b}]0;evil", 128), "a");
        // A lone ESC is a forbidden character; the byte after it is filtered normally.
        assert_eq!(sanitize_context_string("a\u{1b}b", 128), "ab");
        assert_eq!(sanitize_context_string("ab\u{1b}", 128), "ab");
    }

    #[derive(serde::Deserialize)]
    struct SanitizerVectors {
        cases: Vec<SanitizerVector>,
    }

    #[derive(serde::Deserialize)]
    struct SanitizerVector {
        name: String,
        input: String,
        max_bytes: usize,
        expected: String,
    }

    /// Every sanitizer vector, including one case per code point of the whitespace and
    /// forbidden sets and the truncation boundaries.
    ///
    /// The same file drives `ContextSanitizerTest.kt` on the Android side, so the two
    /// implementations cannot drift: the defect this catches is the Kotlin mirror
    /// silently disagreeing with this one (deleting a tab instead of collapsing it, or
    /// appending an ellipsis at a 3-byte budget).
    ///
    /// The case count is asserted exactly, not as a lower bound: a bound would let the
    /// file lose whole groups (every truncation boundary, say) while staying green.
    /// Adding a vector means bumping this number and `ContextSanitizerTest`'s together.
    #[test]
    fn test_context_sanitizer_vectors_are_honoured() {
        const EXPECTED_CASES: usize = 130;

        let vectors: SanitizerVectors = serde_json::from_str(include_str!(
            "../../testdata/context_sanitizer_vectors.json"
        ))
        .expect("context sanitizer vector file must parse");
        assert_eq!(
            vectors.cases.len(),
            EXPECTED_CASES,
            "the shared vector file must hold exactly {EXPECTED_CASES} cases, found {}",
            vectors.cases.len()
        );

        for case in &vectors.cases {
            assert_eq!(
                sanitize_context_string(&case.input, case.max_bytes),
                case.expected,
                "vector '{}' (max_bytes={})",
                case.name,
                case.max_bytes
            );
        }
    }

    #[test]
    fn test_sanitize_context_string_collapses_and_trims_whitespace() {
        assert_eq!(sanitize_context_string("a \t\n  b", 32), "a b");
        assert_eq!(sanitize_context_string("  spaced  out  ", 32), "spaced out");
        assert_eq!(sanitize_context_string("   ", 32), "");
        assert_eq!(sanitize_context_string("a b", 32), "a b");
    }

    #[test]
    fn test_sanitize_context_string_truncates_within_budget() {
        let input = "x".repeat(64);
        let out = sanitize_context_string(&input, 10);

        assert_eq!(
            out.len(),
            10,
            "must use the whole byte budget, ellipsis included"
        );
        assert!(out.ends_with('\u{2026}'));
        assert_eq!(out.chars().filter(|c| *c == 'x').count(), 7);

        // Short input is not truncated and gains no ellipsis.
        assert_eq!(sanitize_context_string("short", 10), "short");

        // max_bytes == 0 yields an empty string.
        assert_eq!(sanitize_context_string("anything", 0), "");
    }

    #[test]
    fn test_sanitize_context_string_never_splits_multibyte_characters() {
        let input = "\u{20ac}".repeat(20); // 3 bytes per character

        for max_bytes in 1..=12usize {
            let out = sanitize_context_string(&input, max_bytes);
            assert!(
                out.len() <= max_bytes,
                "len {} exceeds budget {}",
                out.len(),
                max_bytes
            );
            // Valid UTF-8 by construction: every char survived intact.
            assert_eq!(out.replace('\u{2026}', "").len() % 3, 0);
            assert!(out.chars().all(|c| c == '\u{20ac}' || c == '\u{2026}'));
        }

        // 10-byte budget: 7 content bytes -> two 3-byte chars, then the ellipsis.
        assert_eq!(
            sanitize_context_string(&input, 10),
            "\u{20ac}\u{20ac}\u{2026}"
        );
        // Below 4 bytes no ellipsis is added.
        assert_eq!(sanitize_context_string(&input, 2), "");
        assert_eq!(sanitize_context_string(&input, 3), "\u{20ac}");
    }

    #[test]
    fn test_username_and_hostname_budget() {
        // A username that cannot fit is refused, never truncated: the defect this
        // catches is a 200-byte username silently cut to 32 bytes, i.e. the phone
        // authorizing (and displaying) a different account than the one asking.
        let long_username = "u".repeat(200);
        assert!(matches!(
            create_auth_request_with_context(&long_username, "host", &[1u8; 32], "", "", "", false),
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
            "luca",
            &long_hostname,
            &[0x5Au8; 32],
            "sudo",
            "sudo",
            &"c".repeat(COMMAND_PREVIEW_MAX_BYTES),
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
