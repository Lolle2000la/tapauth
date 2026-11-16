//! The handshake's signature payloads and the abort's direction tag: what a
//! pairing transcript is made of, as opposed to the envelope ([`super::wire`])
//! that carries it or the single fields ([`super::fields`]) it is built from.

use super::NegotiatedAlgorithms;
use crate::crypto::{verify_pairing_abort_tag, PairingSessionKeys};
use crate::protocol::messages::ProtocolError;
use crate::protocol::pb::PairingAbort;

/// `context || H` — the signature payload of `PairingResponse` and the AEAD AAD of
/// both confirmation messages.
pub(super) fn context_with_hash(context: &[u8], transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(context.len() + transcript_hash.len());
    data.extend_from_slice(context);
    data.extend_from_slice(transcript_hash);
    data
}

/// `context || H || csk` — the signature payload of the completion proof.
pub(super) fn complete_signature_message(
    context: &[u8],
    transcript_hash: &[u8; 32],
    csk: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(context.len() + transcript_hash.len() + csk.len());
    data.extend_from_slice(context);
    data.extend_from_slice(transcript_hash);
    data.extend_from_slice(csk);
    data
}

/// The three session values both state machines hand out together.
pub(super) fn session_material<'a>(
    keys: &'a Option<PairingSessionKeys>,
    transcript_hash: &'a Option<[u8; 32]>,
    negotiated: &'a Option<NegotiatedAlgorithms>,
) -> Result<(&'a PairingSessionKeys, &'a [u8; 32], NegotiatedAlgorithms), ProtocolError> {
    let keys = keys
        .as_ref()
        .ok_or(ProtocolError::MissingField("pairing_session_keys"))?;
    let transcript_hash = transcript_hash
        .as_ref()
        .ok_or(ProtocolError::MissingField("transcript_hash"))?;
    let negotiated = negotiated
        .as_ref()
        .ok_or(ProtocolError::MissingField("negotiated_algorithms"))?;
    Ok((keys, transcript_hash, *negotiated))
}

/// Verify an abort's direction key: `K_s2c` on the desktop, `K_c2s` on the phone.
pub(super) fn verify_abort_tag(
    abort: &PairingAbort,
    directional_key: Option<&[u8; 32]>,
    transcript_hash: Option<&[u8; 32]>,
) -> Result<bool, ProtocolError> {
    let tag = abort.auth_tag.as_slice();
    match (directional_key, transcript_hash) {
        (Some(key), Some(transcript_hash)) => {
            // Keys exist, so an unauthenticated abort is spoofable: refuse it.
            if tag.is_empty() {
                return Err(ProtocolError::InvalidSignature);
            }
            if verify_pairing_abort_tag(key, transcript_hash, abort.reason, tag) {
                Ok(true)
            } else {
                Err(ProtocolError::InvalidSignature)
            }
        }
        _ => {
            if tag.is_empty() {
                // Nothing to verify yet; report it as unauthenticated rather than valid.
                Ok(false)
            } else {
                // A tag we cannot check must not be treated as a successful abort.
                Err(ProtocolError::InvalidSignature)
            }
        }
    }
}
