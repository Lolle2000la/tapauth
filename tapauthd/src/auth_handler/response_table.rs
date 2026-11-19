//! Which phone replies this authentication session may act on.
//!
//! A pure policy table: the payload types that count as a decision, the
//! signature check each one runs against every Server allowed to answer for the
//! user, and the verdict an accepted answer produces. No session state and no I/O,
//! so every rule here is testable on its own.

use shared::config::PairedServer;
use shared::protocol::messages::{verify_auth_denial, verify_auth_grant};
use shared::protocol::pb::{PayloadType, WrapperMessage};
use shared::protocol::ProtocolError;
use std::collections::HashMap;

/// The paired servers that may answer for `username`.
///
/// This is the single place the `allowed_users` filter is applied; everything
/// that verifies a Server response consumes its output rather than
/// `DaemonState::paired_servers`.
pub(super) fn servers_authorized_for(
    paired_servers: &HashMap<String, PairedServer>,
    username: &str,
) -> Vec<PairedServer> {
    paired_servers
        .values()
        .filter(|server| server.is_user_allowed(username))
        .cloned()
        .collect()
}

/// What a decrypted Server response means for this authentication session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerResponseVerdict {
    /// A Server authorized for this user signed a matching `AuthenticationGrant`.
    Grant,
    /// A Server authorized for this user signed a matching `AuthenticationDenial`.
    Denial,
    /// Not an answer this client may act on: nobody signed it that is allowed to
    /// answer for this user, or the challenge does not match, or it is not a
    /// grant/denial at all.
    Unattributed,
}

/// The signature check a row runs: [`verify_auth_grant`] or [`verify_auth_denial`],
/// which share a signature and differ only in the inner payload they accept.
pub(super) type PayloadVerifier =
    fn(&WrapperMessage, &[u8; 32], &[u8; 32], i32) -> Result<(), ProtocolError>;

/// One row of the response table: the payload type it answers for, the verifier
/// it runs against every `allowed_servers` entry, and the verdict it produces
/// when that verifier accepts.
pub(super) struct ResponseRow {
    pub(super) payload_type: PayloadType,
    verify: PayloadVerifier,
    pub(super) verdict: ServerResponseVerdict,
}

/// The Server answers a client may act on, keyed on payload type, first match
/// wins.
///
/// Only a payload type with a row here can produce a verdict other than
/// [`ServerResponseVerdict::Unattributed`], and a row is only reached after the
/// enclosing checks in
/// [`AuthSession::wait_for_response`](super::AuthSession::wait_for_response) have
/// attributed the signature to a Server authorized for this user. A new Server
/// answer is one row plus one case in `covering_cases` (the covering test fails
/// without it), never another `else if` beside the allowlist check.
pub(super) static RESPONSE_ROWS: [ResponseRow; 2] = [
    ResponseRow {
        payload_type: PayloadType::AuthGrant,
        verify: verify_auth_grant,
        verdict: ServerResponseVerdict::Grant,
    },
    ResponseRow {
        payload_type: PayloadType::AuthDenial,
        verify: verify_auth_denial,
        verdict: ServerResponseVerdict::Denial,
    },
];

/// The row answering `payload_type`, or `None` when no row does — a payload type
/// the protocol does not define, or one that is not a decision at all
/// (`AuthRequest`, `GrantConfirmation`, `AuthCancel`, `Unspecified`).
pub(super) fn response_row(payload_type: i32) -> Option<&'static ResponseRow> {
    RESPONSE_ROWS
        .iter()
        .find(|row| row.payload_type as i32 == payload_type)
}

/// The explicit refusal of a payload type no row answers for.
///
/// This is the outcome the dispatch used to reach by falling out of its `if`
/// chain. It stays [`ServerResponseVerdict::Unattributed`] — not a verdict of its
/// own — so an unrecognised type is neither a grant nor a denial here, and
/// `process_auth_response` keeps answering it with `ResponseError::InvalidMessage`
/// and its "Unexpected message type" debug line.
pub(super) fn refuse_unrecognised_payload_type() -> ServerResponseVerdict {
    ServerResponseVerdict::Unattributed
}

/// Whether any Server authorized for this session accepts `wrapper` under `verify`.
///
/// Each candidate is checked with *its own* negotiated signature algorithm, so a
/// Server cannot claim an algorithm the pairing did not agree on.
pub(super) fn any_authorized_server_verifies(
    allowed_servers: &[PairedServer],
    challenge: &[u8; 32],
    wrapper: &WrapperMessage,
    verify: PayloadVerifier,
) -> bool {
    allowed_servers.iter().any(|server| {
        server_public_key(server).is_some_and(|public_key| {
            verify(
                wrapper,
                challenge,
                &public_key,
                server.signature_algorithm as i32,
            )
            .is_ok()
        })
    })
}

/// Decide what a decrypted Server response means for this session.
///
/// Pure — no I/O and no clock — so the authorization decision can be tested
/// directly. Every check runs against `allowed_servers` only: a Server paired for
/// a different account is not in that slice, so its grant cannot authenticate
/// this user and its denial cannot cancel the prompt for it.
pub(super) fn classify_server_response(
    allowed_servers: &[PairedServer],
    challenge: &[u8; 32],
    wrapper: &WrapperMessage,
) -> ServerResponseVerdict {
    let row = match response_row(wrapper.payload_type) {
        Some(row) => row,
        None => return refuse_unrecognised_payload_type(),
    };

    if any_authorized_server_verifies(allowed_servers, challenge, wrapper, row.verify) {
        row.verdict
    } else {
        ServerResponseVerdict::Unattributed
    }
}

/// Decode a paired server's Ed25519 public key.
pub(super) fn server_public_key(server: &PairedServer) -> Option<[u8; 32]> {
    let bytes = hex::decode(&server.public_key).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes);
    Some(public_key)
}

/// Error type for response processing
pub(super) enum ResponseError {
    /// Invalid message that should be ignored (wait for another response)
    InvalidMessage,
}
