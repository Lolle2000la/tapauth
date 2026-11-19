//! Unified UDP + BLE pairing state machines for protocol v2.
//!
//! Pairing provisions the desktop's long-term `CSK` onto a phone and binds both
//! devices' static Ed25519 identity keys together, over the same two transports
//! used for authentication (UDP and BLE). This module is the transport-agnostic
//! protocol half only: it encodes and decodes
//! [`PairingPacket`](crate::protocol::pb::PairingPacket) frames and runs
//! the handshake state machine. It owns no sockets, no threads, no timers and no
//! I/O — the caller (daemon) does the sending, retransmission and timeouts.
//!
//! ## Roles
//!
//! TapAuth's terminology comes from authentication: the Linux desktop is the
//! protocol **Client** and the Android phone is the protocol **Server**. Pairing
//! keeps that framing, so `PairingInit` carries the *server*'s keys and
//! `PairingResponse` the *client*'s.
//!
//! The two state machines are named after the role each one plays:
//!
//! * [`ClientPairingState`] — the **desktop**. Owns the ephemeral `x_C`/`X_C`
//!   advertised in the QR code, the static `Ed_C`, the session id, the cached
//!   `PairingResponse` and the negotiated keys. It answers `PairingInit`, builds
//!   the `PairingConfirmClient` provisioning payload and verifies the
//!   `PairingConfirmServer` completion proof against `Ed_S`.
//! * [`ServerPairingSession`] — the **phone**. Owns the ephemeral `x_S`/`X_S`
//!   and the static `Ed_S` (`PairingInit`). It verifies the QR commitment and the
//!   desktop's transcript signature, decrypts the provisioning payload, signs the
//!   completion proof with `Ed_S`, and shows the SAS.
//!
//! ## Flow
//!
//! 1. Desktop [`ClientPairingState::start`] → `sid` (16 B), `X_C`, `pairing_adv_id`
//!    for the BLE advertisement and the `tapauth://pair?v=2&...` QR URL.
//! 2. Phone [`ServerPairingSession::new`] + [`ServerPairingSession::create_init`]
//!    → `PairingInit` (`X_S`, `Ed_S`, name, supported algorithm lists).
//! 3. Desktop [`ClientPairingState::handle_init`] → negotiates, computes the
//!    transcript hash `H`, derives `K_c2s`/`K_s2c`/SAS and returns `PairingResponse`
//!    signed with `Ed_C` over `"tapauth-pair-client-sig-v2" || H`.
//! 4. Phone [`ServerPairingSession::verify_response`] → constant-time QR key
//!    comparison, algorithm check, `Ed_C` signature check, key derivation. Both
//!    users now compare the SAS out of band.
//! 5. Desktop [`ClientPairingState::create_confirm_client`] encrypts the
//!    provisioned `{csk, username, client_hostname}` under `K_c2s`; the phone
//!    decrypts it with [`ServerPairingSession::process_confirm_client`].
//! 6. Phone [`ServerPairingSession::create_confirm_server`] signs the completion
//!    proof with `Ed_S` and encrypts it under `K_s2c`; the desktop verifies it
//!    with [`ClientPairingState::verify_confirm_server`].
//!
//! Every handshake field (both ephemeral keys, both identity keys, both device
//! names, the advertised algorithm lists and the selected algorithms) enters `H`,
//! which salts the HKDF that derives the directional keys and the SAS. Tampering
//! with any of them changes the SAS visibly or breaks a signature.
//!
//! ## Client-wide algorithms (pinning)
//!
//! The symmetric and hash algorithms are properties of the **client-wide `CSK`**,
//! not of an individual pairing: one multicast broadcast must stay decryptable by
//! every already-paired server (cryptography-specification.md §1.3). When a `CSK`
//! already exists, the caller must therefore pass its persisted algorithms — read
//! from `ClientConfigManager::load_csk_metadata` — as [`PinnedAlgorithms`] to
//! [`ClientPairingState::start`]. A pinned algorithm is then *required* in the
//! peer's `supported_*` list: a peer that does not offer it is refused with
//! [`ProtocolError::UnsupportedAlgorithm`](crate::protocol::messages::ProtocolError::UnsupportedAlgorithm)
//! instead of silently negotiating a pair
//! that would make the existing broadcast undecryptable for its servers.
//!
//! Pass `None` for the first pairing (no `CSK` yet) and after `RotateCsk`, which
//! invalidates every pairing and is the only way to change the client-wide
//! algorithms. The signature algorithm is per-server, so it is always negotiated
//! and can never be pinned.
//!
//! ## Key lifetime
//!
//! [`ClientPairingState::conclude`] and [`ServerPairingSession::conclude`] drop
//! the derived keys, the transcript hash and the ephemeral X25519 secret, per
//! cryptography-specification.md §4. Each side also takes its ephemeral secret as
//! soon as it derives the keys, so it exists only for the one Diffie-Hellman call
//! that needs it. `conclude` is terminal: afterwards
//! [`ClientPairingState::negotiated`] still answers, [`ClientPairingState::sas`]
//! and the transcript-hash accessors return `None`, and every protocol operation
//! (`handle_init`, `create_init`, `verify_response`, `process_confirm_client`,
//! `verify_confirm_server`, `create_keepalive`, the create/verify confirm and abort
//! methods) fails with
//! [`ProtocolError::SessionConcluded`](crate::protocol::messages::ProtocolError::SessionConcluded)
//! instead of running on a
//! session whose keys are gone. The keepalive is the one that carries no key
//! material, and it is guarded all the same: a path kept open after `conclude` could
//! only deliver a retransmission nothing would answer.
//!
//! ## Where the handshake ends
//!
//! [`ServerPairingSession::create_confirm_server`] builds the last message of the
//! handshake but does **not** end the session: it records that the confirmation
//! has been sent, which refuses a second proof
//! ([`ProtocolError::ConfirmationAlreadySent`](crate::protocol::messages::ProtocolError::ConfirmationAlreadySent))
//! and a late [`ServerPairingSession::create_init`] (same error), while
//! [`ServerPairingSession::process_confirm_client`] stays valid and idempotent, so
//! the responder keeps answering retransmissions of the provisioning frame. Without
//! that, a lost confirmation burst leaves the desktop timing out against a phone
//! that has already paired. Only `conclude()` ends a session; the FFI layer calls it
//! explicitly, or on drop of the last reference.
//!
//! ## Who signs what
//!
//! * `PairingResponse.client_signature` — `Ed_C`, the **desktop's static key**,
//!   verified by the phone.
//! * `PairingCompletePayload.server_signature` — `Ed_S`, the **phone's static
//!   key**, verified by the desktop. The signature proves possession of `Ed_S`
//!   and receipt of the exact `CSK`.
//!
//! ## Caller responsibilities
//!
//! * Session filtering: drop any frame whose `session_id` differs from
//!   [`ClientPairingState::session_id`] / [`ServerPairingSession::session_id`]
//!   before calling into this module ([`pairing_session_id`] extracts it).
//! * Retries: `PairingInit` retries must be answered from
//!   [`ClientPairingState::response`] without calling [`ClientPairingState::handle_init`]
//!   again; `handle_init` is idempotent for an identical `init` and errors on a
//!   conflicting one.
//! * Re-encryption: `PairingConfirmClient`/`PairingConfirmServer` carry a fresh
//!   random nonce per encryption, so a retransmission must reuse the previously
//!   created message rather than re-encrypt (see the "Each call draws a fresh
//!   nonce" note on [`ClientPairingState::create_confirm_client`] and
//!   [`ServerPairingSession::create_confirm_server`]).
//!
//! ## Module layout
//!
//! The module is one file per protocol role, plus the vocabulary both roles
//! share:
//!
//! * `negotiation.rs` — the `SUPPORTED_*` slices, [`NegotiatedAlgorithms`],
//!   [`PinnedAlgorithms`] and the intersection that picks a suite.
//! * `wire.rs` — the envelope (`validate_envelope`) and the codec over it
//!   ([`encode_pairing_packet`] / [`decode_pairing_packet`] /
//!   [`pairing_session_id`]), plus [`PairingEndpoint`] and [`StartedPairing`].
//! * `client.rs` — [`ClientPairingState`], the desktop half.
//! * `server.rs` — [`ServerPairingSession`], the phone half.
//! * `transcript.rs` — the handshake's signature payloads (`context_with_hash`,
//!   `complete_signature_message`), the session values both roles hand out
//!   together (`session_material`) and the abort's direction tag
//!   (`verify_abort_tag`).
//! * `fields.rs` — the per-field helpers both roles apply before a value enters
//!   the transcript: the device-name truncation and the 32-byte key parse.
//!
//! The constants below are the wire vocabulary every one of them names, so they
//! stay here.

mod client;
mod fields;
mod negotiation;
mod server;
mod transcript;
mod wire;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests;

pub use client::ClientPairingState;
pub use negotiation::{
    NegotiatedAlgorithms, PinnedAlgorithms, SUPPORTED_HASH_ALGORITHMS,
    SUPPORTED_SIGNATURE_ALGORITHMS, SUPPORTED_SYMMETRIC_ALGORITHMS,
};
pub use server::ServerPairingSession;
pub use wire::{
    decode_pairing_packet, encode_pairing_packet, pairing_session_id, PairingEndpoint,
    StartedPairing,
};

/// Length in bytes of the random pairing `session_id` (`sid` in the QR code).
pub const PAIRING_SESSION_ID_LEN: usize = 16;

/// Maximum length in UTF-8 bytes of a device display name inside the transcript.
pub const PAIRING_DEVICE_NAME_MAX_BYTES: usize = 64;

/// Signature context prefix of `PairingResponse.client_signature` (signed by the desktop's `Ed_C`).
pub const PAIRING_CLIENT_SIG_CONTEXT: &[u8] = b"tapauth-pair-client-sig-v2";

/// Signature context prefix of `PairingCompletePayload.server_signature`
/// (signed by the phone's static `Ed_S`).
pub const PAIRING_SERVER_SIG_CONTEXT: &[u8] = b"tapauth-pair-server-sig-v2";

/// AEAD associated-data prefix of `PairingConfirmClient.encrypted_payload` (key `K_c2s`).
pub const PAIRING_PROVISION_AAD_CONTEXT: &[u8] = b"tapauth-pair-v2-provision";

/// AEAD associated-data prefix of `PairingConfirmServer.encrypted_complete` (key `K_s2c`).
pub const PAIRING_COMPLETE_AAD_CONTEXT: &[u8] = b"tapauth-pair-v2-complete";
