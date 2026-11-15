//! Unified UDP + BLE pairing state machines for protocol v2.
//!
//! Pairing provisions the desktop's long-term `CSK` onto a phone and binds both
//! devices' static Ed25519 identity keys together, over the same two transports
//! used for authentication (UDP and BLE). This module is the transport-agnostic
//! protocol half only: it encodes and decodes [`PairingPacket`] frames and runs
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
//! [`ProtocolError::UnsupportedAlgorithm`] instead of silently negotiating a pair
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
//! methods) fails with [`ProtocolError::SessionConcluded`] instead of running on a
//! session whose keys are gone. The keepalive is the one that carries no key
//! material, and it is guarded all the same: a path kept open after `conclude` could
//! only deliver a retransmission nothing would answer.
//!
//! ## Where the handshake ends
//!
//! [`ServerPairingSession::create_confirm_server`] builds the last message of the
//! handshake but does **not** end the session: it records that the confirmation
//! has been sent, which refuses a second proof ([`ProtocolError::ConfirmationAlreadySent`])
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
//!   created message rather than re-encrypt (see the "no re-encryption" note on
//!   the create methods).

use prost::Message as ProstMessage;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::{
    compute_pairing_abort_tag, compute_pairing_transcript_hash, decrypt_with_key,
    derive_ble_pairing_adv_id, derive_pairing_keys_and_sas, encrypt_with_key, sign_ed25519,
    verify_ed25519, verify_pairing_abort_tag, CryptoError, Ed25519KeyPair, PairingSessionKeys,
    PairingTranscript, X25519KeyPair,
};
use crate::models::pairing::generate_pairing_url_v2;
use crate::protocol::messages::{ProtocolError, PROTOCOL_VERSION_V2};
use crate::protocol::pb::*;

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

/// Symmetric AEAD algorithms this implementation supports, baseline mandatory first.
///
/// The negotiation keeps this order: `pick_first(SUPPORTED_*, theirs)` walks this
/// slice, so an algorithm added here is chosen ahead of any later entry while a
/// peer that only lists the baseline still intersects on it. A future upgrade
/// therefore puts the Client's newly preferred algorithm **first** (Servers list
/// every algorithm they implement, baseline included, so older Clients still
/// agree on the baseline).
pub const SUPPORTED_SYMMETRIC_ALGORITHMS: &[SymmetricAlgorithm] = &[SymmetricAlgorithm::Aes256Gcm];

/// Hash algorithms this implementation supports, baseline mandatory first.
pub const SUPPORTED_HASH_ALGORITHMS: &[HashAlgorithm] = &[HashAlgorithm::Sha256];

/// Signature algorithms this implementation supports, baseline mandatory first.
pub const SUPPORTED_SIGNATURE_ALGORITHMS: &[SignatureAlgorithm] = &[SignatureAlgorithm::Ed25519];

/// The algorithms both peers agreed on for this pairing session.
///
/// Both directions persist these: the symmetric and hash algorithms become the
/// client-wide broadcast parameters (bound to the `CSK`), the signature algorithm
/// is the per-server one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedAlgorithms {
    /// AEAD algorithm for the provisioning/completion payloads (and, later, `EncryptedPacket`).
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// Hash algorithm for temporal identifiers (and, later, `EncryptedPacket`).
    pub hash_algorithm: HashAlgorithm,
    /// Signature algorithm for identity proofs.
    pub signature_algorithm: SignatureAlgorithm,
}

/// The algorithms a client-wide CSK is already committed to. A client that
/// already holds a CSK must re-pair only with peers that support them,
/// because one multicast broadcast must stay decryptable by every paired server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedAlgorithms {
    pub symmetric_algorithm: SymmetricAlgorithm,
    pub hash_algorithm: HashAlgorithm,
}

/// Encode a [`PairingPacket`] for a UDP datagram payload or a BLE GATT value.
///
/// Rejects a version other than [`PROTOCOL_VERSION_V2`] and a `session_id` that
/// is not exactly [`PAIRING_SESSION_ID_LEN`] bytes.
pub fn encode_pairing_packet(packet: &PairingPacket) -> Result<Vec<u8>, ProtocolError> {
    validate_envelope(packet)?;
    Ok(packet.encode_to_vec())
}

/// Decode a [`PairingPacket`] received from UDP or BLE.
///
/// The same envelope rules as [`encode_pairing_packet`] apply, so a caller never
/// has to defend against a foreign protocol version or a truncated session id.
pub fn decode_pairing_packet(bytes: &[u8]) -> Result<PairingPacket, ProtocolError> {
    let packet = PairingPacket::decode(bytes)?;
    validate_envelope(&packet)?;
    Ok(packet)
}

/// Extract the validated `session_id` of a frame for session filtering.
pub fn pairing_session_id(
    packet: &PairingPacket,
) -> Result<[u8; PAIRING_SESSION_ID_LEN], ProtocolError> {
    validate_envelope(packet)?;
    packet
        .session_id
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::InvalidMessageFormat)
}

/// The address information a pairing session publishes in its QR code.
///
/// These values never enter the transcript; they only build the
/// `tapauth://pair?v=2&...` URL, and may all be absent for BLE-only pairing.
#[derive(Debug, Clone, Copy, Default)]
struct PairingEndpoint {
    /// The UDP pairing port, or `None` when this session has no UDP endpoint
    /// (the network transport is disabled and the phone pairs over BLE only).
    /// `None` omits `&p=` from the QR code entirely; `&p=0` would advertise a
    /// port nothing can send to.
    udp_port: Option<u16>,
    ipv4: Option<std::net::Ipv4Addr>,
    ipv6: Option<std::net::Ipv6Addr>,
}

/// What the desktop needs to show/emit after [`ClientPairingState::start`].
pub struct StartedPairing {
    /// Random 16-byte session id (`sid`), also carried by every `PairingPacket`.
    pub session_id: [u8; PAIRING_SESSION_ID_LEN],
    /// Ephemeral X25519 public key `X_C` — the `pk` committed in the QR code.
    pub client_x25519_public_key: [u8; 32],
    /// 10-byte identifier to advertise in `ServiceData(SERVICE_UUID)` while pairing.
    pub pairing_adv_id: [u8; 10],
    /// `tapauth://pair?v=2&sid=...&pk=...&p=...` QR code URL.
    pub qr_url: String,
}

/// Desktop-side pairing state (the protocol *Client*; see the module docs).
///
/// Created by [`ClientPairingState::start`], fed a `PairingInit` through
/// [`ClientPairingState::handle_init`], then driven through provisioning and
/// completion. All key material is dropped (and zeroized) when the value is
/// dropped, which the caller must do as soon as pairing concludes.
pub struct ClientPairingState {
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    /// Public half `X_C`, committed in the QR code. Public data, kept after the
    /// secret is taken so the accessor stays answerable.
    client_x25519_public_key: [u8; 32],
    /// Ephemeral `x_C`. Taken — and zeroized on drop — as soon as the session
    /// keys are derived, and again on [`ClientPairingState::conclude`], so the
    /// secret cannot be reused by a later operation.
    x25519_keypair: Option<X25519KeyPair>,
    client_identity: Ed25519KeyPair,
    client_device_name: String,
    /// Encoding of the first accepted `PairingInit`, for idempotent retries.
    accepted_init: Option<Vec<u8>>,
    response: Option<PairingResponse>,
    /// `Ed_S`, captured from the accepted `PairingInit` (and bound into `H`); the
    /// key the phone's completion proof is verified under.
    server_ed25519_public_key: Option<[u8; 32]>,
    transcript_hash: Option<[u8; 32]>,
    keys: Option<PairingSessionKeys>,
    negotiated: Option<NegotiatedAlgorithms>,
    /// The active CSK's algorithms, which negotiation must reproduce.
    pinned: Option<PinnedAlgorithms>,
    /// Terminal flag: set by [`ClientPairingState::conclude`], after which every
    /// protocol operation is refused.
    concluded: bool,
}

impl ClientPairingState {
    /// Start a pairing session: random `sid`, ephemeral `x_C`, BLE advertisement
    /// id and QR URL.
    ///
    /// `udp_port`, `ipv4` and `ipv6` only feed the QR URL (they may be absent for
    /// BLE-only pairing). `udp_port == 0` means "this session has no UDP
    /// endpoint": it is omitted from the QR code rather than published as
    /// `&p=0`, a port nothing can send to. Negotiation happens in
    /// [`ClientPairingState::handle_init`]; `pinned` carries the algorithms an
    /// existing `CSK` is already committed to (see the module docs), and must be
    /// `None` for a first pairing.
    pub fn start(
        client_identity: Ed25519KeyPair,
        client_device_name: &str,
        udp_port: u16,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
        pinned: Option<PinnedAlgorithms>,
    ) -> Result<(Self, StartedPairing), ProtocolError> {
        let mut session_id = [0u8; PAIRING_SESSION_ID_LEN];
        getrandom::fill(&mut session_id)
            .map_err(|_| ProtocolError::Crypto(CryptoError::RandomGenerationFailed))?;
        let x25519_keypair = X25519KeyPair::generate()?;
        Ok(Self::build(
            session_id,
            x25519_keypair,
            client_identity,
            client_device_name,
            PairingEndpoint {
                // Port 0 is never a real UDP endpoint: a session that has none
                // (network transport disabled) must not publish `&p=0`.
                udp_port: (udp_port != 0).then_some(udp_port),
                ipv4,
                ipv6,
            },
            pinned,
        ))
    }

    /// Assemble the state and its [`StartedPairing`] from already-chosen material.
    ///
    /// Split out of [`ClientPairingState::start`] so a test can re-create a state
    /// with the *same* `x_C`/`Ed_C`/`sid` and vary one transcript field at a time.
    fn build(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        x25519_keypair: X25519KeyPair,
        client_identity: Ed25519KeyPair,
        client_device_name: &str,
        endpoint: PairingEndpoint,
        pinned: Option<PinnedAlgorithms>,
    ) -> (Self, StartedPairing) {
        let client_x25519_public_key = x25519_keypair.public_key_bytes();
        let pairing_adv_id = derive_ble_pairing_adv_id(&session_id, &client_x25519_public_key);
        let qr_url = generate_pairing_url_v2(
            &session_id,
            &hex::encode(client_x25519_public_key),
            endpoint.udp_port,
            endpoint.ipv4,
            endpoint.ipv6,
        );

        let state = Self {
            session_id,
            client_x25519_public_key,
            x25519_keypair: Some(x25519_keypair),
            client_identity,
            client_device_name: truncate_utf8(client_device_name, PAIRING_DEVICE_NAME_MAX_BYTES),
            accepted_init: None,
            response: None,
            server_ed25519_public_key: None,
            transcript_hash: None,
            keys: None,
            negotiated: None,
            pinned,
            concluded: false,
        };
        let started = StartedPairing {
            session_id,
            client_x25519_public_key,
            pairing_adv_id,
            qr_url,
        };
        (state, started)
    }

    /// The random session id every frame of this pairing must carry.
    pub fn session_id(&self) -> &[u8; PAIRING_SESSION_ID_LEN] {
        &self.session_id
    }

    /// The ephemeral `X_C` committed in the QR code.
    pub fn client_x25519_public_key(&self) -> [u8; 32] {
        self.client_x25519_public_key
    }

    /// The static `Ed_C` this desktop proves possession of.
    pub fn client_ed25519_public_key(&self) -> [u8; 32] {
        self.client_identity.verifying_key_bytes()
    }

    /// Handle a `PairingInit`: negotiate, derive `H`/keys/SAS, answer with a
    /// signed `PairingResponse`.
    ///
    /// The caller must have checked `session_id` (see [`pairing_session_id`]).
    /// Calling this twice with the *same* `init` (a UDP retry) returns the cached
    /// response; calling it with a *different* `init` after the session is
    /// established fails with [`ProtocolError::InvalidMessageFormat`], because the
    /// transcript and the derived keys are already committed.
    pub fn handle_init(&mut self, init: &PairingInit) -> Result<&PairingResponse, ProtocolError> {
        ensure_live(self.concluded)?;
        let server_x25519_public_key =
            key_32(&init.server_x25519_public_key, "server_x25519_public_key")?;
        let server_ed25519_public_key =
            key_32(&init.server_ed25519_public_key, "server_ed25519_public_key")?;

        let encoded_init = init.encode_to_vec();
        if let Some(accepted) = self.accepted_init.as_ref() {
            if accepted == &encoded_init {
                return self
                    .response
                    .as_ref()
                    .ok_or(ProtocolError::InvalidMessageFormat);
            }
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let supported_symmetric = symmetric_algorithms(&init.supported_symmetric_algorithms)?;
        let supported_hash = hash_algorithms(&init.supported_hash_algorithms)?;
        let supported_signature = signature_algorithms(&init.supported_signature_algorithms)?;
        let negotiated = negotiate(
            &supported_symmetric,
            &supported_hash,
            &supported_signature,
            self.pinned,
        )?;

        let client_x25519_public_key = self.client_x25519_public_key;
        let client_ed25519_public_key = self.client_identity.verifying_key_bytes();

        let transcript = PairingTranscript {
            version: PROTOCOL_VERSION_V2,
            session_id: &self.session_id,
            client_x25519_public_key: &client_x25519_public_key,
            server_x25519_public_key: &server_x25519_public_key,
            client_ed25519_public_key: &client_ed25519_public_key,
            server_ed25519_public_key: &server_ed25519_public_key,
            client_device_name: &self.client_device_name,
            server_device_name: &init.server_device_name,
            // Exactly as received, order included: both sides must hash the same bytes.
            supported_symmetric: &supported_symmetric,
            supported_hash: &supported_hash,
            supported_signature: &supported_signature,
            selected_symmetric: negotiated.symmetric_algorithm,
            selected_hash: negotiated.hash_algorithm,
            selected_signature: negotiated.signature_algorithm,
        };
        let transcript_hash = compute_pairing_transcript_hash(&transcript);

        let shared_secret = Zeroizing::new(
            self.x25519_keypair
                .as_ref()
                .ok_or(ProtocolError::MissingField("x25519_keypair"))?
                .diffie_hellman(&server_x25519_public_key)?,
        );
        let keys = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash)?;
        drop(shared_secret);
        // `x_C` has served its only purpose. Take it now so it is zeroized and can
        // never be reused, even by a later retry or a resurrected session.
        self.x25519_keypair = None;

        let signed = context_with_hash(PAIRING_CLIENT_SIG_CONTEXT, &transcript_hash);
        let client_signature = sign_ed25519(&self.client_identity, &signed);

        let response = PairingResponse {
            client_x25519_public_key: client_x25519_public_key.to_vec(),
            client_ed25519_public_key: client_ed25519_public_key.to_vec(),
            client_device_name: self.client_device_name.clone(),
            selected_symmetric_algorithm: negotiated.symmetric_algorithm as i32,
            selected_hash_algorithm: negotiated.hash_algorithm as i32,
            selected_signature_algorithm: negotiated.signature_algorithm as i32,
            client_signature,
        };

        self.accepted_init = Some(encoded_init);
        self.response = Some(response);
        self.server_ed25519_public_key = Some(server_ed25519_public_key);
        self.transcript_hash = Some(transcript_hash);
        self.keys = Some(keys);
        self.negotiated = Some(negotiated);

        self.response
            .as_ref()
            .ok_or(ProtocolError::InvalidMessageFormat)
    }

    /// The cached `PairingResponse` to re-send for a retried `PairingInit`.
    pub fn response(&self) -> Option<&PairingResponse> {
        self.response.as_ref()
    }

    /// Drop the session keys, the transcript hash and the ephemeral `x_C`.
    ///
    /// Call this once the pairing has completed ([`ClientPairingState::verify_confirm_server`]
    /// returned `Ok`) or as soon as it is aborted, so `K_c2s`/`K_s2c`/`H` do not
    /// linger in memory (cryptography-specification.md §4). Afterwards
    /// [`ClientPairingState::sas`] and [`ClientPairingState::transcript_hash`] return
    /// `None`, and [`ClientPairingState::negotiated`] still answers.
    ///
    /// `conclude` is **terminal**: every protocol operation (`handle_init`,
    /// `create_confirm_client`, `verify_confirm_server`, `create_abort`,
    /// `verify_abort`) then fails with
    /// [`ProtocolError::SessionConcluded`], so a late retransmission cannot
    /// resurrect a session whose keys are gone. Calling it twice is a no-op.
    pub fn conclude(&mut self) {
        if self.concluded {
            return;
        }
        self.concluded = true;
        self.keys = None;
        self.transcript_hash = None;
        // Zeroized on drop: the secret is gone with the keys it derived.
        self.x25519_keypair = None;
    }

    /// Whether [`ClientPairingState::conclude`] has run.
    ///
    /// The public half of `x_C` stays exposed by
    /// [`ClientPairingState::client_x25519_public_key`].
    #[cfg(test)]
    fn ephemeral_keypair_present(&self) -> bool {
        self.x25519_keypair.is_some()
    }

    /// The negotiated algorithms, once `PairingInit` has been handled.
    pub fn negotiated(&self) -> Option<NegotiatedAlgorithms> {
        self.negotiated
    }

    /// The handshake transcript hash `H`, once `PairingInit` has been handled.
    pub fn transcript_hash(&self) -> Option<&[u8; 32]> {
        self.transcript_hash.as_ref()
    }

    /// The SAS to display (`"123-456"`), once `PairingInit` has been handled.
    pub fn sas(&self) -> Option<&str> {
        self.keys.as_ref().map(|keys| keys.sas.as_str())
    }

    /// Build the provisioning payload for the phone (`PairingConfirmClient`).
    ///
    /// **Desktop → phone** (initial-key-exchange.md Step 5): encodes
    /// `PairingProvisionPayload { csk, username, client_hostname }` and
    /// AEAD-encrypts it under `K_c2s` with
    /// `AAD = "tapauth-pair-v2-provision" || H`, so neither the CSK nor the
    /// username/hostname travels in cleartext.
    ///
    /// Each call draws a fresh nonce: a retransmission must re-send the same
    /// [`PairingConfirmClient`], not call this again.
    ///
    /// Fails with [`ProtocolError::SessionConcluded`] once [`ClientPairingState::conclude`]
    /// has run.
    pub fn create_confirm_client(
        &self,
        csk: &[u8; 32],
        username: &str,
        client_hostname: &str,
    ) -> Result<PairingConfirmClient, ProtocolError> {
        ensure_live(self.concluded)?;
        let (keys, transcript_hash, negotiated) =
            session_material(&self.keys, &self.transcript_hash, &self.negotiated)?;
        let payload = PairingProvisionPayload {
            csk: csk.to_vec(),
            username: username.to_string(),
            client_hostname: client_hostname.to_string(),
        };
        let aad = context_with_hash(PAIRING_PROVISION_AAD_CONTEXT, transcript_hash);
        let encrypted_payload = encrypt_with_key(
            negotiated.symmetric_algorithm,
            &keys.k_c2s,
            &payload.encode_to_vec(),
            &aad,
        )?;
        Ok(PairingConfirmClient { encrypted_payload })
    }

    /// Verify the phone's completion proof for the CSK we provisioned.
    ///
    /// **Phone → desktop** (initial-key-exchange.md Step 6): decrypts
    /// `encrypted_complete` under `K_s2c` with
    /// `AAD = "tapauth-pair-v2-complete" || H`, decodes
    /// `PairingCompletePayload`, requires a 64-byte signature, then verifies
    /// `verify_ed25519(Ed_S, "tapauth-pair-server-sig-v2" || H || csk, signature)`.
    /// `Ed_S` is the `server_ed25519_public_key` captured from the accepted
    /// `PairingInit` — never this desktop's own `Ed_C`.
    ///
    /// Fails with [`ProtocolError::SessionConcluded`] once
    /// [`ClientPairingState::conclude`] has run: the keys are gone by design then,
    /// which is not a malformed message.
    pub fn verify_confirm_server(
        &self,
        confirm: &PairingConfirmServer,
        csk: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        ensure_live(self.concluded)?;
        let (keys, transcript_hash, negotiated) =
            session_material(&self.keys, &self.transcript_hash, &self.negotiated)?;
        let server_ed25519_public_key = self
            .server_ed25519_public_key
            .ok_or(ProtocolError::MissingField("server_ed25519_public_key"))?;

        let aad = context_with_hash(PAIRING_COMPLETE_AAD_CONTEXT, transcript_hash);
        let plaintext = decrypt_with_key(
            negotiated.symmetric_algorithm,
            &keys.k_s2c,
            &confirm.encrypted_complete,
            &aad,
        )?;
        let payload = PairingCompletePayload::decode(plaintext.as_slice())?;
        if payload.server_signature.len() != 64 {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let signed = complete_signature_message(PAIRING_SERVER_SIG_CONTEXT, transcript_hash, csk);
        verify_ed25519(
            &server_ed25519_public_key,
            &signed,
            &payload.server_signature,
        )
        .map_err(|_| ProtocolError::InvalidSignature)
    }

    /// Build an abort, authenticated with `K_c2s` when the keys already exist.
    ///
    /// Before the keys exist the abort is sent untagged: the peer only learns that
    /// somebody asked to stop, which is all it can authenticate anyway.
    ///
    /// Fails with [`ProtocolError::SessionConcluded`] once [`ClientPairingState::conclude`]
    /// has run.
    pub fn create_abort(&self, reason: PairingAbortReason) -> Result<PairingAbort, ProtocolError> {
        ensure_live(self.concluded)?;
        let auth_tag = match (self.keys.as_ref(), self.transcript_hash.as_ref()) {
            (Some(keys), Some(transcript_hash)) => {
                compute_pairing_abort_tag(&keys.k_c2s, transcript_hash, reason as i32).to_vec()
            }
            _ => Vec::new(),
        };
        Ok(PairingAbort {
            reason: reason as i32,
            auth_tag,
        })
    }

    /// Verify an abort received from the phone (tagged with `K_s2c`).
    ///
    /// Returns `Ok(true)` for an authenticated abort, `Ok(false)` for a tag-less
    /// abort received before any key exists (unauthenticated by construction), and
    /// [`ProtocolError::InvalidSignature`] for a bad tag, a tag-less abort once
    /// keys exist, or a tag before keys exist. Once the session concluded it fails
    /// with [`ProtocolError::SessionConcluded`].
    pub fn verify_abort(&self, abort: &PairingAbort) -> Result<bool, ProtocolError> {
        ensure_live(self.concluded)?;
        verify_abort_tag(
            abort,
            self.keys.as_ref().map(|keys| &*keys.k_s2c),
            self.transcript_hash.as_ref(),
        )
    }
}

/// Phone-side pairing session (the protocol *Server*; see the module docs).
///
/// Created from the QR code's session id, then driven through `PairingInit`,
/// response verification, provisioning and completion. Dropping it zeroizes the
/// ephemeral key and the derived session keys.
pub struct ServerPairingSession {
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    /// Public half `X_S`, kept after the secret is taken so a cached
    /// `PairingInit` and the transcript stay answerable.
    server_x25519_public_key: [u8; 32],
    /// Ephemeral `x_S`. Taken — and zeroized on drop — as soon as the session
    /// keys are derived, and again on [`ServerPairingSession::conclude`].
    x25519_keypair: Option<X25519KeyPair>,
    server_identity: Ed25519KeyPair,
    server_device_name: String,
    /// Exactly what `PairingInit` advertised; these lists enter `H`, so they are
    /// cached and reused verbatim in [`ServerPairingSession::verify_response`].
    advertised_symmetric: Vec<SymmetricAlgorithm>,
    advertised_hash: Vec<HashAlgorithm>,
    advertised_signature: Vec<SignatureAlgorithm>,
    init: Option<PairingInit>,
    negotiated: Option<NegotiatedAlgorithms>,
    transcript_hash: Option<[u8; 32]>,
    keys: Option<PairingSessionKeys>,
    /// Set by [`ServerPairingSession::create_confirm_server`]: the completion proof
    /// went out, so the handshake has moved past every earlier step while the keys
    /// stay available for `process_confirm_client` retransmissions.
    confirmation_sent: bool,
    /// Terminal flag: set by [`ServerPairingSession::conclude`], after which every
    /// protocol operation is refused.
    concluded: bool,
}

impl ServerPairingSession {
    /// Create the phone's half of a pairing, from the scanned QR `sid`.
    ///
    /// `server_identity` is the phone's long-term `Ed_S`.
    pub fn new(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        server_identity: Ed25519KeyPair,
        server_device_name: &str,
    ) -> Result<Self, ProtocolError> {
        Ok(Self::build(
            session_id,
            X25519KeyPair::generate()?,
            server_identity,
            server_device_name,
        ))
    }

    /// Assemble the session around an already-chosen ephemeral `X_S`.
    ///
    /// Split out of [`ServerPairingSession::new`] so a test can pin `X_S` and get a
    /// deterministic `Z`, `H` and SAS (see `transcript_hash_binds_every_negotiated_field`).
    fn build(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        x25519_keypair: X25519KeyPair,
        server_identity: Ed25519KeyPair,
        server_device_name: &str,
    ) -> Self {
        let server_x25519_public_key = x25519_keypair.public_key_bytes();
        Self {
            session_id,
            server_x25519_public_key,
            x25519_keypair: Some(x25519_keypair),
            server_identity,
            server_device_name: truncate_utf8(server_device_name, PAIRING_DEVICE_NAME_MAX_BYTES),
            advertised_symmetric: SUPPORTED_SYMMETRIC_ALGORITHMS.to_vec(),
            advertised_hash: SUPPORTED_HASH_ALGORITHMS.to_vec(),
            advertised_signature: SUPPORTED_SIGNATURE_ALGORITHMS.to_vec(),
            init: None,
            negotiated: None,
            transcript_hash: None,
            keys: None,
            confirmation_sent: false,
            concluded: false,
        }
    }

    /// The session id every frame of this pairing must carry.
    pub fn session_id(&self) -> &[u8; PAIRING_SESSION_ID_LEN] {
        &self.session_id
    }

    /// Build (once) the `PairingInit` to send, retransmitting the cached copy.
    ///
    /// Fails with [`ProtocolError::SessionConcluded`] once
    /// [`ServerPairingSession::conclude`] has run, and with
    /// [`ProtocolError::ConfirmationAlreadySent`] once
    /// [`ServerPairingSession::create_confirm_server`] has: the handshake is past
    /// the init step by then, so a late `PairingInit` must not be answered.
    pub fn create_init(&mut self) -> Result<PairingInit, ProtocolError> {
        ensure_live(self.concluded)?;
        if self.confirmation_sent {
            return Err(ProtocolError::ConfirmationAlreadySent);
        }
        if let Some(init) = self.init.as_ref() {
            return Ok(init.clone());
        }
        let init = PairingInit {
            server_x25519_public_key: self.server_x25519_public_key.to_vec(),
            server_ed25519_public_key: self.server_identity.verifying_key_bytes().to_vec(),
            server_device_name: self.server_device_name.clone(),
            supported_symmetric_algorithms: self
                .advertised_symmetric
                .iter()
                .map(|algorithm| *algorithm as i32)
                .collect(),
            supported_hash_algorithms: self
                .advertised_hash
                .iter()
                .map(|algorithm| *algorithm as i32)
                .collect(),
            supported_signature_algorithms: self
                .advertised_signature
                .iter()
                .map(|algorithm| *algorithm as i32)
                .collect(),
        };
        self.init = Some(init.clone());
        Ok(init)
    }

    /// Verify the desktop's `PairingResponse` and derive the session keys.
    ///
    /// `expected_qr_pk` is the `pk` from the scanned QR code. Order matters: the
    /// QR commitment is checked first so a substituted `X_C` cannot even reach the
    /// signature/derivation steps, and nothing is cached until every check passed.
    ///
    /// A `client_x25519_public_key` that is not 32 bytes is reported as
    /// [`ProtocolError::ChallengeMismatch`] too — it can never equal the QR key,
    /// and the caller's remedy (abort with `KEY_MISMATCH`) is the same.
    ///
    /// The phone must have built its `PairingInit` first (the transcript it
    /// advertised is the one it verifies against) and may verify exactly one
    /// response: while keys exist, a second response is refused with
    /// [`ProtocolError::InvalidMessageFormat`] rather than re-deriving over a live
    /// session. After [`ServerPairingSession::conclude`] the call fails with
    /// [`ProtocolError::SessionConcluded`].
    pub fn verify_response(
        &mut self,
        response: &PairingResponse,
        expected_qr_pk: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        ensure_live(self.concluded)?;
        if self.init.is_none() || self.keys.is_some() {
            return Err(ProtocolError::InvalidMessageFormat);
        }
        let client_x25519_public_key: [u8; 32] = response
            .client_x25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::ChallengeMismatch)?;
        if !bool::from(client_x25519_public_key.ct_eq(expected_qr_pk)) {
            return Err(ProtocolError::ChallengeMismatch);
        }

        let client_ed25519_public_key = key_32(
            &response.client_ed25519_public_key,
            "client_ed25519_public_key",
        )?;

        let selected_symmetric =
            SymmetricAlgorithm::try_from(response.selected_symmetric_algorithm)
                .map_err(|_| ProtocolError::UnsupportedAlgorithm)?;
        let selected_hash = HashAlgorithm::try_from(response.selected_hash_algorithm)
            .map_err(|_| ProtocolError::UnsupportedAlgorithm)?;
        let selected_signature =
            SignatureAlgorithm::try_from(response.selected_signature_algorithm)
                .map_err(|_| ProtocolError::UnsupportedAlgorithm)?;
        if !self.advertised_symmetric.contains(&selected_symmetric)
            || !self.advertised_hash.contains(&selected_hash)
            || !self.advertised_signature.contains(&selected_signature)
        {
            return Err(ProtocolError::UnsupportedAlgorithm);
        }
        let negotiated = NegotiatedAlgorithms {
            symmetric_algorithm: selected_symmetric,
            hash_algorithm: selected_hash,
            signature_algorithm: selected_signature,
        };

        let server_x25519_public_key = self.server_x25519_public_key;
        let server_ed25519_public_key = self.server_identity.verifying_key_bytes();

        let transcript = PairingTranscript {
            version: PROTOCOL_VERSION_V2,
            session_id: &self.session_id,
            client_x25519_public_key: &client_x25519_public_key,
            server_x25519_public_key: &server_x25519_public_key,
            client_ed25519_public_key: &client_ed25519_public_key,
            server_ed25519_public_key: &server_ed25519_public_key,
            client_device_name: &response.client_device_name,
            server_device_name: &self.server_device_name,
            supported_symmetric: &self.advertised_symmetric,
            supported_hash: &self.advertised_hash,
            supported_signature: &self.advertised_signature,
            selected_symmetric,
            selected_hash,
            selected_signature,
        };
        let transcript_hash = compute_pairing_transcript_hash(&transcript);

        let signed = context_with_hash(PAIRING_CLIENT_SIG_CONTEXT, &transcript_hash);
        verify_ed25519(
            &client_ed25519_public_key,
            &signed,
            &response.client_signature,
        )
        .map_err(|_| ProtocolError::InvalidSignature)?;

        let shared_secret = Zeroizing::new(
            self.x25519_keypair
                .as_ref()
                .ok_or(ProtocolError::MissingField("x25519_keypair"))?
                .diffie_hellman(&client_x25519_public_key)?,
        );
        let keys = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash)?;
        drop(shared_secret);
        // `x_S` has served its only purpose: take it so it is zeroized and the
        // session cannot derive a second set of keys from it.
        self.x25519_keypair = None;

        self.negotiated = Some(negotiated);
        self.transcript_hash = Some(transcript_hash);
        self.keys = Some(keys);
        Ok(())
    }

    /// The negotiated algorithms, once the response has been verified.
    pub fn negotiated(&self) -> Option<NegotiatedAlgorithms> {
        self.negotiated
    }

    /// The handshake transcript hash `H`, once the response has been verified.
    pub fn transcript_hash(&self) -> Option<&[u8; 32]> {
        self.transcript_hash.as_ref()
    }

    /// The SAS to display (`"123-456"`), once the response has been verified.
    pub fn sas(&self) -> Option<&str> {
        self.keys.as_ref().map(|keys| keys.sas.as_str())
    }

    /// Drop the session keys, the transcript hash and the ephemeral `x_S`.
    ///
    /// Call this once the completion proof is acknowledged — or simply on
    /// [`ServerPairingSession::create_abort`], or on releasing the session — so
    /// `K_c2s`/`K_s2c`/`H` do not linger in memory (cryptography-specification.md §4).
    /// Note that sending the proof itself ([`ServerPairingSession::create_confirm_server`])
    /// is **not** the moment to conclude: the keys must stay available while the
    /// desktop may still retransmit its provisioning frame.
    /// Same post-conditions as [`ClientPairingState::conclude`]: `conclude` is
    /// terminal, so every later protocol operation (`create_init`, `verify_response`,
    /// `create_confirm_server`, `process_confirm_client`, `create_abort`,
    /// `verify_abort`) fails with [`ProtocolError::SessionConcluded`]. Calling it
    /// twice is a no-op.
    pub fn conclude(&mut self) {
        if self.concluded {
            return;
        }
        self.concluded = true;
        self.keys = None;
        self.transcript_hash = None;
        self.x25519_keypair = None;
    }

    /// Whether the ephemeral `x_S` is still held.
    #[cfg(test)]
    fn ephemeral_keypair_present(&self) -> bool {
        self.x25519_keypair.is_some()
    }

    /// Decrypt the desktop's provisioning payload (`PairingConfirmClient`).
    ///
    /// **Desktop → phone** (initial-key-exchange.md Step 5): decrypts
    /// `encrypted_payload` under `K_c2s` with
    /// `AAD = "tapauth-pair-v2-provision" || H` and decodes
    /// `PairingProvisionPayload`. Returns `csk`/`username`/`client_hostname`; the
    /// caller persists them and requires `csk` to be 32 bytes (enforced here).
    ///
    /// Idempotent by design: the desktop retransmits the *same* frame until it sees
    /// the completion proof, so this stays valid after
    /// [`ServerPairingSession::create_confirm_server`] and returns the same payload
    /// for the same bytes. Only [`ServerPairingSession::conclude`] ends it, and then
    /// the call fails with [`ProtocolError::SessionConcluded`].
    pub fn process_confirm_client(
        &self,
        confirm: &PairingConfirmClient,
    ) -> Result<PairingProvisionPayload, ProtocolError> {
        ensure_live(self.concluded)?;
        let (keys, transcript_hash, negotiated) =
            session_material(&self.keys, &self.transcript_hash, &self.negotiated)?;
        let aad = context_with_hash(PAIRING_PROVISION_AAD_CONTEXT, transcript_hash);
        let plaintext = decrypt_with_key(
            negotiated.symmetric_algorithm,
            &keys.k_c2s,
            &confirm.encrypted_payload,
            &aad,
        )?;
        let payload = PairingProvisionPayload::decode(plaintext.as_slice())?;
        if payload.csk.len() != 32 {
            return Err(ProtocolError::InvalidMessageFormat);
        }
        Ok(payload)
    }

    /// Build the completion proof after the user confirmed the SAS on both screens.
    ///
    /// **Phone → desktop** (initial-key-exchange.md Step 6): signs
    /// `"tapauth-pair-server-sig-v2" || H || csk` with this phone's static `Ed_S`
    /// (proving possession of `Ed_S` and exact receipt of `csk`) and AEAD-encrypts
    /// `PairingCompletePayload { server_signature }` under `K_s2c` with
    /// `AAD = "tapauth-pair-v2-complete" || H`.
    ///
    /// Each call draws a fresh nonce: a retransmission must re-send the same
    /// [`PairingConfirmServer`], not call this again.
    ///
    /// **Not terminal.** On success the session records that the confirmation went
    /// out: a second call fails with [`ProtocolError::ConfirmationAlreadySent`] and
    /// so does a later [`ServerPairingSession::create_init`], but
    /// [`ServerPairingSession::process_confirm_client`] keeps answering the desktop's
    /// provisioning retransmissions (it needs the same keys). [`ServerPairingSession::conclude`]
    /// is what ends the session; afterwards every entry point, including this one,
    /// fails with [`ProtocolError::SessionConcluded`] — the liveness check runs
    /// first, so a concluded session is never reported as "already sent".
    pub fn create_confirm_server(
        &mut self,
        csk: &[u8; 32],
    ) -> Result<PairingConfirmServer, ProtocolError> {
        ensure_live(self.concluded)?;
        if self.confirmation_sent {
            return Err(ProtocolError::ConfirmationAlreadySent);
        }
        let (keys, transcript_hash, negotiated) =
            session_material(&self.keys, &self.transcript_hash, &self.negotiated)?;
        let signed = complete_signature_message(PAIRING_SERVER_SIG_CONTEXT, transcript_hash, csk);
        let server_signature = sign_ed25519(&self.server_identity, &signed);
        let payload = PairingCompletePayload { server_signature };
        let aad = context_with_hash(PAIRING_COMPLETE_AAD_CONTEXT, transcript_hash);
        let encrypted_complete = encrypt_with_key(
            negotiated.symmetric_algorithm,
            &keys.k_s2c,
            &payload.encode_to_vec(),
            &aad,
        )?;
        self.confirmation_sent = true;
        Ok(PairingConfirmServer { encrypted_complete })
    }

    /// Build the empty `PairingKeepalive` body.
    ///
    /// A keepalive carries no key material and drives no state transition: it exists
    /// only to keep a NAT mapping or a BLE link open while the peer's next frame is on
    /// its way. That is exactly why it needs the liveness check too — the only frame a
    /// concluded session could still be waiting for is a `PairingConfirmClient`
    /// retransmission, and [`ServerPairingSession::process_confirm_client`] refuses it
    /// once the keys are gone, so keeping the path open for it would be pointless.
    /// Fails with [`ProtocolError::SessionConcluded`] once
    /// [`ServerPairingSession::conclude`] has run.
    pub fn create_keepalive(&self) -> Result<PairingKeepalive, ProtocolError> {
        ensure_live(self.concluded)?;
        Ok(PairingKeepalive {})
    }

    /// Build an abort, authenticated with `K_s2c` when the keys already exist.
    ///
    /// Fails with [`ProtocolError::SessionConcluded`] once
    /// [`ServerPairingSession::conclude`] has run.
    pub fn create_abort(&self, reason: PairingAbortReason) -> Result<PairingAbort, ProtocolError> {
        ensure_live(self.concluded)?;
        let auth_tag = match (self.keys.as_ref(), self.transcript_hash.as_ref()) {
            (Some(keys), Some(transcript_hash)) => {
                compute_pairing_abort_tag(&keys.k_s2c, transcript_hash, reason as i32).to_vec()
            }
            _ => Vec::new(),
        };
        Ok(PairingAbort {
            reason: reason as i32,
            auth_tag,
        })
    }

    /// Verify an abort received from the desktop (tagged with `K_c2s`).
    ///
    /// Same result contract as [`ClientPairingState::verify_abort`]; after
    /// [`ServerPairingSession::conclude`] it fails with
    /// [`ProtocolError::SessionConcluded`].
    pub fn verify_abort(&self, abort: &PairingAbort) -> Result<bool, ProtocolError> {
        ensure_live(self.concluded)?;
        verify_abort_tag(
            abort,
            self.keys.as_ref().map(|keys| &*keys.k_c2s),
            self.transcript_hash.as_ref(),
        )
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Refuse a protocol operation on a session whose `conclude()` already ran.
///
/// `conclude()` is the terminal transition: it drops every key and the ephemeral
/// secret, so anything arriving afterwards is a retransmission of a finished
/// handshake — or an attempt to resurrect it — and must be reported as such
/// instead of being answered from a half-dead state.
fn ensure_live(concluded: bool) -> Result<(), ProtocolError> {
    if concluded {
        return Err(ProtocolError::SessionConcluded);
    }
    Ok(())
}

/// Envelope rules shared by the encoder, the decoder and the session-id accessor.
fn validate_envelope(packet: &PairingPacket) -> Result<(), ProtocolError> {
    if packet.version != PROTOCOL_VERSION_V2 {
        return Err(ProtocolError::InvalidMessageFormat);
    }
    if packet.session_id.len() != PAIRING_SESSION_ID_LEN {
        return Err(ProtocolError::InvalidMessageFormat);
    }
    Ok(())
}

/// Truncate a device name to `max_bytes` on a UTF-8 char boundary.
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    match value.get(..end) {
        Some(truncated) => truncated.to_string(),
        None => String::new(),
    }
}

/// `context || H` — the signature payload of `PairingResponse` and the AEAD AAD of
/// both confirmation messages.
fn context_with_hash(context: &[u8], transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(context.len() + transcript_hash.len());
    data.extend_from_slice(context);
    data.extend_from_slice(transcript_hash);
    data
}

/// `context || H || csk` — the signature payload of the completion proof.
fn complete_signature_message(
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

/// Parse a 32-byte protobuf `bytes` field, distinguishing "absent" from "wrong length".
fn key_32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::MissingField(field));
    }
    bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidMessageFormat)
}

/// Reject unknown enum values instead of silently dropping them: the lists enter
/// the transcript verbatim, so a value we cannot name cannot be hashed either.
fn symmetric_algorithms(values: &[i32]) -> Result<Vec<SymmetricAlgorithm>, ProtocolError> {
    values
        .iter()
        .map(|value| {
            SymmetricAlgorithm::try_from(*value).map_err(|_| ProtocolError::UnsupportedAlgorithm)
        })
        .collect()
}

fn hash_algorithms(values: &[i32]) -> Result<Vec<HashAlgorithm>, ProtocolError> {
    values
        .iter()
        .map(|value| {
            HashAlgorithm::try_from(*value).map_err(|_| ProtocolError::UnsupportedAlgorithm)
        })
        .collect()
}

fn signature_algorithms(values: &[i32]) -> Result<Vec<SignatureAlgorithm>, ProtocolError> {
    values
        .iter()
        .map(|value| {
            SignatureAlgorithm::try_from(*value).map_err(|_| ProtocolError::UnsupportedAlgorithm)
        })
        .collect()
}

/// First of `ours` that `theirs` also lists — i.e. our preference order wins.
fn pick_first<T: Copy + PartialEq>(ours: &[T], theirs: &[T]) -> Option<T> {
    ours.iter()
        .copied()
        .find(|candidate| theirs.contains(candidate))
}

/// Intersect all three lists, requiring a non-empty intersection for each.
///
/// A pinned (client-wide) algorithm must be present in the peer's list *and* be
/// one this build implements; otherwise negotiation fails instead of selecting a
/// pair the existing `CSK` is not using. The signature algorithm is per-server and
/// is never pinned.
fn negotiate(
    symmetric: &[SymmetricAlgorithm],
    hash: &[HashAlgorithm],
    signature: &[SignatureAlgorithm],
    pinned: Option<PinnedAlgorithms>,
) -> Result<NegotiatedAlgorithms, ProtocolError> {
    let symmetric_algorithm = match pinned {
        Some(pinned) => {
            if !SUPPORTED_SYMMETRIC_ALGORITHMS.contains(&pinned.symmetric_algorithm)
                || !symmetric.contains(&pinned.symmetric_algorithm)
            {
                return Err(ProtocolError::UnsupportedAlgorithm);
            }
            pinned.symmetric_algorithm
        }
        None => pick_first(SUPPORTED_SYMMETRIC_ALGORITHMS, symmetric)
            .ok_or(ProtocolError::UnsupportedAlgorithm)?,
    };
    let hash_algorithm = match pinned {
        Some(pinned) => {
            if !SUPPORTED_HASH_ALGORITHMS.contains(&pinned.hash_algorithm)
                || !hash.contains(&pinned.hash_algorithm)
            {
                return Err(ProtocolError::UnsupportedAlgorithm);
            }
            pinned.hash_algorithm
        }
        None => pick_first(SUPPORTED_HASH_ALGORITHMS, hash)
            .ok_or(ProtocolError::UnsupportedAlgorithm)?,
    };
    let signature_algorithm = pick_first(SUPPORTED_SIGNATURE_ALGORITHMS, signature)
        .ok_or(ProtocolError::UnsupportedAlgorithm)?;
    Ok(NegotiatedAlgorithms {
        symmetric_algorithm,
        hash_algorithm,
        signature_algorithm,
    })
}

/// The three session values both state machines hand out together.
fn session_material<'a>(
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
fn verify_abort_tag(
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const DESKTOP_SEED: [u8; 32] = [0xA1; 32];
    const PHONE_SEED: [u8; 32] = [0xB2; 32];

    fn desktop_identity() -> Ed25519KeyPair {
        Ed25519KeyPair::from_signing_key_bytes(&DESKTOP_SEED).unwrap()
    }

    fn phone_identity() -> Ed25519KeyPair {
        Ed25519KeyPair::from_signing_key_bytes(&PHONE_SEED).unwrap()
    }

    fn start_desktop() -> (ClientPairingState, StartedPairing) {
        start_desktop_with_pins(None)
    }

    fn start_desktop_with_pins(
        pinned: Option<PinnedAlgorithms>,
    ) -> (ClientPairingState, StartedPairing) {
        ClientPairingState::start(
            desktop_identity(),
            "thinkpad",
            36692,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            None,
            pinned,
        )
        .unwrap()
    }

    /// Rebuild a desktop state that is byte-identical in its key material and
    /// session id, so a test can vary exactly one transcript field.
    fn seeded_desktop(session_id: [u8; PAIRING_SESSION_ID_LEN]) -> ClientPairingState {
        ClientPairingState::build(
            session_id,
            X25519KeyPair::from_secret_bytes([0x11; 32]),
            desktop_identity(),
            "thinkpad",
            PairingEndpoint {
                udp_port: Some(36692),
                ipv4: None,
                ipv6: None,
            },
            None,
        )
        .0
    }

    /// The phone counterpart of [`seeded_desktop`]: a fixed `X_S`, so `Z`, `H` and
    /// the SAS are the same on every run.
    fn seeded_phone(session_id: [u8; PAIRING_SESSION_ID_LEN]) -> ServerPairingSession {
        ServerPairingSession::build(
            session_id,
            X25519KeyPair::from_secret_bytes([0x22; 32]),
            phone_identity(),
            "pixel",
        )
    }

    /// Desktop + phone with `PairingInit` sent and `PairingResponse` received, but
    /// not yet verified by the phone.
    fn exchange() -> (
        ClientPairingState,
        ServerPairingSession,
        PairingResponse,
        [u8; 32],
    ) {
        let (mut desktop, started) = start_desktop();
        let mut phone =
            ServerPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        let init = phone.create_init().unwrap();
        let response = desktop.handle_init(&init).unwrap().clone();
        (desktop, phone, response, started.client_x25519_public_key)
    }

    /// A fully established pairing: keys and SAS derived on both sides.
    fn established() -> (ClientPairingState, ServerPairingSession) {
        let (desktop, mut phone, response, qr_pk) = exchange();
        phone.verify_response(&response, &qr_pk).unwrap();
        (desktop, phone)
    }

    /// A `PairingInit` carrying the given **raw wire ids** in its three lists, so a
    /// test can advertise a tag no enum member names (`2`, `99`). The key material
    /// is fixed, like [`seeded_desktop`]'s, so the negotiation outcome is the
    /// only variable.
    fn init_with_algorithms(
        symmetric: Vec<i32>,
        hash: Vec<i32>,
        signature: Vec<i32>,
    ) -> PairingInit {
        PairingInit {
            server_x25519_public_key: X25519KeyPair::from_secret_bytes([0x22; 32])
                .public_key_bytes()
                .to_vec(),
            server_ed25519_public_key: phone_identity().verifying_key_bytes().to_vec(),
            server_device_name: "pixel".to_string(),
            supported_symmetric_algorithms: symmetric,
            supported_hash_algorithms: hash,
            supported_signature_algorithms: signature,
        }
    }

    fn assert_sas_shape(sas: &str) {
        let bytes = sas.as_bytes();
        assert_eq!(bytes.len(), 7, "SAS must look like ddd-ddd, got {sas:?}");
        assert_eq!(bytes[3], b'-', "SAS must look like ddd-ddd, got {sas:?}");
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(i, b)| i == 3 || b.is_ascii_digit()),
            "SAS must look like ddd-ddd, got {sas:?}"
        );
    }

    // --- 1. Happy path ----------------------------------------------------

    #[test]
    fn end_to_end_pairing_matches_sas_and_provisions_csk() {
        let (mut desktop, started) = start_desktop();
        assert_eq!(
            started.pairing_adv_id,
            derive_ble_pairing_adv_id(&started.session_id, &started.client_x25519_public_key)
        );
        assert!(started.qr_url.starts_with("tapauth://pair?v=2"));
        assert!(started
            .qr_url
            .contains(&format!("sid={}", hex::encode(started.session_id))));
        assert!(
            started
                .qr_url
                .contains(&hex::encode(started.client_x25519_public_key)),
            "QR must commit X_C: {}",
            started.qr_url
        );
        assert!(started.qr_url.contains("p=36692"));
        assert!(started.qr_url.contains("ip4=192.168.1.10"));

        let mut phone =
            ServerPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        assert_eq!(phone.session_id(), &started.session_id);

        let init = phone.create_init().unwrap();
        assert_eq!(
            init.server_ed25519_public_key,
            phone_identity().verifying_key_bytes().to_vec()
        );
        assert_eq!(init.server_device_name, "pixel");
        assert_eq!(
            init.supported_symmetric_algorithms,
            vec![SymmetricAlgorithm::Aes256Gcm as i32]
        );
        assert_eq!(
            init.supported_hash_algorithms,
            vec![HashAlgorithm::Sha256 as i32]
        );
        assert_eq!(
            init.supported_signature_algorithms,
            vec![SignatureAlgorithm::Ed25519 as i32]
        );

        let response = desktop.handle_init(&init).unwrap().clone();
        assert_eq!(
            response.client_ed25519_public_key,
            desktop_identity().verifying_key_bytes().to_vec()
        );
        assert_eq!(response.client_device_name, "thinkpad");

        phone
            .verify_response(&response, &started.client_x25519_public_key)
            .unwrap();

        let expected = NegotiatedAlgorithms {
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::Ed25519,
        };
        assert_eq!(desktop.negotiated(), Some(expected));
        assert_eq!(phone.negotiated(), Some(expected));
        assert_eq!(desktop.transcript_hash(), phone.transcript_hash());

        let desktop_sas = desktop.sas().unwrap();
        let phone_sas = phone.sas().unwrap();
        assert_sas_shape(desktop_sas);
        assert_sas_shape(phone_sas);
        assert_eq!(desktop_sas, phone_sas);

        let csk = [0x42u8; 32];
        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        let payload = phone.process_confirm_client(&confirm_client).unwrap();
        assert_eq!(payload.csk, csk.to_vec());
        assert_eq!(payload.username, "luca");
        assert_eq!(payload.client_hostname, "thinkpad");

        let confirm_server = phone.create_confirm_server(&csk).unwrap();
        desktop
            .verify_confirm_server(&confirm_server, &csk)
            .unwrap();
        // The proof pins the exact CSK: a different one must not verify.
        assert!(matches!(
            desktop
                .verify_confirm_server(&confirm_server, &[0x43u8; 32])
                .unwrap_err(),
            ProtocolError::InvalidSignature
        ));
    }

    /// The completion proof must be `Ed_S`'s signature, not `Ed_C`'s.
    /// The defect this catches: the phone signing with the wrong identity key
    /// (e.g. a proof built on the desktop's `Ed_C`, as the inverted flow did),
    /// which the desktop would then verify against the wrong key.
    #[test]
    fn completion_proof_is_signed_by_ed_s_not_ed_c() {
        let (desktop, mut phone) = established();
        let csk = [0x42u8; 32];
        let confirm = phone.create_confirm_server(&csk).unwrap();

        // Open the proof with the phone's own `K_s2c`, exactly as the desktop does.
        let keys = phone.keys.as_ref().unwrap();
        let transcript_hash = phone.transcript_hash.unwrap();
        let aad = context_with_hash(PAIRING_COMPLETE_AAD_CONTEXT, &transcript_hash);
        let plaintext = decrypt_with_key(
            SymmetricAlgorithm::Aes256Gcm,
            &keys.k_s2c,
            &confirm.encrypted_complete,
            &aad,
        )
        .unwrap();
        let payload = PairingCompletePayload::decode(plaintext.as_slice()).unwrap();
        assert_eq!(payload.server_signature.len(), 64);

        let signed = complete_signature_message(PAIRING_SERVER_SIG_CONTEXT, &transcript_hash, &csk);
        // Under the phone's `Ed_S` (the key captured from `PairingInit`) it verifies.
        verify_ed25519(
            &phone_identity().verifying_key_bytes(),
            &signed,
            &payload.server_signature,
        )
        .unwrap();
        // Under the desktop's own `Ed_C` it must not.
        assert!(verify_ed25519(
            &desktop.client_ed25519_public_key(),
            &signed,
            &payload.server_signature
        )
        .is_err());
        // Which is exactly what the desktop-side check concludes.
        assert_eq!(
            desktop.client_ed25519_public_key(),
            desktop_identity().verifying_key_bytes()
        );
        assert!(desktop.verify_confirm_server(&confirm, &csk).is_ok());

        // A proof built by a session with a different identity cannot pass for this
        // pairing: the desktop only trusts the `Ed_S` bound into `H`.
        let foreign_session_id = [0x99u8; PAIRING_SESSION_ID_LEN];
        let mut foreign_desktop = seeded_desktop(foreign_session_id);
        let mut foreign_phone = ServerPairingSession::new(
            foreign_session_id,
            Ed25519KeyPair::from_signing_key_bytes(&[0xC3; 32]).unwrap(),
            "pixel",
        )
        .unwrap();
        let foreign_init = foreign_phone.create_init().unwrap();
        let foreign_response = foreign_desktop.handle_init(&foreign_init).unwrap().clone();
        foreign_phone
            .verify_response(
                &foreign_response,
                &foreign_desktop.client_x25519_public_key(),
            )
            .unwrap();
        let foreign_confirm = foreign_phone.create_confirm_server(&csk).unwrap();
        assert!(desktop
            .verify_confirm_server(&foreign_confirm, &csk)
            .is_err());
    }

    /// The provisioning payload must travel under `K_c2s` only: the phone's own
    /// `K_s2c` (any wrong directional key) must not open it, and a tampered
    /// ciphertext byte must be rejected rather than decrypted to garbage.
    /// The defect this catches: the payload encrypted under the wrong directional
    /// key, or accepted without AEAD authentication (e.g. a plaintext or unsealed
    /// `encrypted_payload`).
    #[test]
    fn provision_payload_is_sealed_under_k_c2s_only() {
        let (desktop, phone) = established();
        let csk = [0x42u8; 32];
        let confirm = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();

        // The phone opens it with `K_c2s`.
        let payload = phone.process_confirm_client(&confirm).unwrap();
        assert_eq!(payload.csk, csk.to_vec());
        assert_eq!(payload.username, "luca");
        assert_eq!(payload.client_hostname, "thinkpad");

        // The same bytes do not open under the reverse-direction key or a different AAD.
        let keys = phone.keys.as_ref().unwrap();
        let transcript_hash = phone.transcript_hash.unwrap();
        let aad = context_with_hash(PAIRING_PROVISION_AAD_CONTEXT, &transcript_hash);
        assert!(matches!(
            decrypt_with_key(
                SymmetricAlgorithm::Aes256Gcm,
                &keys.k_s2c,
                &confirm.encrypted_payload,
                &aad
            ),
            Err(CryptoError::DecryptionFailed)
        ));
        let wrong_aad = context_with_hash(PAIRING_COMPLETE_AAD_CONTEXT, &transcript_hash);
        assert!(matches!(
            decrypt_with_key(
                SymmetricAlgorithm::Aes256Gcm,
                &keys.k_c2s,
                &confirm.encrypted_payload,
                &wrong_aad
            ),
            Err(CryptoError::DecryptionFailed)
        ));

        // A single flipped ciphertext byte is rejected by the AEAD tag.
        let mut tampered = confirm.clone();
        tampered.encrypted_payload[0] ^= 0x01;
        assert!(phone.process_confirm_client(&tampered).is_err());
    }

    // --- 2. QR key commitment --------------------------------------------

    #[test]
    fn response_for_a_different_qr_key_is_rejected() {
        let (_desktop, mut phone, response, qr_pk) = exchange();

        // A different expected QR key.
        let mut other_qr_pk = qr_pk;
        other_qr_pk[31] ^= 0x80;
        assert!(matches!(
            phone.verify_response(&response, &other_qr_pk).unwrap_err(),
            ProtocolError::ChallengeMismatch
        ));

        // A response that substituted X_C.
        let mut tampered = response.clone();
        tampered.client_x25519_public_key[0] ^= 0x01;
        assert!(matches!(
            phone.verify_response(&tampered, &qr_pk).unwrap_err(),
            ProtocolError::ChallengeMismatch
        ));

        assert!(phone.sas().is_none());
        assert!(phone.transcript_hash().is_none());
        assert!(phone.negotiated().is_none());
        // No keys were derived, so nothing can be built or opened.
        assert!(matches!(
            phone.create_confirm_server(&[0u8; 32]),
            Err(ProtocolError::MissingField("pairing_session_keys"))
        ));
        assert!(matches!(
            phone.process_confirm_client(&PairingConfirmClient {
                encrypted_payload: vec![0u8; 44],
            }),
            Err(ProtocolError::MissingField("pairing_session_keys"))
        ));
    }

    // --- 3. Client signature / identity key ------------------------------

    #[test]
    fn tampered_client_signature_is_rejected() {
        let (_desktop, mut phone, response, qr_pk) = exchange();
        let mut tampered = response.clone();
        tampered.client_signature[0] ^= 0xff;
        assert!(matches!(
            phone.verify_response(&tampered, &qr_pk).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
        assert!(phone.sas().is_none());
    }

    #[test]
    fn tampered_client_identity_key_is_rejected() {
        let (_desktop, mut phone, response, qr_pk) = exchange();
        let mut tampered = response.clone();
        tampered.client_ed25519_public_key[0] ^= 0xff;
        assert!(matches!(
            phone.verify_response(&tampered, &qr_pk).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
        assert!(phone.transcript_hash().is_none());
    }

    // --- 4. Algorithm downgrade / unsupported ----------------------------

    #[test]
    fn init_offering_no_supported_algorithm_is_rejected() {
        let (mut desktop, _started) = start_desktop();
        let mut init = PairingInit {
            server_x25519_public_key: X25519KeyPair::from_secret_bytes([0x33; 32])
                .public_key_bytes()
                .to_vec(),
            server_ed25519_public_key: phone_identity().verifying_key_bytes().to_vec(),
            server_device_name: "pixel".to_string(),
            supported_symmetric_algorithms: vec![SymmetricAlgorithm::Unspecified as i32],
            supported_hash_algorithms: vec![HashAlgorithm::Sha256 as i32],
            supported_signature_algorithms: vec![SignatureAlgorithm::Ed25519 as i32],
        };
        assert!(matches!(
            desktop.handle_init(&init).unwrap_err(),
            ProtocolError::UnsupportedAlgorithm
        ));

        init.supported_symmetric_algorithms = Vec::new();
        init.supported_hash_algorithms = Vec::new();
        init.supported_signature_algorithms = Vec::new();
        assert!(matches!(
            desktop.handle_init(&init).unwrap_err(),
            ProtocolError::UnsupportedAlgorithm
        ));
        // A rejected init must leave the session untouched.
        assert!(desktop.response().is_none());
        assert!(desktop.sas().is_none());

        // An unknown enum value is refused rather than silently dropped from H.
        init.supported_symmetric_algorithms = vec![99];
        init.supported_hash_algorithms = vec![HashAlgorithm::Sha256 as i32];
        init.supported_signature_algorithms = vec![SignatureAlgorithm::Ed25519 as i32];
        assert!(matches!(
            desktop.handle_init(&init).unwrap_err(),
            ProtocolError::UnsupportedAlgorithm
        ));
    }

    /// A `PairingInit` whose only advertised ids are the **reserved** tag `2`
    /// (retired `CHACHA20_POLY1305` / `BLAKE3`) must be refused, not defaulted
    /// and not accepted because "something was advertised".
    /// The defect this catches: a decoder that drops ids it cannot name from the
    /// list (leaving it empty and the negotiation free to pick a suite the peer
    /// never offered), or one that maps an unknown id onto the baseline.
    #[test]
    fn init_advertising_only_the_reserved_algorithm_tag_is_refused() {
        let mut init = init_with_algorithms(vec![2], vec![1], vec![1]);
        let mut desktop = seeded_desktop([0x6Au8; PAIRING_SESSION_ID_LEN]);
        assert!(
            matches!(
                desktop.handle_init(&init).unwrap_err(),
                ProtocolError::UnsupportedAlgorithm
            ),
            "a peer advertising only tag 2 must be refused"
        );

        // The same raw tag in the hash list.
        init = init_with_algorithms(vec![1], vec![2], vec![1]);
        let mut desktop = seeded_desktop([0x6Au8; PAIRING_SESSION_ID_LEN]);
        assert!(
            matches!(
                desktop.handle_init(&init).unwrap_err(),
                ProtocolError::UnsupportedAlgorithm
            ),
            "a peer advertising only hash tag 2 must be refused"
        );

        // Nothing was committed by either refusal.
        assert!(desktop.response().is_none());
        assert!(desktop.negotiated().is_none());
        assert!(desktop.sas().is_none());
    }

    /// An id this build cannot name at all (`99`) is refused for every list.
    /// The defect this catches: `try_from` collapsing an unknown id onto a
    /// default variant, which would both accept the offer and hash a different
    /// transcript than the peer did.
    #[test]
    fn init_advertising_only_an_unknown_algorithm_id_is_refused() {
        for lists in [
            (vec![99], vec![1], vec![1]),
            (vec![1], vec![99], vec![1]),
            (vec![1], vec![1], vec![99]),
        ] {
            let (symmetric, hash, signature) = lists.clone();
            let init = init_with_algorithms(symmetric, hash, signature);
            let mut desktop = seeded_desktop([0x6Bu8; PAIRING_SESSION_ID_LEN]);
            assert!(
                matches!(
                    desktop.handle_init(&init).unwrap_err(),
                    ProtocolError::UnsupportedAlgorithm
                ),
                "lists {lists:?} must be refused"
            );
            assert!(desktop.response().is_none());
        }
    }

    /// An empty advertised list is refused rather than silently allowing a
    /// default suite: empty means "I support nothing", which cannot be negotiated.
    /// The defect this catches: `pick_first` returning a default when the
    /// intersection is empty (`unwrap_or(Aes256Gcm)`), which would pair with a
    /// peer that never agreed to the suite.
    #[test]
    fn init_advertising_no_algorithms_is_refused() {
        for lists in [
            (Vec::new(), vec![1], vec![1]),
            (vec![1], Vec::new(), vec![1]),
            (vec![1], vec![1], Vec::new()),
        ] {
            let (symmetric, hash, signature) = lists.clone();
            let init = init_with_algorithms(symmetric, hash, signature);
            let mut desktop = seeded_desktop([0x6Cu8; PAIRING_SESSION_ID_LEN]);
            assert!(
                matches!(
                    desktop.handle_init(&init).unwrap_err(),
                    ProtocolError::UnsupportedAlgorithm
                ),
                "lists {lists:?} must be refused"
            );
            assert!(desktop.negotiated().is_none());
            assert!(desktop.sas().is_none());
        }
    }

    #[test]
    fn response_selecting_unadvertised_algorithm_is_rejected() {
        let (mut desktop, started) = start_desktop();
        let mut phone =
            ServerPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        // The phone only advertises AES-256-GCM, so it can never accept the
        // reserved tag 2 (or any other id it did not list).
        phone.advertised_symmetric = vec![SymmetricAlgorithm::Aes256Gcm];
        let init = phone.create_init().unwrap();
        assert_eq!(
            init.supported_symmetric_algorithms,
            vec![SymmetricAlgorithm::Aes256Gcm as i32]
        );

        let mut response = desktop.handle_init(&init).unwrap().clone();
        assert_eq!(
            response.selected_symmetric_algorithm,
            SymmetricAlgorithm::Aes256Gcm as i32
        );
        response.selected_symmetric_algorithm = 2;
        assert!(matches!(
            phone
                .verify_response(&response, &started.client_x25519_public_key)
                .unwrap_err(),
            ProtocolError::UnsupportedAlgorithm
        ));

        response.selected_symmetric_algorithm = SymmetricAlgorithm::Unspecified as i32;
        assert!(matches!(
            phone
                .verify_response(&response, &started.client_x25519_public_key)
                .unwrap_err(),
            ProtocolError::UnsupportedAlgorithm
        ));
    }

    // --- 5. Aborts --------------------------------------------------------

    #[test]
    fn authenticated_abort_round_trips() {
        let (desktop, phone) = established();

        let desktop_abort = desktop
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();
        assert_eq!(
            desktop_abort.reason,
            PairingAbortReason::UserRejectedSas as i32
        );
        assert_eq!(desktop_abort.auth_tag.len(), 32);
        assert!(phone.verify_abort(&desktop_abort).unwrap());

        let phone_abort = phone.create_abort(PairingAbortReason::KeyMismatch).unwrap();
        assert_eq!(phone_abort.reason, PairingAbortReason::KeyMismatch as i32);
        assert_eq!(phone_abort.auth_tag.len(), 32);
        assert!(desktop.verify_abort(&phone_abort).unwrap());
    }

    #[test]
    fn abort_tag_is_bound_to_the_key_direction() {
        let (desktop, phone) = established();
        // A phone-built abort is tagged with K_s2c and must not verify on the phone
        // (which checks K_c2s), even though both were built from the same Z and H.
        let phone_abort = phone
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();
        assert!(matches!(
            phone.verify_abort(&phone_abort).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
        assert!(desktop.verify_abort(&phone_abort).unwrap());
    }

    #[test]
    fn tampered_abort_tag_is_rejected() {
        let (desktop, phone) = established();
        let mut abort = desktop
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();
        abort.auth_tag[0] ^= 0xff;
        assert!(matches!(
            phone.verify_abort(&abort).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
    }

    #[test]
    fn abort_reason_must_match_the_tag() {
        let (desktop, phone) = established();
        let mut abort = desktop
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();
        abort.reason = PairingAbortReason::SessionExpired as i32;
        assert!(matches!(
            phone.verify_abort(&abort).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
    }

    #[test]
    fn tagless_abort_before_keys_is_unauthenticated() {
        let (desktop, _started) = start_desktop();
        let phone = ServerPairingSession::new([0x07; 16], phone_identity(), "pixel").unwrap();

        let untagged = PairingAbort {
            reason: PairingAbortReason::SessionExpired as i32,
            auth_tag: Vec::new(),
        };
        assert!(!desktop.verify_abort(&untagged).unwrap());
        assert!(!phone.verify_abort(&untagged).unwrap());

        // A tag before any key exists cannot be checked and must not be trusted.
        let tagged = PairingAbort {
            reason: PairingAbortReason::SessionExpired as i32,
            auth_tag: vec![0u8; 32],
        };
        assert!(matches!(
            desktop.verify_abort(&tagged).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
        assert!(matches!(
            phone.verify_abort(&tagged).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
    }

    #[test]
    fn tagless_abort_after_keys_is_rejected() {
        let (desktop, phone) = established();
        let untagged = PairingAbort {
            reason: PairingAbortReason::UserRejectedSas as i32,
            auth_tag: Vec::new(),
        };
        assert!(matches!(
            desktop.verify_abort(&untagged).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
        assert!(matches!(
            phone.verify_abort(&untagged).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
    }

    // --- 6. Frame codec ---------------------------------------------------

    #[test]
    fn pairing_packet_round_trips_every_variant() {
        let session_id = [0x5Au8; PAIRING_SESSION_ID_LEN];
        let messages = vec![
            pairing_packet::Msg::Init(PairingInit {
                server_x25519_public_key: vec![1u8; 32],
                server_ed25519_public_key: vec![2u8; 32],
                server_device_name: "pixel".to_string(),
                supported_symmetric_algorithms: vec![SymmetricAlgorithm::Aes256Gcm as i32],
                supported_hash_algorithms: vec![HashAlgorithm::Sha256 as i32],
                supported_signature_algorithms: vec![SignatureAlgorithm::Ed25519 as i32],
            }),
            pairing_packet::Msg::Response(PairingResponse {
                client_x25519_public_key: vec![3u8; 32],
                client_ed25519_public_key: vec![4u8; 32],
                client_device_name: "thinkpad".to_string(),
                selected_symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
                selected_hash_algorithm: HashAlgorithm::Sha256 as i32,
                selected_signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
                client_signature: vec![5u8; 64],
            }),
            pairing_packet::Msg::ConfirmClient(PairingConfirmClient {
                encrypted_payload: vec![6u8; 44],
            }),
            pairing_packet::Msg::ConfirmServer(PairingConfirmServer {
                encrypted_complete: vec![7u8; 92],
            }),
            pairing_packet::Msg::Abort(PairingAbort {
                reason: PairingAbortReason::ProtocolError as i32,
                auth_tag: vec![8u8; 32],
            }),
            pairing_packet::Msg::Keepalive(PairingKeepalive {}),
        ];

        for msg in messages {
            let packet = PairingPacket {
                version: PROTOCOL_VERSION_V2,
                session_id: session_id.to_vec(),
                msg: Some(msg),
            };
            let encoded = encode_pairing_packet(&packet).unwrap();
            let decoded = decode_pairing_packet(&encoded).unwrap();
            assert_eq!(decoded, packet);
            assert_eq!(pairing_session_id(&decoded).unwrap(), session_id);
        }
    }

    #[test]
    fn pairing_packet_rejects_wrong_version() {
        let packet = PairingPacket {
            version: 1,
            session_id: vec![0u8; PAIRING_SESSION_ID_LEN],
            msg: Some(pairing_packet::Msg::Keepalive(PairingKeepalive {})),
        };
        assert!(matches!(
            encode_pairing_packet(&packet).unwrap_err(),
            ProtocolError::InvalidMessageFormat
        ));

        // Also on the wire, where encode() was bypassed.
        let raw = packet.encode_to_vec();
        assert!(matches!(
            decode_pairing_packet(&raw).unwrap_err(),
            ProtocolError::InvalidMessageFormat
        ));
        assert!(matches!(
            pairing_session_id(&packet).unwrap_err(),
            ProtocolError::InvalidMessageFormat
        ));
    }

    #[test]
    fn pairing_packet_rejects_wrong_session_id_length() {
        for sid_len in [PAIRING_SESSION_ID_LEN - 1, PAIRING_SESSION_ID_LEN + 1] {
            let packet = PairingPacket {
                version: PROTOCOL_VERSION_V2,
                session_id: vec![0u8; sid_len],
                msg: Some(pairing_packet::Msg::Keepalive(PairingKeepalive {})),
            };
            assert!(
                matches!(
                    encode_pairing_packet(&packet).unwrap_err(),
                    ProtocolError::InvalidMessageFormat
                ),
                "encode must reject a {sid_len}-byte session id"
            );
            let raw = packet.encode_to_vec();
            assert!(
                matches!(
                    decode_pairing_packet(&raw).unwrap_err(),
                    ProtocolError::InvalidMessageFormat
                ),
                "decode must reject a {sid_len}-byte session id"
            );
            assert!(
                matches!(
                    pairing_session_id(&packet).unwrap_err(),
                    ProtocolError::InvalidMessageFormat
                ),
                "pairing_session_id must reject a {sid_len}-byte session id"
            );
        }
    }

    // --- 7. Transcript sensitivity ---------------------------------------

    #[test]
    fn transcript_hash_binds_every_negotiated_field() {
        let session_id = [0x5Au8; PAIRING_SESSION_ID_LEN];

        // Baseline pairing on a desktop whose key material can be reproduced.
        let mut desktop = seeded_desktop(session_id);
        let qr_pk = desktop.client_x25519_public_key();
        // ...and a phone whose ephemeral `X_S` is fixed too: `Z`, `H` and the SAS are
        // then a fixed property of this fixture rather than a per-run draw, so the
        // "the SAS must change" assertions below cannot flake on a 1-in-10^6
        // SAS collision.
        let mut phone = seeded_phone(session_id);
        let init = phone.create_init().unwrap();
        let response = desktop.handle_init(&init).unwrap().clone();
        phone.verify_response(&response, &qr_pk).unwrap();

        let baseline_hash = *phone.transcript_hash().unwrap();
        assert_eq!(desktop.transcript_hash(), phone.transcript_hash());
        let baseline_sas = phone.sas().unwrap().to_string();
        assert_eq!(desktop.sas().unwrap(), baseline_sas);

        let mut renamed = init.clone();
        renamed.server_device_name = "pixel-two".to_string();

        let mut key_swapped = init.clone();
        key_swapped.server_ed25519_public_key = Ed25519KeyPair::from_signing_key_bytes(&[0xC3; 32])
            .unwrap()
            .verifying_key_bytes()
            .to_vec();

        let mut reordered = init.clone();
        // Same algorithm, duplicated: the *list* enters H verbatim (length and
        // order included), so a peer that advertises it twice hashes differently
        // even though the negotiated pair is identical.
        reordered.supported_hash_algorithms =
            vec![HashAlgorithm::Sha256 as i32, HashAlgorithm::Sha256 as i32];

        for (field, mutated_init) in [
            ("server_device_name", renamed),
            ("server_ed25519_public_key", key_swapped),
            ("supported_hash_algorithms", reordered),
        ] {
            // Same x_C/Ed_C/sid: only the mutated field differs.
            let mut fresh = seeded_desktop(session_id);
            assert_eq!(fresh.client_x25519_public_key(), qr_pk);
            let mutated_response = fresh.handle_init(&mutated_init).unwrap().clone();

            assert_ne!(
                fresh.transcript_hash().unwrap(),
                &baseline_hash,
                "mutating {field} must change H"
            );
            assert_ne!(
                fresh.sas().unwrap(),
                baseline_sas.as_str(),
                "mutating {field} must change the SAS"
            );

            // The phone rebuilds H from its own view, so the desktop's signature
            // over the mutated transcript no longer verifies. A verified session
            // refuses a second `verify_response`, so each attempt runs on a fresh
            // phone with the same fixed key material (and therefore the same view).
            let mut fresh_phone = seeded_phone(session_id);
            fresh_phone.create_init().unwrap();
            assert!(
                matches!(
                    fresh_phone
                        .verify_response(&mutated_response, &qr_pk)
                        .unwrap_err(),
                    ProtocolError::InvalidSignature
                ),
                "mutating {field} must break the response signature check"
            );
            // ... and the failed attempt must have cached nothing.
            assert!(fresh_phone.transcript_hash().is_none());
            assert!(fresh_phone.sas().is_none());
            assert!(fresh_phone.keys.is_none());
        }

        // The genuine pairing still holds the baseline values: the mutated
        // attempts above never touched it.
        assert_eq!(phone.transcript_hash().unwrap(), &baseline_hash);
        assert_eq!(phone.sas().unwrap(), baseline_sas.as_str());
    }

    // --- 8. Client-wide algorithm pinning --------------------------------

    /// Pair a desktop started with `pinned` against a phone that advertises
    /// `advertised`, and return the desktop's negotiation result.
    fn pair_with_pins(
        pinned: Option<PinnedAlgorithms>,
        advertised_symmetric: Vec<SymmetricAlgorithm>,
        advertised_hash: Vec<HashAlgorithm>,
    ) -> (
        Result<(ClientPairingState, ServerPairingSession), ProtocolError>,
        [u8; 32],
    ) {
        // Fixed key material: the negotiation outcome, not the keys, is the subject.
        let session_id = [0x7Eu8; PAIRING_SESSION_ID_LEN];
        let (mut desktop, started) = ClientPairingState::build(
            session_id,
            X25519KeyPair::from_secret_bytes([0x11; 32]),
            desktop_identity(),
            "thinkpad",
            PairingEndpoint::default(),
            pinned,
        );
        let mut phone = ServerPairingSession::new(started.session_id, phone_identity(), "pixel")
            .expect("phone session");
        phone.advertised_symmetric = advertised_symmetric;
        phone.advertised_hash = advertised_hash;
        let init = phone.create_init().expect("init");
        let response = match desktop.handle_init(&init) {
            Ok(response) => response.clone(),
            Err(err) => return (Err(err), started.client_x25519_public_key),
        };
        let outcome = phone
            .verify_response(&response, &started.client_x25519_public_key)
            .map(|()| (desktop, phone));
        (outcome, started.client_x25519_public_key)
    }

    /// A pinned suite is selected, reported in the `PairingResponse`, and the whole
    /// pairing completes under it.
    /// The defect this catches: negotiation ignoring the pins and reporting a
    /// different pair than the one the client-wide `CSK` is committed to, which
    /// would silently produce a pairing whose broadcast every already-paired
    /// server fails to decrypt. (With one active primitive per slot the pinned
    /// pair and the baseline are the same values, so what is exercised here is
    /// that the pin path runs at all and reports itself, not that it outvotes a
    /// baseline.)
    #[test]
    fn a_pinned_suite_is_selected_and_the_pairing_completes() {
        let pinned = PinnedAlgorithms {
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            hash_algorithm: HashAlgorithm::Sha256,
        };
        let (outcome, _qr_pk) = pair_with_pins(
            Some(pinned),
            vec![SymmetricAlgorithm::Aes256Gcm],
            vec![HashAlgorithm::Sha256],
        );
        let (desktop, mut phone) = outcome.expect("a pinned algorithm the peer offers must pair");

        let expected = NegotiatedAlgorithms {
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::Ed25519,
        };
        assert_eq!(desktop.negotiated(), Some(expected));
        assert_eq!(phone.negotiated(), Some(expected));
        assert_eq!(
            desktop.response().unwrap().selected_symmetric_algorithm,
            SymmetricAlgorithm::Aes256Gcm as i32
        );
        assert_eq!(
            desktop.response().unwrap().selected_hash_algorithm,
            HashAlgorithm::Sha256 as i32
        );

        // The whole pairing still completes under the pinned algorithm.
        let csk = [0x42u8; 32];
        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        assert_eq!(
            phone.process_confirm_client(&confirm_client).unwrap().csk,
            csk.to_vec()
        );
        let confirm_server = phone.create_confirm_server(&csk).unwrap();
        desktop
            .verify_confirm_server(&confirm_server, &csk)
            .unwrap();
        assert_eq!(desktop.sas(), phone.sas());
    }

    /// A peer that does not offer the pinned suite cannot be paired, and the
    /// refusal must not leave a half-established session behind.
    /// The defect this catches: falling back to a negotiated algorithm the CSK is
    /// not using (the "pair a second phone at the wrong algorithm" bug).
    #[test]
    fn pinned_symmetric_algorithm_absent_from_the_peer_is_refused() {
        // The peer's hash list is empty, so the pinned hash cannot be honoured.
        let (outcome, _qr_pk) = pair_with_pins(
            Some(PinnedAlgorithms {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                hash_algorithm: HashAlgorithm::Sha256,
            }),
            vec![SymmetricAlgorithm::Aes256Gcm],
            vec![],
        );
        match outcome {
            Err(ProtocolError::UnsupportedAlgorithm) => {}
            Err(other) => panic!("expected UnsupportedAlgorithm, got {other:?}"),
            Ok(_) => panic!("a peer without the pinned hash algorithm must be refused"),
        }

        // Same for the symmetric algorithm: an empty list offers nothing.
        let (outcome, _qr_pk) = pair_with_pins(
            Some(PinnedAlgorithms {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                hash_algorithm: HashAlgorithm::Sha256,
            }),
            vec![],
            vec![HashAlgorithm::Sha256],
        );
        match outcome {
            Err(ProtocolError::UnsupportedAlgorithm) => {}
            Err(other) => panic!("expected UnsupportedAlgorithm, got {other:?}"),
            Ok(_) => panic!("a peer without the pinned symmetric algorithm must be refused"),
        }

        // The refusal leaves the desktop state untouched: no response, no keys.
        let session_id = [0x7Fu8; PAIRING_SESSION_ID_LEN];
        let (mut desktop, _started) = ClientPairingState::build(
            session_id,
            X25519KeyPair::from_secret_bytes([0x11; 32]),
            desktop_identity(),
            "thinkpad",
            PairingEndpoint::default(),
            Some(PinnedAlgorithms {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                hash_algorithm: HashAlgorithm::Sha256,
            }),
        );
        // The peer's hash list carries only the reserved tag: nothing the pin can
        // be honoured with.
        let init = init_with_algorithms(vec![1], vec![2], vec![1]);
        assert!(matches!(
            desktop.handle_init(&init).unwrap_err(),
            ProtocolError::UnsupportedAlgorithm
        ));
        assert!(desktop.response().is_none());
        assert!(desktop.negotiated().is_none());
        assert!(desktop.keys.is_none());
    }

    /// Without pins, negotiation selects the suite the peer offers.
    /// (With a single active primitive per slot there is no second value for the
    /// peer's list order to steer negotiation towards; what remains verified here
    /// is that the unpinned path still negotiates and reports the triple.)
    #[test]
    fn unpinned_negotiation_selects_the_offered_suite() {
        let (outcome, _qr_pk) = pair_with_pins(
            None,
            vec![SymmetricAlgorithm::Aes256Gcm],
            vec![HashAlgorithm::Sha256],
        );
        let (desktop, phone) = outcome.unwrap();
        let expected = NegotiatedAlgorithms {
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::Ed25519,
        };
        assert_eq!(desktop.negotiated(), Some(expected));
        assert_eq!(phone.negotiated(), Some(expected));
    }

    // --- 9. Key lifetime -------------------------------------------------

    /// After `conclude`, both state machines must refuse to touch the retained
    /// session material: the SAS and `H` are gone and every keyed operation fails.
    /// The defect this catches: `conclude` that only drops the SAS (leaving
    /// `K_c2s`/`K_s2c` usable, so a concluded session can still emit or accept
    /// confirm messages) or one that clears `negotiated()` as well.
    #[test]
    fn conclude_drops_keys_and_transcript_but_keeps_the_negotiation() {
        let (mut desktop, mut phone) = established();
        let expected = desktop.negotiated().unwrap();
        let csk = [0x42u8; 32];

        // A genuine confirm round-trips before concluding, so the errors below are
        // caused by `conclude` and not by a broken fixture.
        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        phone.process_confirm_client(&confirm_client).unwrap();
        let confirm_server = phone.create_confirm_server(&csk).unwrap();
        desktop
            .verify_confirm_server(&confirm_server, &csk)
            .unwrap();

        desktop.conclude();
        phone.conclude();

        // Negotiated algorithms survive (they are persisted metadata, not key material).
        assert_eq!(desktop.negotiated(), Some(expected));
        assert_eq!(phone.negotiated(), Some(expected));
        // Keys and transcript hash do not.
        assert!(desktop.sas().is_none());
        assert!(phone.sas().is_none());
        assert!(desktop.transcript_hash().is_none());
        assert!(phone.transcript_hash().is_none());

        assert!(matches!(
            desktop.create_confirm_client(&csk, "luca", "thinkpad"),
            Err(ProtocolError::SessionConcluded)
        ));
        // The key-dependent readers report the conclusion, not a missing field:
        // the keys are gone because the caller ended the session, and the FFI layer
        // must not turn that into a security failure.
        assert!(matches!(
            desktop.verify_confirm_server(&confirm_server, &csk),
            Err(ProtocolError::SessionConcluded)
        ));
        assert!(matches!(
            phone.create_confirm_server(&csk),
            Err(ProtocolError::SessionConcluded)
        ));
        assert!(matches!(
            phone.process_confirm_client(&confirm_client),
            Err(ProtocolError::SessionConcluded)
        ));
    }

    /// Sending the completion proof does not end the session: the responder keeps
    /// answering retransmissions of the provisioning frame, while every step the
    /// handshake has already passed is refused.
    /// The defect this catches: `create_confirm_server` concluding the session, so a
    /// lost confirmation burst is answered with
    /// `MissingField("pairing_session_keys")` — nothing on the wire — and the desktop
    /// times out against a phone that has already paired.
    #[test]
    fn confirm_server_keeps_answering_retransmissions() {
        let (desktop, mut phone, response, qr_pk) = exchange();
        phone.verify_response(&response, &qr_pk).unwrap();
        let csk = [0x42u8; 32];

        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        phone.create_confirm_server(&csk).unwrap();

        // The desktop retransmits the same frame until the proof reaches it.
        let first = phone.process_confirm_client(&confirm_client).unwrap();
        let second = phone.process_confirm_client(&confirm_client).unwrap();
        assert_eq!(first.csk, csk.to_vec());
        assert_eq!(
            first.encode_to_vec(),
            second.encode_to_vec(),
            "a retransmitted provisioning frame must be answered with the same payload"
        );

        // Past steps stay refused, and as a state error: the handshake moved on, it
        // did not break.
        assert!(matches!(
            phone.create_confirm_server(&csk),
            Err(ProtocolError::ConfirmationAlreadySent)
        ));
        assert!(matches!(
            phone.create_init(),
            Err(ProtocolError::ConfirmationAlreadySent)
        ));
        assert!(matches!(
            phone.verify_response(&response, &qr_pk),
            Err(ProtocolError::InvalidMessageFormat)
        ));
    }

    /// A concluded session reports the conclusion on both sides, not the fields
    /// `conclude` dropped.
    /// The defect this catches: `SessionConcluded` on the create methods but
    /// `MissingField("pairing_session_keys")` on `verify_confirm_server` /
    /// `process_confirm_client`, which the FFI layer maps to `TapauthError::Security`
    /// — a legitimate post-conclude call reported to Kotlin as an attack.
    #[test]
    fn concluded_sessions_report_the_conclusion_not_the_missing_keys() {
        let (mut desktop, mut phone) = established();
        let csk = [0x42u8; 32];
        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();

        // The phone sent its proof, then concluded: the provisioning retransmission
        // finds a concluded session, not a session without keys.
        let confirm_server = phone.create_confirm_server(&csk).unwrap();
        phone.conclude();
        assert!(matches!(
            phone.process_confirm_client(&confirm_client),
            Err(ProtocolError::SessionConcluded)
        ));

        desktop.conclude();
        assert!(matches!(
            desktop.verify_confirm_server(&confirm_server, &csk),
            Err(ProtocolError::SessionConcluded)
        ));
    }

    /// `conclude` is terminal: every protocol entry point of both state machines
    /// refuses a call afterwards instead of answering from a half-dropped state.
    /// The defect this catches: a session that stays usable after `conclude`, so a
    /// retransmitted `PairingInit` or a second completion proof is accepted after
    /// the keys (and the ephemeral secret) are gone.
    #[test]
    fn post_conclude_rejects_every_protocol_entry_point() {
        let (mut desktop, started) = start_desktop();
        let mut phone =
            ServerPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        let init = phone.create_init().unwrap();
        let response = desktop.handle_init(&init).unwrap().clone();
        phone
            .verify_response(&response, &started.client_x25519_public_key)
            .unwrap();

        let csk = [0x42u8; 32];
        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        let confirm_server = phone.create_confirm_server(&csk).unwrap();
        desktop
            .verify_confirm_server(&confirm_server, &csk)
            .unwrap();
        let abort = desktop
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();

        desktop.conclude();
        phone.conclude();

        // Desktop: the state-machine entries report the terminal state ...
        assert!(matches!(
            desktop.handle_init(&init).unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            desktop
                .create_confirm_client(&csk, "luca", "thinkpad")
                .unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            desktop
                .create_abort(PairingAbortReason::UserRejectedSas)
                .unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            desktop.verify_abort(&abort).unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        // ... and the key-dependent reader reports the concluded session, exactly
        // like the state-machine entries (not the keys it dropped).
        assert!(matches!(
            desktop
                .verify_confirm_server(&confirm_server, &csk)
                .unwrap_err(),
            ProtocolError::SessionConcluded
        ));

        // Phone: same rule on every entry point.
        assert!(matches!(
            phone.create_init().unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            phone
                .verify_response(&response, &started.client_x25519_public_key)
                .unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            phone.create_confirm_server(&csk).unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            phone
                .create_abort(PairingAbortReason::UserRejectedSas)
                .unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            phone.verify_abort(&abort).unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        assert!(matches!(
            phone.process_confirm_client(&confirm_client).unwrap_err(),
            ProtocolError::SessionConcluded
        ));
        // The keepalive carries no key material, and is still refused: the path it
        // would keep open could only deliver a retransmission nothing can answer.
        assert!(matches!(
            phone.create_keepalive().unwrap_err(),
            ProtocolError::SessionConcluded
        ));

        // Metadata survives: only key material and protocol operations are gone.
        assert_eq!(desktop.session_id(), &started.session_id);
        assert_eq!(
            desktop.client_x25519_public_key(),
            started.client_x25519_public_key
        );
        assert_eq!(desktop.negotiated(), phone.negotiated());
        assert!(desktop.transcript_hash().is_none());
        assert!(phone.transcript_hash().is_none());
    }

    /// The phone verifies exactly one response, and only after it built the
    /// `PairingInit` whose transcript that response answers.
    /// The defect this catches: a second `verify_response` re-deriving `H` and the
    /// directional keys over an already-established session (a replay of an old
    /// response replacing the live SAS), or a response verified against a transcript
    /// the phone never advertised.
    #[test]
    fn a_second_verify_response_is_rejected() {
        let (desktop, mut phone, response, qr_pk) = exchange();
        let session_id = *phone.session_id();
        phone.verify_response(&response, &qr_pk).unwrap();
        let hash = *phone.transcript_hash().unwrap();
        let sas = phone.sas().unwrap().to_string();

        assert!(matches!(
            phone.verify_response(&response, &qr_pk).unwrap_err(),
            ProtocolError::InvalidMessageFormat
        ));

        // The first verification stands: the second call neither re-derived the
        // keys nor cleared them.
        assert_eq!(phone.transcript_hash(), Some(&hash));
        assert_eq!(phone.sas(), Some(sas.as_str()));
        assert_eq!(phone.negotiated(), desktop.negotiated());

        // A phone that never sent its `PairingInit` has no transcript to verify
        // against, so it refuses the response instead of inventing one.
        let mut uninitialised =
            ServerPairingSession::new(session_id, phone_identity(), "pixel").unwrap();
        assert!(matches!(
            uninitialised
                .verify_response(&response, &qr_pk)
                .unwrap_err(),
            ProtocolError::InvalidMessageFormat
        ));
        assert!(uninitialised.keys.is_none());
        assert!(uninitialised.sas().is_none());
    }

    /// Once the desktop concluded after the phone's completion proof, it cannot
    /// build another provisioning payload — while the phone that sent the proof is
    /// still live (sending it is not a conclusion; see
    /// `confirm_server_keeps_answering_retransmissions`).
    /// The defect this catches: a concluded desktop that still writes a
    /// `PairingConfirmClient` (provisioning the CSK again) because `conclude` only
    /// cleared the SAS.
    #[test]
    fn create_confirm_server_then_create_confirm_client_is_rejected() {
        let (mut desktop, mut phone) = established();
        let csk = [0x42u8; 32];

        let confirm_server = phone.create_confirm_server(&csk).unwrap();
        desktop
            .verify_confirm_server(&confirm_server, &csk)
            .unwrap();
        desktop.conclude();

        assert!(matches!(
            desktop
                .create_confirm_client(&csk, "luca", "thinkpad")
                .unwrap_err(),
            ProtocolError::SessionConcluded
        ));
    }

    /// The ephemeral X25519 secret is taken as soon as it has derived the session
    /// keys, and on `conclude` even if no keys were ever derived. The public half
    /// stays answerable so the QR code and the retry path keep working.
    /// The defect this catches: a session that keeps `x_C`/`x_S` alive for its whole
    /// lifetime (the secret then outlives the handshake it belongs to).
    #[test]
    fn the_ephemeral_keypair_is_taken_on_derivation_and_on_conclude() {
        let (mut desktop, started) = start_desktop();
        assert!(
            desktop.ephemeral_keypair_present(),
            "x_C exists before the handshake"
        );
        let mut phone =
            ServerPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        assert!(
            phone.ephemeral_keypair_present(),
            "x_S exists before the handshake"
        );

        let init = phone.create_init().unwrap();
        let response = desktop.handle_init(&init).unwrap().clone();
        assert!(
            !desktop.ephemeral_keypair_present(),
            "x_C is taken once the keys are derived"
        );
        assert_eq!(
            desktop.client_x25519_public_key(),
            started.client_x25519_public_key,
            "the public half stays answerable after the secret is taken"
        );
        // A retried init is still answered from the cache.
        assert_eq!(desktop.handle_init(&init).unwrap(), &response);

        phone
            .verify_response(&response, &started.client_x25519_public_key)
            .unwrap();
        assert!(
            !phone.ephemeral_keypair_present(),
            "x_S is taken once the keys are derived"
        );

        // A session that never derived keys drops its secret at `conclude`, and
        // concluding twice is a no-op.
        let (mut unused_desktop, _started) = start_desktop();
        unused_desktop.conclude();
        assert!(!unused_desktop.ephemeral_keypair_present());
        unused_desktop.conclude();
        assert!(!unused_desktop.ephemeral_keypair_present());

        let mut unused_phone =
            ServerPairingSession::new([0x33u8; PAIRING_SESSION_ID_LEN], phone_identity(), "pixel")
                .unwrap();
        assert!(unused_phone.ephemeral_keypair_present());
        unused_phone.conclude();
        assert!(!unused_phone.ephemeral_keypair_present());
    }

    // --- Misc -------------------------------------------------------------

    #[test]
    fn handle_init_is_idempotent_for_identical_inits() {
        let mut desktop = seeded_desktop([0x5Au8; PAIRING_SESSION_ID_LEN]);
        let mut phone =
            ServerPairingSession::new([0x5Au8; PAIRING_SESSION_ID_LEN], phone_identity(), "pixel")
                .unwrap();
        let init = phone.create_init().unwrap();

        let first = desktop.handle_init(&init).unwrap().clone();
        let cached = desktop.response().unwrap().clone();
        assert_eq!(first, cached);
        // A UDP retry of the very same init gets the cached response, not a new one.
        let retried = desktop.handle_init(&init).unwrap().clone();
        assert_eq!(retried, first);
        assert_eq!(retried.client_signature, first.client_signature);

        // A different init on an established session is refused.
        let mut conflicting = init.clone();
        conflicting.server_device_name = "pixel-two".to_string();
        assert!(matches!(
            desktop.handle_init(&conflicting).unwrap_err(),
            ProtocolError::InvalidMessageFormat
        ));
    }

    #[test]
    fn device_names_are_truncated_on_a_char_boundary() {
        // Two-byte characters: 64 bytes land exactly on a boundary.
        let two_byte = "é".repeat(40);
        let truncated = truncate_utf8(&two_byte, PAIRING_DEVICE_NAME_MAX_BYTES);
        assert_eq!(truncated.len(), 64);
        assert_eq!(truncated.chars().count(), 32);

        // Three-byte characters: byte 64 splits a character, so the cut backs off
        // to 63. The defect this catches: slicing at the byte limit without
        // walking back to a char boundary (panics, or silently drops the name).
        let long_name = "€".repeat(40);
        assert_eq!(long_name.len(), 120);
        let truncated = truncate_utf8(&long_name, PAIRING_DEVICE_NAME_MAX_BYTES);
        assert_eq!(truncated.len(), 63);
        assert_eq!(truncated.chars().count(), 21);
        assert!(long_name.starts_with(&truncated));

        let (mut desktop, started) =
            ClientPairingState::start(desktop_identity(), &long_name, 36692, None, None, None)
                .unwrap();
        assert_eq!(desktop.client_device_name.len(), 63);

        let mut phone =
            ServerPairingSession::new(started.session_id, phone_identity(), &long_name).unwrap();
        assert_eq!(phone.server_device_name.len(), 63);
        let init = phone.create_init().unwrap();
        assert_eq!(init.server_device_name.len(), 63);
        // Truncating identically on both sides keeps the transcript consistent.
        desktop.handle_init(&init).unwrap();
        phone
            .verify_response(
                desktop.response().unwrap(),
                &desktop.client_x25519_public_key(),
            )
            .unwrap();
        assert_eq!(desktop.sas(), phone.sas());
    }

    // --- 11. Whole handshake over the wire codec --------------------------

    /// The full handshake with **every** frame serialized by
    /// [`encode_pairing_packet`] and read back by [`decode_pairing_packet`], as a UDP
    /// datagram or BLE value would be.
    ///
    /// The defect this catches: a state machine that only agrees with itself when the
    /// caller passes structs straight through — a field that changes meaning across the
    /// protobuf encoding (an algorithm list order, an enum value, a `bytes` field) makes
    /// the two sides derive different `H`/SAS over the wire while an in-process test
    /// still passes.
    #[test]
    fn full_pairing_round_trips_every_frame_through_the_wire_codec() {
        fn wire(session_id: &[u8; PAIRING_SESSION_ID_LEN], msg: pairing_packet::Msg) -> Vec<u8> {
            encode_pairing_packet(&PairingPacket {
                version: PROTOCOL_VERSION_V2,
                session_id: session_id.to_vec(),
                msg: Some(msg),
            })
            .unwrap()
        }

        fn read(bytes: &[u8], session_id: &[u8; PAIRING_SESSION_ID_LEN]) -> pairing_packet::Msg {
            let packet = decode_pairing_packet(bytes).unwrap();
            assert_eq!(packet.version, PROTOCOL_VERSION_V2);
            assert_eq!(packet.session_id.as_slice(), session_id.as_slice());
            assert!(packet.msg.is_some());
            packet.msg.unwrap()
        }

        let (mut desktop, started) = start_desktop();
        let mut phone =
            ServerPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();

        // 1. Phone → desktop: PairingInit.
        let init_bytes = wire(
            &started.session_id,
            pairing_packet::Msg::Init(phone.create_init().unwrap()),
        );
        let init = match read(&init_bytes, &started.session_id) {
            pairing_packet::Msg::Init(init) => init,
            other => panic!("expected PairingInit, got {other:?}"),
        };
        assert_eq!(init.server_device_name, "pixel");

        // 2. Desktop → phone: PairingResponse, carrying Ed_C (not X_C, not Ed_S).
        let response_bytes = wire(
            &started.session_id,
            pairing_packet::Msg::Response(desktop.handle_init(&init).unwrap().clone()),
        );
        let response = match read(&response_bytes, &started.session_id) {
            pairing_packet::Msg::Response(response) => response,
            other => panic!("expected PairingResponse, got {other:?}"),
        };
        assert_eq!(
            response.client_ed25519_public_key,
            desktop_identity().verifying_key_bytes().to_vec()
        );
        assert_eq!(
            response.client_x25519_public_key,
            started.client_x25519_public_key.to_vec()
        );

        // The QR pin the phone scanned still matches after the round trip.
        phone
            .verify_response(&response, &started.client_x25519_public_key)
            .unwrap();
        assert_sas_shape(phone.sas().unwrap());
        assert_eq!(desktop.sas(), phone.sas());
        assert_eq!(desktop.transcript_hash(), phone.transcript_hash());
        assert_eq!(desktop.negotiated(), phone.negotiated());

        // 3. Desktop → phone: the provisioning payload, CSK included.
        let csk = [0x42u8; 32];
        let confirm_client_bytes = wire(
            &started.session_id,
            pairing_packet::Msg::ConfirmClient(
                desktop
                    .create_confirm_client(&csk, "luca", "thinkpad")
                    .unwrap(),
            ),
        );
        let provision = match read(&confirm_client_bytes, &started.session_id) {
            pairing_packet::Msg::ConfirmClient(confirm) => {
                phone.process_confirm_client(&confirm).unwrap()
            }
            other => panic!("expected PairingConfirmClient, got {other:?}"),
        };
        assert_eq!(provision.csk, csk.to_vec());
        assert_eq!(provision.username, "luca");
        assert_eq!(provision.client_hostname, "thinkpad");

        // 4. A PairingKeepalive survives the wire with the session id intact.
        let keepalive_bytes = wire(
            &started.session_id,
            pairing_packet::Msg::Keepalive(PairingKeepalive {}),
        );
        assert_eq!(
            read(&keepalive_bytes, &started.session_id),
            pairing_packet::Msg::Keepalive(PairingKeepalive {})
        );

        // 5. Phone → desktop: the completion proof still verifies.
        let confirm_server_bytes = wire(
            &started.session_id,
            pairing_packet::Msg::ConfirmServer(phone.create_confirm_server(&csk).unwrap()),
        );
        let confirm_server = match read(&confirm_server_bytes, &started.session_id) {
            pairing_packet::Msg::ConfirmServer(confirm) => confirm,
            other => panic!("expected PairingConfirmServer, got {other:?}"),
        };
        desktop
            .verify_confirm_server(&confirm_server, &csk)
            .unwrap();
        assert!(matches!(
            desktop
                .verify_confirm_server(&confirm_server, &[0x43u8; 32])
                .unwrap_err(),
            ProtocolError::InvalidSignature
        ));

        // 6. Aborts, both directions, over the wire: each verifies with the peer's
        // directional key and fails with the key its own side uses.
        let phone_abort_bytes = wire(
            &started.session_id,
            pairing_packet::Msg::Abort(
                phone.create_abort(PairingAbortReason::KeyMismatch).unwrap(),
            ),
        );
        let phone_abort = match read(&phone_abort_bytes, &started.session_id) {
            pairing_packet::Msg::Abort(abort) => abort,
            other => panic!("expected PairingAbort, got {other:?}"),
        };
        assert_eq!(phone_abort.auth_tag.len(), 32);
        assert!(desktop.verify_abort(&phone_abort).unwrap());
        assert!(matches!(
            phone.verify_abort(&phone_abort).unwrap_err(),
            ProtocolError::InvalidSignature
        ));

        let desktop_abort_bytes = wire(
            &started.session_id,
            pairing_packet::Msg::Abort(
                desktop
                    .create_abort(PairingAbortReason::UserRejectedSas)
                    .unwrap(),
            ),
        );
        let desktop_abort = match read(&desktop_abort_bytes, &started.session_id) {
            pairing_packet::Msg::Abort(abort) => abort,
            other => panic!("expected PairingAbort, got {other:?}"),
        };
        assert!(phone.verify_abort(&desktop_abort).unwrap());
        assert!(matches!(
            desktop.verify_abort(&desktop_abort).unwrap_err(),
            ProtocolError::InvalidSignature
        ));
    }
}
