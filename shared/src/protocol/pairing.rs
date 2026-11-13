//! Unified UDP + BLE pairing state machines for protocol v2.
//!
//! Pairing provisions the desktop's long-term `CSK` onto a phone and binds both
//! devices' static Ed25519 identity keys together, over the same two transports
//! used for authentication (UDP and BLE). This module is the transport-agnostic
//! protocol half only: it encodes and decodes [`PairingPacket`] frames and runs
//! the handshake state machine. It owns no sockets, no threads, no timers and no
//! I/O — the caller (daemon) does the sending, retransmission and timeouts.
//!
//! ## Roles (and the naming oddity)
//!
//! TapAuth's terminology comes from authentication: the Linux desktop is the
//! protocol **Client** and the Android phone is the protocol **Server**. In the
//! v2 pairing messages the proto author kept that framing, so `PairingInit`
//! carries the *server*'s keys and `PairingResponse` the *client*'s.
//!
//! The two state machines are therefore named after the pairing messages they
//! drive, not after the transport role:
//!
//! * [`ServerPairingState`] — the **desktop**. Owns the ephemeral `x_C`/`X_C`
//!   advertised in the QR code, the static `Ed_C`, the session id, the cached
//!   `PairingResponse` and the negotiated keys. It answers `PairingInit`, decrypts
//!   the `PairingConfirmClient` provisioning payload and builds the
//!   `PairingConfirmServer` completion proof.
//! * [`ClientPairingSession`] — the **phone**. Owns the ephemeral `x_S`/`X_S`
//!   and the static `Ed_S` (`PairingInit`). It verifies the QR commitment, the
//!   desktop's transcript signature and the completion proof, and shows the SAS.
//!
//! ## Flow
//!
//! 1. Desktop [`ServerPairingState::start`] → `sid` (16 B), `X_C`, `pairing_adv_id`
//!    for the BLE advertisement and the `tapauth://pair?v=2&...` QR URL.
//! 2. Phone [`ClientPairingSession::new`] + [`ClientPairingSession::create_init`]
//!    → `PairingInit` (`X_S`, `Ed_S`, name, supported algorithm lists).
//! 3. Desktop [`ServerPairingState::handle_init`] → negotiates, computes the
//!    transcript hash `H`, derives `K_c2s`/`K_s2c`/SAS and returns `PairingResponse`
//!    signed with `Ed_C` over `"tapauth-pair-client-sig-v2" || H`.
//! 4. Phone [`ClientPairingSession::verify_response`] → constant-time QR key
//!    comparison, algorithm check, `Ed_C` signature check, key derivation. Both
//!    users now compare the SAS out of band.
//! 5. Desktop [`ServerPairingState::process_confirm_client`] decrypts the
//!    provisioned `{csk, username, client_hostname}` under `K_c2s`; the phone built
//!    it with [`ClientPairingSession::create_confirm_client`].
//! 6. Desktop encrypts its completion proof under `K_s2c`
//!    ([`ServerPairingState::create_confirm_server`]), the phone verifies it
//!    ([`ClientPairingSession::verify_confirm_server`]).
//!
//! Every handshake field (both ephemeral keys, both identity keys, both device
//! names, the advertised algorithm lists and the selected algorithms) enters `H`,
//! which salts the HKDF that derives the directional keys and the SAS. Tampering
//! with any of them changes the SAS visibly or breaks a signature.
//!
//! ## Who signs what
//!
//! * `PairingResponse.client_signature` — `Ed_C`, the **desktop's static key**,
//!   verified by the phone.
//! * `PairingCompletePayload.server_signature` — also `Ed_C`, verified by the
//!   phone. The field name is historical: the proto calls the phone the "server",
//!   but the completion proof travels desktop → phone in this implementation (see
//!   the direction note on [`ServerPairingState::create_confirm_server`]).
//!
//! ## Direction note (deliberate departure from the prose specs)
//!
//! `proto/auth_protocol.proto` and `initial-key-exchange.md` Step 6 describe
//! `PairingConfirmServer` as *phone → desktop*, signed by `Ed_S` and verified by
//! the desktop. This implementation follows the integration contract the daemon
//! consumes instead: the **desktop** builds the proof with its own `Ed_C` and the
//! **phone** verifies it. The wire message, its AAD and its context string are
//! unchanged — only the direction and the signing key differ.
//!
//! ## Caller responsibilities
//!
//! * Session filtering: drop any frame whose `session_id` differs from
//!   [`ServerPairingState::session_id`] / [`ClientPairingSession::session_id`]
//!   before calling into this module ([`pairing_session_id`] extracts it).
//! * Retries: `PairingInit` retries must be answered from
//!   [`ServerPairingState::response`] without calling [`ServerPairingState::handle_init`]
//!   again; `handle_init` is idempotent for an identical `init` and errors on a
//!   conflicting one.
//! * Re-encryption: `PairingConfirmClient`/`PairingConfirmServer` carry a fresh
//!   random nonce per encryption, so a retransmission must reuse the previously
//!   created message rather than re-encrypt (see the "no re-encryption" note on
//!   the create methods).

use prost::Message as ProstMessage;

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
/// (signed by the desktop's `Ed_C`; see the direction note on
/// [`ServerPairingState::create_confirm_server`]).
pub const PAIRING_SERVER_SIG_CONTEXT: &[u8] = b"tapauth-pair-server-sig-v2";

/// AEAD associated-data prefix of `PairingConfirmClient.encrypted_payload` (key `K_c2s`).
pub const PAIRING_PROVISION_AAD_CONTEXT: &[u8] = b"tapauth-pair-v2-provision";

/// AEAD associated-data prefix of `PairingConfirmServer.encrypted_complete` (key `K_s2c`).
pub const PAIRING_COMPLETE_AAD_CONTEXT: &[u8] = b"tapauth-pair-v2-complete";

/// Symmetric AEAD algorithms this implementation supports, baseline mandatory first.
///
/// The negotiation keeps this order: both sides list the baseline algorithm first
/// so an older peer still intersects on it.
pub const SUPPORTED_SYMMETRIC_ALGORITHMS: &[SymmetricAlgorithm] = &[
    SymmetricAlgorithm::Aes256Gcm,
    // prost renders `CHACHA20_POLY1305` as `Chacha20Poly1305` (not `ChaCha20Poly1305`).
    SymmetricAlgorithm::Chacha20Poly1305,
];

/// Hash algorithms this implementation supports, baseline mandatory first.
pub const SUPPORTED_HASH_ALGORITHMS: &[HashAlgorithm] =
    &[HashAlgorithm::Sha256, HashAlgorithm::Blake3];

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

/// What the desktop needs to show/emit after [`ServerPairingState::start`].
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
/// Created by [`ServerPairingState::start`], fed a `PairingInit` through
/// [`ServerPairingState::handle_init`], then driven through provisioning and
/// completion. All key material is dropped (and zeroized) when the value is
/// dropped, which the caller must do as soon as pairing concludes.
pub struct ServerPairingState {
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    x25519_keypair: X25519KeyPair,
    client_identity: Ed25519KeyPair,
    client_device_name: String,
    /// Encoding of the first accepted `PairingInit`, for idempotent retries.
    accepted_init: Option<Vec<u8>>,
    response: Option<PairingResponse>,
    transcript_hash: Option<[u8; 32]>,
    keys: Option<PairingSessionKeys>,
    negotiated: Option<NegotiatedAlgorithms>,
}

impl ServerPairingState {
    /// Start a pairing session: random `sid`, ephemeral `x_C`, BLE advertisement
    /// id and QR URL.
    ///
    /// `udp_port`, `ipv4` and `ipv6` only feed the QR URL (they may be absent for
    /// BLE-only pairing). The CSK does not exist yet at this point, so no
    /// algorithm is pinned here — negotiation happens in
    /// [`ServerPairingState::handle_init`].
    pub fn start(
        client_identity: Ed25519KeyPair,
        client_device_name: &str,
        udp_port: u16,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
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
            udp_port,
            ipv4,
            ipv6,
        ))
    }

    /// Assemble the state and its [`StartedPairing`] from already-chosen material.
    ///
    /// Split out of [`ServerPairingState::start`] so a test can re-create a state
    /// with the *same* `x_C`/`Ed_C`/`sid` and vary one transcript field at a time.
    fn build(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        x25519_keypair: X25519KeyPair,
        client_identity: Ed25519KeyPair,
        client_device_name: &str,
        udp_port: u16,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) -> (Self, StartedPairing) {
        let client_x25519_public_key = x25519_keypair.public_key_bytes();
        let pairing_adv_id = derive_ble_pairing_adv_id(&session_id, &client_x25519_public_key);
        let qr_url = generate_pairing_url_v2(
            &session_id,
            &hex::encode(client_x25519_public_key),
            Some(udp_port),
            ipv4,
            ipv6,
        );

        let state = Self {
            session_id,
            x25519_keypair,
            client_identity,
            client_device_name: truncate_utf8(client_device_name, PAIRING_DEVICE_NAME_MAX_BYTES),
            accepted_init: None,
            response: None,
            transcript_hash: None,
            keys: None,
            negotiated: None,
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
        self.x25519_keypair.public_key_bytes()
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
        let negotiated = negotiate(&supported_symmetric, &supported_hash, &supported_signature)?;

        let client_x25519_public_key = self.x25519_keypair.public_key_bytes();
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

        let shared_secret = self
            .x25519_keypair
            .diffie_hellman(&server_x25519_public_key)?;
        let keys = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash)?;

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

    /// Decrypt the provisioning payload sent by the phone.
    ///
    /// Returns `csk`/`username`/`client_hostname`; the caller checks that `csk`
    /// is 32 bytes (enforced here) and persists both.
    pub fn process_confirm_client(
        &mut self,
        confirm: &PairingConfirmClient,
    ) -> Result<PairingProvisionPayload, ProtocolError> {
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
    /// **Direction departure (deliberate).** The proto and
    /// `initial-key-exchange.md` Step 6 describe `PairingConfirmServer` as
    /// phone → desktop, signed by `Ed_S`. This implementation sends it
    /// desktop → phone and signs it with the desktop's **static `Ed_C`** instead,
    /// which is why the field is verified under `response.client_ed25519_public_key`
    /// on the receiving side. The context string, the AAD and the signed transcript
    /// are exactly the documented ones.
    ///
    /// Each call draws a fresh nonce: a retransmission must re-send the same
    /// [`PairingConfirmServer`], not call this again.
    pub fn create_confirm_server(
        &self,
        csk: &[u8; 32],
    ) -> Result<PairingConfirmServer, ProtocolError> {
        let (keys, transcript_hash, negotiated) =
            session_material(&self.keys, &self.transcript_hash, &self.negotiated)?;
        let signed = complete_signature_message(PAIRING_SERVER_SIG_CONTEXT, transcript_hash, csk);
        let server_signature = sign_ed25519(&self.client_identity, &signed);
        let payload = PairingCompletePayload { server_signature };
        let aad = context_with_hash(PAIRING_COMPLETE_AAD_CONTEXT, transcript_hash);
        let encrypted_complete = encrypt_with_key(
            negotiated.symmetric_algorithm,
            &keys.k_s2c,
            &payload.encode_to_vec(),
            &aad,
        )?;
        Ok(PairingConfirmServer { encrypted_complete })
    }

    /// Build an abort, authenticated with `K_c2s` when the keys already exist.
    ///
    /// Before the keys exist the abort is sent untagged: the peer only learns that
    /// somebody asked to stop, which is all it can authenticate anyway.
    pub fn create_abort(&self, reason: PairingAbortReason) -> Result<PairingAbort, ProtocolError> {
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
    /// keys exist, or a tag before keys exist.
    pub fn verify_abort(&self, abort: &PairingAbort) -> Result<bool, ProtocolError> {
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
pub struct ClientPairingSession {
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    x25519_keypair: X25519KeyPair,
    server_identity: Ed25519KeyPair,
    server_device_name: String,
    /// Exactly what `PairingInit` advertised; these lists enter `H`, so they are
    /// cached and reused verbatim in [`ClientPairingSession::verify_response`].
    advertised_symmetric: Vec<SymmetricAlgorithm>,
    advertised_hash: Vec<HashAlgorithm>,
    advertised_signature: Vec<SignatureAlgorithm>,
    init: Option<PairingInit>,
    /// `Ed_C`, learned from the verified `PairingResponse`.
    client_ed25519_public_key: Option<[u8; 32]>,
    negotiated: Option<NegotiatedAlgorithms>,
    transcript_hash: Option<[u8; 32]>,
    keys: Option<PairingSessionKeys>,
}

impl ClientPairingSession {
    /// Create the phone's half of a pairing, from the scanned QR `sid`.
    ///
    /// `server_identity` is the phone's long-term `Ed_S`.
    pub fn new(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        server_identity: Ed25519KeyPair,
        server_device_name: &str,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            session_id,
            x25519_keypair: X25519KeyPair::generate()?,
            server_identity,
            server_device_name: truncate_utf8(server_device_name, PAIRING_DEVICE_NAME_MAX_BYTES),
            advertised_symmetric: SUPPORTED_SYMMETRIC_ALGORITHMS.to_vec(),
            advertised_hash: SUPPORTED_HASH_ALGORITHMS.to_vec(),
            advertised_signature: SUPPORTED_SIGNATURE_ALGORITHMS.to_vec(),
            init: None,
            client_ed25519_public_key: None,
            negotiated: None,
            transcript_hash: None,
            keys: None,
        })
    }

    /// The session id every frame of this pairing must carry.
    pub fn session_id(&self) -> &[u8; PAIRING_SESSION_ID_LEN] {
        &self.session_id
    }

    /// Build (once) the `PairingInit` to send, retransmitting the cached copy.
    pub fn create_init(&mut self) -> Result<PairingInit, ProtocolError> {
        if let Some(init) = self.init.as_ref() {
            return Ok(init.clone());
        }
        let init = PairingInit {
            server_x25519_public_key: self.x25519_keypair.public_key_bytes().to_vec(),
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
    pub fn verify_response(
        &mut self,
        response: &PairingResponse,
        expected_qr_pk: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        let client_x25519_public_key: [u8; 32] = response
            .client_x25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::ChallengeMismatch)?;
        if !constant_time_eq(&client_x25519_public_key, expected_qr_pk) {
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

        let server_x25519_public_key = self.x25519_keypair.public_key_bytes();
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

        let shared_secret = self
            .x25519_keypair
            .diffie_hellman(&client_x25519_public_key)?;
        let keys = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash)?;

        self.client_ed25519_public_key = Some(client_ed25519_public_key);
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

    /// Encrypt the provisioning payload (`{csk, username, client_hostname}`) under
    /// `K_c2s`.
    ///
    /// Each call draws a fresh nonce: a retransmission must re-send the same
    /// [`PairingConfirmClient`], not call this again.
    pub fn create_confirm_client(
        &self,
        csk: &[u8; 32],
        username: &str,
        client_hostname: &str,
    ) -> Result<PairingConfirmClient, ProtocolError> {
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

    /// Verify the desktop's completion proof for the CSK we provisioned.
    ///
    /// The proof is `Ed_C`'s signature over `"tapauth-pair-server-sig-v2" || H || csk`,
    /// verified with the `Ed_C` cached from the verified `PairingResponse` — so the
    /// phone must not call this before [`ClientPairingSession::verify_response`].
    pub fn verify_confirm_server(
        &self,
        confirm: &PairingConfirmServer,
        csk: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        let (keys, transcript_hash, negotiated) =
            session_material(&self.keys, &self.transcript_hash, &self.negotiated)?;
        let client_ed25519_public_key = self
            .client_ed25519_public_key
            .ok_or(ProtocolError::MissingField("client_ed25519_public_key"))?;

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
            &client_ed25519_public_key,
            &signed,
            &payload.server_signature,
        )
        .map_err(|_| ProtocolError::InvalidSignature)
    }

    /// Build an abort, authenticated with `K_s2c` when the keys already exist.
    pub fn create_abort(&self, reason: PairingAbortReason) -> Result<PairingAbort, ProtocolError> {
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
    /// Same result contract as [`ServerPairingState::verify_abort`].
    pub fn verify_abort(&self, abort: &PairingAbort) -> Result<bool, ProtocolError> {
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

/// Byte-wise equality without an early exit, for the QR key commitment.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    std::hint::black_box(difference) == 0
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
fn negotiate(
    symmetric: &[SymmetricAlgorithm],
    hash: &[HashAlgorithm],
    signature: &[SignatureAlgorithm],
) -> Result<NegotiatedAlgorithms, ProtocolError> {
    let symmetric_algorithm = pick_first(SUPPORTED_SYMMETRIC_ALGORITHMS, symmetric)
        .ok_or(ProtocolError::UnsupportedAlgorithm)?;
    let hash_algorithm =
        pick_first(SUPPORTED_HASH_ALGORITHMS, hash).ok_or(ProtocolError::UnsupportedAlgorithm)?;
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

    fn start_desktop() -> (ServerPairingState, StartedPairing) {
        ServerPairingState::start(
            desktop_identity(),
            "thinkpad",
            36692,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            None,
        )
        .unwrap()
    }

    /// Rebuild a desktop state that is byte-identical in its key material and
    /// session id, so a test can vary exactly one transcript field.
    fn seeded_desktop(session_id: [u8; PAIRING_SESSION_ID_LEN]) -> ServerPairingState {
        ServerPairingState::build(
            session_id,
            X25519KeyPair::from_secret_bytes([0x11; 32]),
            desktop_identity(),
            "thinkpad",
            36692,
            None,
            None,
        )
        .0
    }

    /// Desktop + phone with `PairingInit` sent and `PairingResponse` received, but
    /// not yet verified by the phone.
    fn exchange() -> (
        ServerPairingState,
        ClientPairingSession,
        PairingResponse,
        [u8; 32],
    ) {
        let (mut desktop, started) = start_desktop();
        let mut phone =
            ClientPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        let init = phone.create_init().unwrap();
        let response = desktop.handle_init(&init).unwrap().clone();
        (desktop, phone, response, started.client_x25519_public_key)
    }

    /// A fully established pairing: keys and SAS derived on both sides.
    fn established() -> (ServerPairingState, ClientPairingSession) {
        let (desktop, mut phone, response, qr_pk) = exchange();
        phone.verify_response(&response, &qr_pk).unwrap();
        (desktop, phone)
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
            ClientPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        assert_eq!(phone.session_id(), &started.session_id);

        let init = phone.create_init().unwrap();
        assert_eq!(
            init.server_ed25519_public_key,
            phone_identity().verifying_key_bytes().to_vec()
        );
        assert_eq!(init.server_device_name, "pixel");
        assert_eq!(
            init.supported_symmetric_algorithms,
            vec![
                SymmetricAlgorithm::Aes256Gcm as i32,
                SymmetricAlgorithm::Chacha20Poly1305 as i32
            ]
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
        let confirm_client = phone
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        let payload = desktop.process_confirm_client(&confirm_client).unwrap();
        assert_eq!(payload.csk, csk.to_vec());
        assert_eq!(payload.username, "luca");
        assert_eq!(payload.client_hostname, "thinkpad");

        let confirm_server = desktop.create_confirm_server(&csk).unwrap();
        phone.verify_confirm_server(&confirm_server, &csk).unwrap();
        // The proof pins the exact CSK: a different one must not verify.
        assert!(matches!(
            phone
                .verify_confirm_server(&confirm_server, &[0x43u8; 32])
                .unwrap_err(),
            ProtocolError::InvalidSignature
        ));
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
        // No keys were derived, so nothing can be provisioned.
        assert!(matches!(
            phone.create_confirm_client(&[0u8; 32], "luca", "thinkpad"),
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

    #[test]
    fn response_selecting_unadvertised_algorithm_is_rejected() {
        let (mut desktop, started) = start_desktop();
        let mut phone =
            ClientPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
        // The phone only advertises AES-256-GCM, so it can never accept ChaCha20.
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
        response.selected_symmetric_algorithm = SymmetricAlgorithm::Chacha20Poly1305 as i32;
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
        let phone = ClientPairingSession::new([0x07; 16], phone_identity(), "pixel").unwrap();

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
        let mut phone = ClientPairingSession::new(session_id, phone_identity(), "pixel").unwrap();
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
        reordered.supported_hash_algorithms =
            vec![HashAlgorithm::Blake3 as i32, HashAlgorithm::Sha256 as i32];

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
            // over the mutated transcript no longer verifies.
            assert!(
                matches!(
                    phone
                        .verify_response(&mutated_response, &qr_pk)
                        .unwrap_err(),
                    ProtocolError::InvalidSignature
                ),
                "mutating {field} must break the response signature check"
            );
            // ... and the failed attempt must not have overwritten the phone state.
            assert_eq!(phone.transcript_hash().unwrap(), &baseline_hash);
            assert_eq!(phone.sas().unwrap(), baseline_sas.as_str());
        }
    }

    // --- Misc -------------------------------------------------------------

    #[test]
    fn handle_init_is_idempotent_for_identical_inits() {
        let mut desktop = seeded_desktop([0x5Au8; PAIRING_SESSION_ID_LEN]);
        let mut phone =
            ClientPairingSession::new([0x5Au8; PAIRING_SESSION_ID_LEN], phone_identity(), "pixel")
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
            ServerPairingState::start(desktop_identity(), &long_name, 36692, None, None).unwrap();
        assert_eq!(desktop.client_device_name.len(), 63);

        let mut phone =
            ClientPairingSession::new(started.session_id, phone_identity(), &long_name).unwrap();
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
}
