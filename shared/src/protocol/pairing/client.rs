use super::negotiation::{hash_algorithms, negotiate, signature_algorithms, symmetric_algorithms};
use super::transcript::{
    complete_signature_message, context_with_hash, key_32, session_material, truncate_utf8,
    verify_abort_tag,
};
use super::wire::PairingEndpoint;
use super::*;
use crate::crypto::{
    compute_pairing_abort_tag, compute_pairing_transcript_hash, decrypt_with_key,
    derive_ble_pairing_adv_id, derive_pairing_keys_and_sas, encrypt_with_key, sign_ed25519,
    verify_ed25519, CryptoError, Ed25519KeyPair, PairingSessionKeys, PairingTranscript,
    X25519KeyPair,
};
use crate::models::pairing::generate_pairing_url_v2;
use crate::protocol::messages::{ProtocolError, PROTOCOL_VERSION_V2};
use crate::protocol::pb::*;
use prost::Message as ProstMessage;
use zeroize::Zeroizing;

/// Desktop-side pairing state (the protocol *Client*; see the module docs).
///
/// Created by [`ClientPairingState::start`], fed a `PairingInit` through
/// [`ClientPairingState::handle_init`], then driven through provisioning and
/// completion. All key material is dropped (and zeroized) when the value is
/// dropped, which the caller must do as soon as pairing concludes.
///
/// The handshake state itself lives in a [`LiveClientPairing`], which only
/// [`ClientPairingState::live`] and [`ClientPairingState::live_mut`] hand out. A
/// method that does not go through one of them cannot name the keys, the
/// transcript hash, the ephemeral secret, the accepted `init` or the captured
/// `Ed_S`, so the liveness check is not a line that can be forgotten — it is the
/// only way to reach the state. What stays here is what the API promises to keep
/// answering after [`ClientPairingState::conclude`]: the session id, the public
/// halves, the already-sent `PairingResponse` and the negotiated algorithms.
pub struct ClientPairingState {
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    /// Public half `X_C`, committed in the QR code. Public data, kept after the
    /// secret is taken so the accessor stays answerable.
    client_x25519_public_key: [u8; 32],
    /// Public half of `Ed_C`, cached so the accessor stays answerable once `Ed_C`
    /// itself is dropped with the live state.
    client_ed25519_public_key: [u8; 32],
    /// The cached `PairingResponse`. It already went out on the wire and carries no
    /// key material, so it survives the conclusion like the public halves do.
    response: Option<PairingResponse>,
    negotiated: Option<NegotiatedAlgorithms>,
    /// The live handshake state; `None` once [`ClientPairingState::conclude`] took
    /// it.
    pub(super) live: Option<LiveClientPairing>,
}

/// Everything a desktop pairing owns while it is live.
///
/// Reached only through [`ClientPairingState::live`]/[`ClientPairingState::live_mut`];
/// dropping it (which [`ClientPairingState::conclude`] does) zeroizes the session
/// keys, the transcript hash and the ephemeral X25519 secret.
pub(super) struct LiveClientPairing {
    /// Ephemeral `x_C`. Taken — and zeroized on drop — as soon as the session
    /// keys are derived, and again on [`ClientPairingState::conclude`], so the
    /// secret cannot be reused by a later operation.
    x25519_keypair: Option<X25519KeyPair>,
    client_identity: Ed25519KeyPair,
    client_device_name: String,
    /// Encoding of the first accepted `PairingInit`, for idempotent retries.
    accepted_init: Option<Vec<u8>>,
    /// `Ed_S`, captured from the accepted `PairingInit` (and bound into `H`); the
    /// key the phone's completion proof is verified under.
    server_ed25519_public_key: Option<[u8; 32]>,
    transcript_hash: Option<[u8; 32]>,
    keys: Option<PairingSessionKeys>,
    /// The active CSK's algorithms, which negotiation must reproduce.
    pinned: Option<PinnedAlgorithms>,
}

impl ClientPairingState {
    /// The live handshake state, or [`ProtocolError::SessionConcluded`] once
    /// [`ClientPairingState::conclude`] has run.
    ///
    /// This is the liveness gate, and it is the only way to name the keys, the
    /// transcript hash, the ephemeral `x_C`, the accepted `init` or the captured
    /// `Ed_S`. A protocol entry point written without it does not compile, so the
    /// mistake class — a 13th method that forgot the check and ran against
    /// zeroized key material — is unrepresentable rather than documented.
    pub(super) fn live(&self) -> Result<&LiveClientPairing, ProtocolError> {
        self.live.as_ref().ok_or(ProtocolError::SessionConcluded)
    }

    /// The mutable counterpart of [`ClientPairingState::live`].
    pub(super) fn live_mut(&mut self) -> Result<&mut LiveClientPairing, ProtocolError> {
        self.live.as_mut().ok_or(ProtocolError::SessionConcluded)
    }

    /// Start a pairing session: random `sid`, ephemeral `x_C`, BLE advertisement
    /// id and QR URL.
    ///
    /// `endpoint` only feeds the QR URL. Its port is an `Option` here for the
    /// same reason the URL's `p` is: a session with no UDP endpoint publishes
    /// none, so there is no port to spell — see [`PairingEndpoint`]. The caller
    /// decides whether there is one, because only it knows whether it bound a
    /// socket. Negotiation happens in [`ClientPairingState::handle_init`];
    /// `pinned` carries the algorithms an existing `CSK` is already committed to
    /// (see the module docs), and must be `None` for a first pairing.
    pub fn start(
        client_identity: Ed25519KeyPair,
        client_device_name: &str,
        endpoint: PairingEndpoint,
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
            endpoint,
            pinned,
        ))
    }

    /// Assemble the state and its [`StartedPairing`] from already-chosen material.
    ///
    /// Split out of [`ClientPairingState::start`] so a test can re-create a state
    /// with the *same* `x_C`/`Ed_C`/`sid` and vary one transcript field at a time.
    pub(super) fn build(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        x25519_keypair: X25519KeyPair,
        client_identity: Ed25519KeyPair,
        client_device_name: &str,
        endpoint: PairingEndpoint,
        pinned: Option<PinnedAlgorithms>,
    ) -> (Self, StartedPairing) {
        let client_x25519_public_key = x25519_keypair.public_key_bytes();
        let client_ed25519_public_key = client_identity.verifying_key_bytes();
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
            client_ed25519_public_key,
            response: None,
            negotiated: None,
            live: Some(LiveClientPairing {
                x25519_keypair: Some(x25519_keypair),
                client_identity,
                client_device_name: truncate_utf8(
                    client_device_name,
                    PAIRING_DEVICE_NAME_MAX_BYTES,
                ),
                accepted_init: None,
                server_ed25519_public_key: None,
                transcript_hash: None,
                keys: None,
                pinned,
            }),
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
        self.client_ed25519_public_key
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
        let live = self.live()?;
        let server_x25519_public_key =
            key_32(&init.server_x25519_public_key, "server_x25519_public_key")?;
        let server_ed25519_public_key =
            key_32(&init.server_ed25519_public_key, "server_ed25519_public_key")?;

        let encoded_init = init.encode_to_vec();
        if let Some(accepted) = live.accepted_init.as_ref() {
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
            live.pinned,
        )?;

        let client_x25519_public_key = self.client_x25519_public_key;
        let client_ed25519_public_key = self.client_ed25519_public_key;

        let transcript = PairingTranscript {
            version: PROTOCOL_VERSION_V2,
            session_id: &self.session_id,
            client_x25519_public_key: &client_x25519_public_key,
            server_x25519_public_key: &server_x25519_public_key,
            client_ed25519_public_key: &client_ed25519_public_key,
            server_ed25519_public_key: &server_ed25519_public_key,
            client_device_name: &live.client_device_name,
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
            live.x25519_keypair
                .as_ref()
                .ok_or(ProtocolError::MissingField("x25519_keypair"))?
                .diffie_hellman(&server_x25519_public_key)?,
        );
        let keys = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash)?;
        drop(shared_secret);

        let signed = context_with_hash(PAIRING_CLIENT_SIG_CONTEXT, &transcript_hash);
        let client_signature = sign_ed25519(&live.client_identity, &signed);

        let response = PairingResponse {
            client_x25519_public_key: client_x25519_public_key.to_vec(),
            client_ed25519_public_key: client_ed25519_public_key.to_vec(),
            client_device_name: live.client_device_name.clone(),
            selected_symmetric_algorithm: negotiated.symmetric_algorithm as i32,
            selected_hash_algorithm: negotiated.hash_algorithm as i32,
            selected_signature_algorithm: negotiated.signature_algorithm as i32,
            client_signature,
        };

        // Commit under the same gate: nothing above this line has written state, so a
        // failed verification leaves the session exactly as it was.
        let live = self.live_mut()?;
        live.accepted_init = Some(encoded_init);
        live.server_ed25519_public_key = Some(server_ed25519_public_key);
        live.transcript_hash = Some(transcript_hash);
        live.keys = Some(keys);
        // `x_C` has served its only purpose. Take it now so it is zeroized and can
        // never be reused, even by a later retry or a resurrected session.
        live.x25519_keypair = None;
        // Persisted metadata, not key material: it stays answerable after `conclude`.
        self.negotiated = Some(negotiated);
        self.response = Some(response);

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
        // The single transition out of the live phase. Taking the state drops the
        // derived keys, the transcript hash, the accepted `init`, the captured `Ed_S`
        // and the ephemeral secret (all zeroizing), and `live()`/`live_mut()` now
        // report `SessionConcluded` for every caller. A second call finds `None` and
        // is a no-op.
        drop(self.live.take());
    }

    /// Whether the ephemeral `x_C` is still held.
    ///
    /// The public half of `x_C` stays exposed by
    /// [`ClientPairingState::client_x25519_public_key`].
    #[cfg(test)]
    pub(super) fn ephemeral_keypair_present(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| live.x25519_keypair.is_some())
    }

    /// Whether the session keys are still held.
    #[cfg(test)]
    pub(super) fn session_keys_present(&self) -> bool {
        self.live.as_ref().is_some_and(|live| live.keys.is_some())
    }

    /// The device name actually stored (truncated at build time).
    #[cfg(test)]
    pub(super) fn client_device_name(&self) -> Option<&str> {
        self.live
            .as_ref()
            .map(|live| live.client_device_name.as_str())
    }

    /// The negotiated algorithms, once `PairingInit` has been handled.
    pub fn negotiated(&self) -> Option<NegotiatedAlgorithms> {
        self.negotiated
    }

    /// The handshake transcript hash `H`, once `PairingInit` has been handled.
    pub fn transcript_hash(&self) -> Option<&[u8; 32]> {
        let live = self.live().ok()?;
        live.transcript_hash.as_ref()
    }

    /// The SAS to display (`"123-456"`), once `PairingInit` has been handled.
    pub fn sas(&self) -> Option<&str> {
        let live = self.live().ok()?;
        live.keys.as_ref().map(|keys| keys.sas.as_str())
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
        let live = self.live()?;
        let (keys, transcript_hash, negotiated) =
            session_material(&live.keys, &live.transcript_hash, &self.negotiated)?;
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
        let live = self.live()?;
        let (keys, transcript_hash, negotiated) =
            session_material(&live.keys, &live.transcript_hash, &self.negotiated)?;
        let server_ed25519_public_key = live
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
        let live = self.live()?;
        let auth_tag = match (live.keys.as_ref(), live.transcript_hash.as_ref()) {
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
        let live = self.live()?;
        verify_abort_tag(
            abort,
            live.keys.as_ref().map(|keys| &*keys.k_s2c),
            live.transcript_hash.as_ref(),
        )
    }
}
