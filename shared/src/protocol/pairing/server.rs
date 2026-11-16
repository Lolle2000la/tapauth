use super::fields::{key_32, truncate_utf8};
use super::transcript::{
    complete_signature_message, context_with_hash, session_material, verify_abort_tag,
};
use super::*;
use crate::crypto::{
    compute_pairing_abort_tag, compute_pairing_transcript_hash, decrypt_with_key,
    derive_pairing_keys_and_sas, encrypt_with_key, sign_ed25519, verify_ed25519, Ed25519KeyPair,
    PairingSessionKeys, PairingTranscript, X25519KeyPair,
};
use crate::protocol::messages::{ProtocolError, PROTOCOL_VERSION_V2};
use crate::protocol::pb::*;
use prost::Message as ProstMessage;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Phone-side pairing session (the protocol *Server*; see the module docs).
///
/// Created from the QR code's session id, then driven through `PairingInit`,
/// response verification, provisioning and completion. Dropping it zeroizes the
/// ephemeral key and the derived session keys.
///
/// Like [`ClientPairingState`], the handshake state lives in a [`LiveServerPairing`]
/// that only [`ServerPairingSession::live`]/[`ServerPairingSession::live_mut`] hand
/// out, so an entry point cannot reach the keys, the transcript hash, the ephemeral
/// `x_S`, the cached `init` or the "confirmation sent" record without passing the
/// liveness gate first.
pub struct ServerPairingSession {
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    negotiated: Option<NegotiatedAlgorithms>,
    /// The live handshake state; `None` once [`ServerPairingSession::conclude`] took
    /// it. Private: only [`ServerPairingSession::live`]/[`ServerPairingSession::live_mut`]
    /// name it, so no sibling module can reach the keys behind the gate.
    live: Option<LiveServerPairing>,
}

/// Everything a phone-side pairing owns while it is live.
///
/// Reached only through [`ServerPairingSession::live`]/[`ServerPairingSession::live_mut`];
/// dropping it (which [`ServerPairingSession::conclude`] does) zeroizes the session
/// keys, the transcript hash and the ephemeral X25519 secret.
pub(super) struct LiveServerPairing {
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
    transcript_hash: Option<[u8; 32]>,
    keys: Option<PairingSessionKeys>,
    /// Set by [`ServerPairingSession::create_confirm_server`]: the completion proof
    /// went out, so the handshake has moved past every earlier step while the keys
    /// stay available for `process_confirm_client` retransmissions.
    confirmation_sent: bool,
}

impl ServerPairingSession {
    /// The live handshake state, or [`ProtocolError::SessionConcluded`] once
    /// [`ServerPairingSession::conclude`] has run.
    ///
    /// The same structural gate as [`ClientPairingState::live`]: the fields it
    /// guards cannot be named without it.
    fn live(&self) -> Result<&LiveServerPairing, ProtocolError> {
        self.live.as_ref().ok_or(ProtocolError::SessionConcluded)
    }

    /// The mutable counterpart of [`ServerPairingSession::live`].
    fn live_mut(&mut self) -> Result<&mut LiveServerPairing, ProtocolError> {
        self.live.as_mut().ok_or(ProtocolError::SessionConcluded)
    }

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
    /// Split out of [`ServerPairingSession::new`], and private on purpose: a sibling
    /// module must not be able to build a live session around key material of its own
    /// choosing. The test seam is [`ServerPairingSession::build_with_material`].
    fn build(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        x25519_keypair: X25519KeyPair,
        server_identity: Ed25519KeyPair,
        server_device_name: &str,
    ) -> Self {
        let server_x25519_public_key = x25519_keypair.public_key_bytes();
        Self {
            session_id,
            negotiated: None,
            live: Some(LiveServerPairing {
                server_x25519_public_key,
                x25519_keypair: Some(x25519_keypair),
                server_identity,
                server_device_name: truncate_utf8(
                    server_device_name,
                    PAIRING_DEVICE_NAME_MAX_BYTES,
                ),
                advertised_symmetric: SUPPORTED_SYMMETRIC_ALGORITHMS.to_vec(),
                advertised_hash: SUPPORTED_HASH_ALGORITHMS.to_vec(),
                advertised_signature: SUPPORTED_SIGNATURE_ALGORITHMS.to_vec(),
                init: None,
                transcript_hash: None,
                keys: None,
                confirmation_sent: false,
            }),
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
        let live = self.live_mut()?;
        if live.confirmation_sent {
            return Err(ProtocolError::ConfirmationAlreadySent);
        }
        if let Some(init) = live.init.as_ref() {
            return Ok(init.clone());
        }
        let init = PairingInit {
            server_x25519_public_key: live.server_x25519_public_key.to_vec(),
            server_ed25519_public_key: live.server_identity.verifying_key_bytes().to_vec(),
            server_device_name: live.server_device_name.clone(),
            supported_symmetric_algorithms: live
                .advertised_symmetric
                .iter()
                .map(|algorithm| *algorithm as i32)
                .collect(),
            supported_hash_algorithms: live
                .advertised_hash
                .iter()
                .map(|algorithm| *algorithm as i32)
                .collect(),
            supported_signature_algorithms: live
                .advertised_signature
                .iter()
                .map(|algorithm| *algorithm as i32)
                .collect(),
        };
        live.init = Some(init.clone());
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
        let session_id = self.session_id;
        let negotiated = {
            let live = self.live_mut()?;
            if live.init.is_none() || live.keys.is_some() {
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
            if !live.advertised_symmetric.contains(&selected_symmetric)
                || !live.advertised_hash.contains(&selected_hash)
                || !live.advertised_signature.contains(&selected_signature)
            {
                return Err(ProtocolError::UnsupportedAlgorithm);
            }
            // Both ids decode to `1` today, so a transposition of the two fields
            // below is undetectable by value; the pair only tells itself apart once a
            // second suite exists. When one is added, restore
            // `the_two_selected_algorithm_ids_are_not_transposed`: it must have the
            // peer select a different id per slot and read each back in its own field.
            let negotiated = NegotiatedAlgorithms {
                symmetric_algorithm: selected_symmetric,
                hash_algorithm: selected_hash,
                signature_algorithm: selected_signature,
            };

            let server_x25519_public_key = live.server_x25519_public_key;
            let server_ed25519_public_key = live.server_identity.verifying_key_bytes();

            let transcript = PairingTranscript {
                version: PROTOCOL_VERSION_V2,
                session_id: &session_id,
                client_x25519_public_key: &client_x25519_public_key,
                server_x25519_public_key: &server_x25519_public_key,
                client_ed25519_public_key: &client_ed25519_public_key,
                server_ed25519_public_key: &server_ed25519_public_key,
                client_device_name: &response.client_device_name,
                server_device_name: &live.server_device_name,
                supported_symmetric: &live.advertised_symmetric,
                supported_hash: &live.advertised_hash,
                supported_signature: &live.advertised_signature,
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
                live.x25519_keypair
                    .as_ref()
                    .ok_or(ProtocolError::MissingField("x25519_keypair"))?
                    .diffie_hellman(&client_x25519_public_key)?,
            );
            let keys = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash)?;
            drop(shared_secret);
            // `x_S` has served its only purpose: take it so it is zeroized and the
            // session cannot derive a second set of keys from it.
            live.x25519_keypair = None;

            live.transcript_hash = Some(transcript_hash);
            live.keys = Some(keys);
            negotiated
        };
        // Persisted metadata, not key material: it stays answerable after `conclude`.
        self.negotiated = Some(negotiated);
        Ok(())
    }

    /// The negotiated algorithms, once the response has been verified.
    pub fn negotiated(&self) -> Option<NegotiatedAlgorithms> {
        self.negotiated
    }

    /// The handshake transcript hash `H`, once the response has been verified.
    pub fn transcript_hash(&self) -> Option<&[u8; 32]> {
        let live = self.live().ok()?;
        live.transcript_hash.as_ref()
    }

    /// The SAS to display (`"123-456"`), once the response has been verified.
    pub fn sas(&self) -> Option<&str> {
        let live = self.live().ok()?;
        live.keys.as_ref().map(|keys| keys.sas.as_str())
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
        // The single transition out of the live phase, exactly as on the desktop:
        // taking the state drops the derived keys, the transcript hash, the cached
        // `init` and the ephemeral secret (all zeroizing), and `live()`/`live_mut()`
        // now report `SessionConcluded` for every caller. A second call finds `None`
        // and is a no-op.
        drop(self.live.take());
    }

    /// Assemble a session around an already-chosen ephemeral `X_S`.
    ///
    /// Test seam onto the private [`ServerPairingSession::build`]: a test pins
    /// `X_S` and gets a deterministic `Z`, `H` and SAS (see
    /// `transcript_hash_binds_every_negotiated_field`).
    #[cfg(test)]
    pub(super) fn build_with_material(
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        x25519_keypair: X25519KeyPair,
        server_identity: Ed25519KeyPair,
        server_device_name: &str,
    ) -> Self {
        Self::build(
            session_id,
            x25519_keypair,
            server_identity,
            server_device_name,
        )
    }

    /// Whether the live handshake state is still held.
    ///
    /// Test hook: the field is private, so this reports the phase transition the
    /// conclusion test asserts without handing a sibling module the keys.
    #[cfg(test)]
    pub(super) fn is_live(&self) -> bool {
        self.live.is_some()
    }

    /// The liveness gate, reduced to its answer.
    ///
    /// Test hook, so the conclusion test can assert the `SessionConcluded` answer
    /// without receiving the state the gate guards.
    #[cfg(test)]
    pub(super) fn live_gate(&self) -> Result<(), ProtocolError> {
        self.live().map(|_| ())
    }

    /// The mutable counterpart of [`ServerPairingSession::live_gate`].
    #[cfg(test)]
    pub(super) fn live_gate_mut(&mut self) -> Result<(), ProtocolError> {
        self.live_mut().map(|_| ())
    }

    /// Whether the ephemeral `x_S` is still held.
    #[cfg(test)]
    pub(super) fn ephemeral_keypair_present(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| live.x25519_keypair.is_some())
    }

    /// Whether the session keys are still held.
    ///
    /// A test hook for "a refused response derived nothing": the keys are dropped
    /// with the live state, so a concluded session answers `false` too.
    #[cfg(test)]
    pub(super) fn session_keys_present(&self) -> bool {
        self.live.as_ref().is_some_and(|live| live.keys.is_some())
    }

    /// The session keys, as held by the live state.
    ///
    /// Test hook: the live state is the only way to reach them, so a test that
    /// decrypts a frame "exactly as the desktop does" reads them through here.
    #[cfg(test)]
    pub(super) fn keys(&self) -> Option<&PairingSessionKeys> {
        self.live.as_ref().and_then(|live| live.keys.as_ref())
    }

    /// The device name actually stored (truncated at build time).
    #[cfg(test)]
    pub(super) fn server_device_name(&self) -> Option<&str> {
        self.live
            .as_ref()
            .map(|live| live.server_device_name.as_str())
    }

    /// Replace the advertised algorithm lists: a peer that offers less than this
    /// build implements.
    ///
    /// Test hook behind the same gate as every other entry point.
    #[cfg(test)]
    pub(super) fn set_advertised(
        &mut self,
        symmetric: Vec<SymmetricAlgorithm>,
        hash: Vec<HashAlgorithm>,
    ) -> Result<(), ProtocolError> {
        let live = self.live_mut()?;
        live.advertised_symmetric = symmetric;
        live.advertised_hash = hash;
        Ok(())
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
        let live = self.live()?;
        let (keys, transcript_hash, negotiated) =
            session_material(&live.keys, &live.transcript_hash, &self.negotiated)?;
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
        // Copy the negotiated algorithms out first: `NegotiatedAlgorithms` is small,
        // and it has to be readable while the live state is mutably borrowed.
        let selected = self.negotiated;
        let live = self.live_mut()?;
        if live.confirmation_sent {
            return Err(ProtocolError::ConfirmationAlreadySent);
        }
        let (keys, transcript_hash, negotiated) =
            session_material(&live.keys, &live.transcript_hash, &selected)?;
        let signed = complete_signature_message(PAIRING_SERVER_SIG_CONTEXT, transcript_hash, csk);
        let server_signature = sign_ed25519(&live.server_identity, &signed);
        let payload = PairingCompletePayload { server_signature };
        let aad = context_with_hash(PAIRING_COMPLETE_AAD_CONTEXT, transcript_hash);
        let encrypted_complete = encrypt_with_key(
            negotiated.symmetric_algorithm,
            &keys.k_s2c,
            &payload.encode_to_vec(),
            &aad,
        )?;
        live.confirmation_sent = true;
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
        self.live()?;
        Ok(PairingKeepalive {})
    }

    /// Build an abort, authenticated with `K_s2c` when the keys already exist.
    ///
    /// Fails with [`ProtocolError::SessionConcluded`] once
    /// [`ServerPairingSession::conclude`] has run.
    pub fn create_abort(&self, reason: PairingAbortReason) -> Result<PairingAbort, ProtocolError> {
        let live = self.live()?;
        let auth_tag = match (live.keys.as_ref(), live.transcript_hash.as_ref()) {
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
        let live = self.live()?;
        verify_abort_tag(
            abort,
            live.keys.as_ref().map(|keys| &*keys.k_c2s),
            live.transcript_hash.as_ref(),
        )
    }
}
