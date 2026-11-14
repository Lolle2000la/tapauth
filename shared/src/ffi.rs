//! The Rust↔Kotlin surface of the TapAuth protocol v2 core.
//!
//! This module is the whole surface the Android application calls, and UniFFI
//! generates the Kotlin bindings from it (see `shared/uniffi.toml` and
//! `src/bin/uniffi-bindgen.rs`). Kotlin never parses protobuf: every
//! `*_packet`/`*_bytes` argument and return value is an opaque serialized protobuf
//! blob, and every signature, AEAD operation and pairing state transition happens
//! **inside** Rust. [`ops`] holds the byte-level logic (and its tests); this file
//! only converts arguments, calls into `ops`, and lets [`TapauthError`] surface as a
//! Kotlin `TapauthException`.
//!
//! ## Protocol role
//!
//! Android is the protocol **Server**: it verifies `AuthenticationRequest`,
//! `GrantConfirmation` and `AuthenticationCancel` envelopes from a paired Client,
//! answers with a signed+encrypted Grant or Denial, and runs the phone half of the
//! pairing handshake. Long-term keys (CSK, `Ed_S`, and the pairing session's
//! directional keys) stay in Rust; Kotlin holds a [`PairingSession`] handle whose
//! keys it can never read.
//!
//! ## Threading and safety
//!
//! Every free function here is stateless. The only shared state is a
//! [`PairingSession`], which owns its [`crate::protocol::pairing::ServerPairingSession`]
//! behind a [`Mutex`]; UniFFI objects must be `Send + Sync`, so a session is passed
//! across threads as an `Arc` and each call takes the lock.
//!
//! ## Errors
//!
//! [`TapauthError`] carries four variants that map 1:1 onto the Kotlin exceptions
//! the previous hand-written surface threw:
//!
//! - [`TapauthError::Argument`] — malformed caller input: wrong key/challenge/session
//!   lengths, an unsupported caller-chosen negotiation algorithm id, or a
//!   `PairingPacket` for another session.
//! - [`TapauthError::Security`] — an Ed25519 signature that does not verify, an AEAD
//!   tag/AAD failure, an algorithm downgrade, an unsupported protocol version or a
//!   persisted per-Client `SignatureAlgorithm` id this build cannot verify, a tampered
//!   temporal identifier, or a signed message of the wrong payload type.
//! - [`TapauthError::Io`] — bytes that are not a decodable protobuf message.
//! - [`TapauthError::State`] — internal state failures (a poisoned session lock, an
//!   unencodable packet, or a protocol call on a pairing session that already
//!   concluded).
//!
//! ## Verification ordering
//!
//! Every parse entry point verifies the `WrapperMessage` signature **before** the
//! inner payload is decoded, and pins `payload_type` before dispatching on it. A
//! forged envelope therefore never reaches a protobuf decoder.
//!
//! ## Key-material secrecy
//!
//! `K_c2s`, `K_s2c`, the transcript hash `H` and the ephemeral X25519 secret never
//! reach Kotlin. `Ed_S` is copied into the session and never returned. The values
//! Kotlin does receive are the ones it must persist or show: the paired client's
//! static `Ed_C`, the negotiated algorithms, the SAS, the provisioned CSK, and the
//! authentication context fields.

mod ops;

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::crypto::Ed25519KeyPair;
use crate::protocol::pairing::{ServerPairingSession, PAIRING_SESSION_ID_LEN};

use ops::{
    ProvisionedClient, VerifiedAuthRequest, VerifiedPairingResponse, CHALLENGE_LEN, CSK_LEN,
};

pub use ops::TapauthError;

/// Length of an Ed25519 public key.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

#[cfg(target_os = "android")]
use tracing_subscriber::prelude::*;

// ---------------------------------------------------------------------------
// Argument reading
// ---------------------------------------------------------------------------

/// Read a fixed-size key or identifier argument.
///
/// The message text is the one the previous JNI argument reader produced, so a
/// caller-side log or test that matched on it keeps matching.
fn fixed<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], TapauthError> {
    bytes.try_into().map_err(|_| TapauthError::Argument {
        detail: format!("{name} must be {N} bytes"),
    })
}

/// Read a 32-byte CSK argument. The Rust-side copy is zeroized on drop.
fn read_csk(bytes: &[u8]) -> Result<Zeroizing<[u8; CSK_LEN]>, TapauthError> {
    Ok(Zeroizing::new(fixed::<CSK_LEN>(bytes, "csk")?))
}

/// Read an Ed25519 keypair: a 32-byte signing key or a 64-byte full keypair.
///
/// A 64-byte keypair carries the signing key in its first half, which is the form
/// `generate_keypair` hands back, so a caller may persist and return either.
fn read_ed25519_keypair(bytes: &[u8], name: &str) -> Result<Ed25519KeyPair, TapauthError> {
    let signing_key: [u8; 32] = match bytes.len() {
        32 => fixed(bytes, name)?,
        64 => {
            let (signing_key, _public_key) = bytes.split_at(ED25519_PUBLIC_KEY_LEN);
            fixed(signing_key, name)?
        }
        _ => {
            return Err(TapauthError::Argument {
                detail: format!("{name} must be 32 bytes (signing key) or 64 bytes (full keypair)"),
            })
        }
    };

    Ed25519KeyPair::from_signing_key_bytes(&signing_key).map_err(|err| TapauthError::Argument {
        detail: format!("invalid Ed25519 keypair: {err}"),
    })
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// An `AuthenticationRequest` whose Ed25519 signature has been verified.
///
/// The four context fields are returned verbatim; Android sanitizes them for display.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ParsedAuthRequest {
    /// 32-byte challenge the Server must answer with a Grant or Denial.
    pub challenge: Vec<u8>,
    /// Target Linux account.
    pub username: String,
    /// Client hostname.
    pub hostname: String,
    /// Client wall-clock time, Unix seconds.
    pub timestamp_unix_seconds: i64,
    /// PAM service that triggered the request (verbatim).
    pub pam_service: String,
    /// Process name that triggered the request (verbatim).
    pub process_name: String,
    /// Truncated command line for display (verbatim).
    pub command_preview: String,
    /// Whether the requesting session has a terminal.
    pub tty_present: bool,
}

/// The provisioning payload of `PairingConfirmClient`, after AEAD decryption.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ParsedPairingProvision {
    /// The CSK the desktop provisioned; must be persisted by the phone.
    pub csk: Vec<u8>,
    /// Linux account this pairing authorizes.
    pub username: String,
    /// Authenticated Client hostname.
    pub client_hostname: String,
}

/// A `PairingResponse` whose QR commitment, signature and algorithm selection all
/// verified on the phone.
///
/// These are exactly the values the phone persists for the new paired device (its
/// static `Ed_C` and the three negotiated algorithms) plus the SAS the two users
/// compare out of band. `H`, `K_c2s`, `K_s2c` and the ephemeral secrets are
/// deliberately absent: they stay inside the [`PairingSession`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct ParsedPairingResponse {
    /// The SAS to display, for example `"123-456"`.
    pub sas: String,
    /// The desktop's static `Ed_C`, persisted as the paired device's public key.
    pub client_ed25519_public_key: Vec<u8>,
    /// Negotiated AEAD algorithm (client-wide, bound to the CSK).
    pub symmetric_algorithm: i32,
    /// Negotiated hash algorithm (client-wide, bound to the CSK).
    pub hash_algorithm: i32,
    /// Negotiated signature algorithm (per-server).
    pub signature_algorithm: i32,
}

impl From<VerifiedAuthRequest> for ParsedAuthRequest {
    fn from(verified: VerifiedAuthRequest) -> Self {
        Self {
            challenge: verified.challenge.to_vec(),
            username: verified.username,
            hostname: verified.hostname,
            timestamp_unix_seconds: verified.timestamp_unix_seconds as i64,
            pam_service: verified.pam_service,
            process_name: verified.process_name,
            command_preview: verified.command_preview,
            tty_present: verified.tty_present,
        }
    }
}

impl From<ProvisionedClient> for ParsedPairingProvision {
    fn from(provision: ProvisionedClient) -> Self {
        Self {
            csk: provision.csk.to_vec(),
            username: provision.username,
            client_hostname: provision.client_hostname,
        }
    }
}

impl From<VerifiedPairingResponse> for ParsedPairingResponse {
    fn from(verified: VerifiedPairingResponse) -> Self {
        Self {
            sas: verified.sas,
            client_ed25519_public_key: verified.client_ed25519_public_key.to_vec(),
            symmetric_algorithm: verified.symmetric_algorithm,
            hash_algorithm: verified.hash_algorithm,
            signature_algorithm: verified.signature_algorithm,
        }
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 keypair for the phone's long-term identity (`Ed_S`).
///
/// ## Returns
///
/// A 2-element array containing `[private key (32), public key (32)]`.
///
/// ## Errors
///
/// - [`TapauthError::Security`]: CSPRNG failure
#[uniffi::export]
pub fn generate_keypair() -> Result<Vec<Vec<u8>>, TapauthError> {
    let keypair = Ed25519KeyPair::generate().map_err(|err| TapauthError::Security {
        detail: format!("key generation failed: {err}"),
    })?;
    let private_bytes = Zeroizing::new(keypair.signing_key_bytes());
    Ok(vec![
        private_bytes.to_vec(),
        keypair.verifying_key_bytes().to_vec(),
    ])
}

// ---------------------------------------------------------------------------
// Encrypted packet (outer AEAD framing)
// ---------------------------------------------------------------------------

/// Decrypt an `EncryptedPacket` under the CSK and return the serialized
/// `WrapperMessage` bytes.
///
/// The packet's `encryption_algorithm` must equal `expected_symmetric_algorithm`; the
/// check runs before any AEAD work. The AAD is `tapauth-pkt-v2 || be32(algorithm) ||
/// be16(len) || temporal_identifier`, so a tampered identifier or a relabelled
/// algorithm fails the tag.
///
/// ## Arguments
///
/// * `encrypted_packet_bytes` - serialized `EncryptedPacket`
/// * `csk` - 32-byte Client Symmetric Key
/// * `expected_symmetric_algorithm` - negotiated `SymmetricAlgorithm` id (1 =
///   AES-256-GCM, 2 = ChaCha20-Poly1305)
///
/// ## Returns
///
/// The decrypted `WrapperMessage` bytes, exactly as the peer serialized them.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong CSK length, unknown algorithm id
/// - [`TapauthError::Io`]: `encrypted_packet_bytes` is not a decodable
///   `EncryptedPacket`
/// - [`TapauthError::Security`]: algorithm mismatch, AEAD tag/AAD failure
#[uniffi::export]
pub fn decrypt_encrypted_packet(
    encrypted_packet_bytes: Vec<u8>,
    csk: Vec<u8>,
    expected_symmetric_algorithm: i32,
) -> Result<Vec<u8>, TapauthError> {
    let csk = read_csk(&csk)?;
    ops::decrypt_packet_bytes(&encrypted_packet_bytes, &csk, expected_symmetric_algorithm)
}

/// Read the 16-byte `temporal_identifier` of a serialized `EncryptedPacket`.
///
/// This is the pre-decryption filter: Kotlin can match the identifier against the
/// paired Clients' per-device CSKs before spending CPU on AEAD.
///
/// ## Errors
///
/// - [`TapauthError::Io`]: `packet_bytes` is not a decodable `EncryptedPacket`
/// - [`TapauthError::Argument`]: the identifier is not 16 bytes
#[uniffi::export]
pub fn extract_temporal_identifier(packet_bytes: Vec<u8>) -> Result<Vec<u8>, TapauthError> {
    Ok(ops::encrypted_packet_temporal_identifier(&packet_bytes)?.to_vec())
}

// ---------------------------------------------------------------------------
// Authentication messages from the Client
// ---------------------------------------------------------------------------

/// Verify an `AuthenticationRequest` and return its fields.
///
/// The Ed25519 signature is verified over the raw payload bytes **before** the inner
/// protobuf is decoded, and `payload_type` must be `PAYLOAD_TYPE_AUTH_REQUEST`.
///
/// ## Arguments
///
/// * `wrapper_bytes` - decrypted serialized `WrapperMessage`
/// * `client_ed25519_pub` - 32-byte public key of the paired Client
/// * `protocol_version` - must be `2`
/// * `expected_signature_algorithm` - the paired Client's persisted
///   `SignatureAlgorithm` id (`1` = ED25519); never derived from the message
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong key/challenge length
/// - [`TapauthError::Io`]: `wrapper_bytes` is not a decodable `WrapperMessage`
/// - [`TapauthError::Security`]: `protocol_version != 2`, bad signature, wrong payload
///   type, wrong wrapper version, or an `expected_signature_algorithm` this build
///   cannot verify
#[uniffi::export]
pub fn parse_and_verify_auth_request(
    wrapper_bytes: Vec<u8>,
    client_ed25519_pub: Vec<u8>,
    protocol_version: i32,
    expected_signature_algorithm: i32,
) -> Result<ParsedAuthRequest, TapauthError> {
    let public_key = fixed::<ED25519_PUBLIC_KEY_LEN>(&client_ed25519_pub, "clientEd25519Pub")?;
    let parsed = ops::parse_auth_request_verified(
        &wrapper_bytes,
        &public_key,
        protocol_version,
        expected_signature_algorithm,
    )?;

    // The protobuf field is `uint64`; a value that does not fit the Kotlin `Long`
    // is a caller-visible range failure, not a silently wrapped timestamp.
    if parsed.timestamp_unix_seconds > i64::MAX as u64 {
        return Err(TapauthError::Argument {
            detail: "timestamp is out of range".to_string(),
        });
    }
    Ok(parsed.into())
}

/// Verify a `GrantConfirmation` and return the acknowledged challenge.
///
/// ## Returns
///
/// The 32-byte challenge the Client confirmed.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong key/challenge length
/// - [`TapauthError::Io`]: `wrapper_bytes` is not a decodable `WrapperMessage`
/// - [`TapauthError::Security`]: `protocol_version != 2`, bad signature, wrong payload
///   type, or an `expected_signature_algorithm` this build cannot verify
#[uniffi::export]
pub fn parse_and_verify_grant_confirmation(
    wrapper_bytes: Vec<u8>,
    client_ed25519_pub: Vec<u8>,
    protocol_version: i32,
    expected_signature_algorithm: i32,
) -> Result<Vec<u8>, TapauthError> {
    let public_key = fixed::<ED25519_PUBLIC_KEY_LEN>(&client_ed25519_pub, "clientEd25519Pub")?;
    Ok(ops::parse_grant_confirmation_verified(
        &wrapper_bytes,
        &public_key,
        protocol_version,
        expected_signature_algorithm,
    )?
    .to_vec())
}

/// Verify an `AuthenticationCancel` and return the cancelled challenge.
///
/// ## Returns
///
/// The 32-byte challenge the Client cancelled.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong key/challenge length
/// - [`TapauthError::Io`]: `wrapper_bytes` is not a decodable `WrapperMessage`
/// - [`TapauthError::Security`]: `protocol_version != 2`, bad signature, wrong payload
///   type, or an `expected_signature_algorithm` this build cannot verify
#[uniffi::export]
pub fn parse_and_verify_auth_cancel(
    wrapper_bytes: Vec<u8>,
    client_ed25519_pub: Vec<u8>,
    protocol_version: i32,
    expected_signature_algorithm: i32,
) -> Result<Vec<u8>, TapauthError> {
    let public_key = fixed::<ED25519_PUBLIC_KEY_LEN>(&client_ed25519_pub, "clientEd25519Pub")?;
    Ok(ops::parse_auth_cancel_verified(
        &wrapper_bytes,
        &public_key,
        protocol_version,
        expected_signature_algorithm,
    )?
    .to_vec())
}

/// Name the payload type of a serialized `WrapperMessage`, for dispatch only.
///
/// The returned name is **not** authenticated; Kotlin uses it solely to choose which
/// verifying parse entry point to call next, and that entry point re-checks the
/// signature and the payload type.
///
/// ## Returns
///
/// `"AUTH_REQUEST"`, `"AUTH_GRANT"`, `"AUTH_DENIAL"`, `"GRANT_CONFIRMATION"`,
/// `"AUTH_CANCEL"`, or `None` for an `UNSPECIFIED` payload type.
///
/// ## Errors
///
/// - [`TapauthError::Io`]: `wrapper_message_bytes` is not a decodable
///   `WrapperMessage`
#[uniffi::export]
pub fn determine_message_type(
    wrapper_message_bytes: Vec<u8>,
) -> Result<Option<String>, TapauthError> {
    Ok(ops::message_type_name(&wrapper_message_bytes)?.map(str::to_string))
}

// ---------------------------------------------------------------------------
// Grant / Denial construction
// ---------------------------------------------------------------------------

/// Sign a Grant and return the serialized `EncryptedPacket` to send.
///
/// The single Ed25519 signature covers
/// `"tapauth-sig-v2" || be32(version) || be32(signature_algorithm) ||
/// be32(payload_type) || payload`; the packet is then AEAD-encrypted under the CSK
/// with the negotiated symmetric and hash algorithms.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong challenge/CSK/key length, unknown algorithm id
/// - [`TapauthError::Security`]: signing, temporal-identifier derivation or
///   encryption fails
/// - [`TapauthError::Io`]: protobuf encoding fails
#[uniffi::export]
pub fn create_grant_wrapper_message(
    challenge: Vec<u8>,
    server_priv_key: Vec<u8>,
    csk: Vec<u8>,
    symmetric_algorithm: i32,
    hash_algorithm: i32,
) -> Result<Vec<u8>, TapauthError> {
    let challenge = fixed::<CHALLENGE_LEN>(&challenge, "challenge")?;
    let keypair = read_ed25519_keypair(&server_priv_key, "serverPrivKey")?;
    let csk = read_csk(&csk)?;
    ops::build_grant_packet(
        &challenge,
        &keypair,
        &csk,
        symmetric_algorithm,
        hash_algorithm,
    )
}

/// Sign a Denial and return the serialized `EncryptedPacket` to send.
///
/// `reason` travels inside the signed payload and is shown on the Client's PAM
/// prompt, so it must not contain secrets.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong challenge/CSK/key length, unknown algorithm id
/// - [`TapauthError::Security`]: signing, temporal-identifier derivation or
///   encryption fails
/// - [`TapauthError::Io`]: protobuf encoding fails
#[uniffi::export]
pub fn create_denial_wrapper_message(
    challenge: Vec<u8>,
    reason: String,
    server_priv_key: Vec<u8>,
    csk: Vec<u8>,
    symmetric_algorithm: i32,
    hash_algorithm: i32,
) -> Result<Vec<u8>, TapauthError> {
    let challenge = fixed::<CHALLENGE_LEN>(&challenge, "challenge")?;
    let keypair = read_ed25519_keypair(&server_priv_key, "serverPrivKey")?;
    let csk = read_csk(&csk)?;
    ops::build_denial_packet(
        &challenge,
        &reason,
        &keypair,
        &csk,
        symmetric_algorithm,
        hash_algorithm,
    )
}

// ---------------------------------------------------------------------------
// Discovery: temporal identifiers
// ---------------------------------------------------------------------------

/// Derive the 16-byte UDP/GATT temporal identifier for `window`.
///
/// The identifier is `HMAC-SHA256(csk, be64(window))` (or keyed BLAKE3) truncated to
/// 16 bytes, so it proves CSK possession without revealing the key. Each paired
/// Client persists its own `hashAlgorithm`; Kotlin must pass that stored value.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong CSK length, negative window, unknown hash
///   algorithm id
/// - [`TapauthError::Security`]: derivation fails
#[uniffi::export]
pub fn generate_temporal_identifier(
    csk: Vec<u8>,
    window: i64,
    hash_algorithm: i32,
) -> Result<Vec<u8>, TapauthError> {
    let csk = read_csk(&csk)?;
    Ok(ops::temporal_identifier(&csk, window, hash_algorithm)?.to_vec())
}

/// Derive the 10-byte BLE advertisement temporal identifier for `window`.
///
/// Same keyed MAC as [`generate_temporal_identifier`], truncated to 10 bytes to fit
/// the advertisement budget.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong CSK length, negative window, unknown hash
///   algorithm id
/// - [`TapauthError::Security`]: derivation fails
#[uniffi::export]
pub fn generate_ble_temporal_identifier(
    csk: Vec<u8>,
    window: i64,
    hash_algorithm: i32,
) -> Result<Vec<u8>, TapauthError> {
    let csk = read_csk(&csk)?;
    Ok(ops::ble_temporal_identifier(&csk, window, hash_algorithm)?.to_vec())
}

/// The current 60-second time window (`unix_seconds / 60`).
///
/// ## Errors
///
/// - [`TapauthError::Security`]: the system clock is before the Unix epoch
#[uniffi::export]
pub fn current_time_window() -> Result<i64, TapauthError> {
    ops::time_window_now()
}

/// Check a received temporal identifier against the current and previous window.
///
/// Accepts both the 16-byte UDP/GATT form and the 10-byte BLE form. Use the paired
/// Client's stored `hashAlgorithm`.
///
/// ## Returns
///
/// `true` if the identifier matches the current or previous window.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong CSK length, identifier is neither 10 nor 16
///   bytes, unknown hash algorithm id
/// - [`TapauthError::Security`]: derivation fails
#[uniffi::export]
pub fn verify_temporal_identifier(
    temporal_identifier: Vec<u8>,
    csk: Vec<u8>,
    hash_algorithm: i32,
) -> Result<bool, TapauthError> {
    let csk = read_csk(&csk)?;
    ops::verify_temporal_identifier(&temporal_identifier, &csk, hash_algorithm)
}

/// Derive the 10-byte BLE pairing advertisement identifier from the scanned QR code.
///
/// The value is `SHA-256("tapauth-ble-pair-v2" || sessionId || clientX25519Pub)[..10]`.
///
/// ## Arguments
///
/// * `session_id` - 16-byte `sid` from the QR code
/// * `client_x25519_pub` - 32-byte `pk` from the QR code
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: wrong session-id or public-key length
#[uniffi::export]
pub fn derive_ble_pairing_adv_id(
    session_id: Vec<u8>,
    client_x25519_pub: Vec<u8>,
) -> Result<Vec<u8>, TapauthError> {
    let public_key = fixed::<ED25519_PUBLIC_KEY_LEN>(&client_x25519_pub, "clientX25519Pub")?;
    Ok(ops::ble_pairing_adv_id(&session_id, &public_key)?.to_vec())
}

/// Extract the 16-byte `session_id` of a serialized `PairingPacket`.
///
/// Used to filter frames for the session currently pairing before spending any crypto
/// on them. A frame with a foreign protocol version or a session id that is not 16
/// bytes is rejected.
///
/// ## Errors
///
/// - [`TapauthError::Argument`]: undecodable packet, wrong version, wrong session-id
///   length
#[uniffi::export]
pub fn pairing_packet_session_id(packet_bytes: Vec<u8>) -> Result<Vec<u8>, TapauthError> {
    Ok(ops::pairing_packet_session_id(&packet_bytes)?.to_vec())
}

// ---------------------------------------------------------------------------
// Pairing (phone side; stateful, one object per session)
// ---------------------------------------------------------------------------

/// A phone-side pairing session.
///
/// The object owns the ephemeral X25519 secret and the directional keys; `Ed_S` is
/// copied into it and never returned. Kotlin holds an `Arc` of this object, so a
/// session is released by dropping the reference — there is no handle to free, and
/// therefore no stale-handle or double-free case to represent or to guard against.
///
/// Dropping the last reference zeroizes the keys: the session's fields are
/// `SecretBox` (`Ed_S`, `x_S`) and `Zeroizing` (`K_c2s`, `K_s2c`) values, and the
/// transcript hash is a plain array inside the session struct.
#[derive(uniffi::Object)]
pub struct PairingSession {
    /// The protocol state machine, guarded so `&self` methods can take `&mut` access.
    inner: Mutex<ServerPairingSession>,
}

impl PairingSession {
    /// Run `f` with exclusive access to the session state.
    ///
    /// A poisoned lock (a panic while the session was borrowed) is a
    /// [`TapauthError::State`] rather than a propagated panic, so Kotlin sees an
    /// exception on its own thread instead of an unwind across the FFI boundary.
    fn with<T>(
        &self,
        f: impl FnOnce(&mut ServerPairingSession) -> Result<T, TapauthError>,
    ) -> Result<T, TapauthError> {
        let mut session = self.inner.lock().map_err(|_| TapauthError::State {
            detail: "pairing session state is poisoned".to_string(),
        })?;
        f(&mut session)
    }
}

#[uniffi::export]
impl PairingSession {
    /// Start a phone-side pairing session from the scanned QR code.
    ///
    /// ## Arguments
    ///
    /// * `session_id` - 16-byte `sid` from the QR code
    /// * `server_ed25519_priv_key` - 32-byte (or 64-byte keypair) private `Ed_S`
    /// * `server_device_name` - display name, truncated to 64 UTF-8 bytes
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::Argument`]: wrong session-id or key length
    /// - [`TapauthError::Security`]: ephemeral key generation fails
    #[uniffi::constructor]
    pub fn new(
        session_id: Vec<u8>,
        server_ed25519_priv_key: Vec<u8>,
        server_device_name: String,
    ) -> Result<Arc<Self>, TapauthError> {
        let session_id = fixed::<PAIRING_SESSION_ID_LEN>(&session_id, "sessionId")?;
        let identity = read_ed25519_keypair(&server_ed25519_priv_key, "serverEd25519PrivKey")?;
        let session = ServerPairingSession::new(session_id, identity, &server_device_name)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(session),
        }))
    }

    /// Build the `PairingInit` to send (serialized `PairingPacket`).
    ///
    /// Retransmissions must re-send these exact bytes rather than calling this again
    /// for a fresh message; the cached copy is returned either way.
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::State`]: the session already concluded, the packet cannot
    ///   be encoded, or the session lock is poisoned
    pub fn create_init(&self) -> Result<Vec<u8>, TapauthError> {
        self.with(ops::pairing_create_init)
    }

    /// Verify the desktop's `PairingResponse` and return the SAS, `Ed_C` and the
    /// negotiated algorithms.
    ///
    /// The QR commitment (`client_x25519_public_key == pk`) is checked first, in
    /// constant time and without any "skip the pin" sentinel, then the Client's
    /// Ed25519 signature over the transcript hash, then the keys and SAS are derived.
    /// A response that fails any of these caches nothing, so a later genuine response
    /// still verifies. `H`, `K_c2s` and `K_s2c` stay inside this object and are never
    /// returned.
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::Argument`]: undecodable or foreign-session packet, wrong
    ///   packet type or key length
    /// - [`TapauthError::Security`]: QR key mismatch, bad client signature,
    ///   unsupported algorithm selection, key derivation failure
    /// - [`TapauthError::State`]: the session already concluded, or the session lock
    ///   is poisoned
    pub fn verify_response(
        &self,
        response_packet: Vec<u8>,
        expected_qr_pk: Vec<u8>,
    ) -> Result<ParsedPairingResponse, TapauthError> {
        let qr_public_key = fixed::<ED25519_PUBLIC_KEY_LEN>(&expected_qr_pk, "expectedQrPk")?;
        self.with(|session| {
            ops::pairing_verify_response(session, &response_packet, &qr_public_key)
                .map(ParsedPairingResponse::from)
        })
    }

    /// Decrypt the desktop's provisioning payload (`PairingConfirmClient`).
    ///
    /// ## Returns
    ///
    /// The 32-byte CSK, the authorized username and the Client hostname. The CSK must
    /// be persisted by the caller.
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::Argument`]: undecodable or foreign-session packet, wrong
    ///   packet type
    /// - [`TapauthError::Security`]: AEAD failure, or a provisioning payload whose CSK
    ///   is not 32 bytes
    /// - [`TapauthError::State`]: the session lock is poisoned
    pub fn process_confirm_client(
        &self,
        confirm_client_packet: Vec<u8>,
    ) -> Result<ParsedPairingProvision, TapauthError> {
        self.with(|session| {
            ops::pairing_process_confirm_client(session, &confirm_client_packet)
                .map(ParsedPairingProvision::from)
        })
    }

    /// Build the completion proof (serialized `PairingPacket` with
    /// `PairingConfirmServer`).
    ///
    /// The phone signs `"tapauth-pair-server-sig-v2" || H || csk` with `Ed_S` and
    /// encrypts it under `K_s2c`. Retransmissions must re-send the same bytes.
    ///
    /// This is a **terminal** call: on success the session concludes, so every
    /// later call fails with [`TapauthError::State`] instead of reviving a session
    /// whose keys are gone. A failed call leaves the session untouched.
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::Argument`]: wrong CSK length
    /// - [`TapauthError::Security`]: the session is not keyed yet, signing or
    ///   encryption fails
    /// - [`TapauthError::State`]: the session already concluded, the packet cannot
    ///   be encoded, or the session lock is poisoned
    pub fn create_confirm_server(&self, csk: Vec<u8>) -> Result<Vec<u8>, TapauthError> {
        let csk = read_csk(&csk)?;
        self.with(|session| {
            let frame = ops::pairing_create_confirm_server(session, &csk)?;
            // Terminal: the completion proof is the last message of the handshake.
            session.conclude();
            Ok(frame)
        })
    }

    /// Build a keepalive frame (serialized `PairingPacket` with `PairingKeepalive`).
    ///
    /// The frame carries no key material and drives no state transition: it only keeps
    /// the transport path open while the users compare the SAS. Retransmission is
    /// idempotent, since the message body is empty.
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::State`]: the packet cannot be encoded, or the session lock is
    ///   poisoned
    pub fn create_keepalive(&self) -> Result<Vec<u8>, TapauthError> {
        self.with(|session| ops::pairing_create_keepalive(session))
    }

    /// Build an abort (serialized `PairingPacket` with `PairingAbort`).
    ///
    /// Once the session keys exist the abort carries an HMAC tag, so a network observer
    /// cannot spoof a cancellation.
    ///
    /// Like [`PairingSession::create_confirm_server`], this is a **terminal** call:
    /// on success the session concludes, so a second abort (or any other call) fails
    /// with [`TapauthError::State`].
    ///
    /// ## Arguments
    ///
    /// * `reason` - `PairingAbortReason` id (1 = USER_REJECTED_SAS, 2 = KEY_MISMATCH,
    ///   3 = UNSUPPORTED_ALGORITHM, 4 = PROTOCOL_ERROR, 5 = SESSION_EXPIRED)
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::Argument`]: unknown reason id
    /// - [`TapauthError::State`]: the session already concluded, the packet cannot
    ///   be encoded, or the session lock is poisoned
    pub fn create_abort(&self, reason: i32) -> Result<Vec<u8>, TapauthError> {
        self.with(|session| {
            let frame = ops::pairing_create_abort(session, reason)?;
            // Terminal: nothing follows a cancellation.
            session.conclude();
            Ok(frame)
        })
    }

    /// Verify an abort received from the desktop.
    ///
    /// ## Returns
    ///
    /// `true` for an authenticated abort, `false` for a tag-less abort received before
    /// any key exists (unauthenticated by construction, so it must not cancel the
    /// pairing).
    ///
    /// ## Errors
    ///
    /// - [`TapauthError::Argument`]: undecodable or foreign-session packet, wrong
    ///   packet type
    /// - [`TapauthError::Security`]: bad abort tag, or a tag-less abort once the keys
    ///   exist
    /// - [`TapauthError::State`]: the session already concluded, or the session lock
    ///   is poisoned
    pub fn verify_abort(&self, abort_packet: Vec<u8>) -> Result<bool, TapauthError> {
        self.with(|session| ops::pairing_verify_abort(session, &abort_packet))
    }
}

// ---------------------------------------------------------------------------
// Logging initialization
// ---------------------------------------------------------------------------

/// Initialize native Android logcat forwarding for tracing events.
///
/// Configures a global tracing subscriber with API 30 structured log support.
/// Automatically hooks file strings, line counts, and thread naming metadata.
///
/// Must be called once after `System.loadLibrary`. Subsequent calls are no-ops
/// thanks to `std::sync::Once`.
#[cfg(target_os = "android")]
static INIT_LOGGING: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "android")]
#[uniffi::export]
pub fn init_logging() {
    INIT_LOGGING.call_once(|| {
        let android_layer = paranoid_android::layer("TapAuthNative")
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .with_thread_names(true)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG);

        tracing_subscriber::registry().with(android_layer).init();
    });
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
    use crate::crypto::{encrypted_packet_aad, generate_temporal_id_with_alg, ClientSymmetricKey};
    use crate::protocol::messages::{
        create_auth_request_with_context, sign_wrapper_message, verify_and_decode_payload,
        DecodedPayload, PROTOCOL_VERSION_V2,
    };
    use crate::protocol::packet::{
        create_encrypted_packet_with_csk_nonce, decrypt_encrypted_packet_with_csk_nonce,
        extract_challenge, wrap_auth_cancel, wrap_auth_request, wrap_grant_confirmation,
    };
    use crate::protocol::pairing::{
        decode_pairing_packet, encode_pairing_packet, ClientPairingState, PinnedAlgorithms,
        PAIRING_SESSION_ID_LEN,
    };
    use crate::protocol::pb::{
        pairing_packet, AuthenticationCancel, AuthenticationRequest, EncryptedPacket,
        GrantConfirmation, HashAlgorithm, PairingAbort, PairingAbortReason, PairingKeepalive,
        PairingPacket, PayloadType, SignatureAlgorithm, SymmetricAlgorithm, WrapperMessage,
    };
    use ops::{BLE_TEMPORAL_ID_LEN, TEMPORAL_ID_LEN};
    use prost::Message as ProstMessage;

    const AES: i32 = SymmetricAlgorithm::Aes256Gcm as i32;
    const CHACHA: i32 = SymmetricAlgorithm::Chacha20Poly1305 as i32;
    const SHA256: i32 = HashAlgorithm::Sha256 as i32;
    const BLAKE3: i32 = HashAlgorithm::Blake3 as i32;
    const ED25519: i32 = SignatureAlgorithm::Ed25519 as i32;

    fn context_request(challenge: [u8; 32]) -> AuthenticationRequest {
        create_auth_request_with_context(
            "luca",
            "thinkpad",
            &challenge,
            "sudo",
            "sudo",
            "apt upgrade",
            true,
        )
        .unwrap()
    }

    /// Sign a request wrapper with `keypair` and return its wire bytes.
    fn signed_request(keypair: &Ed25519KeyPair, request: AuthenticationRequest) -> Vec<u8> {
        let mut wrapper = wrap_auth_request(request);
        sign_wrapper_message(&mut wrapper, keypair).unwrap();
        wrapper.encode_to_vec()
    }

    /// An `EncryptedPacket` carrying a signed grant, serialized.
    fn grant_packet(
        csk: &[u8; 32],
        signer: &Ed25519KeyPair,
        symmetric: i32,
        challenge: [u8; 32],
    ) -> Vec<u8> {
        create_grant_wrapper_message(
            challenge.to_vec(),
            signer.signing_key_bytes().to_vec(),
            csk.to_vec(),
            symmetric,
            SHA256,
        )
        .unwrap()
    }

    fn session_packet(
        session_id: &[u8; PAIRING_SESSION_ID_LEN],
        msg: pairing_packet::Msg,
    ) -> Vec<u8> {
        encode_pairing_packet(&PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: session_id.to_vec(),
            msg: Some(msg),
        })
        .unwrap()
    }

    fn init_of(packet_bytes: &[u8]) -> crate::protocol::pb::PairingInit {
        match decode_pairing_packet(packet_bytes).unwrap().msg {
            Some(pairing_packet::Msg::Init(init)) => init,
            other => panic!("expected PairingInit, got {other:?}"),
        }
    }

    fn confirm_server_of(packet_bytes: &[u8]) -> crate::protocol::pb::PairingConfirmServer {
        match decode_pairing_packet(packet_bytes).unwrap().msg {
            Some(pairing_packet::Msg::ConfirmServer(confirm)) => confirm,
            other => panic!("expected PairingConfirmServer, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // generateKeypair
    // ---------------------------------------------------------------

    /// The exported keypair is `[private (32), public (32)]`, the two halves belong
    /// together, and two calls yield different identities.
    /// The defect this catches: the array returned in the other order (a caller that
    /// persists element 0 as the public key would pair with a private key), a half
    /// that does not correspond to the other (a signature made with element 0 fails to
    /// verify under element 1), a wrong length, or a "generation" that returns a
    /// constant.
    #[test]
    fn generate_keypair_returns_a_signing_key_and_its_public_key() {
        let keypair = generate_keypair().unwrap();
        assert_eq!(keypair.len(), 2, "the result is [private, public]");
        assert_eq!(keypair[0].len(), 32);
        assert_eq!(keypair[1].len(), 32);
        assert_ne!(
            keypair[0], keypair[1],
            "the private key is not the public one"
        );

        let seed: [u8; 32] = keypair[0].as_slice().try_into().unwrap();
        let signing = Ed25519KeyPair::from_signing_key_bytes(&seed).unwrap();
        assert_eq!(signing.verifying_key_bytes().to_vec(), keypair[1]);

        let bytes = signed_request(&signing, context_request([0x0F; 32]));
        let parsed = parse_and_verify_auth_request(bytes, keypair[1].clone(), 2, ED25519).unwrap();
        assert_eq!(parsed.challenge, vec![0x0F; 32]);

        assert_ne!(
            generate_keypair().unwrap()[0],
            keypair[0],
            "each call must draw a fresh key"
        );
    }

    // ---------------------------------------------------------------
    // decryptEncryptedPacket
    // ---------------------------------------------------------------

    /// A genuine packet decrypts to the exact serialized `WrapperMessage` bytes for
    /// both AEAD algorithms, byte for byte — including protobuf fields this build does
    /// not know, which a decode/re-encode round trip would silently drop.
    /// The defect this catches: a decrypt path that ignores the caller's pinned
    /// algorithm, rebuilds the plaintext from a decoded struct instead of returning the
    /// peer's bytes, or only implements one of the two negotiated algorithms.
    #[test]
    fn decrypt_packet_accepts_genuine_packets_for_both_algorithms() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();

        for symmetric in [AES, CHACHA] {
            let algorithm = SymmetricAlgorithm::try_from(symmetric).unwrap();
            let mut wrapper = wrap_auth_request(context_request([0x21; 32]));
            sign_wrapper_message(&mut wrapper, &keypair).unwrap();

            let packet = create_encrypted_packet_with_csk_nonce(
                &csk,
                algorithm,
                HashAlgorithm::Sha256,
                &wrapper,
            )
            .unwrap();
            let plaintext =
                decrypt_encrypted_packet(packet.encode_to_vec(), csk_bytes.to_vec(), symmetric)
                    .unwrap();
            assert_eq!(plaintext, wrapper.encode_to_vec());

            // Hand-build the packet so the plaintext carries an unknown field
            // (field 99, wire type 2: key 0x031A -> [0x9a, 0x06], len 3, "xyz").
            // A decrypt that re-encodes a decoded `WrapperMessage` loses those bytes.
            let mut wire = wrapper.encode_to_vec();
            wire.extend_from_slice(&[0x9a, 0x06, 0x03, b'x', b'y', b'z']);
            let temporal_identifier = generate_temporal_id_with_alg(
                &csk,
                current_time_window().unwrap() as u64,
                HashAlgorithm::Sha256,
            )
            .unwrap();
            let aad = encrypted_packet_aad(symmetric, &temporal_identifier);
            let ciphertext =
                crate::crypto::encrypt_with_csk_and_random_nonce(&csk, algorithm, &wire, &aad)
                    .unwrap();
            let raw_packet = EncryptedPacket {
                temporal_identifier: temporal_identifier.to_vec(),
                encryption_algorithm: symmetric,
                ciphertext,
            };

            let plaintext =
                decrypt_encrypted_packet(raw_packet.encode_to_vec(), csk_bytes.to_vec(), symmetric)
                    .unwrap();
            assert_eq!(
                plaintext, wire,
                "the peer's plaintext bytes are returned verbatim"
            );

            // The decrypted bytes still verify, so the pipeline is intact end to end.
            let verified = parse_and_verify_auth_request(
                plaintext,
                keypair.verifying_key_bytes().to_vec(),
                2,
                ED25519,
            )
            .unwrap();
            assert_eq!(verified.challenge, vec![0x21; 32]);
        }
    }

    /// A packet whose header names a different algorithm than the caller pinned is
    /// rejected before any AEAD work.
    /// The defect this catches: a downgrade accepted by decrypting under the packet's
    /// self-declared algorithm instead of the negotiated one.
    #[test]
    fn decrypt_packet_rejects_algorithm_mismatch_before_decrypting() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();

        let mut packet =
            EncryptedPacket::decode(grant_packet(&csk_bytes, &keypair, AES, [0x31; 32]).as_slice())
                .unwrap();
        assert_eq!(packet.encryption_algorithm, AES);

        // Unusable ciphertext: only a pre-decryption check can report a mismatch here.
        packet.ciphertext = vec![0x00];
        let bytes = packet.encode_to_vec();

        match decrypt_encrypted_packet(bytes.clone(), csk_bytes.to_vec(), CHACHA) {
            Err(TapauthError::Security { detail }) => {
                assert!(detail.contains("algorithm"), "unexpected message: {detail}");
            }
            other => panic!("expected an algorithm mismatch, got {other:?}"),
        }

        // Control: with the matching algorithm the same packet is a crypto failure,
        // not an algorithm mismatch.
        assert!(matches!(
            decrypt_encrypted_packet(bytes.clone(), csk_bytes.to_vec(), AES),
            Err(TapauthError::Security { detail }) if detail.contains("decryption failed")
        ));

        // An unknown/unspecified algorithm id is a caller error, not a security event.
        assert!(matches!(
            decrypt_encrypted_packet(bytes, csk_bytes.to_vec(), 0),
            Err(TapauthError::Argument { .. })
        ));
    }

    /// A flipped ciphertext bit and a flipped temporal-identifier bit both fail the tag.
    /// The defect this catches: a missing AAD binding (temporal identifier tampering
    /// silently accepted) or a decrypt path that returns empty bytes instead of
    /// raising.
    #[test]
    fn decrypt_packet_rejects_tampered_tag_and_temporal_identifier() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();
        let genuine = grant_packet(&csk_bytes, &keypair, AES, [0x41; 32]);

        let packet = EncryptedPacket::decode(genuine.as_slice()).unwrap();

        // Tampered tag (last byte of the AEAD tag).
        let mut tampered_tag = packet.clone();
        let last = tampered_tag.ciphertext.len() - 1;
        tampered_tag.ciphertext[last] ^= 0x01;
        assert_eq!(tampered_tag.ciphertext.len(), packet.ciphertext.len());
        match decrypt_encrypted_packet(tampered_tag.encode_to_vec(), csk_bytes.to_vec(), AES) {
            Err(TapauthError::Security { detail }) => {
                assert!(
                    detail.contains("decryption failed"),
                    "unexpected message: {detail}"
                );
            }
            other => panic!("expected an AEAD failure, got {other:?}"),
        }

        // Tampered temporal identifier (bound into the AAD).
        let mut tampered_id = packet.clone();
        tampered_id.temporal_identifier[0] ^= 0x01;
        assert_eq!(tampered_id.ciphertext, packet.ciphertext);
        assert!(matches!(
            decrypt_encrypted_packet(tampered_id.encode_to_vec(), csk_bytes.to_vec(), AES),
            Err(TapauthError::Security { .. })
        ));

        // The untouched packet still decrypts, so the tampering above was the cause.
        assert!(decrypt_encrypted_packet(genuine, csk_bytes.to_vec(), AES).is_ok());
    }

    /// Bytes that are not a decodable `EncryptedPacket` are an I/O failure, not a panic.
    #[test]
    fn decrypt_packet_rejects_undecodable_packet() {
        assert!(matches!(
            decrypt_encrypted_packet(vec![0xFF, 0xFF, 0xFF], vec![0x11u8; 32], AES),
            Err(TapauthError::Io { .. })
        ));
    }

    /// A `temporal_identifier` that is not 16 bytes is a malformed envelope on the
    /// path Android actually uses, so it must be an *argument* failure raised before
    /// any decryption.
    /// The defect this catches: `decrypt_packet_bytes` skipping the length rule that
    /// `decrypt_encrypted_packet_with_csk_nonce` enforces, so a short identifier is
    /// either accepted as a valid frame or reported only as an AEAD failure (which
    /// makes a malformed envelope indistinguishable from a forged one).
    #[test]
    fn decrypt_packet_rejects_non_16_byte_temporal_identifier() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk_bytes = *csk.as_bytes();
        let genuine = grant_packet(&csk_bytes, &keypair, AES, [0x42; 32]);

        // The genuine 16-byte packet still decrypts, and to the genuine signed
        // grant, so the rejections below are caused by the identifier length and
        // nothing else.
        let decrypted = decrypt_encrypted_packet(genuine.clone(), csk_bytes.to_vec(), AES).unwrap();
        let wrapper = WrapperMessage::decode(decrypted.as_slice()).unwrap();
        match verify_and_decode_payload(&wrapper, &keypair.verifying_key_bytes(), ED25519).unwrap()
        {
            DecodedPayload::AuthGrant(grant) => assert_eq!(grant.challenge, vec![0x42; 32]),
            other => panic!("expected the genuine AuthGrant, got {other:?}"),
        }

        let packet = EncryptedPacket::decode(genuine.as_slice()).unwrap();
        assert_eq!(packet.temporal_identifier.len(), TEMPORAL_ID_LEN);

        for len in [5usize, 17] {
            let mut resized = packet.clone();
            resized.temporal_identifier = vec![0xAB; len];
            match decrypt_encrypted_packet(resized.encode_to_vec(), csk_bytes.to_vec(), AES) {
                Err(TapauthError::Argument { detail }) => {
                    assert!(
                        detail.contains("temporal identifier"),
                        "unexpected message: {detail}"
                    );
                }
                other => panic!(
                    "a {len}-byte temporal identifier must be an argument error, got {other:?}"
                ),
            }
        }
    }

    // ---------------------------------------------------------------
    // parseAndVerifyAuthRequest
    // ---------------------------------------------------------------

    /// A validly signed request yields every field verbatim, including all four
    /// context fields.
    /// The defect this catches: dropped/renamed context fields, a re-sanitized
    /// username or hostname, or a timestamp truncated by a wrong width.
    #[test]
    fn parse_auth_request_accepts_signed_request_with_context() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let request = AuthenticationRequest {
            challenge: vec![0x51; 32],
            username: "luca".to_string(),
            hostname: "thinkpad".to_string(),
            timestamp_unix_seconds: 1_700_000_123,
            pam_service: "sudo".to_string(),
            process_name: "sudo".to_string(),
            command_preview: "apt  upgrade".to_string(),
            tty_present: true,
        };
        let bytes = signed_request(&keypair, request);

        let parsed = parse_and_verify_auth_request(
            bytes,
            keypair.verifying_key_bytes().to_vec(),
            2,
            ED25519,
        )
        .unwrap();
        assert_eq!(parsed.challenge, vec![0x51; 32]);
        assert_eq!(parsed.username, "luca");
        assert_eq!(parsed.hostname, "thinkpad");
        assert_eq!(parsed.timestamp_unix_seconds, 1_700_000_123);
        assert_eq!(parsed.pam_service, "sudo");
        assert_eq!(parsed.process_name, "sudo");
        // Verbatim as signed: no second sanitization pass collapses the double space.
        assert_eq!(parsed.command_preview, "apt  upgrade");
        assert!(parsed.tty_present);
    }

    /// A timestamp that does not fit the Kotlin `Long` is an argument failure, while
    /// the largest value that does fit passes through unchanged.
    /// The defect this catches: the `u64` timestamp crossing into the `i64` field
    /// unchecked (a wrapped, negative timestamp reaching the Server), or a range check
    /// with an off-by-one bound that also rejects `i64::MAX`.
    #[test]
    fn parse_auth_request_rejects_timestamp_beyond_i64() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let mut request = context_request([0x66; 32]);
        request.timestamp_unix_seconds = u64::MAX;
        let bytes = signed_request(&keypair, request);

        match parse_and_verify_auth_request(
            bytes,
            keypair.verifying_key_bytes().to_vec(),
            2,
            ED25519,
        ) {
            Err(TapauthError::Argument { detail }) => {
                assert_eq!(detail, "timestamp is out of range");
            }
            other => panic!("expected a timestamp range rejection, got {other:?}"),
        }

        // The boundary itself is still accepted: only values that do not fit a `Long`
        // are refused.
        let mut request = context_request([0x66; 32]);
        request.timestamp_unix_seconds = i64::MAX as u64;
        let bytes = signed_request(&keypair, request);
        let parsed = parse_and_verify_auth_request(
            bytes,
            keypair.verifying_key_bytes().to_vec(),
            2,
            ED25519,
        )
        .unwrap();
        assert_eq!(parsed.timestamp_unix_seconds, i64::MAX);
    }

    /// A request signed by another key is refused.
    /// The defect this catches: a parse path that decodes the payload without
    /// checking the signature against the paired Client's key.
    #[test]
    fn parse_auth_request_rejects_wrong_signer() {
        let signer = Ed25519KeyPair::generate().unwrap();
        let other = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&signer, context_request([0x61; 32]));

        assert!(matches!(
            parse_and_verify_auth_request(bytes, other.verifying_key_bytes().to_vec(), 2, ED25519),
            Err(TapauthError::Security { detail }) if detail.contains("signature")
        ));
    }

    /// Re-encoding a signed payload with one byte changed breaks the signature.
    /// The defect this catches: verification over a re-serialized struct instead of
    /// the raw wire bytes, which would let the tampered field through.
    #[test]
    fn parse_auth_request_rejects_tampered_payload() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&keypair, context_request([0x62; 32]));

        let mut wrapper = WrapperMessage::decode(bytes.as_slice()).unwrap();
        let index = wrapper.payload.len() / 2;
        wrapper.payload[index] ^= 0x01;

        assert!(matches!(
            parse_and_verify_auth_request(
                wrapper.encode_to_vec(),
                keypair.verifying_key_bytes().to_vec(),
                2,
                ED25519
            ),
            Err(TapauthError::Security { .. })
        ));
    }

    /// `payload_type` is covered by the signature, so relabelling a signed message is
    /// refused instead of being decoded as the new type.
    /// The defect this catches: dispatch on an unauthenticated `payload_type`, which
    /// lets a signed Grant be replayed as an AuthRequest.
    #[test]
    fn parse_auth_request_rejects_relabelled_payload_type() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&keypair, context_request([0x63; 32]));

        let mut wrapper = WrapperMessage::decode(bytes.as_slice()).unwrap();
        assert_eq!(wrapper.payload_type, PayloadType::AuthRequest as i32);
        wrapper.payload_type = PayloadType::AuthGrant as i32;

        match parse_and_verify_auth_request(
            wrapper.encode_to_vec(),
            keypair.verifying_key_bytes().to_vec(),
            2,
            ED25519,
        ) {
            Err(TapauthError::Security { detail }) => {
                assert!(
                    detail.contains("payload type"),
                    "unexpected message: {detail}"
                );
            }
            other => panic!("expected a payload-type rejection, got {other:?}"),
        }
    }

    /// A well-signed request whose challenge is not 32 bytes is rejected.
    /// The defect this catches: a challenge length accepted by truncation or padding,
    /// which would let the peer shrink the answer space.
    #[test]
    fn parse_auth_request_rejects_non_32_byte_challenge() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let mut request = context_request([0x64; 32]);
        request.challenge = vec![0x64; 31];
        let bytes = signed_request(&keypair, request);

        match parse_and_verify_auth_request(
            bytes,
            keypair.verifying_key_bytes().to_vec(),
            2,
            ED25519,
        ) {
            Err(TapauthError::Argument { detail }) => {
                assert!(detail.contains("challenge"), "unexpected message: {detail}");
            }
            other => panic!("expected a challenge-length rejection, got {other:?}"),
        }
    }

    /// The caller's protocol version is pinned to v2.
    /// The defect this catches: a v1 (or future) frame accepted because the version
    /// argument is ignored, i.e. a compatibility branch sneaking back in.
    /// It is a `Security` failure, not an `Argument` one: the value is the paired
    /// Client's persisted `protocolVersion`, so a value this build cannot speak means
    /// the stored pairing is unusable.
    #[test]
    fn parse_auth_request_rejects_other_protocol_versions() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = signed_request(&keypair, context_request([0x65; 32]));

        for version in [0, 1, 3] {
            assert!(
                matches!(
                    parse_and_verify_auth_request(
                        bytes.clone(),
                        keypair.verifying_key_bytes().to_vec(),
                        version,
                        ED25519
                    ),
                    Err(TapauthError::Security { detail }) if detail.contains("protocol version")
                ),
                "protocol version {version} must be refused"
            );
        }

        // The wrapper's own version field is signed and pinned too.
        let mut wrapper = WrapperMessage::decode(bytes.as_slice()).unwrap();
        wrapper.version = 1;
        assert!(matches!(
            parse_and_verify_auth_request(
                wrapper.encode_to_vec(),
                keypair.verifying_key_bytes().to_vec(),
                2,
                ED25519
            ),
            Err(TapauthError::Security { .. })
        ));
    }

    /// With an invalid signature *and* an undecodable payload, the reported failure is
    /// the signature, not the decode.
    /// The defect this catches: decoding before verifying, which hands attacker-chosen
    /// bytes to the protobuf decoder and reports a parse error where an authentication
    /// failure belongs.
    #[test]
    fn parse_auth_request_fails_on_signature_before_decoding() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let wrapper = WrapperMessage {
            version: PROTOCOL_VERSION_V2,
            signature_algorithm: ED25519,
            payload_type: PayloadType::AuthRequest as i32,
            payload: vec![0xFF, 0xFF, 0xFF],
            signature: vec![0x00; 64],
        };
        assert!(AuthenticationRequest::decode([0xFFu8, 0xFF, 0xFF].as_slice()).is_err());

        match parse_and_verify_auth_request(
            wrapper.encode_to_vec(),
            keypair.verifying_key_bytes().to_vec(),
            2,
            ED25519,
        ) {
            Err(TapauthError::Security { detail }) => {
                assert!(detail.contains("signature"), "unexpected message: {detail}");
            }
            other => panic!("expected a signature failure, got {other:?}"),
        }
    }

    /// The three parse entry points must verify against the caller-supplied,
    /// per-Client `signature_algorithm`, and refuse an id this build cannot verify.
    /// The defect this catches: verification pinned to a hard-coded `ED25519`
    /// constant, so the persisted per-server algorithm is never consulted and any
    /// value Kotlin passes (including `UNSPECIFIED`) is silently accepted as ED25519.
    #[test]
    fn parse_entry_points_pin_the_caller_supplied_signature_algorithm() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.verifying_key_bytes().to_vec();
        let challenge = [0x73u8; 32];
        let request_bytes = signed_request(&keypair, context_request(challenge));

        let mut confirmation = wrap_grant_confirmation(GrantConfirmation {
            challenge: challenge.to_vec(),
        });
        sign_wrapper_message(&mut confirmation, &keypair).unwrap();
        let confirmation_bytes = confirmation.encode_to_vec();

        let mut cancel = wrap_auth_cancel(AuthenticationCancel {
            challenge: challenge.to_vec(),
        });
        sign_wrapper_message(&mut cancel, &keypair).unwrap();
        let cancel_bytes = cancel.encode_to_vec();

        // The persisted value (ED25519) succeeds on all three entry points.
        assert_eq!(
            parse_and_verify_auth_request(request_bytes.clone(), public_key.clone(), 2, ED25519)
                .unwrap()
                .challenge,
            challenge.to_vec()
        );
        assert_eq!(
            parse_and_verify_grant_confirmation(
                confirmation_bytes.clone(),
                public_key.clone(),
                2,
                ED25519
            )
            .unwrap(),
            challenge.to_vec()
        );
        assert_eq!(
            parse_and_verify_auth_cancel(cancel_bytes.clone(), public_key.clone(), 2, ED25519)
                .unwrap(),
            challenge.to_vec()
        );

        // `UNSPECIFIED` (0) and an unknown id (99) are refused on every entry
        // point, before any signature check.
        for algorithm in [0, 99] {
            assert!(
                matches!(
                    parse_and_verify_auth_request(
                        request_bytes.clone(),
                        public_key.clone(),
                        2,
                        algorithm
                    ),
                    Err(TapauthError::Security { detail }) if detail.contains("signature algorithm")
                ),
                "signature algorithm {algorithm} must be refused for AuthRequest"
            );
            assert!(
                matches!(
                    parse_and_verify_grant_confirmation(
                        confirmation_bytes.clone(),
                        public_key.clone(),
                        2,
                        algorithm
                    ),
                    Err(TapauthError::Security { detail }) if detail.contains("signature algorithm")
                ),
                "signature algorithm {algorithm} must be refused for GrantConfirmation"
            );
            assert!(
                matches!(
                    parse_and_verify_auth_cancel(cancel_bytes.clone(), public_key.clone(), 2, algorithm),
                    Err(TapauthError::Security { detail }) if detail.contains("signature algorithm")
                ),
                "signature algorithm {algorithm} must be refused for AuthCancel"
            );
        }
    }

    // ---------------------------------------------------------------
    // parseAndVerifyGrantConfirmation / parseAndVerifyAuthCancel
    // ---------------------------------------------------------------

    /// Both acknowledgement messages verify and return their challenge, and each is
    /// refused where the other one is expected.
    /// The defect this catches: a shared parse path that returns the challenge without
    /// pinning `payload_type`, so a Cancel satisfies a Grant wait (or vice versa).
    #[test]
    fn grant_confirmation_and_cancel_verify_before_returning_the_challenge() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.verifying_key_bytes().to_vec();
        let challenge = [0x71u8; 32];

        let mut confirmation = wrap_grant_confirmation(GrantConfirmation {
            challenge: challenge.to_vec(),
        });
        sign_wrapper_message(&mut confirmation, &keypair).unwrap();
        let confirmation_bytes = confirmation.encode_to_vec();

        let mut cancel = wrap_auth_cancel(AuthenticationCancel {
            challenge: challenge.to_vec(),
        });
        sign_wrapper_message(&mut cancel, &keypair).unwrap();
        let cancel_bytes = cancel.encode_to_vec();

        assert_eq!(
            parse_and_verify_grant_confirmation(
                confirmation_bytes.clone(),
                public_key.clone(),
                2,
                ED25519
            )
            .unwrap(),
            challenge.to_vec()
        );
        assert_eq!(
            parse_and_verify_auth_cancel(cancel_bytes.clone(), public_key.clone(), 2, ED25519)
                .unwrap(),
            challenge.to_vec()
        );

        assert!(matches!(
            parse_and_verify_grant_confirmation(cancel_bytes.clone(), public_key.clone(), 2, ED25519),
            Err(TapauthError::Security { detail }) if detail.contains("payload type")
        ));
        assert!(matches!(
            parse_and_verify_auth_cancel(confirmation_bytes.clone(), public_key.clone(), 2, ED25519),
            Err(TapauthError::Security { detail }) if detail.contains("payload type")
        ));

        // Wrong signer is refused on both paths.
        let other = Ed25519KeyPair::generate().unwrap();
        assert!(matches!(
            parse_and_verify_grant_confirmation(
                confirmation_bytes,
                other.verifying_key_bytes().to_vec(),
                2,
                ED25519,
            ),
            Err(TapauthError::Security { .. })
        ));
        assert!(matches!(
            parse_and_verify_auth_cancel(
                cancel_bytes,
                other.verifying_key_bytes().to_vec(),
                2,
                ED25519,
            ),
            Err(TapauthError::Security { .. })
        ));
    }

    // ---------------------------------------------------------------
    // createGrantWrapperMessage / createDenialWrapperMessage
    // ---------------------------------------------------------------

    /// Both builders produce an `EncryptedPacket` that decrypts back to the right
    /// payload type and challenge under the negotiated algorithms.
    /// The defect this catches: a grant/denial that is signed but not encrypted, one
    /// built with the wrong payload type, or one whose challenge is not the answered
    /// challenge.
    #[test]
    fn grant_and_denial_builders_round_trip_through_the_csk() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let csk_bytes = *csk.as_bytes();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [0x81u8; 32];

        for symmetric in [AES, CHACHA] {
            let grant_bytes = create_grant_wrapper_message(
                challenge.to_vec(),
                keypair.signing_key_bytes().to_vec(),
                csk_bytes.to_vec(),
                symmetric,
                SHA256,
            )
            .expect("grant packet");
            let signature_algorithm = ED25519;
            let grant = decrypt_encrypted_packet_with_csk_nonce(
                &csk,
                SymmetricAlgorithm::try_from(symmetric).unwrap(),
                &EncryptedPacket::decode(grant_bytes.as_slice()).unwrap(),
            )
            .unwrap();
            assert_eq!(grant.payload_type, PayloadType::AuthGrant as i32);
            assert_eq!(grant.signature.len(), 64);
            verify_and_decode_payload(&grant, &keypair.verifying_key_bytes(), signature_algorithm)
                .unwrap();
            assert_eq!(extract_challenge(&grant).unwrap(), challenge.to_vec());

            let denial_bytes = create_denial_wrapper_message(
                challenge.to_vec(),
                "user rejected".to_string(),
                keypair.signing_key_bytes().to_vec(),
                csk_bytes.to_vec(),
                symmetric,
                SHA256,
            )
            .expect("denial packet");
            let denial = decrypt_encrypted_packet_with_csk_nonce(
                &csk,
                SymmetricAlgorithm::try_from(symmetric).unwrap(),
                &EncryptedPacket::decode(denial_bytes.as_slice()).unwrap(),
            )
            .unwrap();
            assert_eq!(denial.payload_type, PayloadType::AuthDenial as i32);
            match verify_and_decode_payload(
                &denial,
                &keypair.verifying_key_bytes(),
                signature_algorithm,
            )
            .unwrap()
            {
                DecodedPayload::AuthDenial(message) => {
                    assert_eq!(message.challenge, challenge.to_vec());
                    assert_eq!(message.reason, "user rejected");
                }
                other => panic!("expected an AuthDenial, got {other:?}"),
            }
        }
    }

    /// An unsupported algorithm id supplied by the caller is refused, not defaulted.
    /// The defect this catches: `UNSPECIFIED` silently selecting AES-256-GCM or SHA-256.
    #[test]
    fn builders_reject_unsupported_algorithm_ids() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let csk = [0x91u8; 32];
        let challenge = [0x92u8; 32];

        assert!(matches!(
            create_grant_wrapper_message(
                challenge.to_vec(),
                keypair.signing_key_bytes().to_vec(),
                csk.to_vec(),
                0,
                SHA256
            ),
            Err(TapauthError::Argument { .. })
        ));
        assert!(matches!(
            create_grant_wrapper_message(
                challenge.to_vec(),
                keypair.signing_key_bytes().to_vec(),
                csk.to_vec(),
                AES,
                0
            ),
            Err(TapauthError::Argument { .. })
        ));
        assert!(matches!(
            create_denial_wrapper_message(
                challenge.to_vec(),
                "no".to_string(),
                keypair.signing_key_bytes().to_vec(),
                csk.to_vec(),
                99,
                SHA256
            ),
            Err(TapauthError::Argument { .. })
        ));
    }

    // ---------------------------------------------------------------
    // Discovery
    // ---------------------------------------------------------------

    /// Temporal identifiers are keyed, window-bound and algorithm-dispatched, and the
    /// verifier accepts only the current/previous window.
    /// The defect this catches: a per-device algorithm dispatch that ignores the
    /// stored `hashAlgorithm` (a BLAKE3 client's packets would never match).
    #[test]
    fn temporal_identifiers_dispatch_on_the_persisted_algorithm() {
        let csk = [0xA1u8; 32];
        let window = current_time_window().unwrap();

        let sha16 = generate_temporal_identifier(csk.to_vec(), window, SHA256).unwrap();
        let blake16 = generate_temporal_identifier(csk.to_vec(), window, 2).unwrap();
        assert_eq!(sha16.len(), TEMPORAL_ID_LEN);
        assert_ne!(sha16, blake16, "the hash algorithm must be dispatched on");

        let sha10 = generate_ble_temporal_identifier(csk.to_vec(), window, SHA256).unwrap();
        assert_eq!(sha10.len(), BLE_TEMPORAL_ID_LEN);
        assert_eq!(&sha10[..], &sha16[..BLE_TEMPORAL_ID_LEN]);

        assert!(verify_temporal_identifier(sha16.clone(), csk.to_vec(), SHA256).unwrap());
        assert!(verify_temporal_identifier(sha10, csk.to_vec(), SHA256).unwrap());
        assert!(verify_temporal_identifier(blake16.clone(), csk.to_vec(), 2).unwrap());

        // The wrong algorithm never matches.
        assert!(!verify_temporal_identifier(blake16, csk.to_vec(), SHA256).unwrap());
        // A window two periods old is stale.
        let stale = generate_temporal_identifier(csk.to_vec(), window - 2, SHA256).unwrap();
        assert!(!verify_temporal_identifier(stale, csk.to_vec(), SHA256).unwrap());

        // Caller errors are refused rather than defaulted.
        assert!(matches!(
            generate_temporal_identifier(csk.to_vec(), -1, SHA256),
            Err(TapauthError::Argument { .. })
        ));
        assert!(matches!(
            generate_temporal_identifier(csk.to_vec(), window, 0),
            Err(TapauthError::Argument { .. })
        ));
        assert!(matches!(
            verify_temporal_identifier(vec![0u8; 8], csk.to_vec(), SHA256),
            Err(TapauthError::Argument { .. })
        ));
    }

    /// The BLE pairing advertisement id is 10 bytes and rejects a malformed session id.
    #[test]
    fn ble_pairing_adv_id_rejects_wrong_length_session_ids() {
        let session_id = [0xB1u8; PAIRING_SESSION_ID_LEN];
        let public_key = [0xB2u8; 32];

        let id = derive_ble_pairing_adv_id(session_id.to_vec(), public_key.to_vec()).unwrap();
        assert_eq!(
            id,
            crate::crypto::derive_ble_pairing_adv_id(&session_id, &public_key)
        );
        assert_eq!(id.len(), BLE_TEMPORAL_ID_LEN);

        assert!(matches!(
            derive_ble_pairing_adv_id(session_id[..15].to_vec(), public_key.to_vec()),
            Err(TapauthError::Argument { .. })
        ));
    }

    /// `determine_message_type` names every payload type the protocol defines and
    /// reports an `UNSPECIFIED` payload as `None`, and undecodable bytes as an I/O
    /// failure.
    /// The defect this catches: a dispatch table that reports an `UNSPECIFIED` or
    /// unknown payload as a name (so Kotlin would route a frame no parse entry point
    /// accepts), a missing mapping for one of the five message types, or a decode
    /// error swallowed into `None`.
    #[test]
    fn determine_message_type_names_the_signed_payload() {
        for (payload_type, expected) in [
            (PayloadType::AuthRequest, Some("AUTH_REQUEST")),
            (PayloadType::AuthGrant, Some("AUTH_GRANT")),
            (PayloadType::AuthDenial, Some("AUTH_DENIAL")),
            (PayloadType::GrantConfirmation, Some("GRANT_CONFIRMATION")),
            (PayloadType::AuthCancel, Some("AUTH_CANCEL")),
            (PayloadType::Unspecified, None),
        ] {
            let wrapper = WrapperMessage {
                version: PROTOCOL_VERSION_V2,
                signature_algorithm: ED25519,
                payload_type: payload_type as i32,
                payload: Vec::new(),
                signature: Vec::new(),
            };
            assert_eq!(
                determine_message_type(wrapper.encode_to_vec()).unwrap(),
                expected.map(str::to_string),
                "{payload_type:?}"
            );
        }

        assert!(matches!(
            determine_message_type(vec![0xFF, 0xFF, 0xFF]),
            Err(TapauthError::Io { .. })
        ));
    }

    // ---------------------------------------------------------------
    // Pairing (phone side, one object per session)
    // ---------------------------------------------------------------

    /// The whole phone-side pairing path, driven from a real desktop
    /// `ClientPairingState`: constructor → init (twice, idempotent) → verify response
    /// (correct and wrong QR key) → provision → confirm server, which the desktop then
    /// verifies.
    /// The defect this catches: a wrong QR `pk` accepted (a substituted `X_C` would
    /// silently pair), a `create_init` that mints a fresh `X_S` on retransmission (the
    /// desktop would answer an init the session never sent), a provisioning payload
    /// that never reaches Kotlin, or a completion proof the desktop rejects because the
    /// directional keys or the transcript were wrong.
    #[test]
    fn pairing_session_path_matches_the_desktop_state_machine() {
        let (mut desktop, started) = ClientPairingState::start(
            Ed25519KeyPair::generate().unwrap(),
            "thinkpad",
            36_692,
            None,
            None,
            None,
        )
        .unwrap();
        // The session id comes from the QR code the desktop generated.
        let session_id = started.session_id;

        let identity = Ed25519KeyPair::generate().unwrap();
        let identity_public = identity.verifying_key_bytes();
        let session = PairingSession::new(
            session_id.to_vec(),
            identity.signing_key_bytes().to_vec(),
            "pixel".to_string(),
        )
        .unwrap();

        // Step 1: the phone builds its PairingInit, and a retransmission re-sends it.
        let init_bytes = session.create_init().unwrap();
        assert_eq!(
            session.create_init().unwrap(),
            init_bytes,
            "create_init must return the cached PairingInit"
        );
        let init = init_of(&init_bytes);
        assert_eq!(init.server_ed25519_public_key, identity_public.to_vec());
        assert_eq!(init.server_device_name, "pixel");

        // Step 2: the desktop answers.
        let response = desktop.handle_init(&init).unwrap().clone();
        let response_bytes =
            session_packet(&started.session_id, pairing_packet::Msg::Response(response));

        // A response carrying another session id never reaches the session.
        let foreign = session_packet(
            &[0xC2u8; PAIRING_SESSION_ID_LEN],
            match decode_pairing_packet(&response_bytes).unwrap().msg {
                Some(msg) => msg,
                None => panic!("response packet has no message"),
            },
        );
        assert!(matches!(
            session.verify_response(foreign, started.client_x25519_public_key.to_vec()),
            Err(TapauthError::Argument { detail }) if detail.contains("session id")
        ));

        // A substituted X_C is refused.
        assert!(matches!(
            session.verify_response(response_bytes.clone(), vec![0x00u8; 32]),
            Err(TapauthError::Security { .. })
        ));

        // The genuine response verifies and both sides derive the same SAS.
        let verified = session
            .verify_response(response_bytes, started.client_x25519_public_key.to_vec())
            .unwrap();
        let sas = verified.sas;
        assert_eq!(sas, desktop.sas().unwrap());
        assert_eq!(sas.len(), 7, "SAS is 6 digits plus the dash");
        assert!(sas.as_bytes()[3] == b'-');

        // Step 3: the desktop provisions the CSK and the phone decrypts it.
        let csk = [0xC3u8; 32];
        let confirm_client = desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap();
        let provision = session
            .process_confirm_client(session_packet(
                &started.session_id,
                pairing_packet::Msg::ConfirmClient(confirm_client),
            ))
            .unwrap();
        assert_eq!(provision.csk, csk.to_vec());
        assert_eq!(provision.username, "luca");
        assert_eq!(provision.client_hostname, "thinkpad");

        // Aborts authenticate in both directions once the keys exist. The phone
        // verifies the desktop's abort before it emits its own, because creating an
        // abort concludes the phone session (see `create_abort`'s doc).
        let abort = desktop
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();
        let abort_bytes = session_packet(&started.session_id, pairing_packet::Msg::Abort(abort));
        assert!(session.verify_abort(abort_bytes.clone()).unwrap());

        let mut tampered_abort = decode_pairing_packet(&abort_bytes).unwrap();
        match tampered_abort.msg.as_mut() {
            Some(pairing_packet::Msg::Abort(abort)) => {
                abort.reason = PairingAbortReason::KeyMismatch as i32
            }
            other => panic!("expected PairingAbort, got {other:?}"),
        }
        assert!(matches!(
            session.verify_abort(encode_pairing_packet(&tampered_abort).unwrap()),
            Err(TapauthError::Security { .. })
        ));

        // Step 4: the phone's completion proof satisfies the desktop.
        let confirm = confirm_server_of(&session.create_confirm_server(csk.to_vec()).unwrap());
        desktop.verify_confirm_server(&confirm, &csk).unwrap();

        // The same proof for a different CSK is refused by the desktop, which proves
        // the phone signed the provisioned key and not something else.
        assert!(desktop
            .verify_confirm_server(&confirm, &[0xC4u8; 32])
            .is_err());

        // The completion proof concluded the session: no second proof, no late
        // response and no abort can be built from it any more.
        assert!(matches!(
            session.create_confirm_server(csk.to_vec()),
            Err(TapauthError::State { detail }) if detail.contains("concluded")
        ));
        assert!(matches!(
            session.create_abort(PairingAbortReason::KeyMismatch as i32),
            Err(TapauthError::State { detail }) if detail.contains("concluded")
        ));
        assert!(matches!(
            session.create_init(),
            Err(TapauthError::State { detail }) if detail.contains("concluded")
        ));

        // Releasing a session is dropping its reference, so "unknown handle" no longer
        // exists. What must still hold is that a session built afterwards starts from
        // scratch: no state outlives the dropped object.
        drop(session);
        let fresh = PairingSession::new(
            session_id.to_vec(),
            Ed25519KeyPair::generate()
                .unwrap()
                .signing_key_bytes()
                .to_vec(),
            "pixel".to_string(),
        )
        .unwrap();
        assert_eq!(
            fresh.create_init().unwrap(),
            fresh.create_init().unwrap(),
            "the fresh session owns its own, stable PairingInit"
        );

        // A packet of the wrong type for the call is refused.
        assert!(matches!(
            fresh.verify_response(
                session_packet(
                    &session_id,
                    pairing_packet::Msg::Keepalive(Default::default())
                ),
                vec![0u8; 32]
            ),
            Err(TapauthError::Argument { .. })
        ));
    }

    /// A phone session plus the desktop's `PairingResponse` as a wire frame the phone
    /// has not verified yet. This is the state `verify_response` is called from.
    ///
    /// The desktop is started with client-wide pins for a **non-baseline** algorithm
    /// pair, so the negotiated triple differs from the AES-256-GCM/SHA-256/Ed25519
    /// default: a caller that hard-codes the baseline instead of reporting
    /// `session.negotiated()` fails here. The phone advertises both algorithms, so
    /// negotiation picks up the pins.
    fn pending_session() -> (
        ClientPairingState,
        Arc<PairingSession>,
        [u8; PAIRING_SESSION_ID_LEN],
        [u8; 32],
        Vec<u8>,
    ) {
        let (mut desktop, started) = ClientPairingState::start(
            Ed25519KeyPair::generate().unwrap(),
            "thinkpad",
            36_692,
            None,
            None,
            Some(PinnedAlgorithms {
                symmetric_algorithm: SymmetricAlgorithm::Chacha20Poly1305,
                hash_algorithm: HashAlgorithm::Blake3,
            }),
        )
        .unwrap();
        let session = PairingSession::new(
            started.session_id.to_vec(),
            Ed25519KeyPair::generate()
                .unwrap()
                .signing_key_bytes()
                .to_vec(),
            "pixel".to_string(),
        )
        .unwrap();

        let init = init_of(&session.create_init().unwrap());
        let response = desktop.handle_init(&init).unwrap().clone();
        let response_bytes =
            session_packet(&started.session_id, pairing_packet::Msg::Response(response));
        (
            desktop,
            session,
            started.session_id,
            started.client_x25519_public_key,
            response_bytes,
        )
    }

    /// `verify_response` returns exactly what the phone persists — the SAS, the
    /// desktop's `Ed_C` and the negotiated algorithm triple — and the desktop derives
    /// the same SAS and transcript hash from the very same wire frame.
    /// The defect this catches: a result that drops the device key or the algorithms
    /// (leaving `PairedDevice` unverifiable), one that carries the ephemeral `X_C` or
    /// the phone's own `Ed_S` instead of `Ed_C`, or one that reports a fixed triple —
    /// the AES-256-GCM/SHA-256/Ed25519 baseline — rather than the pinned algorithms
    /// the session actually negotiated.
    #[test]
    fn pairing_verify_response_returns_the_persistable_fields() {
        let (desktop, session, session_id, qr_pk, response_bytes) = pending_session();

        let verified = session
            .verify_response(response_bytes, qr_pk.to_vec())
            .unwrap();

        // The SAS is the one both sides derived; the desktop's is the out-of-band
        // reference, and it is shaped `ddd-ddd`.
        assert_eq!(verified.sas, desktop.sas().unwrap());
        assert_eq!(verified.sas.len(), 7, "SAS is 6 digits plus the dash");
        assert_eq!(verified.sas.as_bytes()[3], b'-');

        // The persisted key is the desktop's static `Ed_C`, not the ephemeral `X_C`
        // committed in the QR code and not anything else.
        assert_eq!(
            verified.client_ed25519_public_key,
            desktop.client_ed25519_public_key().to_vec()
        );
        assert_ne!(verified.client_ed25519_public_key, qr_pk.to_vec());
        assert_ne!(verified.client_ed25519_public_key, vec![0u8; 32]);

        // The triple is what negotiation selected — the pinned, non-baseline pair, so
        // a hard-coded (AES-256-GCM, SHA-256, Ed25519) fails here — and the desktop's
        // own answer agrees with it. (`Chacha20Poly1305` and `Blake3` are both id 2,
        // so the wire numbers alone cannot tell the two fields apart; the
        // `desktop.negotiated()` comparisons below are what pin the mapping.)
        assert_eq!(verified.symmetric_algorithm, CHACHA);
        assert_eq!(verified.hash_algorithm, BLAKE3);
        assert_eq!(verified.signature_algorithm, ED25519);
        let negotiated = desktop.negotiated().unwrap();
        assert_eq!(
            negotiated.symmetric_algorithm,
            SymmetricAlgorithm::Chacha20Poly1305
        );
        assert_eq!(negotiated.hash_algorithm, HashAlgorithm::Blake3);
        assert_eq!(
            verified.symmetric_algorithm,
            negotiated.symmetric_algorithm as i32
        );
        assert_eq!(verified.hash_algorithm, negotiated.hash_algorithm as i32);
        assert_eq!(
            verified.signature_algorithm,
            negotiated.signature_algorithm as i32
        );

        // The frame the session read is the one the desktop answered, so the phone's
        // transcript hash is the desktop's — and nothing about `H` was handed to
        // Kotlin by `verify_response`.
        let phone_transcript_hash = session.inner.lock().unwrap().transcript_hash().copied();
        assert_eq!(phone_transcript_hash, desktop.transcript_hash().copied());
        assert_eq!(&session_id, desktop.session_id());
    }

    /// The QR pin is mandatory: a response checked against the wrong `pk` — including
    /// the all-zero sentinel — is a security failure that caches nothing, so the
    /// genuine response still verifies afterwards.
    /// The defect this catches: a "no QR key available, skip the comparison" path
    /// (which lets a substituted `X_C` pair silently), or a failed attempt that leaves
    /// the session poisoned or already keyed.
    #[test]
    fn pairing_verify_response_rejects_a_wrong_qr_pin_and_stays_usable() {
        let (desktop, session, _session_id, qr_pk, response_bytes) = pending_session();

        let mut wrong_pin = qr_pk;
        wrong_pin[0] ^= 0x01;
        for pin in [wrong_pin, [0x00u8; 32]] {
            assert!(matches!(
                session.verify_response(response_bytes.clone(), pin.to_vec()),
                Err(TapauthError::Security { detail }) if detail.contains("challenge")
            ));
            // Nothing was cached: no SAS, no transcript hash, no keys.
            let state = {
                let session_state = session.inner.lock().unwrap();
                (
                    session_state.sas().map(str::to_string),
                    session_state.transcript_hash().is_some(),
                    session_state.negotiated().is_some(),
                )
            };
            assert_eq!(state, (None, false, false));
        }

        // The session is still usable: the genuine response now verifies.
        let verified = session
            .verify_response(response_bytes, qr_pk.to_vec())
            .unwrap();
        assert_eq!(verified.sas, desktop.sas().unwrap());
        assert_eq!(
            verified.client_ed25519_public_key,
            desktop.client_ed25519_public_key().to_vec()
        );
    }

    /// Aborts authenticate in the right direction: a phone-built abort verifies on the
    /// desktop, a desktop-built abort verifies on the phone, a flipped tag byte fails,
    /// and a tag-less abort once the keys exist is refused rather than reported as the
    /// "unauthenticated" `false`.
    /// The defect this catches: `verify_abort` checking the wrong directional key
    /// (`K_s2c` instead of `K_c2s`), or accepting an empty tag after the keys exist, so
    /// any observer on the path can cancel a pairing.
    #[test]
    fn pairing_aborts_authenticate_in_both_directions() {
        let (desktop, session, session_id, qr_pk, response_bytes) = pending_session();
        session
            .verify_response(response_bytes, qr_pk.to_vec())
            .unwrap();

        // Desktop → phone: verified here, with the `K_c2s` direction the desktop does
        // not use, so the desktop itself must reject its own frame.
        let desktop_abort = desktop
            .create_abort(PairingAbortReason::KeyMismatch)
            .unwrap();
        let desktop_abort_bytes = session_packet(
            &session_id,
            pairing_packet::Msg::Abort(desktop_abort.clone()),
        );
        assert!(session.verify_abort(desktop_abort_bytes).unwrap());
        assert!(desktop.verify_abort(&desktop_abort).is_err());

        // One flipped tag byte fails the direction check.
        let mut flipped = desktop_abort.clone();
        flipped.auth_tag[0] ^= 0xFF;
        assert!(matches!(
            session.verify_abort(session_packet(&session_id, pairing_packet::Msg::Abort(flipped))),
            Err(TapauthError::Security { detail }) if detail.contains("signature")
        ));

        // Keys exist, so a tag-less abort is spoofable: it must be an error, not the
        // `false` that means "unauthenticated abort before any key existed".
        let untagged = PairingAbort {
            reason: PairingAbortReason::ProtocolError as i32,
            auth_tag: Vec::new(),
        };
        assert!(matches!(
            session.verify_abort(session_packet(&session_id, pairing_packet::Msg::Abort(untagged))),
            Err(TapauthError::Security { detail }) if detail.contains("signature")
        ));

        // Phone → desktop, built last: creating an abort concludes the phone session,
        // so nothing else may run on it afterwards.
        let phone_abort = match decode_pairing_packet(
            &session
                .create_abort(PairingAbortReason::UserRejectedSas as i32)
                .unwrap(),
        )
        .unwrap()
        .msg
        {
            Some(pairing_packet::Msg::Abort(abort)) => abort,
            other => panic!("expected PairingAbort, got {other:?}"),
        };
        assert_eq!(
            phone_abort.reason,
            PairingAbortReason::UserRejectedSas as i32
        );
        assert_eq!(phone_abort.auth_tag.len(), 32);
        assert!(desktop.verify_abort(&phone_abort).unwrap());
    }

    /// `create_abort` emits the requested reason with an authenticated tag, rejects an
    /// unknown reason id before touching the session, and concludes the session.
    ///
    /// The defect this catches: an abort whose `reason` is dropped or remapped, a tag
    /// that is not the phone's `K_s2c` one, or a terminal call that leaves the session
    /// live so Kotlin can keep using a cancelled pairing.
    #[test]
    fn pairing_create_abort_is_terminal_and_validates_the_reason() {
        let (_desktop, session, _session_id, qr_pk, response_bytes) = pending_session();
        session
            .verify_response(response_bytes, qr_pk.to_vec())
            .unwrap();

        match decode_pairing_packet(
            &session
                .create_abort(PairingAbortReason::SessionExpired as i32)
                .unwrap(),
        )
        .unwrap()
        .msg
        {
            Some(pairing_packet::Msg::Abort(abort)) => {
                assert_eq!(abort.reason, PairingAbortReason::SessionExpired as i32);
                assert_eq!(abort.auth_tag.len(), 32);
            }
            other => panic!("expected PairingAbort, got {other:?}"),
        }

        // The abort concluded the session: a second one, or any other protocol
        // operation, reports the terminal state instead of running on.
        assert!(matches!(
            session.create_abort(PairingAbortReason::KeyMismatch as i32),
            Err(TapauthError::State { detail }) if detail.contains("concluded")
        ));
        assert!(matches!(
            session.create_confirm_server(vec![0x00u8; 32]),
            Err(TapauthError::State { detail }) if detail.contains("concluded")
        ));
        assert!(matches!(
            session.create_init(),
            Err(TapauthError::State { detail }) if detail.contains("concluded")
        ));

        // An unknown reason id is a caller error, and it is resolved before the
        // session is touched, so even a concluded session reports it as such.
        assert!(matches!(
            session.create_abort(99),
            Err(TapauthError::Argument { .. })
        ));
    }

    /// Before any key exists, an abort that carries no tag is reported as
    /// **unauthenticated** (`false`), and an abort that carries a tag we cannot check
    /// is a security failure.
    /// The defect this catches: reporting an unauthenticated abort as a verified one
    /// (a bare `true`, or an `Ok(false)` that Kotlin's caller treats as "cancel
    /// accepted"), or treating an unverifiable tag as merely unauthenticated and
    /// letting it through.
    #[test]
    fn pairing_verify_abort_before_any_key_is_unauthenticated_not_valid() {
        let session_id = [0xBAu8; PAIRING_SESSION_ID_LEN];
        let session = PairingSession::new(
            session_id.to_vec(),
            Ed25519KeyPair::generate()
                .unwrap()
                .signing_key_bytes()
                .to_vec(),
            "pixel".to_string(),
        )
        .unwrap();

        let untagged = PairingAbort {
            reason: PairingAbortReason::ProtocolError as i32,
            auth_tag: Vec::new(),
        };
        assert!(
            !session
                .verify_abort(session_packet(
                    &session_id,
                    pairing_packet::Msg::Abort(untagged)
                ))
                .unwrap(),
            "a tag-less abort before any key is unauthenticated, not valid"
        );

        let tagged = PairingAbort {
            reason: PairingAbortReason::ProtocolError as i32,
            auth_tag: vec![0xAA; 32],
        };
        assert!(matches!(
            session.verify_abort(session_packet(
                &session_id,
                pairing_packet::Msg::Abort(tagged)
            )),
            Err(TapauthError::Security { .. })
        ));
    }

    /// `create_keepalive` emits a real, decodable `PairingPacket` for the session:
    /// v2, its 16-byte session id and an empty `PairingKeepalive`.
    /// The defect this catches: a frame built to another version or with the wrong
    /// session id (which the peer's envelope filter drops), or an envelope carrying the
    /// wrong `msg` variant.
    #[test]
    fn pairing_create_keepalive_emits_a_decodable_v2_frame() {
        let session_id = [0xF1u8; PAIRING_SESSION_ID_LEN];
        let session = PairingSession::new(
            session_id.to_vec(),
            Ed25519KeyPair::generate()
                .unwrap()
                .signing_key_bytes()
                .to_vec(),
            "pixel".to_string(),
        )
        .unwrap();

        let bytes = session.create_keepalive().unwrap();
        let packet = decode_pairing_packet(&bytes).unwrap();
        assert_eq!(packet.version, PROTOCOL_VERSION_V2);
        assert_eq!(packet.session_id, session_id.to_vec());
        assert_eq!(packet.session_id.len(), PAIRING_SESSION_ID_LEN);
        assert_eq!(
            packet.msg,
            Some(pairing_packet::Msg::Keepalive(PairingKeepalive {}))
        );
    }

    /// Two sessions are two objects: even with the same session id they own their own
    /// ephemeral key, and releasing one leaves the other intact.
    /// The defect this catches: a shared table keyed by session id (the removed
    /// `SESSIONS` map) reintroduced behind the object, where a second pairing for the
    /// same id would overwrite the first, and a release that invalidates a session
    /// that was never released.
    #[test]
    fn pairing_sessions_do_not_share_state() {
        let session_id = [0xD5u8; PAIRING_SESSION_ID_LEN];
        let identity = Ed25519KeyPair::generate().unwrap();
        let first = PairingSession::new(
            session_id.to_vec(),
            identity.signing_key_bytes().to_vec(),
            "pixel".to_string(),
        )
        .unwrap();
        let second = PairingSession::new(
            session_id.to_vec(),
            identity.signing_key_bytes().to_vec(),
            "pixel".to_string(),
        )
        .unwrap();

        let first_init = init_of(&first.create_init().unwrap());
        let second_init = init_of(&second.create_init().unwrap());
        assert_eq!(
            first_init.server_ed25519_public_key,
            second_init.server_ed25519_public_key
        );
        assert_ne!(
            first_init.server_x25519_public_key, second_init.server_x25519_public_key,
            "each session owns its own ephemeral X_S"
        );

        drop(first);
        assert_eq!(
            init_of(&second.create_init().unwrap()).server_x25519_public_key,
            second_init.server_x25519_public_key,
            "releasing one session must not disturb another"
        );
    }

    /// A lock poisoned by a panic while the session was borrowed surfaces as
    /// `TapauthError::State` instead of propagating the panic (or aborting the process)
    /// across the FFI boundary.
    /// The defect this catches: `lock().unwrap()` — or `lock().expect(..)` — on the
    /// session mutex, which turns a poisoned lock into a propagated panic. UniFFI does
    /// translate a panic into a Kotlin exception, but only a generic
    /// `InternalException`; what this asserts is that the failure stays the typed
    /// `TapauthError::State` and does not degrade to that untyped, undiagnosable case.
    #[test]
    fn poisoned_pairing_session_lock_is_a_state_error() {
        let session = PairingSession::new(
            [0xC1u8; PAIRING_SESSION_ID_LEN].to_vec(),
            Ed25519KeyPair::generate()
                .unwrap()
                .signing_key_bytes()
                .to_vec(),
            "pixel".to_string(),
        )
        .unwrap();

        let poisoned = Arc::clone(&session);
        let joined = std::thread::spawn(move || {
            let _guard = poisoned.inner.lock().unwrap();
            panic!("poison the session lock");
        })
        .join();
        assert!(joined.is_err(), "the worker must have panicked");

        assert!(matches!(
            session.create_init(),
            Err(TapauthError::State { detail }) if detail.contains("poisoned")
        ));
    }

    /// `pairing_packet_session_id` validates the envelope and returns the 16-byte id.
    /// The defect this catches: a transport filter accepting a v1 frame or a
    /// truncated/padded session id.
    #[test]
    fn pairing_packet_session_id_validates_the_envelope() {
        let session_id = [0xD1u8; PAIRING_SESSION_ID_LEN];
        let bytes = session_packet(
            &session_id,
            pairing_packet::Msg::Keepalive(Default::default()),
        );
        assert_eq!(
            pairing_packet_session_id(bytes).unwrap(),
            session_id.to_vec()
        );

        // Wrong version.
        let wrong_version = PairingPacket {
            version: 1,
            session_id: session_id.to_vec(),
            msg: Some(pairing_packet::Msg::Keepalive(Default::default())),
        }
        .encode_to_vec();
        assert!(matches!(
            pairing_packet_session_id(wrong_version),
            Err(TapauthError::Argument { .. })
        ));

        // Truncated session id.
        let short = PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: session_id[..15].to_vec(),
            msg: Some(pairing_packet::Msg::Keepalive(Default::default())),
        }
        .encode_to_vec();
        assert!(matches!(
            pairing_packet_session_id(short),
            Err(TapauthError::Argument { .. })
        ));

        assert!(matches!(
            pairing_packet_session_id(vec![0xFF, 0xFF]),
            Err(TapauthError::Argument { .. })
        ));
    }

    /// The pre-decryption temporal-identifier read requires the 16-byte UDP/GATT form.
    #[test]
    fn encrypted_packet_temporal_identifier_requires_16_bytes() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = grant_packet(csk.as_bytes(), &keypair, AES, [0xE1; 32]);

        let identifier = extract_temporal_identifier(bytes.clone()).unwrap();
        assert_eq!(identifier.len(), TEMPORAL_ID_LEN);

        let mut short = EncryptedPacket::decode(bytes.as_slice()).unwrap();
        short.temporal_identifier.truncate(5);
        assert!(matches!(
            extract_temporal_identifier(short.encode_to_vec()),
            Err(TapauthError::Argument { .. })
        ));
    }
}
