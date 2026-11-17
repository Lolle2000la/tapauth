use super::fields::truncate_utf8;
use super::transcript::{complete_signature_message, context_with_hash};
use super::wire::PairingEndpoint;
use super::*;
use crate::crypto::{
    decrypt_with_key, derive_ble_pairing_adv_id, verify_ed25519, CryptoError, Ed25519KeyPair,
    X25519KeyPair,
};
use crate::protocol::messages::{ProtocolError, PROTOCOL_VERSION_V2};
use crate::protocol::pb::*;
use prost::Message as ProstMessage;

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
        PairingEndpoint {
            udp_port: Some(36692),
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 10)),
            ipv6: None,
        },
        pinned,
    )
    .unwrap()
}

/// Rebuild a desktop state that is byte-identical in its key material and
/// session id, so a test can vary exactly one transcript field.
fn seeded_desktop(session_id: [u8; PAIRING_SESSION_ID_LEN]) -> ClientPairingState {
    ClientPairingState::build_with_material(
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
    ServerPairingSession::build_with_material(
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
fn init_with_algorithms(symmetric: Vec<i32>, hash: Vec<i32>, signature: Vec<i32>) -> PairingInit {
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
    let keys = phone.keys().unwrap();
    let transcript_hash = *phone.transcript_hash().unwrap();
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
    let keys = phone.keys().unwrap();
    let transcript_hash = *phone.transcript_hash().unwrap();
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
    phone
        .set_advertised(
            vec![SymmetricAlgorithm::Aes256Gcm],
            SUPPORTED_HASH_ALGORITHMS.to_vec(),
        )
        .unwrap();
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
        assert!(!fresh_phone.session_keys_present());
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
    let (mut desktop, started) = ClientPairingState::build_with_material(
        session_id,
        X25519KeyPair::from_secret_bytes([0x11; 32]),
        desktop_identity(),
        "thinkpad",
        PairingEndpoint::default(),
        pinned,
    );
    let mut phone = ServerPairingSession::new(started.session_id, phone_identity(), "pixel")
        .expect("phone session");
    phone
        .set_advertised(advertised_symmetric, advertised_hash)
        .unwrap();
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
///
/// The outvote half is not expressible until a second suite exists: when one
/// is added, restore `pinned_algorithms_win_over_the_baseline`, which pins the
/// non-baseline suite while the peer lists the baseline first and requires the
/// pinned one to win.
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
    let (mut desktop, _started) = ClientPairingState::build_with_material(
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
    assert!(!desktop.session_keys_present());
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

/// `conclude` is a phase transition, not a flag. Both state machines keep their
/// handshake state behind `live()`/`live_mut()`, so after `conclude` there is no
/// live state left to resurrect, and an entry point written without the gate has
/// no fields to name.
/// The defect this catches: `conclude` keeping the state reachable behind a
/// `bool` — or clearing selected fields but leaving the rest — so the next entry
/// point added runs against zeroized key material and answers instead of
/// reporting the end of the session.
#[test]
fn conclude_leaves_no_live_state_behind() {
    let (mut desktop, mut phone) = established();
    let csk = [0x42u8; 32];
    let reason = PairingAbortReason::UserRejectedSas;
    // Taken while both sessions are live: the frames and the cached response a
    // post-conclude call is handed are the ones a retransmission would carry.
    let init = phone.create_init().unwrap();
    let response = desktop.response().unwrap().clone();
    let qr_pk = desktop.client_x25519_public_key();
    let confirm_client = desktop
        .create_confirm_client(&csk, "luca", "thinkpad")
        .unwrap();
    let confirm_server = phone.create_confirm_server(&csk).unwrap();
    let desktop_abort = desktop.create_abort(reason).unwrap();
    let phone_abort = phone.create_abort(reason).unwrap();
    let negotiated = desktop.negotiated();

    // While live, the gate hands the state out.
    assert!(desktop.live_gate().is_ok());
    assert!(desktop.live_gate_mut().is_ok());
    assert!(phone.live_gate().is_ok());
    assert!(phone.live_gate_mut().is_ok());

    desktop.conclude();
    phone.conclude();

    // The live phase is gone, not merely flagged: the state that held the keys,
    // `H` and the ephemeral secret was dropped, so the gate that guards every
    // field has nothing to hand out.
    assert!(!desktop.is_live(), "the desktop state must be taken");
    assert!(!phone.is_live(), "the phone state must be taken");
    assert!(matches!(
        desktop.live_gate(),
        Err(ProtocolError::SessionConcluded)
    ));
    assert!(matches!(
        desktop.live_gate_mut(),
        Err(ProtocolError::SessionConcluded)
    ));
    assert!(matches!(
        phone.live_gate(),
        Err(ProtocolError::SessionConcluded)
    ));
    assert!(matches!(
        phone.live_gate_mut(),
        Err(ProtocolError::SessionConcluded)
    ));
    assert!(!desktop.ephemeral_keypair_present());
    assert!(!phone.ephemeral_keypair_present());
    assert!(!desktop.session_keys_present());
    assert!(!phone.session_keys_present());

    // Enumerated rather than sampled: **every** entry point of both state
    // machines reports the conclusion and nothing else. A method that reports a
    // `MissingField` for the keys it dropped, an `InvalidMessageFormat`, or a
    // silent `Ok` fails here — and one added without the gate cannot compile,
    // because the fields it would act on are behind `live()`/`live_mut()`.
    let desktop_errors = [
        desktop.handle_init(&init).unwrap_err(),
        desktop
            .create_confirm_client(&csk, "luca", "thinkpad")
            .unwrap_err(),
        desktop
            .verify_confirm_server(&confirm_server, &csk)
            .unwrap_err(),
        desktop.create_abort(reason).unwrap_err(),
        desktop.verify_abort(&phone_abort).unwrap_err(),
    ];
    for error in desktop_errors {
        assert!(
            matches!(error, ProtocolError::SessionConcluded),
            "a concluded desktop reported {error:?}"
        );
    }
    let phone_errors = [
        phone.create_init().unwrap_err(),
        phone.verify_response(&response, &qr_pk).unwrap_err(),
        phone.create_confirm_server(&csk).unwrap_err(),
        phone.process_confirm_client(&confirm_client).unwrap_err(),
        phone.create_keepalive().unwrap_err(),
        phone.create_abort(reason).unwrap_err(),
        phone.verify_abort(&desktop_abort).unwrap_err(),
    ];
    for error in phone_errors {
        assert!(
            matches!(error, ProtocolError::SessionConcluded),
            "a concluded phone reported {error:?}"
        );
    }

    // What the API promises to keep answering still answers: the public halves,
    // the already-sent response and the negotiated metadata; the key-dependent
    // readers report the conclusion as `None`.
    assert_eq!(desktop.session_id(), phone.session_id());
    assert_eq!(desktop.client_x25519_public_key(), qr_pk);
    assert_eq!(
        desktop.client_ed25519_public_key(),
        desktop_identity().verifying_key_bytes()
    );
    assert_eq!(desktop.response().unwrap(), &response);
    assert_eq!(desktop.negotiated(), negotiated);
    assert!(desktop.transcript_hash().is_none());
    assert!(phone.transcript_hash().is_none());
    assert!(desktop.sas().is_none());
    assert!(phone.sas().is_none());

    // A second conclusion finds nothing left to take.
    desktop.conclude();
    phone.conclude();
    assert!(!desktop.is_live());
    assert!(!phone.is_live());
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
    assert!(!uninitialised.session_keys_present());
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

    let (mut desktop, started) = ClientPairingState::start(
        desktop_identity(),
        &long_name,
        PairingEndpoint {
            udp_port: Some(36692),
            ipv4: None,
            ipv6: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(desktop.client_device_name().unwrap().len(), 63);

    let mut phone =
        ServerPairingSession::new(started.session_id, phone_identity(), &long_name).unwrap();
    assert_eq!(phone.server_device_name().unwrap().len(), 63);
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
        pairing_packet::Msg::Abort(phone.create_abort(PairingAbortReason::KeyMismatch).unwrap()),
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

// --- 12. The peer-supplied device name is bounded on receive ----------

/// A `PairingInit` naming its phone with more than 64 bytes is refused, never
/// shortened into the transcript.
///
/// The defect this catches: `ClientPairingState::handle_init` splicing
/// `init.server_device_name` into `H` exactly as received while only *our* own
/// name is cut to [`PAIRING_DEVICE_NAME_MAX_BYTES`] at build time — so the stated
/// bound on that transcript field does not hold against a hostile peer, and a
/// name shortened on one side (or not shortened at all) makes two peers hash
/// different bytes for the same handshake. The 64-byte form is asserted to still
/// pair, so the check is a bound and not a ban.
#[test]
fn a_pairing_init_with_an_over_long_device_name_is_refused() {
    let (mut desktop, started) = start_desktop();
    let mut phone =
        ServerPairingSession::new(started.session_id, phone_identity(), "pixel").unwrap();
    let mut init = phone.create_init().unwrap();

    // 65 bytes: one byte past the budget.
    init.server_device_name = "x".repeat(PAIRING_DEVICE_NAME_MAX_BYTES + 1);
    assert!(matches!(
        desktop.handle_init(&init).unwrap_err(),
        ProtocolError::InvalidMessageFormat
    ));
    // The refusal is not a partial handshake: nothing was cached, derived or
    // taken, so the session is exactly as it was before the frame arrived.
    assert!(
        desktop.response().is_none(),
        "a refused init must not be cached"
    );
    assert!(desktop.transcript_hash().is_none(), "no H may exist");
    assert!(desktop.sas().is_none(), "no session keys may be derived");
    assert!(desktop.negotiated().is_none());
    assert!(!desktop.session_keys_present());
    assert!(
        desktop.ephemeral_keypair_present(),
        "the ephemeral x_C is taken only by a derivation, so a refused init keeps it"
    );

    // 66 bytes made of three-byte characters: the budget is on bytes, so this is
    // refused even though it is only 22 chars.
    init.server_device_name = "\u{20ac}".repeat(22);
    assert_eq!(init.server_device_name.len(), 66);
    assert_eq!(init.server_device_name.chars().count(), 22);
    assert!(matches!(
        desktop.handle_init(&init).unwrap_err(),
        ProtocolError::InvalidMessageFormat
    ));

    // The boundary: exactly 64 bytes still pairs, and both sides agree on the SAS.
    let at_the_limit = "x".repeat(PAIRING_DEVICE_NAME_MAX_BYTES);
    let (mut desktop, started) = start_desktop();
    let mut phone =
        ServerPairingSession::new(started.session_id, phone_identity(), &at_the_limit).unwrap();
    let init = phone.create_init().unwrap();
    assert_eq!(init.server_device_name.len(), PAIRING_DEVICE_NAME_MAX_BYTES);
    let response = desktop.handle_init(&init).unwrap().clone();
    phone
        .verify_response(&response, &started.client_x25519_public_key)
        .unwrap();
    assert_eq!(desktop.sas(), phone.sas());
}

/// The phone applies the same bound to the desktop's `client_device_name`, so the
/// invariant holds symmetrically rather than on one receive path only.
///
/// The defect this catches: `ServerPairingSession::verify_response` hashing an
/// over-long `response.client_device_name` verbatim, which both removes the bound
/// on a peer-supplied transcript field and lets a desktop choose a name the phone
/// would then display and persist.
#[test]
fn a_pairing_response_with_an_over_long_client_device_name_is_refused() {
    let (desktop, mut phone, response, qr_pk) = exchange();

    let mut over_long = response.clone();
    over_long.client_device_name = "\u{e9}".repeat(33); // 66 bytes, 33 chars
    assert_eq!(over_long.client_device_name.len(), 66);
    assert!(matches!(
        phone.verify_response(&over_long, &qr_pk).unwrap_err(),
        ProtocolError::InvalidMessageFormat
    ));
    // Nothing was derived or cached for the refused response...
    assert!(phone.transcript_hash().is_none(), "no H may exist");
    assert!(phone.sas().is_none(), "no session keys may be derived");
    assert!(!phone.session_keys_present());
    assert!(phone.negotiated().is_none());

    // ...and the genuine response still verifies afterwards, so the refusal did
    // not consume the one response a phone may verify.
    phone.verify_response(&response, &qr_pk).unwrap();
    assert_eq!(desktop.sas(), phone.sas());
}
