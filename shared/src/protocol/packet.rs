//! Outer authenticated-encryption framing (`EncryptedPacket`) and `WrapperMessage` builders.
//!
//! v2 has exactly one AEAD construction: a 12-byte random nonce is prepended to the
//! ciphertext, the key is the CSK, and the AAD binds the cleartext packet header
//! (`encryption_algorithm` and `temporal_identifier`) into the tag, so a downgrade or a
//! temporal-ID tamper is detected before the inner payload is decrypted or parsed.

use prost::Message as ProstMessage;

use super::messages::PROTOCOL_VERSION_V2;
use super::ProtocolError;
use crate::crypto::{
    decrypt_with_csk_and_prepended_nonce, encrypt_with_csk_and_random_nonce, encrypted_packet_aad,
    generate_current_temporal_identifier_with_alg, ClientSymmetricKey,
};
use crate::protocol::pb::*;

/// Length in bytes of the `EncryptedPacket.temporal_identifier` on every transport.
///
/// The BLE GATT specification fixes the post-connection identifier at the full
/// 16 bytes (only the advertisement uses the truncated 10-byte form).
pub const TEMPORAL_IDENTIFIER_LEN: usize = 16;

/// Serialize, encrypt and package an already-signed `WrapperMessage` into an `EncryptedPacket`.
///
/// The caller is expected to have signed `wrapper` with
/// [`sign_wrapper_message`](super::messages::sign_wrapper_message); its signature travels
/// inside the ciphertext. The temporal identifier is the current 60s window under
/// `hash_algorithm`, and the AAD is
/// `encrypted_packet_aad(encryption_algorithm, &temporal_identifier)`.
pub fn create_encrypted_packet_with_csk_nonce(
    csk: &ClientSymmetricKey,
    symmetric_algorithm: SymmetricAlgorithm,
    hash_algorithm: HashAlgorithm,
    wrapper: &WrapperMessage,
) -> Result<EncryptedPacket, ProtocolError> {
    let temporal_identifier =
        generate_current_temporal_identifier_with_alg(csk, hash_algorithm)?.to_vec();

    let encryption_algorithm = symmetric_algorithm as i32;
    let aad = encrypted_packet_aad(encryption_algorithm, &temporal_identifier);

    let plaintext = wrapper.encode_to_vec();
    let ciphertext = encrypt_with_csk_and_random_nonce(csk, symmetric_algorithm, &plaintext, &aad)?;

    Ok(EncryptedPacket {
        temporal_identifier,
        encryption_algorithm,
        ciphertext,
    })
}

/// Decrypt an `EncryptedPacket` and recover the signed `WrapperMessage`.
///
/// Rejects a packet whose `encryption_algorithm` differs from
/// `expected_symmetric_algorithm` **before** touching the ciphertext, and one whose
/// `temporal_identifier` is not exactly [`TEMPORAL_IDENTIFIER_LEN`] bytes (the
/// BLE GATT specification fixes the on-air identifier at the full 16 bytes; a short
/// one is a malformed frame, not a shorter identifier). It then decrypts with
/// `AAD = encrypted_packet_aad(packet.encryption_algorithm, &packet.temporal_identifier)`,
/// so a tampered header fails authentication instead of being silently accepted.
pub fn decrypt_encrypted_packet_with_csk_nonce(
    csk: &ClientSymmetricKey,
    expected_symmetric_algorithm: SymmetricAlgorithm,
    packet: &EncryptedPacket,
) -> Result<WrapperMessage, ProtocolError> {
    if packet.encryption_algorithm != expected_symmetric_algorithm as i32 {
        return Err(ProtocolError::AlgorithmMismatch);
    }
    if packet.temporal_identifier.len() != TEMPORAL_IDENTIFIER_LEN {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let aad = encrypted_packet_aad(packet.encryption_algorithm, &packet.temporal_identifier);
    let plaintext = decrypt_with_csk_and_prepended_nonce(
        csk,
        expected_symmetric_algorithm,
        &packet.ciphertext,
        &aad,
    )?;

    let wrapper = WrapperMessage::decode(plaintext.as_slice())?;
    Ok(wrapper)
}

/// Create a WrapperMessage containing an AuthenticationRequest
pub fn wrap_auth_request(request: AuthenticationRequest) -> WrapperMessage {
    WrapperMessage {
        version: PROTOCOL_VERSION_V2,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        payload_type: PayloadType::AuthRequest as i32,
        payload: request.encode_to_vec(),
        signature: Vec::new(),
    }
}

/// Create a WrapperMessage containing an AuthenticationGrant
pub fn wrap_auth_grant(grant: AuthenticationGrant) -> WrapperMessage {
    WrapperMessage {
        version: PROTOCOL_VERSION_V2,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        payload_type: PayloadType::AuthGrant as i32,
        payload: grant.encode_to_vec(),
        signature: Vec::new(),
    }
}

/// Create a WrapperMessage containing an AuthenticationDenial
pub fn wrap_auth_denial(denial: AuthenticationDenial) -> WrapperMessage {
    WrapperMessage {
        version: PROTOCOL_VERSION_V2,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        payload_type: PayloadType::AuthDenial as i32,
        payload: denial.encode_to_vec(),
        signature: Vec::new(),
    }
}

/// Create a WrapperMessage containing a GrantConfirmation
pub fn wrap_grant_confirmation(confirmation: GrantConfirmation) -> WrapperMessage {
    WrapperMessage {
        version: PROTOCOL_VERSION_V2,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        payload_type: PayloadType::GrantConfirmation as i32,
        payload: confirmation.encode_to_vec(),
        signature: Vec::new(),
    }
}

/// Create a WrapperMessage containing an AuthenticationCancel
pub fn wrap_auth_cancel(cancel: AuthenticationCancel) -> WrapperMessage {
    WrapperMessage {
        version: PROTOCOL_VERSION_V2,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        payload_type: PayloadType::AuthCancel as i32,
        payload: cancel.encode_to_vec(),
        signature: Vec::new(),
    }
}

/// Extract the inner `challenge` field, dispatching on `wrapper.payload_type`.
///
/// Returns `None` for an unknown/absent payload type or a payload that does not decode.
///
/// # Security
///
/// This decodes an **unverified** wrapper: it neither checks the signature nor the
/// payload type against a caller expectation, so its output is attacker-controlled
/// until the wrapper has been verified. Only call it on a `WrapperMessage` that has
/// already been authenticated with
/// [`verify_wrapper_signature`](super::messages::verify_wrapper_signature) — or, on
/// the wire path, that came out of
/// [`verify_and_decode_payload`](super::messages::verify_and_decode_payload), which
/// verifies before decoding.
///
/// No authorization decision (grant, denial, cancel, "this challenge is answered")
/// may be taken from this function's output; use `verify_auth_grant` /
/// `verify_auth_denial` or `verify_and_decode_payload` for those.
pub fn extract_challenge(wrapper: &WrapperMessage) -> Option<Vec<u8>> {
    let payload = wrapper.payload.as_slice();
    let payload_type = wrapper.payload_type;

    if payload_type == PayloadType::AuthRequest as i32 {
        AuthenticationRequest::decode(payload)
            .ok()
            .map(|m| m.challenge)
    } else if payload_type == PayloadType::AuthGrant as i32 {
        AuthenticationGrant::decode(payload)
            .ok()
            .map(|m| m.challenge)
    } else if payload_type == PayloadType::AuthDenial as i32 {
        AuthenticationDenial::decode(payload)
            .ok()
            .map(|m| m.challenge)
    } else if payload_type == PayloadType::GrantConfirmation as i32 {
        GrantConfirmation::decode(payload).ok().map(|m| m.challenge)
    } else if payload_type == PayloadType::AuthCancel as i32 {
        AuthenticationCancel::decode(payload)
            .ok()
            .map(|m| m.challenge)
    } else {
        None
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
    use crate::crypto::Ed25519KeyPair;
    use crate::protocol::messages::{
        create_auth_request_with_challenge, create_auth_request_with_context, sign_wrapper_message,
        verify_and_decode_payload, DecodedPayload, COMMAND_PREVIEW_MAX_BYTES,
        PAM_SERVICE_MAX_BYTES, PROCESS_NAME_MAX_BYTES,
    };

    const ED25519: i32 = SignatureAlgorithm::Ed25519 as i32;
    const AES: SymmetricAlgorithm = SymmetricAlgorithm::Aes256Gcm;
    const CHACHA: SymmetricAlgorithm = SymmetricAlgorithm::Chacha20Poly1305;
    const SHA256: HashAlgorithm = HashAlgorithm::Sha256;

    /// The payload type a [`DecodedPayload`] was decoded from.
    fn decoded_payload_type(decoded: &DecodedPayload) -> i32 {
        match decoded {
            DecodedPayload::AuthRequest(_) => PayloadType::AuthRequest as i32,
            DecodedPayload::AuthGrant(_) => PayloadType::AuthGrant as i32,
            DecodedPayload::AuthDenial(_) => PayloadType::AuthDenial as i32,
            DecodedPayload::GrantConfirmation(_) => PayloadType::GrantConfirmation as i32,
            DecodedPayload::AuthCancel(_) => PayloadType::AuthCancel as i32,
        }
    }

    fn signed_grant_wrapper(keypair: &Ed25519KeyPair, challenge: [u8; 32]) -> WrapperMessage {
        let mut wrapper = wrap_auth_grant(AuthenticationGrant {
            challenge: challenge.to_vec(),
        });
        sign_wrapper_message(&mut wrapper, keypair).unwrap();
        wrapper
    }

    #[test]
    fn test_packet_round_trip_for_all_payload_types_and_algorithms() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [0x2Au8; 32];

        let cases: Vec<(WrapperMessage, PayloadType)> = vec![
            (
                wrap_auth_request(
                    create_auth_request_with_challenge("user", "host", &challenge).unwrap(),
                ),
                PayloadType::AuthRequest,
            ),
            (
                wrap_auth_grant(AuthenticationGrant {
                    challenge: challenge.to_vec(),
                }),
                PayloadType::AuthGrant,
            ),
            (
                wrap_auth_denial(AuthenticationDenial {
                    challenge: challenge.to_vec(),
                    reason: "user rejected".to_string(),
                }),
                PayloadType::AuthDenial,
            ),
            (
                wrap_grant_confirmation(GrantConfirmation {
                    challenge: challenge.to_vec(),
                }),
                PayloadType::GrantConfirmation,
            ),
            (
                wrap_auth_cancel(AuthenticationCancel {
                    challenge: challenge.to_vec(),
                }),
                PayloadType::AuthCancel,
            ),
        ];
        assert_eq!(cases.len(), 5);

        for symmetric in [AES, CHACHA] {
            for (unsigned, expected_type) in &cases {
                let mut wrapper = unsigned.clone();
                assert_eq!(wrapper.version, PROTOCOL_VERSION_V2);
                assert_eq!(wrapper.payload_type, *expected_type as i32);
                assert!(wrapper.signature.is_empty());
                // The wrapper carries the raw serialized payload, so a non-empty payload
                // must already be present before signing.
                assert!(!wrapper.payload.is_empty());
                sign_wrapper_message(&mut wrapper, &keypair).unwrap();
                assert_eq!(wrapper.signature.len(), 64);

                let packet =
                    create_encrypted_packet_with_csk_nonce(&csk, symmetric, SHA256, &wrapper)
                        .unwrap();
                assert_eq!(packet.encryption_algorithm, symmetric as i32);
                assert_eq!(packet.temporal_identifier.len(), 16);
                // 12-byte nonce || plaintext || 16-byte tag
                assert_eq!(
                    packet.ciphertext.len(),
                    wrapper.encode_to_vec().len() + 12 + 16
                );

                let decrypted =
                    decrypt_encrypted_packet_with_csk_nonce(&csk, symmetric, &packet).unwrap();
                assert_eq!(decrypted, wrapper);

                let decoded =
                    verify_and_decode_payload(&decrypted, &keypair.verifying_key_bytes(), ED25519)
                        .unwrap();
                assert_eq!(decoded_payload_type(&decoded), *expected_type as i32);
                assert_eq!(extract_challenge(&decrypted).unwrap(), challenge.to_vec());
            }
        }
    }

    #[test]
    fn test_temporal_identifier_tampering_fails_aead() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let wrapper = signed_grant_wrapper(&keypair, [0x31u8; 32]);

        let packet = create_encrypted_packet_with_csk_nonce(&csk, AES, SHA256, &wrapper).unwrap();

        // Flip one bit of the temporal identifier: it is bound into the AAD.
        let mut tampered = packet.clone();
        tampered.temporal_identifier[0] ^= 0x01;
        assert_eq!(tampered.temporal_identifier.len(), 16);
        assert!(matches!(
            decrypt_encrypted_packet_with_csk_nonce(&csk, AES, &tampered),
            Err(ProtocolError::Crypto(_))
        ));

        // Same ciphertext, same length, only the identifier differs by one bit.
        assert_eq!(tampered.ciphertext, packet.ciphertext);
        assert_ne!(tampered.temporal_identifier, packet.temporal_identifier);

        // The untouched packet still decrypts.
        let decrypted = decrypt_encrypted_packet_with_csk_nonce(&csk, AES, &packet).unwrap();
        assert_eq!(decrypted, wrapper);
        assert_eq!(decrypted.payload, wrapper.payload);
    }

    #[test]
    fn test_encryption_algorithm_field_tampering_fails_aead() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let wrapper = signed_grant_wrapper(&keypair, [0x32u8; 32]);

        let packet = create_encrypted_packet_with_csk_nonce(&csk, AES, SHA256, &wrapper).unwrap();

        // Relabel the packet as ChaCha20-Poly1305 without re-encrypting. The verifier
        // follows the claimed algorithm, so this must fail authentication: the AAD now
        // carries a different algorithm id than the tag was produced with.
        let mut tampered = packet.clone();
        tampered.encryption_algorithm = CHACHA as i32;
        assert_eq!(tampered.ciphertext, packet.ciphertext);
        assert!(matches!(
            decrypt_encrypted_packet_with_csk_nonce(&csk, CHACHA, &tampered),
            Err(ProtocolError::Crypto(_))
        ));

        // The original still decrypts under its own algorithm.
        let decrypted = decrypt_encrypted_packet_with_csk_nonce(&csk, AES, &packet).unwrap();
        assert_eq!(decrypted, wrapper);
    }

    #[test]
    fn test_decrypt_rejects_algorithm_mismatch_before_decrypting() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let wrapper = signed_grant_wrapper(&keypair, [0x33u8; 32]);

        let mut packet =
            create_encrypted_packet_with_csk_nonce(&csk, AES, SHA256, &wrapper).unwrap();
        assert_eq!(packet.encryption_algorithm, AES as i32);

        // Replace the ciphertext with unusable bytes: only an algorithm check that runs
        // before decryption can produce AlgorithmMismatch here.
        packet.ciphertext = vec![0x00; 1];

        // Caller pinned to ChaCha20-Poly1305 while the packet claims AES-256-GCM.
        assert!(matches!(
            decrypt_encrypted_packet_with_csk_nonce(&csk, CHACHA, &packet),
            Err(ProtocolError::AlgorithmMismatch)
        ));

        // Control: with the matching algorithm the same packet fails as a cipher error,
        // not as an algorithm mismatch.
        assert!(matches!(
            decrypt_encrypted_packet_with_csk_nonce(&csk, AES, &packet),
            Err(ProtocolError::Crypto(_))
        ));
    }

    #[test]
    fn test_signed_context_request_fits_ble_gatt_budget() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();

        // Every field at its documented maximum.
        let username = "u".repeat(32);
        let hostname = "h".repeat(64);
        let pam_service = "p".repeat(PAM_SERVICE_MAX_BYTES);
        let process_name = "n".repeat(PROCESS_NAME_MAX_BYTES);
        let command_preview = "c".repeat(COMMAND_PREVIEW_MAX_BYTES);

        let request = create_auth_request_with_context(
            &username,
            &hostname,
            &[0x5Au8; 32],
            &pam_service,
            &process_name,
            &command_preview,
            true,
        )
        .unwrap();
        assert_eq!(request.username.len(), 32);
        assert_eq!(request.hostname.len(), 64);
        assert_eq!(request.pam_service.len(), PAM_SERVICE_MAX_BYTES);
        assert_eq!(request.process_name.len(), PROCESS_NAME_MAX_BYTES);
        assert_eq!(request.command_preview.len(), COMMAND_PREVIEW_MAX_BYTES);

        let mut wrapper = wrap_auth_request(request);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        let packet = create_encrypted_packet_with_csk_nonce(&csk, AES, SHA256, &wrapper).unwrap();
        let encoded = packet.encode_to_vec();
        let measured = encoded.len();

        assert!(
            measured <= crate::models::ble::MAX_GATT_PAYLOAD_BYTES,
            "signed EncryptedPacket is {measured} bytes, BLE GATT budget is {}",
            crate::models::ble::MAX_GATT_PAYLOAD_BYTES
        );
        // The exact measured size: 341-byte AuthenticationRequest payload -> 416-byte
        // signed WrapperMessage (14B domain + 3 be32 words are only in the signature
        // transcript, not on the wire) -> 467-byte EncryptedPacket
        // (18B temporal_identifier + 2B algorithm + 12B nonce + 416B plaintext + 16B tag).
        assert_eq!(
            measured, 467,
            "worst-case signed EncryptedPacket size changed"
        );
        assert_eq!(EncryptedPacket::decode(encoded.as_slice()).unwrap(), packet);
    }

    #[test]
    fn test_extract_challenge() {
        let request = create_auth_request_with_challenge("user", "host", &[0x44u8; 32]).unwrap();
        let challenge = request.challenge.clone();
        let wrapper = wrap_auth_request(request);

        let extracted = extract_challenge(&wrapper).unwrap();
        assert_eq!(extracted, challenge);
    }

    #[test]
    fn test_extract_challenge_from_auth_grant() {
        // v2 AuthenticationGrant carries the raw challenge inside the signed payload.
        let wrapper = wrap_auth_grant(AuthenticationGrant {
            challenge: vec![5u8; 32],
        });

        assert_eq!(extract_challenge(&wrapper).unwrap(), vec![5u8; 32]);
    }

    #[test]
    fn test_extract_challenge_empty_wrapper() {
        let wrapper = WrapperMessage {
            version: PROTOCOL_VERSION_V2,
            signature_algorithm: ED25519,
            payload_type: PayloadType::Unspecified as i32,
            payload: Vec::new(),
            signature: Vec::new(),
        };

        assert!(extract_challenge(&wrapper).is_none());
    }

    #[test]
    fn test_extract_challenge_undecodable_payload_is_none() {
        let wrapper = WrapperMessage {
            version: PROTOCOL_VERSION_V2,
            signature_algorithm: ED25519,
            payload_type: PayloadType::AuthGrant as i32,
            payload: vec![0xFF, 0xFF, 0xFF],
            signature: vec![0xAA; 64],
        };

        assert!(extract_challenge(&wrapper).is_none());
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod protobuf_tests {
    use super::*;
    use crate::crypto::{ClientSymmetricKey, Ed25519KeyPair};
    use crate::protocol::messages::{create_auth_request_with_challenge, decode_payload};
    use prost::Message;

    const AES: SymmetricAlgorithm = SymmetricAlgorithm::Aes256Gcm;
    const SHA256: HashAlgorithm = HashAlgorithm::Sha256;

    /// A non-16-byte `temporal_identifier` must be refused by the decrypt path.
    /// The defect this catches: a decrypt that authenticates whatever length the
    /// peer sent, so a 5-byte identifier is accepted as a valid frame even though
    /// the specification fixes it at 16 bytes (which would also let a peer pick
    /// from a much smaller identifier space).
    #[test]
    fn test_decrypt_rejects_non_16_byte_temporal_identifier() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let request = create_auth_request_with_challenge("user", "host", &[0x11u8; 32]).unwrap();
        let mut wrapper = wrap_auth_request(request);
        crate::protocol::messages::sign_wrapper_message(
            &mut wrapper,
            &Ed25519KeyPair::generate().unwrap(),
        )
        .unwrap();

        let genuine = create_encrypted_packet_with_csk_nonce(&csk, AES, SHA256, &wrapper).unwrap();
        assert_eq!(genuine.temporal_identifier.len(), TEMPORAL_IDENTIFIER_LEN);
        assert_eq!(
            decrypt_encrypted_packet_with_csk_nonce(&csk, AES, &genuine).unwrap(),
            wrapper
        );

        for len in [0usize, 5, 15, 17, 32] {
            let mut resized = genuine.clone();
            resized.temporal_identifier = vec![0xAB; len];
            let error = decrypt_encrypted_packet_with_csk_nonce(&csk, AES, &resized).unwrap_err();
            assert!(
                matches!(error, ProtocolError::InvalidMessageFormat),
                "a {len}-byte temporal identifier must be refused, got {error:?}"
            );
        }
    }

    /// `wrap_auth_request` must tag the payload as an `AUTH_REQUEST` and carry the
    /// request's serialized bytes as the signed payload.
    /// The defect this catches: a builder that sets the wrong `PayloadType` or
    /// re-serializes a different struct than the one handed to it.
    #[test]
    fn test_wrapper_message_auth_request_type() {
        let request =
            create_auth_request_with_challenge("testuser", "testhost", &[0xAAu8; 32]).unwrap();
        let wrapper = wrap_auth_request(request.clone());

        assert_eq!(wrapper.payload_type, PayloadType::AuthRequest as i32);
        assert_eq!(wrapper.version, PROTOCOL_VERSION_V2);
        assert_eq!(
            AuthenticationRequest::decode(wrapper.payload.as_slice()).unwrap(),
            request
        );

        // ...and the decoded payload is dispatched back as an AuthRequest.
        match decode_payload(&wrapper).unwrap() {
            crate::protocol::messages::DecodedPayload::AuthRequest(decoded) => {
                assert_eq!(decoded, request);
            }
            other => panic!("expected AuthRequest, got {other:?}"),
        }
    }

    /// `wrap_grant_confirmation` must tag the payload as a `GRANT_CONFIRMATION`
    /// and carry the confirmation's bytes.
    #[test]
    fn test_wrapper_message_grant_confirmation_type() {
        let confirmation = GrantConfirmation {
            challenge: vec![0xCC; 32],
        };
        let wrapper = wrap_grant_confirmation(confirmation.clone());

        assert_eq!(wrapper.payload_type, PayloadType::GrantConfirmation as i32);
        assert_eq!(
            GrantConfirmation::decode(wrapper.payload.as_slice()).unwrap(),
            confirmation
        );
        assert!(matches!(
            decode_payload(&wrapper).unwrap(),
            crate::protocol::messages::DecodedPayload::GrantConfirmation(_)
        ));
    }

    /// `wrap_auth_cancel` must tag the payload as an `AUTH_CANCEL` and carry the
    /// cancel's bytes.
    #[test]
    fn test_wrapper_message_auth_cancel_type() {
        let cancel = AuthenticationCancel {
            challenge: vec![0xDD; 32],
        };
        let wrapper = wrap_auth_cancel(cancel.clone());

        assert_eq!(wrapper.payload_type, PayloadType::AuthCancel as i32);
        assert_eq!(
            AuthenticationCancel::decode(wrapper.payload.as_slice()).unwrap(),
            cancel
        );
        assert!(matches!(
            decode_payload(&wrapper).unwrap(),
            crate::protocol::messages::DecodedPayload::AuthCancel(_)
        ));
    }

    /// `GRANT_CONFIRMATION` and `AUTH_CANCEL` must stay distinct payload types: a
    /// confirmation must not decode as a cancel or vice versa.
    /// The defect this catches: both enums collapsing to one wire value (e.g. a
    /// copy-paste in `payload_type`), which would let a cancel satisfy a grant wait.
    #[test]
    fn test_confirmation_and_cancel_are_distinct_payload_types() {
        let confirmation = wrap_grant_confirmation(GrantConfirmation {
            challenge: vec![0x01; 32],
        });
        let cancel = wrap_auth_cancel(AuthenticationCancel {
            challenge: vec![0x02; 32],
        });

        assert_ne!(confirmation.payload_type, cancel.payload_type);
        assert_eq!(confirmation.payload_type, 4);
        assert_eq!(cancel.payload_type, 5);
    }
}
