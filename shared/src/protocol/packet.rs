use prost::Message as ProstMessage;

use super::ProtocolError;
use crate::crypto::{
    decrypt_with_csk, decrypt_with_csk_and_prepended_nonce, encrypt_with_csk,
    encrypt_with_csk_and_random_nonce, generate_current_temporal_identifier, ClientSymmetricKey,
};
use crate::protocol::pb::*;

#[cfg(test)]
use super::messages::sign_wrapper_message;

/// Encrypt and package a WrapperMessage into an EncryptedPacket
pub fn create_encrypted_packet(
    csk: &ClientSymmetricKey,
    challenge: &[u8; 32],
    context: &[u8],
    wrapper: &WrapperMessage,
) -> Result<EncryptedPacket, ProtocolError> {
    // Generate temporal identifier
    let temporal_identifier = generate_current_temporal_identifier(csk)?.to_vec();

    // Serialize the wrapper message
    let plaintext = wrapper.encode_to_vec();

    // Encrypt with CSK
    let ciphertext = encrypt_with_csk(csk, challenge, context, &plaintext)?;

    Ok(EncryptedPacket {
        temporal_identifier,
        encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
        ciphertext,
    })
}

/// Encrypt and package a WrapperMessage into an EncryptedPacket using CSK with a random nonce
/// The random 12-byte nonce is prepended to the ciphertext; used when challenge is inside payload.
pub fn create_encrypted_packet_with_csk_nonce(
    csk: &ClientSymmetricKey,
    wrapper: &WrapperMessage,
) -> Result<EncryptedPacket, ProtocolError> {
    // Generate temporal identifier
    let temporal_identifier = generate_current_temporal_identifier(csk)?.to_vec();

    // Serialize the wrapper message
    let plaintext = wrapper.encode_to_vec();

    // Encrypt with CSK using a random, prepended nonce
    let ciphertext = encrypt_with_csk_and_random_nonce(csk, &plaintext)?;

    Ok(EncryptedPacket {
        temporal_identifier,
        encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
        ciphertext,
    })
}

/// Decrypt an EncryptedPacket and extract the WrapperMessage
pub fn decrypt_encrypted_packet(
    csk: &ClientSymmetricKey,
    challenge: &[u8; 32],
    context: &[u8],
    packet: &EncryptedPacket,
) -> Result<WrapperMessage, ProtocolError> {
    // Decrypt the ciphertext
    let plaintext = decrypt_with_csk(csk, challenge, context, &packet.ciphertext)?;

    // Deserialize the wrapper message
    let wrapper = WrapperMessage::decode(&plaintext[..])?;

    Ok(wrapper)
}

/// Decrypt an EncryptedPacket created with CSK random, prepended nonce and extract the WrapperMessage
pub fn decrypt_encrypted_packet_with_csk_nonce(
    csk: &ClientSymmetricKey,
    packet: &EncryptedPacket,
) -> Result<WrapperMessage, ProtocolError> {
    // Decrypt the ciphertext using the prepended random nonce
    let plaintext = decrypt_with_csk_and_prepended_nonce(csk, &packet.ciphertext)?;

    // Deserialize the wrapper message
    let wrapper = WrapperMessage::decode(&plaintext[..])?;

    Ok(wrapper)
}

/// Create a WrapperMessage containing an AuthenticationRequest
pub fn wrap_auth_request(request: AuthenticationRequest) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
        payload: Some(wrapper_message::Payload::AuthRequest(request)),
    }
}

/// Create a WrapperMessage containing an AuthenticationGrant
pub fn wrap_auth_grant(grant: AuthenticationGrant) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
        payload: Some(wrapper_message::Payload::AuthGrant(grant)),
    }
}

/// Create a WrapperMessage containing an AuthenticationDenial
pub fn wrap_auth_denial(denial: AuthenticationDenial) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
        payload: Some(wrapper_message::Payload::AuthDenial(denial)),
    }
}

/// Create a WrapperMessage containing a GrantConfirmation
pub fn wrap_grant_confirmation(confirmation: GrantConfirmation) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
        payload: Some(wrapper_message::Payload::GrantConfirmation(confirmation)),
    }
}

/// Create a WrapperMessage containing an AuthenticationCancel
pub fn wrap_auth_cancel(cancel: AuthenticationCancel) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
        payload: Some(wrapper_message::Payload::AuthCancel(cancel)),
    }
}

/// Extract the challenge from a WrapperMessage if it contains a message with a challenge
pub fn extract_challenge(wrapper: &WrapperMessage) -> Option<Vec<u8>> {
    match &wrapper.payload {
        Some(wrapper_message::Payload::AuthRequest(req)) => Some(req.challenge.clone()),
        Some(wrapper_message::Payload::AuthDenial(denial)) => Some(denial.challenge.clone()),
        Some(wrapper_message::Payload::GrantConfirmation(conf)) => Some(conf.challenge.clone()),
        Some(wrapper_message::Payload::AuthCancel(cancel)) => Some(cancel.challenge.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Ed25519KeyPair;
    use crate::protocol::messages::create_auth_request;

    #[test]
    fn test_packet_encryption_decryption() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [1u8; 32];
        let context = b"test_context";

        // Create a request
        let request = create_auth_request("user", "host").unwrap();
        let mut wrapper = wrap_auth_request(request);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Encrypt
        let packet = create_encrypted_packet(&csk, &challenge, context, &wrapper).unwrap();

        // Decrypt
        let decrypted_wrapper =
            decrypt_encrypted_packet(&csk, &challenge, context, &packet).unwrap();

        // Verify the payload matches
        assert!(matches!(
            decrypted_wrapper.payload,
            Some(wrapper_message::Payload::AuthRequest(_))
        ));
    }

    #[test]
    fn test_extract_challenge() {
        let request = create_auth_request("user", "host").unwrap();
        let challenge = request.challenge.clone();
        let wrapper = wrap_auth_request(request);

        let extracted = extract_challenge(&wrapper).unwrap();
        assert_eq!(extracted, challenge);
    }
}

#[cfg(test)]
mod protobuf_tests {
    use super::*;
    use prost::Message;

    #[test]
    fn test_encrypted_packet_temporal_identifier_correct_length() {
        // Create a test EncryptedPacket with exactly 16 bytes
        let temporal_id = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let packet = EncryptedPacket {
            temporal_identifier: temporal_id.clone(),
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };

        // Encode the packet
        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // Decode using prost to verify we get the same temporal_identifier
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier, temporal_id);
        assert_eq!(decoded.temporal_identifier.len(), 16);
    }

    #[test]
    fn test_encrypted_packet_temporal_identifier_wrong_length() {
        // Create packet with wrong length temporal_identifier (should be 16 bytes)
        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5], // Only 5 bytes
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0xAA, 0xBB],
        };

        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // Prost doesn't validate length - just checks it decodes
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier.len(), 5); // Prost allows it
    }

    #[test]
    fn test_encrypted_packet_field_order_independent() {
        // Verify that prost correctly handles fields regardless of encoding order
        let temporal_id = vec![0xFF; 16];
        let ciphertext = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let packet = EncryptedPacket {
            temporal_identifier: temporal_id.clone(),
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: ciphertext.clone(),
        };

        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // Decode and verify all fields are correct
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier, temporal_id);
        assert_eq!(
            decoded.encryption_algorithm,
            SymmetricAlgorithm::Aes256Gcm as i32
        );
        assert_eq!(decoded.ciphertext, ciphertext);
    }

    #[test]
    fn test_encrypted_packet_with_various_ciphertext_lengths() {
        // Test that encoding/decoding works regardless of ciphertext size
        let temporal_id = vec![0x42; 16];

        for ciphertext_len in [0, 1, 100, 1000, 10000] {
            let ciphertext = vec![0xAB; ciphertext_len];

            let packet = EncryptedPacket {
                temporal_identifier: temporal_id.clone(),
                encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
                ciphertext,
            };

            let mut buf = Vec::new();
            packet.encode(&mut buf).unwrap();

            let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
            assert_eq!(
                decoded.temporal_identifier, temporal_id,
                "Failed for ciphertext length {}",
                ciphertext_len
            );
        }
    }

    #[test]
    fn test_encrypted_packet_all_byte_values() {
        // Ensure encoding/decoding works with any byte values in temporal_id
        for byte_val in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
            let temporal_id = vec![byte_val; 16];

            let packet = EncryptedPacket {
                temporal_identifier: temporal_id.clone(),
                encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
                ciphertext: vec![0x00],
            };

            let mut buf = Vec::new();
            packet.encode(&mut buf).unwrap();

            let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
            assert_eq!(
                decoded.temporal_identifier, temporal_id,
                "Failed for byte value 0x{:02X}",
                byte_val
            );
        }
    }

    #[test]
    fn test_wrapper_message_auth_request_type() {
        let request = AuthenticationRequest {
            challenge: vec![0xAA; 32],
            username: "testuser".to_string(),
            hostname: "testhost".to_string(),
            timestamp_unix_seconds: 1234567890,
        };

        let wrapper = WrapperMessage {
            version: 1,
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xBB; 64],
            payload: Some(wrapper_message::Payload::AuthRequest(request)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        // Parse and verify type
        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::AuthRequest(_))
        ));
    }

    #[test]
    fn test_wrapper_message_grant_confirmation_type() {
        let confirmation = GrantConfirmation {
            challenge: vec![0xCC; 32],
        };

        let wrapper = WrapperMessage {
            version: 1,
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xBB; 64],
            payload: Some(wrapper_message::Payload::GrantConfirmation(confirmation)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::GrantConfirmation(_))
        ));
    }

    #[test]
    fn test_wrapper_message_auth_cancel_type() {
        let cancel = AuthenticationCancel {
            challenge: vec![0xDD; 32],
        };

        let wrapper = WrapperMessage {
            version: 1,
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xCC; 64],
            payload: Some(wrapper_message::Payload::AuthCancel(cancel)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::AuthCancel(_))
        ));
    }

    #[test]
    fn test_wrapper_message_with_version() {
        // Verify that version field doesn't interfere with message type detection
        let request = AuthenticationRequest {
            challenge: vec![0xEE; 32],
            username: "user".to_string(),
            hostname: "host".to_string(),
            timestamp_unix_seconds: 1234567890,
        };

        let wrapper = WrapperMessage {
            version: 42, // Non-standard version
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: vec![0xFF; 64],
            payload: Some(wrapper_message::Payload::AuthRequest(request)),
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert_eq!(parsed.version, 42);
        assert!(matches!(
            parsed.payload,
            Some(wrapper_message::Payload::AuthRequest(_))
        ));
    }

    #[test]
    fn test_wrapper_message_unknown_type() {
        // Empty wrapper message (no payload set)
        let wrapper = WrapperMessage {
            version: 1,
            signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
            signature: Vec::new(),
            payload: None,
        };

        let mut buf = Vec::new();
        wrapper.encode(&mut buf).unwrap();

        let parsed = WrapperMessage::decode(&buf[..]).unwrap();
        assert!(parsed.payload.is_none());
    }
}
