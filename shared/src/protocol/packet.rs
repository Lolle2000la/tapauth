use prost::Message as ProstMessage;

use super::ProtocolError;
use crate::crypto::{
    decrypt_with_csk, decrypt_with_csk_static_nonce, encrypt_with_csk,
    encrypt_with_csk_static_nonce, generate_current_temporal_identifier, ClientSymmetricKey,
};
use crate::protocol::pb::*;

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

/// Encrypt and package a WrapperMessage into an EncryptedPacket using CSK-derived nonce
/// This is used for authentication messages where the challenge is inside the encrypted
/// payload and cannot be used for nonce derivation (chicken-egg problem).
pub fn create_encrypted_packet_with_csk_nonce(
    csk: &ClientSymmetricKey,
    wrapper: &WrapperMessage,
) -> Result<EncryptedPacket, ProtocolError> {
    // Generate temporal identifier
    let temporal_identifier = generate_current_temporal_identifier(csk)?.to_vec();

    // Serialize the wrapper message
    let plaintext = wrapper.encode_to_vec();

    // Encrypt with CSK using static nonce (derived from CSK only)
    let ciphertext = encrypt_with_csk_static_nonce(csk, &plaintext)?;

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

/// Decrypt an EncryptedPacket using CSK-derived nonce and extract the WrapperMessage
/// This is used for authentication messages where the challenge is inside the encrypted
/// payload and cannot be used for nonce derivation.
pub fn decrypt_encrypted_packet_with_csk_nonce(
    csk: &ClientSymmetricKey,
    packet: &EncryptedPacket,
) -> Result<WrapperMessage, ProtocolError> {
    // Decrypt the ciphertext using static nonce (derived from CSK only)
    let plaintext = decrypt_with_csk_static_nonce(csk, &packet.ciphertext)?;

    // Deserialize the wrapper message
    let wrapper = WrapperMessage::decode(&plaintext[..])?;

    Ok(wrapper)
}

/// Create a WrapperMessage containing an AuthenticationRequest
pub fn wrap_auth_request(request: AuthenticationRequest) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        payload: Some(wrapper_message::Payload::AuthRequest(request)),
    }
}

/// Create a WrapperMessage containing an AuthenticationGrant
pub fn wrap_auth_grant(grant: AuthenticationGrant) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        payload: Some(wrapper_message::Payload::AuthGrant(grant)),
    }
}

/// Create a WrapperMessage containing an AuthenticationDenial
pub fn wrap_auth_denial(denial: AuthenticationDenial) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        payload: Some(wrapper_message::Payload::AuthDenial(denial)),
    }
}

/// Create a WrapperMessage containing a GrantConfirmation
pub fn wrap_grant_confirmation(confirmation: GrantConfirmation) -> WrapperMessage {
    WrapperMessage {
        version: 1,
        payload: Some(wrapper_message::Payload::GrantConfirmation(confirmation)),
    }
}

/// Create a WrapperMessage containing an AuthenticationCancel
pub fn wrap_auth_cancel(cancel: AuthenticationCancel) -> WrapperMessage {
    WrapperMessage {
        version: 1,
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
        let keypair = Ed25519KeyPair::generate();
        let challenge = [1u8; 32];
        let context = b"test_context";

        // Create a request
        let request = create_auth_request(&keypair, "user", "host").unwrap();
        let wrapper = wrap_auth_request(request);

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
        let keypair = Ed25519KeyPair::generate();
        let request = create_auth_request(&keypair, "user", "host").unwrap();
        let challenge = request.challenge.clone();
        let wrapper = wrap_auth_request(request);

        let extracted = extract_challenge(&wrapper).unwrap();
        assert_eq!(extracted, challenge);
    }
}
