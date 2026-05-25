//! Protocol message creation and verification
//!
//! After refactoring, signatures are now on WrapperMessage instead of individual messages.
//! This provides centralized signature verification and simplifies the protocol.

use prost::Message as ProstMessage;

use crate::crypto::{sign_ed25519, verify_ed25519, CryptoError, Ed25519KeyPair};
use crate::protocol::pb::*;

#[cfg(debug_assertions)]
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    #[cfg(debug_assertions)]
    {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = data;
        "<stripped>".to_string()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] prost::EncodeError),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] prost::DecodeError),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("Invalid message format")]
    InvalidMessageFormat,
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Sign a WrapperMessage with the given keypair
/// This sets the signature_algorithm and signature fields on the wrapper
pub fn sign_wrapper_message(
    wrapper: &mut WrapperMessage,
    keypair: &Ed25519KeyPair,
) -> Result<(), ProtocolError> {
    // Clear signature fields before signing
    wrapper.signature_algorithm = SignatureAlgorithm::Ed25519 as i32;
    wrapper.signature = Vec::new();

    // Serialize the unsigned wrapper
    let data_to_sign = wrapper.encode_to_vec();

    // Sign it
    wrapper.signature = sign_ed25519(keypair, &data_to_sign);

    Ok(())
}

/// Verify a WrapperMessage signature
/// Returns Ok(()) if the signature is valid, Err otherwise
pub fn verify_wrapper_signature(
    wrapper: &WrapperMessage,
    public_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    // Create unsigned copy for verification
    let mut unsigned_wrapper = wrapper.clone();
    unsigned_wrapper.signature = Vec::new();

    let data_to_verify = unsigned_wrapper.encode_to_vec();

    verify_ed25519(public_key, &data_to_verify, &wrapper.signature)?;
    Ok(())
}

/// Create an AuthenticationRequest message (without signature)
/// The signature will be added when wrapping in WrapperMessage
pub fn create_auth_request(
    username: &str,
    hostname: &str,
) -> Result<AuthenticationRequest, ProtocolError> {
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge)
        .map_err(|_| ProtocolError::Crypto(CryptoError::RandomGenerationFailed))?;

    create_auth_request_with_challenge(username, hostname, &challenge)
}

/// Create an AuthenticationRequest with an externally supplied 32-byte challenge
pub fn create_auth_request_with_challenge(
    username: &str,
    hostname: &str,
    challenge: &[u8],
) -> Result<AuthenticationRequest, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProtocolError::Crypto(CryptoError::SystemTimeError))?
        .as_secs();

    Ok(AuthenticationRequest {
        challenge: challenge.to_vec(),
        username: username.to_string(),
        hostname: hostname.to_string(),
        timestamp_unix_seconds: timestamp,
    })
}

/// Validate timestamp in AuthenticationRequest (within ±5 minutes)
pub fn is_request_timestamp_valid(request: &AuthenticationRequest) -> bool {
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return false,
    };

    let timestamp = request.timestamp_unix_seconds;
    const MAX_CLOCK_SKEW: u64 = 60; // 60-second validity window per auth spec

    timestamp <= now + MAX_CLOCK_SKEW && timestamp >= now.saturating_sub(MAX_CLOCK_SKEW)
}

/// Create an AuthenticationGrant message
/// signed_challenge is the server's signature over the original challenge
pub fn create_auth_grant(
    keypair: &Ed25519KeyPair,
    challenge: &[u8],
) -> Result<AuthenticationGrant, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    // Sign the challenge
    let signed_challenge = sign_ed25519(keypair, challenge);

    Ok(AuthenticationGrant { signed_challenge })
}

/// Verify an AuthenticationGrant
/// Checks both the wrapper signature and the signed_challenge
pub fn verify_auth_grant(
    wrapper: &WrapperMessage,
    challenge: &[u8],
    server_public_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    // First: Verify the wrapper message signature
    verify_wrapper_signature(wrapper, server_public_key)?;

    // Second: Extract and verify the signed_challenge
    let grant = match &wrapper.payload {
        Some(wrapper_message::Payload::AuthGrant(g)) => g,
        _ => return Err(ProtocolError::InvalidMessageFormat),
    };

    verify_ed25519(server_public_key, challenge, &grant.signed_challenge)?;
    Ok(())
}

/// Create an AuthenticationDenial message
pub fn create_auth_denial(challenge: &[u8]) -> Result<AuthenticationDenial, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    Ok(AuthenticationDenial {
        challenge: challenge.to_vec(),
    })
}

/// Create a GrantConfirmation message
pub fn create_grant_confirmation(challenge: &[u8]) -> Result<GrantConfirmation, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    Ok(GrantConfirmation {
        challenge: challenge.to_vec(),
    })
}

/// Create an AuthenticationCancel message
pub fn create_auth_cancel(challenge: &[u8]) -> Result<AuthenticationCancel, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    Ok(AuthenticationCancel {
        challenge: challenge.to_vec(),
    })
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
    use crate::protocol::packet::*;

    #[test]
    fn test_wrapper_signature_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();

        // Create a request
        let request = create_auth_request("user", "host").unwrap();
        let mut wrapper = wrap_auth_request(request);

        // Sign it
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Verify with correct key
        assert!(verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes()).is_ok());

        // Verify with wrong key should fail
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_auth_request_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [1u8; 32];

        let request =
            create_auth_request_with_challenge("testuser", "testhost", &challenge).unwrap();
        let mut wrapper = wrap_auth_request(request);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        assert_eq!(wrapper.signature.len(), 64); // Ed25519 signatures are 64 bytes

        // Verification should succeed
        verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_tampered_signature_detection() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [2u8; 32];

        let request = create_auth_request_with_challenge("user", "host", &challenge).unwrap();
        let mut wrapper = wrap_auth_request(request);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Tamper with the signature
        if let Some(byte) = wrapper.signature.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }

        // Verification should fail
        assert!(verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_auth_grant_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [3u8; 32];

        let grant = create_auth_grant(&keypair, &challenge).unwrap();
        assert!(!grant.signed_challenge.is_empty());

        let mut wrapper = wrap_auth_grant(grant);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Verification should succeed
        verify_auth_grant(&wrapper, &challenge, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(
            verify_auth_grant(&wrapper, &challenge, &other_keypair.verifying_key_bytes()).is_err()
        );
    }

    #[test]
    fn test_auth_denial_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [5u8; 32];

        let denial = create_auth_denial(&challenge).unwrap();
        assert_eq!(denial.challenge.len(), 32);

        let mut wrapper = wrap_auth_denial(denial);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Verification should succeed
        verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_grant_confirmation_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [7u8; 32];

        let confirmation = create_grant_confirmation(&challenge).unwrap();
        assert_eq!(confirmation.challenge.len(), 32);

        let mut wrapper = wrap_grant_confirmation(confirmation);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Verification should succeed
        verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_auth_cancel_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let challenge = [9u8; 32];

        let cancel = create_auth_cancel(&challenge).unwrap();
        assert_eq!(cancel.challenge.len(), 32);

        let mut wrapper = wrap_auth_cancel(cancel);
        sign_wrapper_message(&mut wrapper, &keypair).unwrap();

        // Verification should succeed
        verify_wrapper_signature(&wrapper, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(verify_wrapper_signature(&wrapper, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_invalid_challenge_length() {
        // Test that functions reject invalid challenge lengths
        assert!(create_auth_request_with_challenge("user", "host", &[1u8; 16]).is_err());
        assert!(create_auth_denial(&[1u8; 16]).is_err());
        assert!(create_grant_confirmation(&[1u8; 16]).is_err());
        assert!(create_auth_cancel(&[1u8; 16]).is_err());
    }

    #[test]
    fn test_timestamp_validation() {
        let challenge = [1u8; 32];
        let mut request = create_auth_request_with_challenge("user", "host", &challenge).unwrap();

        // Current timestamp should be valid
        assert!(is_request_timestamp_valid(&request));

        // Old timestamp should be invalid
        request.timestamp_unix_seconds = 1000;
        assert!(!is_request_timestamp_valid(&request));
    }

    #[test]
    fn test_timestamp_validation_at_boundary() {
        let challenge = [1u8; 32];
        let request = create_auth_request_with_challenge("user", "host", &challenge).unwrap();

        // Exactly at the +60s boundary (future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut req_plus_60 = request.clone();
        req_plus_60.timestamp_unix_seconds = now + 60;
        assert!(is_request_timestamp_valid(&req_plus_60));

        // Just beyond the +60s boundary
        let mut req_plus_61 = request.clone();
        req_plus_61.timestamp_unix_seconds = now + 61;
        assert!(!is_request_timestamp_valid(&req_plus_61));

        // Exactly at the -60s boundary (past)
        let mut req_minus_60 = request.clone();
        req_minus_60.timestamp_unix_seconds = now.saturating_sub(60);
        assert!(is_request_timestamp_valid(&req_minus_60));

        // Just beyond the -60s boundary
        let mut req_minus_61 = request.clone();
        req_minus_61.timestamp_unix_seconds = now.saturating_sub(61);
        assert!(!is_request_timestamp_valid(&req_minus_61));
    }

    #[test]
    fn test_sha256_hex_debug() {
        let data = b"test data";
        let result = sha256_hex(data);

        // In debug, should be a 64-char hex string
        #[cfg(debug_assertions)]
        {
            assert_eq!(result.len(), 64);
            // All characters should be valid hex
            assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // In release, should return the stripped placeholder
        #[cfg(not(debug_assertions))]
        {
            assert_eq!(result, "<stripped>");
        }
    }
}
