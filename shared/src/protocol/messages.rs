use prost::Message as ProstMessage;

use crate::crypto::{sign_ed25519, verify_ed25519, Ed25519KeyPair};
use crate::protocol::pb::*;
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
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

/// Create an AuthenticationRequest message
pub fn create_auth_request(
    keypair: &Ed25519KeyPair,
    username: &str,
    hostname: &str,
) -> Result<AuthenticationRequest, ProtocolError> {
    // Convenience: generate a random challenge and delegate to the
    // variant that accepts an externally-supplied challenge. This keeps
    // existing callers working while allowing callers who already
    // track the challenge (e.g. client) to sign/verify the same nonce.
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).expect("getrandom failed");

    create_auth_request_with_challenge(keypair, username, hostname, &challenge)
}

/// Create an AuthenticationRequest with an externally supplied 32-byte challenge.
pub fn create_auth_request_with_challenge(
    keypair: &Ed25519KeyPair,
    username: &str,
    hostname: &str,
    challenge: &[u8],
) -> Result<AuthenticationRequest, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_secs();

    let mut request = AuthenticationRequest {
        challenge: challenge.to_vec(),
        username: username.to_string(),
        hostname: hostname.to_string(),
        timestamp_unix_seconds: timestamp,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
    };

    // Sign the request
    let data_to_sign = request.encode_to_vec();
    request.signature = sign_ed25519(keypair, &data_to_sign);

    Ok(request)
}

/// Verify an AuthenticationRequest signature
pub fn verify_auth_request(
    request: &AuthenticationRequest,
    public_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    if request.challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    // Create a copy without signature for verification
    let mut unsigned_request = request.clone();
    unsigned_request.signature = Vec::new();
    let data_to_verify = unsigned_request.encode_to_vec();

    verify_ed25519(public_key, &data_to_verify, &request.signature)?;
    Ok(())
}

/// Check if an authentication request is within the valid time window (60 seconds)
pub fn is_request_timestamp_valid(request: &AuthenticationRequest) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_secs();

    let age = now.saturating_sub(request.timestamp_unix_seconds);
    age <= 60
}

/// Create an AuthenticationGrant message
pub fn create_auth_grant(
    keypair: &Ed25519KeyPair,
    challenge: &[u8],
) -> Result<AuthenticationGrant, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    // Sign the challenge
    let signed_challenge = sign_ed25519(keypair, challenge);

    let mut grant = AuthenticationGrant {
        signed_challenge,
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
    };

    // Sign the grant message
    let data_to_sign = grant.encode_to_vec();
    grant.signature = sign_ed25519(keypair, &data_to_sign);

    Ok(grant)
}

/// Verify an AuthenticationGrant signature and signed challenge
pub fn verify_auth_grant(
    grant: &AuthenticationGrant,
    challenge: &[u8],
    server_public_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    // Verify the grant message signature
    let mut unsigned_grant = grant.clone();
    unsigned_grant.signature = Vec::new();
    let data_to_verify = unsigned_grant.encode_to_vec();

    // First check: grant.signature over the grant message (with signature cleared)
    if let Err(e) = verify_ed25519(server_public_key, &data_to_verify, &grant.signature) {
        // Log diagnostic details for debugging
        tracing::error!(
            "Grant signature verification failed: {:?}; grant_sig_len={}, data_len={}",
            e,
            grant.signature.len(),
            data_to_verify.len()
        );
        // For security, avoid logging raw signature/challenge material in error logs.
        tracing::debug!("Grant (unsigned) sha256: {}", sha256_hex(&data_to_verify));
        tracing::debug!(
            "Grant signature (trunc): {}… (len={})",
            &hex::encode(&grant.signature)
                [..std::cmp::min(16, hex::encode(&grant.signature).len())],
            grant.signature.len()
        );
        return Err(ProtocolError::Crypto(e.into()));
    }

    // Second check: signed_challenge is a signature over the original challenge
    if let Err(e) = verify_ed25519(server_public_key, challenge, &grant.signed_challenge) {
        tracing::error!(
            "Signed-challenge verification failed: {:?}; signed_challenge_len={}, challenge_len={}",
            e,
            grant.signed_challenge.len(),
            challenge.len()
        );
        tracing::debug!("Challenge (sha256): {}", sha256_hex(challenge));
        tracing::debug!(
            "Signed challenge (trunc): {}… (len={})",
            &hex::encode(&grant.signed_challenge)
                [..std::cmp::min(16, hex::encode(&grant.signed_challenge).len())],
            grant.signed_challenge.len()
        );
        return Err(ProtocolError::Crypto(e.into()));
    }

    Ok(())
}

/// Create an AuthenticationDenial message
pub fn create_auth_denial(
    keypair: &Ed25519KeyPair,
    challenge: &[u8],
) -> Result<AuthenticationDenial, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let mut denial = AuthenticationDenial {
        challenge: challenge.to_vec(),
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
    };

    // Sign the denial message
    let data_to_sign = denial.encode_to_vec();
    denial.signature = sign_ed25519(keypair, &data_to_sign);

    Ok(denial)
}

/// Verify an AuthenticationDenial signature
pub fn verify_auth_denial(
    denial: &AuthenticationDenial,
    server_public_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    if denial.challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let mut unsigned_denial = denial.clone();
    unsigned_denial.signature = Vec::new();
    let data_to_verify = unsigned_denial.encode_to_vec();

    verify_ed25519(server_public_key, &data_to_verify, &denial.signature)?;
    Ok(())
}

/// Create a GrantConfirmation message
pub fn create_grant_confirmation(
    keypair: &Ed25519KeyPair,
    challenge: &[u8],
) -> Result<GrantConfirmation, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let mut confirmation = GrantConfirmation {
        challenge: challenge.to_vec(),
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
    };

    let data_to_sign = confirmation.encode_to_vec();
    confirmation.signature = sign_ed25519(keypair, &data_to_sign);

    Ok(confirmation)
}

/// Verify a GrantConfirmation signature
pub fn verify_grant_confirmation(
    confirmation: &GrantConfirmation,
    client_public_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    if confirmation.challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let mut unsigned_confirmation = confirmation.clone();
    unsigned_confirmation.signature = Vec::new();
    let data_to_verify = unsigned_confirmation.encode_to_vec();

    verify_ed25519(client_public_key, &data_to_verify, &confirmation.signature)?;
    Ok(())
}

/// Create an AuthenticationCancel message
pub fn create_auth_cancel(
    keypair: &Ed25519KeyPair,
    challenge: &[u8],
) -> Result<AuthenticationCancel, ProtocolError> {
    if challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let mut cancel = AuthenticationCancel {
        challenge: challenge.to_vec(),
        signature_algorithm: SignatureAlgorithm::Ed25519 as i32,
        signature: Vec::new(),
    };

    let data_to_sign = cancel.encode_to_vec();
    cancel.signature = sign_ed25519(keypair, &data_to_sign);

    Ok(cancel)
}

/// Verify an AuthenticationCancel signature
pub fn verify_auth_cancel(
    cancel: &AuthenticationCancel,
    client_public_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    if cancel.challenge.len() != 32 {
        return Err(ProtocolError::InvalidMessageFormat);
    }

    let mut unsigned_cancel = cancel.clone();
    unsigned_cancel.signature = Vec::new();
    let data_to_verify = unsigned_cancel.encode_to_vec();

    verify_ed25519(client_public_key, &data_to_verify, &cancel.signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_request_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate();
        let request = create_auth_request(&keypair, "testuser", "testhost").unwrap();

        assert_eq!(request.username, "testuser");
        assert_eq!(request.hostname, "testhost");
        assert_eq!(request.challenge.len(), 32);
        assert!(!request.signature.is_empty());

        // Verification should succeed with correct key
        verify_auth_request(&request, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate();
        assert!(verify_auth_request(&request, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_auth_grant_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate();
        let challenge = [1u8; 32];

        let grant = create_auth_grant(&keypair, &challenge).unwrap();

        // Verification should succeed
        verify_auth_grant(&grant, &challenge, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong challenge
        let wrong_challenge = [2u8; 32];
        assert!(
            verify_auth_grant(&grant, &wrong_challenge, &keypair.verifying_key_bytes()).is_err()
        );
    }

    #[test]
    fn test_timestamp_validation() {
        let keypair = Ed25519KeyPair::generate();
        let mut request = create_auth_request(&keypair, "user", "host").unwrap();

        // Current timestamp should be valid
        assert!(is_request_timestamp_valid(&request));

        // Old timestamp should be invalid
        request.timestamp_unix_seconds = 1000;
        assert!(!is_request_timestamp_valid(&request));
    }

    #[test]
    fn test_auth_denial_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate();
        let challenge = [5u8; 32];

        let denial = create_auth_denial(&keypair, &challenge).unwrap();

        assert_eq!(denial.challenge.len(), 32);
        assert!(!denial.signature.is_empty());

        // Verification should succeed
        verify_auth_denial(&denial, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate();
        assert!(verify_auth_denial(&denial, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_grant_confirmation_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate();
        let challenge = [7u8; 32];

        let confirmation = create_grant_confirmation(&keypair, &challenge).unwrap();

        assert_eq!(confirmation.challenge.len(), 32);
        assert!(!confirmation.signature.is_empty());

        // Verification should succeed
        verify_grant_confirmation(&confirmation, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate();
        assert!(
            verify_grant_confirmation(&confirmation, &other_keypair.verifying_key_bytes())
                .is_err()
        );
    }

    #[test]
    fn test_auth_cancel_creation_and_verification() {
        let keypair = Ed25519KeyPair::generate();
        let challenge = [9u8; 32];

        let cancel = create_auth_cancel(&keypair, &challenge).unwrap();

        assert_eq!(cancel.challenge.len(), 32);
        assert!(!cancel.signature.is_empty());

        // Verification should succeed
        verify_auth_cancel(&cancel, &keypair.verifying_key_bytes()).unwrap();

        // Verification should fail with wrong key
        let other_keypair = Ed25519KeyPair::generate();
        assert!(verify_auth_cancel(&cancel, &other_keypair.verifying_key_bytes()).is_err());
    }

    #[test]
    fn test_invalid_challenge_length() {
        let keypair = Ed25519KeyPair::generate();

        // Too short
        let short_challenge = [1u8; 16];
        assert!(create_auth_grant(&keypair, &short_challenge).is_err());
        assert!(create_auth_denial(&keypair, &short_challenge).is_err());
        assert!(create_grant_confirmation(&keypair, &short_challenge).is_err());
        assert!(create_auth_cancel(&keypair, &short_challenge).is_err());

        // Too long
        let long_challenge = [1u8; 64];
        assert!(create_auth_grant(&keypair, &long_challenge).is_err());
    }

    #[test]
    fn test_tampered_signature_detection() {
        let keypair = Ed25519KeyPair::generate();
        let challenge = [3u8; 32];

        let mut grant = create_auth_grant(&keypair, &challenge).unwrap();

        // Tamper with signature
        if !grant.signature.is_empty() {
            grant.signature[0] ^= 0xFF;
        }

        // Verification should fail
        assert!(verify_auth_grant(&grant, &challenge, &keypair.verifying_key_bytes()).is_err());
    }
}
