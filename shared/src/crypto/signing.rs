use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::{CryptoError, Ed25519KeyPair};

/// Sign data using Ed25519
pub fn sign_ed25519(keypair: &Ed25519KeyPair, data: &[u8]) -> Vec<u8> {
    let signature = keypair.sign(data);
    signature.to_bytes().to_vec()
}

/// Verify Ed25519 signature
pub fn verify_ed25519(
    public_key: &[u8; 32],
    data: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidSignature)?;

    if signature.len() != 64 {
        return Err(CryptoError::InvalidSignature);
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(data, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_and_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Test message for signing";

        let signature = sign_ed25519(&keypair, message);

        // Verify with correct key should succeed
        assert!(verify_ed25519(&keypair.verifying_key_bytes(), message, &signature).is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(verify_ed25519(&keypair.verifying_key_bytes(), wrong_message, &signature).is_err());

        // Verify with wrong key should fail
        let other_keypair = Ed25519KeyPair::generate().unwrap();
        assert!(verify_ed25519(&other_keypair.verifying_key_bytes(), message, &signature).is_err());
    }
}
