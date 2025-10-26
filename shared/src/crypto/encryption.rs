use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::Sha256;

use super::{ClientSymmetricKey, CryptoError, PairingSymmetricKey};

/// Encrypt data using AES-256-GCM
pub fn encrypt_aes_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    cipher
        .encrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_aes_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Derive a nonce from challenge and a context string
pub fn derive_nonce(challenge: &[u8; 32], info: &[u8]) -> Result<[u8; 12], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, challenge);
    let mut nonce = [0u8; 12];
    hk.expand(info, &mut nonce)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(nonce)
}

/// Encrypt with CSK using derived nonce
pub fn encrypt_with_csk(
    csk: &ClientSymmetricKey,
    challenge: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = derive_nonce(challenge, context)?;
    encrypt_aes_gcm(csk.as_bytes(), &nonce, plaintext, &[])
}

/// Decrypt with CSK using derived nonce
pub fn decrypt_with_csk(
    csk: &ClientSymmetricKey,
    challenge: &[u8; 32],
    context: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = derive_nonce(challenge, context)?;
    decrypt_aes_gcm(csk.as_bytes(), &nonce, ciphertext, &[])
}

/// Encrypt with CSK using random nonce
/// This is used for authentication messages where the challenge is inside
/// the encrypted payload and cannot be used for nonce derivation.
/// The random nonce is prepended to the ciphertext.
pub fn encrypt_with_csk_static_nonce(
    csk: &ClientSymmetricKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Generate a cryptographically secure random 12-byte nonce using OS RNG
    use rand::rngs::OsRng;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .expect("Failed to obtain OS RNG. Random generation should generally always work on supported systems.");

    // Encrypt the plaintext
    let ciphertext = encrypt_aes_gcm(csk.as_bytes(), &nonce, plaintext, &[])?;

    // Prepend the nonce to the ciphertext (nonce is not secret)
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt with CSK using random nonce
/// This is used for authentication messages where the challenge is inside
/// the encrypted payload and cannot be used for nonce derivation.
/// The nonce is extracted from the first 12 bytes of the input.
pub fn decrypt_with_csk_static_nonce(
    csk: &ClientSymmetricKey,
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Ensure we have at least a nonce
    if ciphertext_with_nonce.len() < 12 {
        return Err(CryptoError::DecryptionFailed);
    }

    // Extract the nonce from the first 12 bytes
    let nonce: [u8; 12] = ciphertext_with_nonce[..12]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Extract the actual ciphertext
    let ciphertext = &ciphertext_with_nonce[12..];

    decrypt_aes_gcm(csk.as_bytes(), &nonce, ciphertext, &[])
}

/// Encrypt with PSK using derived nonce
pub fn encrypt_with_psk(
    psk: &PairingSymmetricKey,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // For PSK, we derive a nonce from the key itself and context
    let hk = Hkdf::<Sha256>::new(None, psk.as_bytes());
    let mut nonce = [0u8; 12];
    hk.expand(context, &mut nonce)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    encrypt_aes_gcm(psk.as_bytes(), &nonce, plaintext, &[])
}

/// Decrypt with PSK using derived nonce
pub fn decrypt_with_psk(
    psk: &PairingSymmetricKey,
    context: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // For PSK, we derive a nonce from the key itself and context
    let hk = Hkdf::<Sha256>::new(None, psk.as_bytes());
    let mut nonce = [0u8; 12];
    hk.expand(context, &mut nonce)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    decrypt_aes_gcm(psk.as_bytes(), &nonce, ciphertext, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encryption() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_nonce_derivation() {
        let challenge = [1u8; 32];
        let info1 = b"context1";
        let info2 = b"context2";

        let nonce1 = derive_nonce(&challenge, info1).unwrap();
        let nonce2 = derive_nonce(&challenge, info2).unwrap();

        // Different contexts should produce different nonces
        assert_ne!(nonce1, nonce2);

        // Same context should produce same nonce
        let nonce1_again = derive_nonce(&challenge, info1).unwrap();
        assert_eq!(nonce1, nonce1_again);
    }

    #[test]
    fn test_csk_encryption() {
        let csk = ClientSymmetricKey::generate();
        let challenge = [2u8; 32];
        let context = b"test_context";
        let plaintext = b"Secret message";

        let ciphertext = encrypt_with_csk(&csk, &challenge, context, plaintext).unwrap();
        let decrypted = decrypt_with_csk(&csk, &challenge, context, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
