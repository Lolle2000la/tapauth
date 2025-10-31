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

/// Encrypt with CSK using a random nonce (prepended to ciphertext)
/// This is used for authentication messages where the challenge is inside
/// the encrypted payload and cannot be used for nonce derivation.
pub fn encrypt_with_csk_and_random_nonce(
    csk: &ClientSymmetricKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use rand::rngs::OsRng;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;

    let ciphertext = encrypt_aes_gcm(csk.as_bytes(), &nonce, plaintext, &[])?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt with CSK where the random nonce is prepended to ciphertext
/// This is used for authentication messages where the challenge is inside
/// the encrypted payload and cannot be used for nonce derivation.
/// The nonce is extracted from the first 12 bytes of the input.
pub fn decrypt_with_csk_and_prepended_nonce(
    csk: &ClientSymmetricKey,
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext_with_nonce.len() < 12 {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce: [u8; 12] = ciphertext_with_nonce[..12]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let ciphertext = &ciphertext_with_nonce[12..];
    decrypt_aes_gcm(csk.as_bytes(), &nonce, ciphertext, &[])
}

/// Encrypt with PSK using a random nonce (prepended to ciphertext)
pub fn encrypt_with_psk(
    psk: &PairingSymmetricKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Use a random nonce, prepend it to the ciphertext to avoid nonce reuse.
    use rand::rngs::OsRng;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;

    let ciphertext = encrypt_aes_gcm(psk.as_bytes(), &nonce, plaintext, &[])?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt with PSK where the random nonce is prepended to ciphertext
pub fn decrypt_with_psk(
    psk: &PairingSymmetricKey,
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Expect the first 12 bytes to be the random nonce.
    if ciphertext_with_nonce.len() < 12 {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce: [u8; 12] = ciphertext_with_nonce[..12]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let ciphertext = &ciphertext_with_nonce[12..];
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
        let csk = ClientSymmetricKey::generate().unwrap();
        let challenge = [2u8; 32];
        let context = b"test_context";
        let plaintext = b"Secret message";

        let ciphertext = encrypt_with_csk(&csk, &challenge, context, plaintext).unwrap();
        let decrypted = decrypt_with_csk(&csk, &challenge, context, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_decryption_fails() {
        let csk1 = ClientSymmetricKey::generate().unwrap();
        let csk2 = ClientSymmetricKey::generate().unwrap();
        let challenge = [3u8; 32];
        let context = b"test";
        let plaintext = b"data";

        let ciphertext = encrypt_with_csk(&csk1, &challenge, context, plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = decrypt_with_csk(&csk2, &challenge, context, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_context_decryption_fails() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let challenge = [4u8; 32];
        let plaintext = b"data";

        let ciphertext = encrypt_with_csk(&csk, &challenge, b"context1", plaintext).unwrap();

        // Decryption with wrong context should fail (different nonce)
        let result = decrypt_with_csk(&csk, &challenge, b"context2", &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let challenge = [5u8; 32];
        let context = b"test";
        let plaintext = b"data";

        let mut ciphertext = encrypt_with_csk(&csk, &challenge, context, plaintext).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication tag mismatch
        let result = decrypt_with_csk(&csk, &challenge, context, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext_encryption() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let challenge = [6u8; 32];
        let context = b"test";
        let plaintext = b"";

        let ciphertext = encrypt_with_csk(&csk, &challenge, context, plaintext).unwrap();
        let decrypted = decrypt_with_csk(&csk, &challenge, context, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext_encryption() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let challenge = [7u8; 32];
        let context = b"test";
        let plaintext = vec![42u8; 10000]; // 10KB of data

        let ciphertext = encrypt_with_csk(&csk, &challenge, context, &plaintext).unwrap();
        let decrypted = decrypt_with_csk(&csk, &challenge, context, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_psk_random_nonce_uniqueness_and_roundtrip() {
        // Create a random PSK
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        let psk = PairingSymmetricKey::from_bytes(bytes);

        let plaintext = b"hello psk";

        // Encrypt twice with same inputs; ciphertexts should differ due to random nonce
        let c1 = encrypt_with_psk(&psk, plaintext).unwrap();
        let c2 = encrypt_with_psk(&psk, plaintext).unwrap();
        assert_ne!(c1, c2);

        // Both should decrypt correctly
        let p1 = decrypt_with_psk(&psk, &c1).unwrap();
        let p2 = decrypt_with_psk(&psk, &c2).unwrap();
        assert_eq!(p1, plaintext);
        assert_eq!(p2, plaintext);
    }
}
