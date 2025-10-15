use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

const AES_NONCE_SIZE: usize = 12;
const TIME_WINDOW_SECONDS: i64 = 60;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Signature verification failed")]
    SignatureVerification,
    #[error("Invalid public key length")]
    InvalidPublicKey,
    #[error("Invalid private key length")]
    InvalidPrivateKey,
    #[error("Invalid challenge length")]
    InvalidChallengeLength,
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Key derivation failed")]
    KeyDerivation,
}

/// Convenience wrapper for an Ed25519 signing key.
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl SigningKeyPair {
    /// Generates a new Ed25519 signing key using a system CSPRNG.
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Returns the verifying key associated with this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs a message with the private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Provides access to the underlying signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl Default for SigningKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifies a signature using the provided verifying key.
pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    verifying_key
        .verify_strict(message, signature)
        .map_err(|_| CryptoError::SignatureVerification)
}

/// Generates a temporal identifier for device discovery.
/// As per `authentication-flow.md`, this is derived from the Client Symmetric Key (CSK)
/// and a time window.
pub fn generate_temporal_identifier(csk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let current_timestamp = Utc::now().timestamp();
    let time_window = current_timestamp / TIME_WINDOW_SECONDS;

    let hkdf = Hkdf::<Sha256>::new(None, csk);
    let mut okm = [0u8; 16]; // 16-byte identifier as per spec
    hkdf.expand(&time_window.to_be_bytes(), &mut okm)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(okm.to_vec())
}

/// Generates a Short Authentication String (SAS) for pairing verification.
/// As per `initial-key-exchange.md`, this is a 6-digit number derived via HKDF
/// from the Pairing Symmetric Key (PSK).
pub fn generate_sas(psk: &[u8]) -> Result<String, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, psk);
    let mut okm = [0u8; 8]; // 64-bit value
    hkdf.expand(b"tapauth-sas", &mut okm)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let num = u64::from_be_bytes(okm);
    let sas_num = num % 1_000_000;

    Ok(format!("{:06}", sas_num))
}

/// Encrypts data using AES-256-GCM.
pub fn encrypt(
    key: &[u8],
    data: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Encryption(e.to_string()))?;
    let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;
    Ok((ciphertext, nonce.to_vec()))
}

/// Decrypts data using AES-256-GCM.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Decryption(e.to_string()))?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::Decryption(e.to_string()))
}

/// Derives a shared key from an X25519 key exchange.
pub fn derive_shared_secret(secret: EphemeralSecret, public_key: &X25519PublicKey) -> Vec<u8> {
    secret.diffie_hellman(public_key).to_bytes().to_vec()
}

/// Derives a deterministic nonce from the session challenge as described in the
/// cryptography specification. The `info` string must be unique per message type.
pub fn derive_nonce_from_challenge(
    challenge: &[u8],
    info: &[u8],
) -> Result<[u8; AES_NONCE_SIZE], CryptoError> {
    if challenge.len() != 32 {
        return Err(CryptoError::InvalidChallengeLength);
    }

    let hkdf = Hkdf::<Sha256>::new(None, challenge);
    let mut nonce = [0u8; AES_NONCE_SIZE];
    hkdf.expand(info, &mut nonce)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_signing_and_verification() {
        let keypair = SigningKeyPair::new();
        let message = b"test message";
        let signature = keypair.sign(message);
        let verifying_key = keypair.verifying_key();
        assert!(verify_signature(message, &signature, &verifying_key).is_ok());
    }

    #[test]
    fn test_verification_fail() {
        let keypair1 = SigningKeyPair::new();
        let keypair2 = SigningKeyPair::new();
        let message = b"test message";
        let signature = keypair1.sign(message);
        let verifying_key = keypair2.verifying_key();
        assert!(verify_signature(message, &signature, &verifying_key).is_err());
    }

    #[test]
    fn test_verification_fail_tampered_message() {
        let keypair = SigningKeyPair::new();
        let message = b"test message";
        let tampered_message = b"test massage";
        let signature = keypair.sign(message);
        let verifying_key = keypair.verifying_key();
        assert!(verify_signature(tampered_message, &signature, &verifying_key).is_err());
    }

    #[test]
    fn test_generate_temporal_identifier() {
        let csk = b"test_key_12345678901234567890123";
        let identifier = generate_temporal_identifier(csk).unwrap();
        assert_eq!(identifier.len(), 16);
    }

    #[test]
    fn test_generate_sas() {
        let psk = b"test-psk-for-sas-generation";
        let sas = generate_sas(psk).unwrap();
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));

        // Test for deterministic output
        let sas2 = generate_sas(psk).unwrap();
        assert_eq!(sas, sas2);
    }

    #[test]
    fn test_encryption_decryption() {
        let mut rng = OsRng;
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let data = b"super secret message";

        let (ciphertext, nonce) = encrypt(&key, data, &mut rng).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decryption_fail_wrong_key() {
        let mut rng = OsRng;
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        rng.fill_bytes(&mut key1);
        rng.fill_bytes(&mut key2);
        let data = b"super secret message";

        let (ciphertext, nonce) = encrypt(&key1, data, &mut rng).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_fail_wrong_nonce() {
        let mut rng = OsRng;
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let data = b"super secret message";

        let (ciphertext, _) = encrypt(&key, data, &mut rng).unwrap();
        let mut wrong_nonce = [0u8; 12];
        rng.fill_bytes(&mut wrong_nonce);

        let result = decrypt(&key, &wrong_nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_fail_corrupted_ciphertext() {
        let mut rng = OsRng;
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let data = b"super secret message";

        let (mut ciphertext, nonce) = encrypt(&key, data, &mut rng).unwrap();
        // Flip a bit in the ciphertext
        ciphertext[0] ^= 0xff;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_key_exchange() {
        let secret1 = EphemeralSecret::random_from_rng(OsRng::default());
        let public1 = X25519PublicKey::from(&secret1);

        let secret2 = EphemeralSecret::random_from_rng(&mut OsRng);
        let public2 = X25519PublicKey::from(&secret2);

        let shared1 = derive_shared_secret(secret1, &public2);
        let shared2 = derive_shared_secret(secret2, &public1);

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_nonce_derivation_is_deterministic_and_distinct() {
        let challenge = [0x11u8; 32];
        let nonce_grant = derive_nonce_from_challenge(&challenge, b"auth_grant").unwrap();
        let nonce_grant_repeat = derive_nonce_from_challenge(&challenge, b"auth_grant").unwrap();
        assert_eq!(nonce_grant, nonce_grant_repeat);

        let nonce_denial = derive_nonce_from_challenge(&challenge, b"auth_denial").unwrap();
        assert_ne!(nonce_grant, nonce_denial);
    }

    #[test]
    fn test_nonce_derivation_rejects_invalid_length() {
        let short_challenge = [0xAAu8; 16];
        assert!(matches!(
            derive_nonce_from_challenge(&short_challenge, b"auth_grant"),
            Err(CryptoError::InvalidChallengeLength)
        ));
    }
}
