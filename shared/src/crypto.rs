use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chrono::Utc;
use ed25519_dalek::{Keypair, Signature, Signer, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRngCore, OsRng};
use sha2::{Digest, Sha256};
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
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Key derivation failed")]
    KeyDerivation,
}

/// An Ed25519 keypair for signing and verification.
pub struct SigningKeyPair {
    pub keypair: Keypair,
}

impl SigningKeyPair {
    /// Generates a new Ed25519 keypair.
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        Self { keypair }
    }

    /// Signs a message with the private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Verifies a signature on a message with the public key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &VerifyingKey,
    ) -> Result<(), CryptoError> {
        public_key
            .verify_strict(message, signature)
            .map_err(|_| CryptoError::SignatureVerification)
    }
}

impl Default for SigningKeyPair {
    fn default() -> Self {
        Self::new()
    }
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
/// As per `initial-key-exchange.md`, this is a 6-digit number derived from
/// the concatenated public keys of the client and server.
pub fn generate_sas(client_pub_key: &[u8], server_pub_key: &[u8]) -> Result<String, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(client_pub_key);
    hasher.update(server_pub_key);
    let hash = hasher.finalize();

    // Take the first 4 bytes of the hash and create a u32
    let num = u32::from_be_bytes(hash[0..4].try_into().unwrap());

    // Get a 6-digit number
    let sas_num = num % 1_000_000;

    Ok(format!("{:06}", sas_num))
}

/// Encrypts data using AES-256-GCM.
pub fn encrypt(
    key: &[u8],
    data: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Encryption(e.to_string()))?;
    let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);
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
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::Decryption(e.to_string()))
}

/// Derives a shared key from an X25519 key exchange.
pub fn derive_shared_secret(secret: EphemeralSecret, public_key: &X25519PublicKey) -> Vec<u8> {
    secret.diffie_hellman(public_key).to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_signing_and_verification() {
        let keypair = SigningKeyPair::new();
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(keypair
            .verify(message, &signature, &keypair.keypair.verifying_key())
            .is_ok());
    }

    #[test]
    fn test_verification_fail() {
        let keypair1 = SigningKeyPair::new();
        let keypair2 = SigningKeyPair::new();
        let message = b"test message";
        let signature = keypair1.sign(message);
        assert!(keypair2
            .verify(message, &signature, &keypair2.keypair.verifying_key())
            .is_err());
    }

    #[test]
    fn test_generate_temporal_identifier() {
        let csk = b"test_key_12345678901234567890123";
        let identifier = generate_temporal_identifier(csk).unwrap();
        assert_eq!(identifier.len(), 16);
    }

    #[test]
    fn test_generate_sas() {
        let client_pk = [0u8; 32];
        let server_pk = [1u8; 32];
        let sas = generate_sas(&client_pk, &server_pk).unwrap();
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_encryption_decryption() {
        let mut rng = OsRng;
        let key = Aes256Gcm::generate_key(&mut rng);
        let data = b"super secret message";

        let (ciphertext, nonce) = encrypt(key.as_slice(), data, &mut rng).unwrap();
        let decrypted = decrypt(key.as_slice(), &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decryption_fail_wrong_key() {
        let mut rng = OsRng;
        let key1 = Aes256Gcm::generate_key(&mut rng);
        let key2 = Aes256Gcm::generate_key(&mut rng);
        let data = b"super secret message";

        let (ciphertext, nonce) = encrypt(key1.as_slice(), data, &mut rng).unwrap();
        let result = decrypt(key2.as_slice(), &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_key_exchange() {
        let secret1 = EphemeralSecret::random_from_rng(OsRng);
        let public1 = X25519PublicKey::from(&secret1);

        let secret2 = EphemeralSecret::random_from_rng(OsRng);
        let public2 = X25519PublicKey::from(&secret2);

        let shared1 = derive_shared_secret(secret1, &public2);
        let shared2 = derive_shared_secret(secret2, &public1);

        assert_eq!(shared1, shared2);
    }
}
