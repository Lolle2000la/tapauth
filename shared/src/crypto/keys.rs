use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::ZeroizeOnDrop;

/// Ed25519 key pair for signing
#[derive(Clone)]
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Self {
        let mut rng = OsRng.unwrap_err(); // Create an INSTANCE
        let signing_key = SigningKey::generate(&mut rng); // Use the INSTANCE
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create from signing key bytes
    pub fn from_signing_key_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get signing key bytes
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get verifying key bytes
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // Zeroize happens automatically for SigningKey
    }
}

/// X25519 key pair for key exchange
#[derive(Clone)]
pub struct X25519KeyPair {
    secret: X25519StaticSecret,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair
    pub fn generate() -> Self {
        let mut rng = OsRng.unwrap_err(); // Create an INSTANCE
        let secret = X25519StaticSecret::random_from_rng(&mut rng); // Use the INSTANCE
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from secret key bytes
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = X25519StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get secret key bytes (use with caution!)
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let their_public_key = X25519PublicKey::from(*their_public);
        let shared_secret = self.secret.diffie_hellman(&their_public_key);
        Ok(shared_secret.to_bytes())
    }
}

/// Client Symmetric Key (CSK) - 32 bytes for AES-256
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct ClientSymmetricKey([u8; 32]);

impl ClientSymmetricKey {
    /// Generate a new random CSK
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; 32];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut key)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(Self(key))
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to bytes (consuming self)
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Pairing Symmetric Key (PSK) - ephemeral key for pairing only
#[derive(Clone, ZeroizeOnDrop)]
pub struct PairingSymmetricKey([u8; 32]);

impl PairingSymmetricKey {
    /// Create from derived key material
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Random number generation failed")]
    RandomGenerationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_key_generation() {
        let keypair = Ed25519KeyPair::generate();
        let bytes = keypair.signing_key_bytes();
        let restored = Ed25519KeyPair::from_signing_key_bytes(&bytes).unwrap();
        assert_eq!(
            keypair.verifying_key_bytes(),
            restored.verifying_key_bytes()
        );
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.diffie_hellman(&bob.public_key_bytes()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice.public_key_bytes()).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_csk_generation() {
        let csk1 = ClientSymmetricKey::generate().unwrap();
        let csk2 = ClientSymmetricKey::generate().unwrap();

        // Keys should be different
        assert_ne!(csk1.as_bytes(), csk2.as_bytes());
    }
}
