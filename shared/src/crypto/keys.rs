use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// Ed25519 key pair for signing
pub struct Ed25519KeyPair {
    signing_key_bytes: SecretBox<[u8; 32]>,
    pub verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Result<Self, CryptoError> {
        // Use OS CSPRNG to generate 32 bytes and construct the signing key
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::RandomGenerationFailed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key_bytes: SecretBox::new(Box::new(seed)),
            verifying_key,
        })
    }

    /// Create from signing key bytes
    pub fn from_signing_key_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key_bytes: SecretBox::new(Box::new(*bytes)),
            verifying_key,
        })
    }

    /// Get signing key bytes
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        *self.signing_key_bytes.expose_secret()
    }
    /// Sign arbitrary data using the signing key
    pub fn sign(&self, data: &[u8]) -> ed25519_dalek::Signature {
        let sk = SigningKey::from_bytes(self.signing_key_bytes.expose_secret());
        sk.sign(data)
    }
    /// Get verifying key bytes
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}
impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Self {
        let bytes = *self.signing_key_bytes.expose_secret();
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Ed25519KeyPair {
            signing_key_bytes: SecretBox::new(Box::new(bytes)),
            verifying_key,
        }
    }
}

/// X25519 key pair for key exchange
pub struct X25519KeyPair {
    secret_bytes: SecretBox<[u8; 32]>,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair
    pub fn generate() -> Result<Self, CryptoError> {
        // Use OS CSPRNG to fill 32 random bytes for the static secret
        let mut sk = [0u8; 32];
        getrandom::fill(&mut sk).map_err(|_| CryptoError::RandomGenerationFailed)?;
        let secret = X25519StaticSecret::from(sk);
        let public = X25519PublicKey::from(&secret);
        Ok(Self {
            secret_bytes: SecretBox::new(Box::new(sk)),
            public,
        })
    }

    /// Create from secret key bytes
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = X25519StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self {
            secret_bytes: SecretBox::new(Box::new(bytes)),
            public,
        }
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get secret key bytes (use with caution!)
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        *self.secret_bytes.expose_secret()
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let their_public_key = X25519PublicKey::from(*their_public);
        let secret = X25519StaticSecret::from(*self.secret_bytes.expose_secret());
        let shared_secret = secret.diffie_hellman(&their_public_key);
        Ok(shared_secret.to_bytes())
    }
}

/// Client Symmetric Key (CSK) - 32 bytes for AES-256
pub struct ClientSymmetricKey(SecretBox<[u8; 32]>);

impl ClientSymmetricKey {
    /// Generate a new random CSK
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(Self(SecretBox::new(Box::new(key))))
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Get key bytes (exposes secret for cryptographic operations)
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Convert to bytes (consuming self, exposes secret)
    pub fn to_bytes(self) -> [u8; 32] {
        *self.0.expose_secret()
    }
}

impl Clone for ClientSymmetricKey {
    fn clone(&self) -> Self {
        let bytes = *self.0.expose_secret();
        ClientSymmetricKey(SecretBox::new(Box::new(bytes)))
    }
}

// Manual Serialize/Deserialize for ClientSymmetricKey since Secret doesn't implement those traits by default
impl Serialize for ClientSymmetricKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClientSymmetricKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Pairing Symmetric Key (PSK) - ephemeral key for pairing only
pub struct PairingSymmetricKey(SecretBox<[u8; 32]>);

impl PairingSymmetricKey {
    /// Create from derived key material
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Get key bytes (exposes secret for cryptographic operations)
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

use super::CryptoError;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_key_generation() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = keypair.signing_key_bytes();
        let restored = Ed25519KeyPair::from_signing_key_bytes(&bytes).unwrap();
        assert_eq!(
            keypair.verifying_key_bytes(),
            restored.verifying_key_bytes()
        );
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

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
