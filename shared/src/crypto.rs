pub mod encryption;
pub mod kdf;
pub mod keys;
pub mod signing;
pub mod temporal;

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
    #[error("System time error")]
    SystemTimeError,
}

pub use encryption::*;
pub use kdf::*;
pub use keys::*;
pub use signing::*;
pub use temporal::*;
