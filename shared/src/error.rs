//! Unified error types for TapAuth shared library.
//!
//! Provides conversion from internal errors (crypto, I/O, protobuf) to
//! typed errors that can be mapped to JNI exceptions or other FFI boundaries.

use thiserror::Error;

/// Central error type for TapAuth operations.
///
/// Maps to JNI exceptions:
/// - `InvalidInput` → `IllegalArgumentException`
/// - `Io`, `ProtoDecode` → `java.io.IOException`
/// - `AeadBadTag` → `javax.crypto.AEADBadTagException`
/// - `Crypto` → `java.security.GeneralSecurityException`
/// - `State` → `IllegalStateException`
#[derive(Error, Debug)]
pub enum TapAuthError {
    /// Invalid input parameters (length, range, type mismatch)
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protobuf decode error
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),

    /// AEAD authentication tag verification failed
    #[error("AEAD bad tag (decryption failed)")]
    AeadBadTag,

    /// General cryptographic error (key derivation, signing, verification)
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Internal state error or invariant violation
    #[error("internal state error: {0}")]
    State(String),
}

impl From<crate::crypto::CryptoError> for TapAuthError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        use crate::crypto::CryptoError;
        match err {
            CryptoError::InvalidKeyLength => {
                TapAuthError::InvalidInput(format!("crypto: {}", err))
            }
            CryptoError::DecryptionFailed => TapAuthError::AeadBadTag,
            CryptoError::InvalidSignature => {
                // Signature verification failure is not an exception in JNI;
                // callers should return false. This variant is for internal errors only.
                TapAuthError::Crypto("signature verification internal error".to_string())
            }
            CryptoError::KeyDerivationFailed => TapAuthError::Crypto("KDF failed".to_string()),
            CryptoError::EncryptionFailed => {
                TapAuthError::Crypto("encryption failed".to_string())
            }
            CryptoError::RandomGenerationFailed => {
                TapAuthError::Crypto("random generation failed".to_string())
            }
            CryptoError::SystemTimeError => {
                TapAuthError::State("system time error".to_string())
            }
        }
    }
}
