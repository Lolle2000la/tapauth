pub mod crypto;
pub mod protocol;
pub mod config;
pub mod network;
pub mod models;

#[cfg(feature = "jni")]
pub mod jni_api;

// Re-export commonly used types
pub use crypto::{
    ClientSymmetricKey, Ed25519KeyPair, X25519KeyPair,
    CryptoError, PairingSymmetricKey,
};
pub use protocol::pb;
pub use config::{ClientConfig, ClientConfigManager, PairedServer, PairedClient, ConfigError};
pub use network::NetworkError;
