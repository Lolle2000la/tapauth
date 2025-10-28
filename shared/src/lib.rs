pub mod config;
pub mod crypto;
pub mod models;
pub mod network;
pub mod protocol;

#[cfg(feature = "jni")]
pub mod jni_api;

#[cfg(feature = "dbus")]
pub mod dbus_interface;

// Re-export commonly used types
pub use config::{ClientConfig, ClientConfigManager, ConfigError, PairedClient, PairedServer};
pub use crypto::{
    ClientSymmetricKey, CryptoError, Ed25519KeyPair, PairingSymmetricKey, X25519KeyPair,
};
pub use network::NetworkError;
pub use protocol::pb;

#[cfg(feature = "dbus")]
pub use dbus_interface::{
    AuthRequest, AuthResult, BleServiceProxy, DBUS_OBJECT_PATH, DBUS_SERVICE_NAME,
};
