//! Shared TapAuth core library.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//!
//! Provides cryptographic primitives, protocol definitions, network transports,
//! and configuration management shared between client (PAM, GUI) and server (Android)
//! components.
//!
//! ## Modules
//!
//! - `config`: Secure configuration file I/O with root privilege enforcement
//! - `crypto`: Ed25519 signing, X25519 key exchange, AES-GCM encryption, temporal identifiers
//! - `network`: UDP discovery with IPv4/IPv6 dual-stack multicast support
//! - `protocol`: Protobuf message definitions and pairing/authentication flows
//! - `jni`: Android JNI bindings (when `jni` feature is enabled)
//!
//! ## Security Model
//!
//! - Pairing uses ephemeral X25519 key exchange with SAS verification to prevent MitM
//! - Authentication uses Ed25519 signatures over unique challenges
//! - Encrypted packets use AES-GCM with temporal identifiers for unlinkability
//! - All configuration files enforce root-only (mode 600/700) permissions

pub mod config;
pub mod crypto;
pub mod error;
pub mod ipc;
pub mod models;
pub mod network;
pub mod protocol;

#[cfg(feature = "jni")]
pub mod jni;

#[cfg(feature = "jni")]
pub mod jni_api;

// Re-export commonly used types
pub use config::{ClientConfig, ClientConfigManager, ConfigError, PairedClient, PairedServer};
pub use crypto::{
    ClientSymmetricKey, CryptoError, Ed25519KeyPair, PairingSymmetricKey, X25519KeyPair,
};
pub use network::NetworkError;
pub use protocol::pb;
