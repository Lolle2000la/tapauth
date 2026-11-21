//! Configuration management for TapAuth client and server.
//!
//! Provides secure file I/O for configuration, paired client/server data,
//! and cryptographic keys. Operations enforce strict file permissions (700 for
//! directories, 600 for files) to protect sensitive cryptographic material.
//!
//! ## Configuration Files
//!
//! - `/etc/tapauth/config.toml`: System-wide configuration (timeouts, ports, TPM)
//! - `/var/lib/tapauth/`: Persistent state (keys, paired devices)
//!
//! ## Security
//!
//! - Persistent state is stored in `/var/lib/tapauth`
//! - Ownership is `tapauthd:tapauthd`; files are mode 0600 (or 0400)
//! - Reads are allowed when owned by root or tapauthd
//! - Writes are allowed when running as tapauthd; when running as root, files/dirs are
//!   safely created then chowned to `tapauthd:tapauthd` to keep strict ownership
//! - File permissions are enforced on every write operation and validated on reads

mod storage;
mod toml_config;

pub use storage::{ensure_secure_directory, get_config_dir, read_secure_file, write_secure_file};
pub use toml_config::{
    bounded_pam_timeout, TapAuthConfig, DEFAULT_CONFIG_PATH, DEFAULT_PAM_REFUSED_SERVICES,
    MAX_PAM_TIMEOUT_SECS,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::crypto::{ClientSymmetricKey, Ed25519KeyPair};
use crate::protocol::pb::{HashAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("Invalid configuration")]
    InvalidConfig,
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// Well-known configuration directory (FHS-compliant persistent state)
pub const CONFIG_DIR: &str = "/var/lib/tapauth";

/// Client configuration file
pub const CLIENT_CONFIG_FILE: &str = "client_config.json";

/// Server configuration file (for storing paired servers on client)
pub const PAIRED_SERVERS_FILE: &str = "paired_servers.json";

/// Client private key file
pub const CLIENT_KEY_FILE: &str = "client_key";

/// Client symmetric key file
pub const CLIENT_SYMMETRIC_KEY_FILE: &str = "client_symmetric_key";

/// Client-wide algorithm metadata that accompanies the CSK (v2)
pub const CSK_META_FILE: &str = "csk_meta.json";

/// Check if the current process is running as root.
///
/// ## Returns
///
/// `true` if the effective user ID is 0 (root), `false` otherwise.
///
/// ## Safety
///
/// Calls `libc::geteuid()` which is safe to call from any context.
/// The function has no preconditions and does not modify any state.
/// The returned UID is a snapshot and may change if the process drops privileges.
pub fn is_root() -> bool {
    // Use nix to query effective UID without unsafe
    nix::unistd::geteuid().as_raw() == 0
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Hostname of this client
    pub hostname: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

/// Information about a paired server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedServer {
    /// Server's display name
    pub name: String,
    /// Server's Ed25519 public key (32 bytes, hex-encoded)
    pub public_key: String,
    /// Username(s) on the client that this server can authenticate
    /// SECURITY: Must contain at least one username to prevent privilege escalation
    /// When a user pairs, their username is added to this list
    #[serde(default)]
    pub allowed_users: Vec<String>,
    /// When this pairing was created
    pub paired_at: chrono::DateTime<chrono::Utc>,
    /// Signature algorithm negotiated with this server (`SignatureAlgorithm::Ed25519`
    /// for a v1 pairing, which stored no algorithm).
    #[serde(default = "default_signature_algorithm")]
    pub signature_algorithm: SignatureAlgorithm,
}

fn default_signature_algorithm() -> SignatureAlgorithm {
    SignatureAlgorithm::Ed25519
}

impl PairedServer {
    /// Check if this server is allowed to authenticate the given user
    /// SECURITY: Empty list means NO users allowed (prevents privilege escalation)
    pub fn is_user_allowed(&self, username: &str) -> bool {
        self.allowed_users.iter().any(|u| u == username)
    }
}

/// Information about a paired client (stored on server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedClient {
    /// Client's display name (hostname)
    pub hostname: String,
    /// Client's Ed25519 public key (32 bytes, hex-encoded)
    pub public_key: String,
    /// Client Symmetric Key (32 bytes, hex-encoded)
    pub csk: String,
    /// Username(s) on the client that this pairing can authenticate
    /// SECURITY: Must contain at least one username to prevent privilege escalation
    /// When a user pairs, their username is added to this list
    #[serde(default)]
    pub allowed_users: Vec<String>,
    /// When this pairing was created
    pub paired_at: chrono::DateTime<chrono::Utc>,
}

impl PairedClient {
    /// Check if this client pairing is allowed to authenticate the given user
    /// SECURITY: Empty list means NO users allowed (prevents privilege escalation)
    pub fn is_user_allowed(&self, username: &str) -> bool {
        self.allowed_users.iter().any(|u| u == username)
    }
}

/// Client-wide cryptographic algorithm metadata for the CSK.
///
/// One multicast/BLE advertisement targets every paired server at once, so the
/// symmetric and hash algorithms are properties of the CSK, not of an individual
/// pairing (cryptography-specification.md §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CskMetadata {
    /// AEAD algorithm used for `EncryptedPacket.ciphertext`.
    #[serde(default = "default_symmetric_algorithm")]
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// Hash algorithm used for the rotating temporal identifiers.
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: HashAlgorithm,
}

fn default_symmetric_algorithm() -> SymmetricAlgorithm {
    SymmetricAlgorithm::Aes256Gcm
}

fn default_hash_algorithm() -> HashAlgorithm {
    HashAlgorithm::Sha256
}

impl Default for CskMetadata {
    fn default() -> Self {
        Self {
            symmetric_algorithm: default_symmetric_algorithm(),
            hash_algorithm: default_hash_algorithm(),
        }
    }
}

/// Client configuration manager
pub struct ClientConfigManager {
    config_dir: PathBuf,
}

impl ClientConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Self {
        Self {
            config_dir: get_config_dir(),
        }
    }

    /// Initialize configuration directory
    pub fn init(&self) -> Result<(), ConfigError> {
        ensure_secure_directory(&self.config_dir)?;
        Ok(())
    }

    /// Load client configuration
    pub fn load_config(&self) -> Result<ClientConfig, ConfigError> {
        let config_path = self.config_dir.join(CLIENT_CONFIG_FILE);

        if !config_path.exists() {
            // Return default config if file doesn't exist
            return Ok(ClientConfig::default());
        }

        let data = read_secure_file(&config_path)?;
        let config = serde_json::from_slice(&data)?;
        Ok(config)
    }

    /// Save client configuration
    pub fn save_config(&self, config: &ClientConfig) -> Result<(), ConfigError> {
        self.init()?;
        let config_path = self.config_dir.join(CLIENT_CONFIG_FILE);
        let data = serde_json::to_vec_pretty(config)?;
        write_secure_file(&config_path, &data)?;
        Ok(())
    }

    /// Load Ed25519 keypair
    ///
    /// If TPM is enabled in config, loads ONLY from TPM (no plaintext fallback).
    /// If TPM is disabled, loads from plaintext file.
    pub fn load_keypair(&self) -> Result<Ed25519KeyPair, ConfigError> {
        // Try TPM if enabled and feature compiled in
        #[cfg(feature = "tpm")]
        {
            let toml_config = TapAuthConfig::load();
            if toml_config.use_tpm {
                let tpm_key_path = self.config_dir.join(format!("{}.tpm", CLIENT_KEY_FILE));

                // TPM mode: ONLY load from TPM, no plaintext fallback
                // This ensures we don't accidentally use old plaintext keys
                if !tpm_key_path.with_extension("pub").exists() {
                    return Err(ConfigError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "TPM enabled but no TPM-sealed key found. Use tapauth-config GUI to regenerate keys.",
                    )));
                }

                match crate::tpm::load_sealed_keypair(&tpm_key_path) {
                    Ok(keypair) => {
                        tracing::info!("Loaded Ed25519 keypair from TPM");
                        return Ok(keypair);
                    }
                    Err(e) => {
                        // TPM unsealing failed - this is a critical error
                        return Err(ConfigError::Io(std::io::Error::other(format!(
                            "Failed to unseal key from TPM: {}. Use tapauth-config GUI to recover.",
                            e
                        ))));
                    }
                }
            }
        }

        // File-only mode: load from plaintext file
        let key_path = self.config_dir.join(CLIENT_KEY_FILE);

        if !key_path.exists() {
            return Err(ConfigError::InvalidConfig);
        }

        let data = Zeroizing::new(read_secure_file(&key_path)?);

        if data.len() != 32 {
            return Err(ConfigError::InvalidConfig);
        }

        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&data);

        tracing::info!("Loaded Ed25519 keypair from file");
        Ok(Ed25519KeyPair::from_signing_key_bytes(&bytes)?)
    }

    /// Save Ed25519 keypair
    ///
    /// If TPM is enabled in config, seals the key with TPM only (no plaintext backup).
    /// If TPM is disabled, saves as plaintext file with 600 permissions.
    pub fn save_keypair(&self, keypair: &Ed25519KeyPair) -> Result<(), ConfigError> {
        self.init()?;

        // Zeroization, same class as `load_keypair` (R2-L5, extended to the save
        // side): `signing_key_bytes()` hands back a plain `[u8; 32]` that lives on
        // the stack until this function returns, past the write it feeds.
        let bytes = Zeroizing::new(keypair.signing_key_bytes());

        #[cfg(feature = "tpm")]
        {
            let toml_config = TapAuthConfig::load();
            if toml_config.use_tpm {
                // TPM-only mode: seal with TPM, no plaintext backup
                if !crate::tpm::is_tpm_available() {
                    return Err(ConfigError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "TPM enabled in config but tpm2-tools not available",
                    )));
                }

                let tpm_key_path = self.config_dir.join(format!("{}.tpm", CLIENT_KEY_FILE));
                let pcr_list = toml_config.tpm_pcr_policy.pcr_list();
                crate::tpm::seal_data_with_tpm(&bytes[..], &tpm_key_path, pcr_list).map_err(
                    |e| {
                        ConfigError::Io(std::io::Error::other(format!(
                            "Failed to seal key with TPM: {}",
                            e
                        )))
                    },
                )?;

                tracing::info!(
                    "Sealed Ed25519 keypair with TPM using PCR policy {:?} (no plaintext backup)",
                    toml_config.tpm_pcr_policy
                );
                return Ok(());
            }
        }

        // File-only mode: save plaintext with 600 permissions
        // (Also used when TPM feature is not compiled in)
        let key_path = self.config_dir.join(CLIENT_KEY_FILE);
        write_secure_file(&key_path, &bytes[..])?;
        tracing::info!("Saved Ed25519 keypair to file");

        Ok(())
    }

    /// Generate and save a new keypair
    pub fn generate_and_save_keypair(&self) -> Result<Ed25519KeyPair, ConfigError> {
        let keypair = Ed25519KeyPair::generate()?;
        self.save_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Load CSK
    pub fn load_csk(&self) -> Result<ClientSymmetricKey, ConfigError> {
        let csk_path = self.config_dir.join(CLIENT_SYMMETRIC_KEY_FILE);

        if !csk_path.exists() {
            return Err(ConfigError::InvalidConfig);
        }

        let data = Zeroizing::new(read_secure_file(&csk_path)?);

        if data.len() != 32 {
            return Err(ConfigError::InvalidConfig);
        }

        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&data);

        Ok(ClientSymmetricKey::from_bytes(*bytes))
    }

    /// Save CSK
    pub fn save_csk(&self, csk: &ClientSymmetricKey) -> Result<(), ConfigError> {
        self.init()?;
        let csk_path = self.config_dir.join(CLIENT_SYMMETRIC_KEY_FILE);
        write_secure_file(&csk_path, csk.as_bytes())?;
        Ok(())
    }

    /// Generate and save a new CSK
    pub fn generate_and_save_csk(&self) -> Result<ClientSymmetricKey, ConfigError> {
        let csk = ClientSymmetricKey::generate()?;
        self.save_csk(&csk)?;
        Ok(csk)
    }

    /// Whether a CSK already exists on disk (file present, may be corrupt)
    pub fn has_csk_file(&self) -> bool {
        self.config_dir.join(CLIENT_SYMMETRIC_KEY_FILE).exists()
    }

    /// Load the CSK algorithm metadata.
    ///
    /// A missing `csk_meta.json` (a v1 state directory, or a CSK that predates
    /// the metadata file) yields [`CskMetadata::default`]: AES-256-GCM + SHA-256,
    /// the v1 wire behaviour.
    pub fn load_csk_metadata(&self) -> Result<CskMetadata, ConfigError> {
        let meta_path = self.config_dir.join(CSK_META_FILE);

        if !meta_path.exists() {
            return Ok(CskMetadata::default());
        }

        let data = read_secure_file(&meta_path)?;
        let metadata = serde_json::from_slice(&data)?;
        Ok(metadata)
    }

    /// Save the CSK algorithm metadata.
    pub fn save_csk_metadata(&self, meta: &CskMetadata) -> Result<(), ConfigError> {
        self.init()?;
        let meta_path = self.config_dir.join(CSK_META_FILE);
        let data = serde_json::to_vec_pretty(meta)?;
        write_secure_file(&meta_path, &data)?;
        Ok(())
    }

    /// Whether the CSK algorithm metadata file is present on disk
    pub fn has_csk_metadata_file(&self) -> bool {
        self.config_dir.join(CSK_META_FILE).exists()
    }

    /// Delete the CSK algorithm metadata file, if there is one.
    ///
    /// Used whenever the device set the metadata describes disappears (a CSK
    /// rotation, the last un-pairing). Nothing to delete is not an error.
    pub fn clear_csk_metadata(&self) -> Result<(), ConfigError> {
        let meta_path = self.config_dir.join(CSK_META_FILE);
        if meta_path.exists() {
            fs::remove_file(meta_path)?;
        }
        Ok(())
    }

    /// Drop the CSK algorithm metadata once no paired server is left.
    ///
    /// The metadata records the algorithm pair the *paired devices* are committed
    /// to (one broadcast reaches all of them). With none left there is no
    /// commitment to honour, so a leftover file would pin a suite for a device
    /// set that no longer exists; the next pairing must be free to negotiate, and
    /// `persist_pairing` writes the file again once it has.
    fn clear_csk_metadata_if_unpaired(
        &self,
        servers: &HashMap<String, PairedServer>,
    ) -> Result<(), ConfigError> {
        if servers.is_empty() {
            self.clear_csk_metadata()?;
        }
        Ok(())
    }

    /// Rotate CSK (generates new one, invalidating all pairings)
    pub fn rotate_csk(&self) -> Result<ClientSymmetricKey, ConfigError> {
        // Delete all paired servers since they have the old CSK. A failure here
        // aborts the rotation: swallowing it would leave devices holding the old
        // CSK next to a freshly generated one, i.e. a pairing set that can never
        // authenticate again and a caller that believes it succeeded.
        self.clear_paired_servers()?;

        // The negotiated algorithm pair described those devices too. It is
        // removed rather than reset to the baseline: after a rotation nothing is
        // pinned, so the next pairing negotiates a suite from scratch and records
        // it on the way out. Writing a default file here would leave a
        // commitment behind for a device set that no longer exists.
        self.clear_csk_metadata()?;

        // Generate and save new CSK
        let csk = self.generate_and_save_csk()?;

        Ok(csk)
    }

    /// Load paired servers
    pub fn load_paired_servers(&self) -> Result<HashMap<String, PairedServer>, ConfigError> {
        let servers_path = self.config_dir.join(PAIRED_SERVERS_FILE);

        if !servers_path.exists() {
            return Ok(HashMap::new());
        }

        let data = read_secure_file(&servers_path)?;
        let servers = serde_json::from_slice(&data)?;
        Ok(servers)
    }

    /// Save paired servers
    pub fn save_paired_servers(
        &self,
        servers: &HashMap<String, PairedServer>,
    ) -> Result<(), ConfigError> {
        tracing::debug!("save_paired_servers: starting");
        self.init()?;
        tracing::debug!("save_paired_servers: init complete");
        let servers_path = self.config_dir.join(PAIRED_SERVERS_FILE);
        tracing::debug!("save_paired_servers: path = {:?}", servers_path);
        let data = serde_json::to_vec_pretty(servers)?;
        tracing::debug!("save_paired_servers: serialized {} bytes", data.len());
        write_secure_file(&servers_path, &data)?;
        tracing::debug!("save_paired_servers: write complete");
        Ok(())
    }

    /// Add a paired server
    pub fn add_paired_server(&self, id: String, server: PairedServer) -> Result<(), ConfigError> {
        let mut servers = self.load_paired_servers()?;
        servers.insert(id, server);
        self.save_paired_servers(&servers)?;
        Ok(())
    }

    /// Remove a paired server
    pub fn remove_paired_server(&self, id: &str) -> Result<(), ConfigError> {
        let mut servers = self.load_paired_servers()?;
        servers.remove(id);
        self.save_paired_servers(&servers)?;
        self.clear_csk_metadata_if_unpaired(&servers)?;
        Ok(())
    }

    /// Remove current user from a paired server's allowed list
    /// If this is the last user, removes the entire pairing
    /// Returns true if the entire pairing was removed, false if just the user was removed
    pub fn remove_user_from_pairing(&self, id: &str, username: &str) -> Result<bool, ConfigError> {
        let mut servers = self.load_paired_servers()?;

        if let Some(server) = servers.get_mut(id) {
            // Remove the username from allowed_users
            server.allowed_users.retain(|u| u != username);

            // If no users left, remove the entire pairing
            if server.allowed_users.is_empty() {
                servers.remove(id);
                self.save_paired_servers(&servers)?;
                self.clear_csk_metadata_if_unpaired(&servers)?;
                Ok(true) // Entire pairing removed
            } else {
                // Save with updated user list
                self.save_paired_servers(&servers)?;
                Ok(false) // Only user removed
            }
        } else {
            // Server not found - nothing to remove. The set is unchanged, but a
            // metadata file left over from an earlier, now empty set is still
            // stale, so the pinning rule is re-asserted.
            self.clear_csk_metadata_if_unpaired(&servers)?;
            Ok(true)
        }
    }

    /// Clear all paired servers
    pub fn clear_paired_servers(&self) -> Result<(), ConfigError> {
        let servers_path = self.config_dir.join(PAIRED_SERVERS_FILE);
        if servers_path.exists() {
            fs::remove_file(servers_path)?;
        }
        Ok(())
    }

    /// Recover from TPM failure by regenerating all keys and clearing pairings
    ///
    /// This is a complete reset that:
    /// 1. Deletes TPM-sealed key files (if they exist)
    /// 2. Deletes plaintext key file (if it exists)
    /// 3. Generates new Ed25519 keypair
    /// 4. Generates new CSK
    /// 5. Clears all paired servers (they used the old keys)
    ///
    /// Returns Ok(()) if successful. The daemon must be restarted after this operation.
    #[cfg(feature = "tpm")]
    pub fn recover_from_tpm_failure(&self) -> Result<(), ConfigError> {
        tracing::warn!("Starting TPM recovery: regenerating all keys and clearing pairings");

        // Delete TPM-sealed key files if they exist
        let tpm_key_path = self.config_dir.join(format!("{}.tpm", CLIENT_KEY_FILE));
        let tpm_pub = tpm_key_path.with_extension("pub");
        let tpm_priv = tpm_key_path.with_extension("priv");

        if tpm_pub.exists() {
            fs::remove_file(&tpm_pub)?;
            tracing::info!("Deleted TPM public key file");
        }
        if tpm_priv.exists() {
            fs::remove_file(&tpm_priv)?;
            tracing::info!("Deleted TPM private key file");
        }

        // Delete plaintext key file if it exists
        let key_path = self.config_dir.join(CLIENT_KEY_FILE);
        if key_path.exists() {
            fs::remove_file(&key_path)?;
            tracing::info!("Deleted plaintext key file");
        }

        // Clear all paired servers since they have the old public key
        self.clear_paired_servers()?;
        tracing::info!("Cleared all paired servers");

        // Generate new Ed25519 keypair
        self.generate_and_save_keypair()?;
        tracing::info!("Generated new Ed25519 keypair");

        // Rotate CSK to force re-pairing
        self.rotate_csk()?;
        tracing::info!("Generated new CSK");

        tracing::warn!(
            "TPM recovery complete. Daemon must be restarted and all devices must be re-paired."
        );
        Ok(())
    }
}

impl Default for ClientConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

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
    fn test_default_config() {
        let config = ClientConfig::default();
        // ClientConfig only contains hostname, which is system-dependent
        // Just verify it's not empty
        assert!(!config.hostname.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = ClientConfig {
            hostname: "test-host".to_string(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ClientConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.hostname, deserialized.hostname);
    }

    #[test]
    fn test_paired_server_user_authorization() {
        let server = PairedServer {
            name: "TestServer".to_string(),
            public_key: "abc123".to_string(),
            allowed_users: vec!["alice".to_string(), "bob".to_string()],
            paired_at: chrono::Utc::now(),
            signature_algorithm: SignatureAlgorithm::Ed25519,
        };

        // Allowed users should pass
        assert!(server.is_user_allowed("alice"));
        assert!(server.is_user_allowed("bob"));

        // Non-allowed users should fail
        assert!(!server.is_user_allowed("charlie"));
        assert!(!server.is_user_allowed(""));
    }

    #[test]
    fn test_paired_server_empty_allowed_users() {
        // SECURITY: Empty allowed_users list should deny all users
        let server = PairedServer {
            name: "TestServer".to_string(),
            public_key: "abc123".to_string(),
            allowed_users: vec![],
            paired_at: chrono::Utc::now(),
            signature_algorithm: SignatureAlgorithm::Ed25519,
        };

        // No user should be allowed when list is empty
        assert!(!server.is_user_allowed("alice"));
        assert!(!server.is_user_allowed("root"));
        assert!(!server.is_user_allowed(""));
    }

    #[test]
    fn test_paired_client_serialization() {
        let client = PairedClient {
            hostname: "client-laptop".to_string(),
            public_key: "def456".to_string(),
            csk: "encrypted_key_data".to_string(),
            allowed_users: vec!["user1".to_string()],
            paired_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&client).unwrap();
        let deserialized: PairedClient = serde_json::from_str(&json).unwrap();

        assert_eq!(client.hostname, deserialized.hostname);
        assert_eq!(client.public_key, deserialized.public_key);
        assert_eq!(client.csk, deserialized.csk);
        assert_eq!(client.allowed_users, deserialized.allowed_users);
    }

    /// A `PairedServer` must round-trip its negotiated signature algorithm, and
    /// the JSON form must be the canonical proto name.
    /// The defect this catches: the field silently dropped from the on-disk
    /// record (so a re-pairing/restart forgets what the server negotiated).
    #[test]
    fn test_paired_server_signature_algorithm_roundtrip() {
        let server = PairedServer {
            name: "Phone".to_string(),
            public_key: "abc123".to_string(),
            allowed_users: vec!["alice".to_string()],
            paired_at: chrono::Utc::now(),
            signature_algorithm: SignatureAlgorithm::Ed25519,
        };

        let json = serde_json::to_string(&server).unwrap();
        assert!(
            json.contains("\"signature_algorithm\":\"ED25519\""),
            "the canonical proto name must be persisted, got: {}",
            json
        );
        let deserialized: PairedServer = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.signature_algorithm,
            SignatureAlgorithm::Ed25519
        );
        assert_eq!(deserialized.name, server.name);
        assert_eq!(deserialized.public_key, server.public_key);
        assert_eq!(deserialized.paired_at, server.paired_at);
    }

    /// A v1 `paired_servers.json` entry has no `signature_algorithm`; it must
    /// load as Ed25519 rather than failing the whole file.
    /// The defect this catches: an upgrade from v1 making every pairing
    /// unreadable (the daemon would then see no paired devices at all).
    #[test]
    fn test_legacy_paired_server_defaults_to_ed25519() {
        let legacy = r#"{
            "name": "OldPhone",
            "public_key": "deadbeef",
            "allowed_users": ["alice"],
            "paired_at": "2024-01-01T00:00:00Z"
        }"#;

        let server: PairedServer = serde_json::from_str(legacy).unwrap();
        assert_eq!(server.signature_algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(server.allowed_users, vec!["alice".to_string()]);
    }

    /// Only the canonical name string deserialises; the numeric form is rejected.
    /// The defect this catches: an integer silently loading as the "same"
    /// algorithm, which would keep a legacy numeric spelling alive in the config
    /// contract (and let an out-of-range value be coerced instead of refused).
    #[test]
    fn test_signature_algorithm_accepts_name_only() {
        let by_name = r#"{
            "name": "Phone",
            "public_key": "abc",
            "allowed_users": [],
            "paired_at": "2024-01-01T00:00:00Z",
            "signature_algorithm": "ED25519"
        }"#;
        let server: PairedServer = serde_json::from_str(by_name).unwrap();
        assert_eq!(server.signature_algorithm, SignatureAlgorithm::Ed25519);

        let by_integer = r#"{
            "name": "Phone",
            "public_key": "abc",
            "allowed_users": [],
            "paired_at": "2024-01-01T00:00:00Z",
            "signature_algorithm": 1
        }"#;
        assert!(serde_json::from_str::<PairedServer>(by_integer).is_err());

        // An unknown name is rejected, not silently defaulted.
        let bogus = r#"{
            "name": "Phone",
            "public_key": "abc",
            "allowed_users": [],
            "paired_at": "2024-01-01T00:00:00Z",
            "signature_algorithm": "ED25519_TYPO"
        }"#;
        assert!(serde_json::from_str::<PairedServer>(bogus).is_err());
    }

    /// `CskMetadata::default()` is the v1 baseline pair, and an empty JSON object
    /// (a metadata file written before any algorithm was negotiated) loads as it.
    /// The defect this catches: a fresh/legacy metadata file defaulting to
    /// anything other than AES-256-GCM + SHA-256, which would break the wire
    /// format every already-paired server expects.
    #[test]
    fn test_csk_metadata_defaults_and_legacy_json() {
        let default = CskMetadata::default();
        assert_eq!(default.symmetric_algorithm, SymmetricAlgorithm::Aes256Gcm);
        assert_eq!(default.hash_algorithm, HashAlgorithm::Sha256);

        let legacy: CskMetadata = serde_json::from_str("{}").unwrap();
        assert_eq!(legacy, default);

        // Missing single field: only that one falls back (with one active primitive
        // per slot the fallback and the explicit value are the same suite, so this
        // exercises `serde(default)` on the omitted field, not a choice of value).
        let partial: CskMetadata = serde_json::from_str(r#"{"hash_algorithm": "SHA256"}"#).unwrap();
        assert_eq!(partial.symmetric_algorithm, SymmetricAlgorithm::Aes256Gcm);
        assert_eq!(partial.hash_algorithm, HashAlgorithm::Sha256);
    }

    /// `CskMetadata` must survive a full JSON round-trip with the canonical names,
    /// and a *retired* algorithm name written by a pre-release build must fail to
    /// load instead of falling back to the baseline.
    /// The defect this catches: a deserialiser that accepts any string it does not
    /// recognise and defaults (a device then believes it shares a suite it does
    /// not), or one that keeps aliasing the reserved tags onto live algorithms.
    #[test]
    fn test_csk_metadata_roundtrip() {
        let metadata = CskMetadata {
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            hash_algorithm: HashAlgorithm::Sha256,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(
            json.contains("\"symmetric_algorithm\":\"AES_256_GCM\""),
            "unexpected JSON: {}",
            json
        );
        assert!(
            json.contains("\"hash_algorithm\":\"SHA256\""),
            "unexpected JSON: {}",
            json
        );

        let parsed: CskMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, metadata);

        // A retired name is not "unknown-but-close": it is refused outright.
        for retired in [
            r#"{"symmetric_algorithm": "CHACHA20_POLY1305"}"#,
            r#"{"hash_algorithm": "BLAKE3"}"#,
            r#"{"symmetric_algorithm": "UNKNOWN_ALG"}"#,
            r#"{"hash_algorithm": "UNKNOWN_ALG"}"#,
            r#"{"symmetric_algorithm": "AES_256_GCM", "hash_algorithm": "BLAKE3"}"#,
        ] {
            assert!(
                serde_json::from_str::<CskMetadata>(retired).is_err(),
                "{retired} must not load"
            );
        }

        // Integer values are rejected: the name is the only on-disk spelling, and
        // the freed tag `2` in particular must never be read back as an algorithm.
        for by_integer in [
            r#"{"symmetric_algorithm": 2, "hash_algorithm": 2}"#,
            r#"{"symmetric_algorithm": 1, "hash_algorithm": 1}"#,
        ] {
            assert!(
                serde_json::from_str::<CskMetadata>(by_integer).is_err(),
                "{by_integer} must not load"
            );
        }
    }

    // ---- CSK metadata lifecycle ------------------------------------------

    fn paired_server(id: &str) -> PairedServer {
        PairedServer {
            name: id.to_string(),
            public_key: id.to_string(),
            allowed_users: vec!["alice".to_string()],
            paired_at: chrono::Utc::now(),
            signature_algorithm: SignatureAlgorithm::Ed25519,
        }
    }

    /// A `ClientConfigManager` rooted at a scratch state directory.
    ///
    /// `write_secure_file`/`read_secure_file` only accept a non-`tapauthd` owner
    /// when `TAPAUTH_STATE_DIR` is set, and that value is process-wide, so the
    /// directory is held exclusively for as long as this guard lives.
    struct ScratchStateDir {
        path: PathBuf,
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    impl ScratchStateDir {
        fn new(tag: &str) -> Self {
            static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
            // A poisoned lock only means an earlier scratch test panicked; the
            // directory it guarded is thrown away below either way.
            let serial = SERIAL
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let path = PathBuf::from(format!(
                "/tmp/opencode/tapauth-config-{}-{}",
                tag,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            std::env::set_var("TAPAUTH_STATE_DIR", &path);
            Self {
                path,
                _serial: serial,
            }
        }

        fn manager(&self) -> ClientConfigManager {
            ClientConfigManager {
                config_dir: self.path.clone(),
            }
        }
    }

    impl Drop for ScratchStateDir {
        fn drop(&mut self) {
            std::env::remove_var("TAPAUTH_STATE_DIR");
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Install one file into a scratch state directory as the daemon leaves it.
    ///
    /// The file is mode 0600 — the posture `write_secure_file` establishes and the
    /// one `read_secure_file` accepts — and owned by the test user, the only
    /// ownership an unprivileged test can produce (and the one accepted for a
    /// `TAPAUTH_STATE_DIR`). No permission check is relaxed: the directory is
    /// installed as a real daemon would have left it.
    fn install_state_file(dir: &std::path::Path, name: &str, contents: &[u8]) {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A rotation deletes every paired device, so nothing is left that the
    /// negotiated algorithm pair could be pinned to.
    ///
    /// The defect this catches: `rotate_csk` writing `CskMetadata::default()`
    /// after clearing the devices. The file then claims a commitment for pairings
    /// that no longer exist, and any reader that trusts the file pins a suite the
    /// next (first) pairing never negotiated.
    #[test]
    fn rotating_the_csk_leaves_nothing_pinned_for_a_renegotiation() {
        let scratch = ScratchStateDir::new("rotate");
        let manager = scratch.manager();
        manager.save_csk_metadata(&CskMetadata::default()).unwrap();
        manager
            .add_paired_server("aa".to_string(), paired_server("aa"))
            .unwrap();
        assert!(manager.has_csk_metadata_file());

        manager.rotate_csk().unwrap();

        assert!(
            manager.load_paired_servers().unwrap().is_empty(),
            "a rotation invalidates every pairing"
        );
        assert!(manager.has_csk_file(), "a rotation writes a fresh CSK");
        assert!(
            !manager.has_csk_metadata_file(),
            "no device is paired any more, so no algorithm suite may stay pinned"
        );
    }

    /// A rotation that cannot delete the paired devices must not replace the CSK.
    ///
    /// The defect this catches: `let _ = self.clear_paired_servers()`, which
    /// reported success while the phones kept a CSK the client had already
    /// replaced — a device set that can never authenticate again.
    #[test]
    fn a_rotation_that_cannot_clear_the_pairings_does_not_replace_the_csk() {
        let scratch = ScratchStateDir::new("rotate-failure");
        let manager = scratch.manager();
        manager.generate_and_save_csk().unwrap();
        let before = manager.load_csk().unwrap().as_bytes().to_vec();
        // `paired_servers.json` as a directory: deleting it fails with `EISDIR`
        // while every other write in the state directory still succeeds.
        fs::create_dir(scratch.path.join(PAIRED_SERVERS_FILE)).unwrap();

        assert!(
            manager.rotate_csk().is_err(),
            "a rotation that cannot clear the pairings must report the failure"
        );
        assert_eq!(
            manager.load_csk().unwrap().as_bytes(),
            before.as_slice(),
            "the CSK must not be replaced behind a failed device reset"
        );
    }

    /// Un-pairing the last device drops the metadata; un-pairing one of several
    /// keeps it, because the remaining device is still committed to that suite.
    ///
    /// The defect this catches: a removal that leaves the metadata behind after
    /// the last device is gone (the next pairing is then refused the suite its
    /// phone offers), and one that drops it too early (a still-paired device's
    /// broadcast can then be re-negotiated out from under it).
    #[test]
    fn un_pairing_the_last_device_drops_the_metadata() {
        let scratch = ScratchStateDir::new("remove");
        let manager = scratch.manager();
        manager.save_csk_metadata(&CskMetadata::default()).unwrap();
        manager
            .add_paired_server("aa".to_string(), paired_server("aa"))
            .unwrap();
        manager
            .add_paired_server("bb".to_string(), paired_server("bb"))
            .unwrap();

        assert!(
            manager.remove_user_from_pairing("aa", "alice").unwrap(),
            "the only allowed user of aa takes the whole pairing with it"
        );
        assert!(
            manager.has_csk_metadata_file(),
            "bb is still paired and committed to the stored suite"
        );

        assert!(manager.remove_user_from_pairing("bb", "alice").unwrap());
        assert!(
            !manager.has_csk_metadata_file(),
            "no device is paired any more, so nothing may stay pinned"
        );

        // The same lifecycle through the other removal entry point.
        manager
            .add_paired_server("cc".to_string(), paired_server("cc"))
            .unwrap();
        manager.save_csk_metadata(&CskMetadata::default()).unwrap();
        manager.remove_paired_server("cc").unwrap();
        assert!(!manager.has_csk_metadata_file());
    }

    /// The on-disk state a v0.12.0 daemon left in `/var/lib/tapauth` still loads.
    ///
    /// Provenance: `shared/testdata/legacy-v0.12.0-state/` is the exact text
    /// v0.12.0 wrote — `serde_json::to_vec_pretty` of `ClientConfig` (`save_config`)
    /// and of the `HashMap<String, PairedServer>` (`save_paired_servers`), with no
    /// `signature_algorithm` in the paired-server record and no `csk_meta.json`
    /// anywhere in the directory. The writers are byte-identical at the release tag
    /// `v0.12.0` (`bb9d3cd`) and at `f30e43c` (`v0.12.0-10-gf30e43c`, this branch's
    /// merge base): `git diff bb9d3cd f30e43c -- shared/src/config.rs
    /// tapauthd/src/admin_handler.rs` differs only in one `pub use` line, so the
    /// fixture describes both revisions. `paired_at` carries nanoseconds because the
    /// daemon's only writer is `chrono::Utc::now()` (`handle_complete_pairing`,
    /// `tapauthd/src/admin_handler.rs:614` in OLD), which serialises with
    /// `SecondsFormat::AutoSi` — full precision, not a whole second.
    ///
    /// The two raw 32-byte key files are synthesised below rather than checked in,
    /// because v0.12.0 wrote them un-framed (`save_keypair` / `save_csk`):
    /// `0x00..=0x1f` is the Ed25519 signing seed, `0xc0..=0xdf` the CSK. Nothing
    /// here is or was a real secret.
    ///
    /// Defects this catches: an upgrade that loses the existing pairing (the v1
    /// record refused, the new algorithm field defaulting to other than Ed25519,
    /// `allowed_users` dropped, or `paired_at` narrowed to whole seconds, which no
    /// real record satisfies), one that refuses to start because the absent
    /// `csk_meta.json` is not defaulted, and one that no longer reads the existing
    /// CSK (the material that makes the pairing usable at all).
    #[test]
    fn an_existing_v0_12_0_state_directory_still_loads() {
        use std::os::unix::fs::PermissionsExt;

        /// v0.12.0's `PairedServer`, field for field and in the same order: the
        /// oracle the fixture is re-serialised through, so a fixture that drifts
        /// from what `save_paired_servers` produced (compact form, a renamed or
        /// reordered key, a numeric `paired_at`) cannot pass this test.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct PairedServerV0120 {
            name: String,
            public_key: String,
            allowed_users: Vec<String>,
            paired_at: chrono::DateTime<chrono::Utc>,
        }

        const LEGACY_CONFIG: &str =
            include_str!("../testdata/legacy-v0.12.0-state/client_config.json");
        const LEGACY_SERVERS: &str =
            include_str!("../testdata/legacy-v0.12.0-state/paired_servers.json");
        /// The synthetic server key: both the map key and `public_key`, as
        /// `add_paired_server(hex::encode(server_public_key), …)` writes them.
        const LEGACY_SERVER_KEY: &str =
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        const LEGACY_CLIENT_KEY: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        const LEGACY_CSK: [u8; 32] = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
            0xdc, 0xdd, 0xde, 0xdf,
        ];

        // A copy of the install, owned by the test user, in the 0700 directory and
        // 0600 files `ensure_secure_directory` / `write_secure_file` leave behind.
        let scratch = ScratchStateDir::new("legacy-v0-12-0");
        fs::set_permissions(&scratch.path, fs::Permissions::from_mode(0o700)).unwrap();
        install_state_file(&scratch.path, CLIENT_CONFIG_FILE, LEGACY_CONFIG.as_bytes());
        install_state_file(
            &scratch.path,
            PAIRED_SERVERS_FILE,
            LEGACY_SERVERS.as_bytes(),
        );
        install_state_file(&scratch.path, CLIENT_KEY_FILE, &LEGACY_CLIENT_KEY);
        install_state_file(&scratch.path, CLIENT_SYMMETRIC_KEY_FILE, &LEGACY_CSK);
        let manager = scratch.manager();

        // `client_config.json`: loaded, and byte-identical to what the writer emits.
        let config = manager.load_config().unwrap();
        assert_eq!(config.hostname, "legacy-laptop");
        assert_eq!(
            serde_json::to_vec_pretty(&config).unwrap(),
            LEGACY_CONFIG.as_bytes(),
            "the fixture must be exactly what `save_config` wrote"
        );

        // `paired_servers.json`: the pairing survives with Ed25519 and its users.
        let servers = manager.load_paired_servers().unwrap();
        assert_eq!(servers.len(), 1, "the v1 pairing must not be dropped");
        let server = servers
            .get(LEGACY_SERVER_KEY)
            .expect("the pairing is keyed by the server's hex public key");
        assert_eq!(server.name, "Pixel 6");
        assert_eq!(server.public_key, LEGACY_SERVER_KEY);
        assert_eq!(
            server.signature_algorithm,
            SignatureAlgorithm::Ed25519,
            "a v1 record stored no algorithm, and the v1 wire format is Ed25519"
        );
        assert_eq!(server.allowed_users, vec!["alice".to_string()]);
        assert!(server.is_user_allowed("alice"));
        assert_eq!(
            server.paired_at,
            chrono::DateTime::parse_from_rfc3339("2024-03-05T08:15:00.123456789Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            "the sub-second part `Utc::now()` writes must survive, not be truncated or refused"
        );
        assert!(
            !LEGACY_SERVERS.contains("signature_algorithm"),
            "v0.12.0 wrote no signature_algorithm; a fixture that has one is not a v1 record"
        );
        let legacy: HashMap<String, PairedServerV0120> =
            serde_json::from_str(LEGACY_SERVERS).unwrap();
        assert_eq!(
            serde_json::to_vec_pretty(&legacy).unwrap(),
            LEGACY_SERVERS.as_bytes(),
            "the fixture must be exactly what `save_paired_servers` wrote"
        );

        // No `csk_meta.json` in a v0.12.0 directory: the default pair is the v1
        // wire behaviour, not an error and not a different suite.
        assert!(!scratch.path.join(CSK_META_FILE).exists());
        let metadata = manager.load_csk_metadata().unwrap();
        assert_eq!(metadata, CskMetadata::default());
        assert_eq!(metadata.symmetric_algorithm, SymmetricAlgorithm::Aes256Gcm);
        assert_eq!(metadata.hash_algorithm, HashAlgorithm::Sha256);

        // The key material that makes the stored pairing usable: the CSK file is
        // still the raw 32 bytes `ClientSymmetricKey::from_bytes` takes, and the
        // Ed25519 seed is still the pairing's `Ed_C`.
        assert_eq!(
            manager.load_csk().unwrap().as_bytes(),
            &LEGACY_CSK,
            "`client_symmetric_key` must still yield the stored pairing's CSK"
        );
        assert_eq!(
            manager.load_keypair().unwrap().signing_key_bytes(),
            LEGACY_CLIENT_KEY
        );
    }

    /// A *present* `csk_meta.json` loads as the baseline suite, but a retired
    /// pre-release name in one is refused rather than aliased.
    ///
    /// Defects this catches: a loader that errors on any present metadata file —
    /// `tapauthd` turns that into a failed authentication for every device paired
    /// by a v2 build (`auth_handler`, the `load_csk_metadata` error arm) — and one
    /// that reads `CHACHA20_POLY1305` or `BLAKE3`, which no shipped release wrote,
    /// as the one live primitive instead of refusing the file.
    #[test]
    fn csk_metadata_loads_the_baseline_from_a_present_file_but_refuses_retired_names() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = ScratchStateDir::new("csk-meta");
        fs::set_permissions(&scratch.path, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = scratch.manager();

        // Positive control: a present, valid file is the everyday case.
        install_state_file(
            &scratch.path,
            CSK_META_FILE,
            br#"{"symmetric_algorithm": "AES_256_GCM", "hash_algorithm": "SHA256"}"#,
        );
        assert!(manager.has_csk_metadata_file());
        let metadata = manager.load_csk_metadata().unwrap();
        assert_eq!(metadata, CskMetadata::default());
        assert_eq!(metadata.symmetric_algorithm, SymmetricAlgorithm::Aes256Gcm);
        assert_eq!(metadata.hash_algorithm, HashAlgorithm::Sha256);

        // Retired pre-release names stay refused rather than being aliased onto the
        // one live primitive.
        for refused in [
            r#"{"symmetric_algorithm": "CHACHA20_POLY1305", "hash_algorithm": "SHA256"}"#,
            r#"{"symmetric_algorithm": "AES_256_GCM", "hash_algorithm": "Blake3"}"#,
            r#"{"symmetric_algorithm": "AES_256_GCM", "hash_algorithm": "BLAKE3"}"#,
        ] {
            install_state_file(&scratch.path, CSK_META_FILE, refused.as_bytes());
            assert!(
                manager.load_csk_metadata().is_err(),
                "{refused} must not load"
            );
        }
    }
}
