//! Configuration management for TapAuth client and server.
//!
//! Provides secure file I/O for configuration, paired client/server data,
//! and cryptographic keys. Operations enforce strict file permissions (700 for
//! directories, 600 for files) to protect sensitive cryptographic material.
//!
//! ## Security
//!
//! - Configuration files are stored in `/etc/tapauth`
//! - Ownership is expected to be `tapauthd:tapauthd`; files must be mode 0600 (or 0400)
//! - Root may read for diagnostics and legacy compatibility, but writes are restricted
//!   to the `tapauthd` user
//! - File permissions are enforced on every write operation and validated on reads

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::crypto::{ClientSymmetricKey, Ed25519KeyPair};
use nix::unistd::{geteuid, User};

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

/// Well-known configuration directory
pub const CONFIG_DIR: &str = "/etc/tapauth";

/// Client configuration file
pub const CLIENT_CONFIG_FILE: &str = "client_config.json";

/// Server configuration file (for storing paired servers on client)
pub const PAIRED_SERVERS_FILE: &str = "paired_servers.json";

/// Client private key file
pub const CLIENT_KEY_FILE: &str = "client_key";

/// Client symmetric key file
pub const CLIENT_SYMMETRIC_KEY_FILE: &str = "client_symmetric_key";

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

/// Resolve the system user "tapauthd" to its UID (cached best-effort).
fn tapauthd_uid() -> Option<u32> {
    // If NSS lookup fails or user does not exist yet (during install), we return None
    // and default to accepting only root-owned files. Callers must handle None.
    User::from_name("tapauthd").ok().flatten().map(|u| u.uid.as_raw())
}

/// Whether the effective UID is the tapauthd user.
fn is_euid_tapauthd() -> bool {
    match tapauthd_uid() {
        Some(uid) => geteuid().as_raw() == uid,
        None => false,
    }
}

/// Ensure configuration directory exists with strict permissions (700)
pub fn ensure_secure_directory(path: &Path) -> Result<(), ConfigError> {
    // Only the tapauthd service user is allowed to create/modify the directory
    if !is_euid_tapauthd() {
        return Err(ConfigError::InsufficientPermissions);
    }

    if !path.exists() {
        fs::create_dir_all(path)?;
    }

    // Set permissions to 700 (rwx for owner only)
    let metadata = fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;

    Ok(())
}

/// Write data to a file with strict owner-only permissions (600)
pub fn write_secure_file(path: &Path, data: &[u8]) -> Result<(), ConfigError> {
    // Only the tapauthd service user is allowed to write configuration or key material
    if !is_euid_tapauthd() {
        return Err(ConfigError::InsufficientPermissions);
    }

    fs::write(path, data)?;

    // Set permissions to 600 (rw for owner only)
    let metadata = fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;

    Ok(())
}

/// Read data from a secure file
pub fn read_secure_file(path: &Path) -> Result<Vec<u8>, ConfigError> {
    // Verify file permissions
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // Check ownership: accept either root:root or tapauthd:tapauthd
    let owner_uid = metadata.uid();
    let tap_uid = tapauthd_uid();
    let owner_ok = owner_uid == 0 || tap_uid.map(|u| owner_uid == u).unwrap_or(false);
    if !owner_ok {
        return Err(ConfigError::InsufficientPermissions);
    }

    // Check group/other permissions
    let mode = permissions.mode() & 0o777;

    // For simplicity and safety, enforce 0600 or 0400 for all files (keys and config)
    if mode != 0o600 && mode != 0o400 {
        return Err(ConfigError::InsufficientPermissions);
    }

    Ok(fs::read(path)?)
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Hostname of this client
    pub hostname: String,
    /// UDP port for authentication (default: 36692)
    pub udp_port: u16,
    /// Whether to use TPM for key storage
    pub use_tpm: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string()),
            udp_port: 36692,
            use_tpm: false,
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

/// Client configuration manager
pub struct ClientConfigManager {
    config_dir: PathBuf,
}

impl ClientConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Self {
        Self {
            config_dir: PathBuf::from(CONFIG_DIR),
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
    pub fn load_keypair(&self) -> Result<Ed25519KeyPair, ConfigError> {
        let key_path = self.config_dir.join(CLIENT_KEY_FILE);

        if !key_path.exists() {
            return Err(ConfigError::InvalidConfig);
        }

        let data = read_secure_file(&key_path)?;

        if data.len() != 32 {
            return Err(ConfigError::InvalidConfig);
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);

        Ok(Ed25519KeyPair::from_signing_key_bytes(&bytes)?)
    }

    /// Save Ed25519 keypair
    pub fn save_keypair(&self, keypair: &Ed25519KeyPair) -> Result<(), ConfigError> {
        self.init()?;
        let key_path = self.config_dir.join(CLIENT_KEY_FILE);
        let bytes = keypair.signing_key_bytes();
        write_secure_file(&key_path, &bytes)?;
        Ok(())
    }

    /// Generate and save a new keypair
    pub fn generate_and_save_keypair(&self) -> Result<Ed25519KeyPair, ConfigError> {
        let keypair = Ed25519KeyPair::generate();
        self.save_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Load CSK
    pub fn load_csk(&self) -> Result<ClientSymmetricKey, ConfigError> {
        let csk_path = self.config_dir.join(CLIENT_SYMMETRIC_KEY_FILE);

        if !csk_path.exists() {
            return Err(ConfigError::InvalidConfig);
        }

        let data = read_secure_file(&csk_path)?;

        if data.len() != 32 {
            return Err(ConfigError::InvalidConfig);
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);

        Ok(ClientSymmetricKey::from_bytes(bytes))
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

    /// Rotate CSK (generates new one, invalidating all pairings)
    pub fn rotate_csk(&self) -> Result<ClientSymmetricKey, ConfigError> {
        // Delete all paired servers since they have the old CSK
        let _ = self.clear_paired_servers();

        // Generate and save new CSK
        self.generate_and_save_csk()
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
        self.init()?;
        let servers_path = self.config_dir.join(PAIRED_SERVERS_FILE);
        let data = serde_json::to_vec_pretty(servers)?;
        write_secure_file(&servers_path, &data)?;
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
                Ok(true) // Entire pairing removed
            } else {
                // Save with updated user list
                self.save_paired_servers(&servers)?;
                Ok(false) // Only user removed
            }
        } else {
            // Server not found - nothing to remove
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
}

impl Default for ClientConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.udp_port, 36692);
    }

    #[test]
    fn test_config_serialization() {
        let config = ClientConfig {
            hostname: "test-host".to_string(),
            udp_port: 12345,
            use_tpm: true,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ClientConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.hostname, deserialized.hostname);
        assert_eq!(config.udp_port, deserialized.udp_port);
        assert_eq!(config.use_tpm, deserialized.use_tpm);
    }

    #[test]
    fn test_paired_server_user_authorization() {
        let server = PairedServer {
            name: "TestServer".to_string(),
            public_key: "abc123".to_string(),
            allowed_users: vec!["alice".to_string(), "bob".to_string()],
            paired_at: chrono::Utc::now(),
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
}
