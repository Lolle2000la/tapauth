//! TOML configuration file handling for TapAuth.
//!
//! Reads system-wide configuration from `/etc/tapauth/config.toml` with sensible defaults.
//! This file contains settings that affect runtime behavior but are not considered
//! persistent state (which is stored in `/var/lib/tapauth`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Default configuration path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tapauth/config.toml";

/// Default PAM operation timeout in seconds
const DEFAULT_PAM_TIMEOUT_SECS: u64 = 3;

/// Default UDP port for authentication
const DEFAULT_UDP_PORT: u16 = 36692;

/// System-wide TapAuth configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TapAuthConfig {
    /// Timeout for individual PAM operations (connect, send, receive) in seconds.
    /// Default: 3 seconds
    ///
    /// This is the per-operation timeout for PAM module interactions with the daemon.
    /// The authentication session on the phone can continue for up to 120 seconds
    /// independently, but PAM operations will timeout after this duration to prevent
    /// user lockouts if the daemon is unresponsive.
    pub pam_operation_timeout_secs: u64,

    /// UDP port for authentication (default: 36692)
    pub udp_port: u16,

    /// Whether to use TPM for key storage
    /// Requires TPM 2.0 hardware and tpm2-tools installed
    #[cfg(feature = "tpm")]
    pub use_tpm: bool,
}

impl Default for TapAuthConfig {
    fn default() -> Self {
        Self {
            pam_operation_timeout_secs: DEFAULT_PAM_TIMEOUT_SECS,
            udp_port: DEFAULT_UDP_PORT,
            #[cfg(feature = "tpm")]
            use_tpm: false,
        }
    }
}

impl TapAuthConfig {
    /// Load configuration from the default path, using defaults for missing fields.
    pub fn load() -> Self {
        Self::load_from_path(DEFAULT_CONFIG_PATH)
    }

    /// Load configuration from a specific path, using defaults for missing fields.
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();

        // If file doesn't exist or can't be read, use defaults
        let contents = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    "Could not read config from {:?}: {}. Using defaults.",
                    path,
                    e
                );
                return Self::default();
            }
        };

        // Parse TOML, use defaults on parse error
        match toml::from_str::<TapAuthConfig>(&contents) {
            Ok(config) => {
                #[cfg(feature = "tpm")]
                tracing::info!(
                    "Loaded config from {:?}: pam_timeout={}s, udp_port={}, use_tpm={}",
                    path,
                    config.pam_operation_timeout_secs,
                    config.udp_port,
                    config.use_tpm
                );
                #[cfg(not(feature = "tpm"))]
                tracing::info!(
                    "Loaded config from {:?}: pam_timeout={}s, udp_port={}",
                    path,
                    config.pam_operation_timeout_secs,
                    config.udp_port,
                );
                config
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to parse config from {:?}: {}. Using defaults.",
                    path,
                    e
                );
                Self::default()
            }
        }
    }

    /// Save configuration to a file
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let contents = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        fs::write(path, contents)?;

        // Set restrictive permissions (readable by all, writable by root)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o644);
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Get the operation timeout as a Duration.
    pub fn operation_timeout(&self) -> Duration {
        Duration::from_secs(self.pam_operation_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TapAuthConfig::default();
        assert_eq!(config.pam_operation_timeout_secs, 3);
        assert_eq!(config.udp_port, 36692);
        #[cfg(feature = "tpm")]
        assert_eq!(config.use_tpm, false);
        assert_eq!(config.operation_timeout(), Duration::from_secs(3));
    }

    #[test]
    fn test_parse_valid_toml() {
        #[cfg(feature = "tpm")]
        let toml = r#"
            pam_operation_timeout_secs = 5
            udp_port = 12345
            use_tpm = true
        "#;
        #[cfg(not(feature = "tpm"))]
        let toml = r#"
            pam_operation_timeout_secs = 5
            udp_port = 12345
        "#;

        let config: TapAuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 5);
        assert_eq!(config.udp_port, 12345);
        #[cfg(feature = "tpm")]
        assert_eq!(config.use_tpm, true);
    }

    #[test]
    fn test_parse_partial_toml() {
        // Missing fields should use defaults
        #[cfg(feature = "tpm")]
        let toml = r#"
            use_tpm = true
        "#;
        #[cfg(not(feature = "tpm"))]
        let toml = r#"
            udp_port = 36692
        "#;
        let config: TapAuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 3);
        assert_eq!(config.udp_port, 36692);
        #[cfg(feature = "tpm")]
        assert_eq!(config.use_tpm, true);
    }

    #[test]
    fn test_roundtrip() {
        let config = TapAuthConfig {
            pam_operation_timeout_secs: 10,
            udp_port: 54321,
            #[cfg(feature = "tpm")]
            use_tpm: true,
        };

        let toml_str = toml::to_string(&config).unwrap();
        let parsed: TapAuthConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(
            parsed.pam_operation_timeout_secs,
            config.pam_operation_timeout_secs
        );
        assert_eq!(parsed.udp_port, config.udp_port);
        #[cfg(feature = "tpm")]
        assert_eq!(parsed.use_tpm, config.use_tpm);
    }
}
