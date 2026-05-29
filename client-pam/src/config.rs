//! Configuration file handling for TapAuth PAM module.
//!
//! Reads configuration from `/etc/tapauth/config.toml` with sensible defaults.
//! Focuses on timeout settings to prevent user lockouts while maintaining security.

use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

const DEFAULT_CONFIG_PATH: &str = "/etc/tapauth/config.toml";
const DEFAULT_PAM_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PamConfig {
    /// Authentication session timeout in seconds.
    /// Default: 120 seconds
    ///
    /// How long the PAM module waits for the daemon to complete an authentication
    /// attempt (including phone discovery, BLE/UDP exchange, and user interaction).
    /// After this deadline, the PAM module falls through to the next authentication
    /// method (typically password) without blocking the user.
    ///
    /// Must be at least as long as the transport-level timeout so the daemon has
    /// time to complete BLE/UDP discovery and receive the phone's response.
    pub pam_operation_timeout_secs: u64,
}

impl Default for PamConfig {
    fn default() -> Self {
        Self {
            pam_operation_timeout_secs: DEFAULT_PAM_TIMEOUT_SECS,
        }
    }
}

impl PamConfig {
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
        match toml::from_str::<PamConfig>(&contents) {
            Ok(config) => {
                tracing::info!(
                    "Loaded PAM config from {:?}: operation_timeout={}s",
                    path,
                    config.pam_operation_timeout_secs
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

    /// Get the operation timeout as a Duration.
    pub fn operation_timeout(&self) -> Duration {
        Duration::from_secs(self.pam_operation_timeout_secs)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PamConfig::default();
        assert_eq!(config.pam_operation_timeout_secs, 120);
        assert_eq!(config.operation_timeout(), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_valid_toml() {
        let toml = r#"
            pam_operation_timeout_secs = 5
        "#;

        let config: PamConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 5);
    }

    #[test]
    fn test_parse_partial_toml() {
        // Missing fields should use defaults
        let toml = "";
        let config: PamConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 120);
    }
}
