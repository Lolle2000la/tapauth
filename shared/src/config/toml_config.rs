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

/// TPM PCR sealing policy - determines which Platform Configuration Registers
/// are used to seal the authentication keys.
///
/// PCRs measure system state at boot time. Sealing to PCRs means keys can only
/// be unsealed if the measured values match, providing protection against
/// boot chain tampering.
#[cfg(feature = "tpm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TpmPcrPolicy {
    /// Standard security - binds to boot integrity only
    ///
    /// PCRs: 7 (Secure Boot state), 14 (MOK keys)
    ///
    /// **Reliability**: High - won't break on kernel or BIOS updates
    /// **Security**: Good - prevents evil maid attacks (modified bootloader)
    ///
    /// This is the recommended setting for most users.
    #[default]
    Standard,

    /// Maximum security - binds to full boot chain
    ///
    /// PCRs: 0 (BIOS), 2 (Option ROMs), 7 (Secure Boot), 14 (MOK)
    ///
    /// **Reliability**: Low - WILL break on BIOS updates, may break on hardware changes
    /// **Security**: Maximum - detects any boot chain modifications
    ///
    /// ⚠️ WARNING: This will require key recovery via GUI after:
    /// - BIOS/UEFI firmware updates
    /// - Secure Boot key changes
    /// - Some hardware changes
    ///
    /// Only use this if you understand the trade-offs and are prepared
    /// to regenerate keys (and re-pair devices) frequently.
    Paranoid,
}

#[cfg(feature = "tpm")]
impl TpmPcrPolicy {
    /// Get the PCR list for tpm2-tools commands
    ///
    /// Returns a comma-separated list like "7,14" or "0,2,7,14"
    pub fn pcr_list(&self) -> &'static str {
        match self {
            TpmPcrPolicy::Standard => "7,14",
            TpmPcrPolicy::Paranoid => "0,2,7,14",
        }
    }

    /// Get a human-readable description of what this policy protects against
    pub fn description(&self) -> &'static str {
        match self {
            TpmPcrPolicy::Standard => "Protects against modified bootloader/kernel (evil maid attacks). Won't break on updates.",
            TpmPcrPolicy::Paranoid => "Maximum protection - detects any boot chain changes. WILL break on BIOS updates.",
        }
    }
}

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

    /// TPM PCR sealing policy - determines boot integrity checks
    ///
    /// - `standard`: Seals to PCR 7+14 (Secure Boot + MOK) - recommended
    /// - `paranoid`: Seals to PCR 0+2+7+14 (BIOS + Option ROMs + Secure Boot + MOK)
    ///
    /// Standard mode provides good security without breaking on updates.
    /// Paranoid mode provides maximum security but WILL break on BIOS updates.
    #[cfg(feature = "tpm")]
    pub tpm_pcr_policy: TpmPcrPolicy,
}

impl Default for TapAuthConfig {
    fn default() -> Self {
        Self {
            pam_operation_timeout_secs: DEFAULT_PAM_TIMEOUT_SECS,
            udp_port: DEFAULT_UDP_PORT,
            #[cfg(feature = "tpm")]
            use_tpm: false,
            #[cfg(feature = "tpm")]
            tpm_pcr_policy: TpmPcrPolicy::default(),
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
                    "Loaded config from {:?}: pam_timeout={}s, udp_port={}, use_tpm={}, tpm_pcr_policy={:?}",
                    path,
                    config.pam_operation_timeout_secs,
                    config.udp_port,
                    config.use_tpm,
                    config.tpm_pcr_policy
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
        let config = TapAuthConfig::default();
        assert_eq!(config.pam_operation_timeout_secs, 3);
        assert_eq!(config.udp_port, 36692);
        #[cfg(feature = "tpm")]
        {
            assert!(!config.use_tpm);
            assert_eq!(config.tpm_pcr_policy, TpmPcrPolicy::Standard);
        }
        assert_eq!(config.operation_timeout(), Duration::from_secs(3));
    }

    #[test]
    fn test_parse_valid_toml() {
        #[cfg(feature = "tpm")]
        let toml = r#"
            pam_operation_timeout_secs = 5
            udp_port = 12345
            use_tpm = true
            tpm_pcr_policy = "paranoid"
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
        {
            assert!(config.use_tpm);
            assert_eq!(config.tpm_pcr_policy, TpmPcrPolicy::Paranoid);
        }
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
        {
            assert!(config.use_tpm);
            assert_eq!(config.tpm_pcr_policy, TpmPcrPolicy::Standard); // Should default
        }
    }

    #[test]
    fn test_roundtrip() {
        let config = TapAuthConfig {
            pam_operation_timeout_secs: 10,
            udp_port: 54321,
            #[cfg(feature = "tpm")]
            use_tpm: true,
            #[cfg(feature = "tpm")]
            tpm_pcr_policy: TpmPcrPolicy::Paranoid,
        };

        let toml_str = toml::to_string(&config).unwrap();
        let parsed: TapAuthConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(
            parsed.pam_operation_timeout_secs,
            config.pam_operation_timeout_secs
        );
        assert_eq!(parsed.udp_port, config.udp_port);
        #[cfg(feature = "tpm")]
        {
            assert_eq!(parsed.use_tpm, config.use_tpm);
            assert_eq!(parsed.tpm_pcr_policy, config.tpm_pcr_policy);
        }
    }
}
