//! TOML configuration file handling for TapAuth.
//!
//! Reads system-wide configuration from `/etc/tapauth/config.toml` with sensible defaults.
//! This file contains settings that affect runtime behavior but are not considered
//! persistent state (which is stored in `/var/lib/tapauth`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Default configuration path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tapauth/config.toml";

/// Default PAM authentication session timeout in seconds
const DEFAULT_PAM_TIMEOUT_SECS: u64 = 120;

/// Default PAM authentication timeout for GUI contexts whose conversation the
/// module cannot drive (the sequential path — a host the rule table in
/// `client-pam/src/policy/table.rs` does not classify as threaded), in seconds.
/// Mirrors the default in the PAM module's `PamConfig` (client-pam).
const DEFAULT_PAM_GUI_TIMEOUT_SECS: u64 = 30;

/// The PAM service names the module always refuses to take part in: `sshd` is
/// OpenSSH's compiled-in `PAMServiceName` default, `sshd-session` the name its
/// per-connection session binary uses on current releases. This list is the one
/// canonical definition (the PAM module's `RemoteRefuse` and its config parser both read it);
/// a deployment that renames `PAMServiceName` adds the new name to
/// `pam_refused_services`, which can only add, never remove.
pub const DEFAULT_PAM_REFUSED_SERVICES: &[&str] = &["sshd", "sshd-session"];

/// Default UDP port for authentication
const DEFAULT_UDP_PORT: u16 = 36692;

/// Transports are enabled by default
const DEFAULT_TRANSPORT_ENABLED: bool = true;

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
    /// Authentication session timeout in seconds.
    /// Default: 120 seconds
    ///
    /// How long the PAM module waits for the daemon to complete an authentication
    /// attempt (including phone discovery, BLE/UDP exchange, and user interaction).
    /// After this deadline, the PAM module falls through to the next authentication
    /// method (typically password).
    ///
    /// Must be at least as long as the transport-level timeout so the daemon has
    /// time to complete BLE/UDP discovery and receive the phone's response.
    pub pam_operation_timeout_secs: u64,

    /// Authentication timeout for graphical PAM contexts whose conversation the
    /// module cannot drive (the sequential path: a host the rule table in
    /// `client-pam/src/policy/table.rs` does not classify as threaded).
    /// Default: 30 seconds
    ///
    /// In those contexts the TapAuth wait is capped at this duration before
    /// falling through to password entry. The PAM module additionally clamps this
    /// to `pam_operation_timeout_secs`, and only for a sequential host **without**
    /// a terminal; hosts whose conversation can be driven from a worker thread are
    /// bounded by `pam_operation_timeout_secs` instead.
    ///
    /// This field must exist here (not only in the PAM module's own parser)
    /// because the daemon rewrites the whole config file on SaveConfig; a
    /// missing field would silently delete the user's setting.
    pub pam_gui_timeout_secs: u64,

    /// Additional PAM service names the module must refuse to take part in.
    ///
    /// The built-ins ([`DEFAULT_PAM_REFUSED_SERVICES`]) are always refused; entries
    /// here are *added* to them and cannot remove one. A deployment that renames
    /// OpenSSH's `PAMServiceName` declares the rename here; without it that stack is
    /// treated as local and the phone is rung for a remote login.
    ///
    /// This field must exist here (not only in the PAM module's own parser)
    /// because the daemon rewrites the whole config file on SaveConfig; a
    /// missing field would silently delete the user's setting.
    pub pam_refused_services: Vec<String>,

    /// UDP port for authentication (default: 36692)
    pub udp_port: u16,

    /// Whether the Local Network (UDP multicast) transport may be
    /// used for authentication attempts (default: true).
    ///
    /// When disabled, the daemon will not multicast authentication requests
    /// over UDP and will not open the firewall port for them.
    pub enable_network: bool,

    /// Whether the Bluetooth Low Energy (BLE) transport may be used for
    /// authentication attempts (default: true).
    ///
    /// Only effective when the daemon is compiled with the `ble` feature.
    /// When disabled, the daemon will not advertise over BLE during
    /// authentication.
    pub enable_ble: bool,

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
            pam_gui_timeout_secs: DEFAULT_PAM_GUI_TIMEOUT_SECS,
            pam_refused_services: DEFAULT_PAM_REFUSED_SERVICES
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            udp_port: DEFAULT_UDP_PORT,
            enable_network: DEFAULT_TRANSPORT_ENABLED,
            enable_ble: DEFAULT_TRANSPORT_ENABLED,
            #[cfg(feature = "tpm")]
            use_tpm: false,
            #[cfg(feature = "tpm")]
            tpm_pcr_policy: TpmPcrPolicy::default(),
        }
    }
}

impl TapAuthConfig {
    /// Load configuration, from `TAPAUTH_STATE_DIR/config.toml` (dev builds only) or
    /// [`DEFAULT_CONFIG_PATH`].
    pub fn load() -> Self {
        #[cfg(any(feature = "dev-state-override", test))]
        if let Ok(state_dir) = std::env::var("TAPAUTH_STATE_DIR") {
            let config_path = std::path::Path::new(&state_dir).join("config.toml");
            if config_path.exists() {
                return Self::load_from_path(config_path);
            }
        }
        Self::load_from_path(DEFAULT_CONFIG_PATH)
    }

    /// Save configuration, to `TAPAUTH_STATE_DIR/config.toml` (dev builds only) or
    /// [`DEFAULT_CONFIG_PATH`].
    pub fn save(&self) -> std::io::Result<()> {
        #[cfg(any(feature = "dev-state-override", test))]
        if let Ok(state_dir) = std::env::var("TAPAUTH_STATE_DIR") {
            let config_path = std::path::Path::new(&state_dir).join("config.toml");
            return self.save_to_path(config_path);
        }
        self.save_to_path(DEFAULT_CONFIG_PATH)
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
                    "Loaded config from {:?}: pam_timeout={}s, udp_port={}, enable_network={}, enable_ble={}, use_tpm={}, tpm_pcr_policy={:?}",
                    path,
                    config.pam_operation_timeout_secs,
                    config.udp_port,
                    config.enable_network,
                    config.enable_ble,
                    config.use_tpm,
                    config.tpm_pcr_policy
                );
                #[cfg(not(feature = "tpm"))]
                tracing::info!(
                    "Loaded config from {:?}: pam_timeout={}s, udp_port={}, enable_network={}, enable_ble={}",
                    path,
                    config.pam_operation_timeout_secs,
                    config.udp_port,
                    config.enable_network,
                    config.enable_ble,
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
        assert_eq!(config.pam_operation_timeout_secs, 120);
        assert_eq!(config.pam_gui_timeout_secs, 30);
        assert_eq!(
            config.pam_refused_services,
            vec!["sshd".to_string(), "sshd-session".to_string()]
        );
        assert_eq!(config.udp_port, 36692);
        assert!(config.enable_network);
        assert!(config.enable_ble);
        #[cfg(feature = "tpm")]
        {
            assert!(!config.use_tpm);
            assert_eq!(config.tpm_pcr_policy, TpmPcrPolicy::Standard);
        }
        assert_eq!(config.operation_timeout(), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_valid_toml() {
        #[cfg(feature = "tpm")]
        let toml = r#"
            pam_operation_timeout_secs = 5
            pam_gui_timeout_secs = 15
            pam_refused_services = ["sshd", "sshd-renamed"]
            udp_port = 12345
            enable_network = false
            enable_ble = false
            use_tpm = true
            tpm_pcr_policy = "paranoid"
        "#;
        #[cfg(not(feature = "tpm"))]
        let toml = r#"
            pam_operation_timeout_secs = 5
            pam_gui_timeout_secs = 15
            pam_refused_services = ["sshd", "sshd-renamed"]
            udp_port = 12345
            enable_network = false
            enable_ble = false
        "#;

        let config: TapAuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 5);
        assert_eq!(config.pam_gui_timeout_secs, 15);
        assert_eq!(
            config.pam_refused_services,
            vec!["sshd".to_string(), "sshd-renamed".to_string()]
        );
        assert_eq!(config.udp_port, 12345);
        assert!(!config.enable_network);
        assert!(!config.enable_ble);
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
        assert_eq!(config.pam_operation_timeout_secs, 120);
        assert_eq!(config.pam_gui_timeout_secs, 30);
        // A missing list is not "refuse nothing": the built-ins are the default.
        assert_eq!(
            config.pam_refused_services,
            vec!["sshd".to_string(), "sshd-session".to_string()]
        );
        assert_eq!(config.udp_port, 36692);
        assert!(config.enable_network);
        assert!(config.enable_ble);
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
            pam_gui_timeout_secs: 20,
            pam_refused_services: vec!["sshd".to_string(), "sshd-renamed".to_string()],
            udp_port: 54321,
            enable_network: false,
            enable_ble: true,
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
        assert_eq!(parsed.pam_gui_timeout_secs, config.pam_gui_timeout_secs);
        assert_eq!(
            parsed.pam_refused_services, config.pam_refused_services,
            "the refused-service list must survive serialization"
        );
        assert_eq!(parsed.udp_port, config.udp_port);
        assert_eq!(parsed.enable_network, config.enable_network);
        assert_eq!(parsed.enable_ble, config.enable_ble);
        #[cfg(feature = "tpm")]
        {
            assert_eq!(parsed.use_tpm, config.use_tpm);
            assert_eq!(parsed.tpm_pcr_policy, config.tpm_pcr_policy);
        }
    }

    /// Regression test: the daemon rewrites the whole config file on
    /// SaveConfig (admin IPC / GUI Settings). A PAM setting that is absent
    /// from `TapAuthConfig` would be silently deleted by that rewrite, so
    /// `pam_gui_timeout_secs` must survive a load → save cycle.
    #[test]
    fn test_save_preserves_pam_gui_timeout() {
        let toml = r#"
            pam_operation_timeout_secs = 60
            pam_gui_timeout_secs = 45
            udp_port = 40000
        "#;
        let config: TapAuthConfig = toml::from_str(toml).unwrap();

        // Simulate the daemon's SaveConfig: mutate unrelated fields and
        // re-serialize the whole struct back to TOML.
        let mut saved = config;
        saved.udp_port = 36692;
        saved.enable_ble = false;
        let rewritten = toml::to_string_pretty(&saved).unwrap();

        let reloaded: TapAuthConfig = toml::from_str(&rewritten).unwrap();
        assert_eq!(reloaded.pam_gui_timeout_secs, 45);
        assert_eq!(reloaded.pam_operation_timeout_secs, 60);
        assert_eq!(reloaded.udp_port, 36692);
        assert!(!reloaded.enable_ble);
        assert!(rewritten.contains("pam_gui_timeout_secs = 45"));
    }

    /// Regression test for the same rewrite hazard as `pam_gui_timeout_secs`.
    ///
    /// The defect this catches: the daemon's SaveConfig round-trip dropping
    /// `pam_refused_services`, so a deployment that declared its renamed
    /// `PAMServiceName` lost the refusal on the first settings change and began
    /// ringing the phone for remote logins again.
    #[test]
    fn test_save_preserves_pam_refused_services() {
        let toml = r#"
            pam_operation_timeout_secs = 60
            pam_refused_services = ["sshd", "sshd-session", "sshd-renamed"]
            udp_port = 40000
        "#;
        let config: TapAuthConfig = toml::from_str(toml).unwrap();

        // Simulate the daemon's SaveConfig: mutate unrelated fields and
        // re-serialize the whole struct back to TOML.
        let mut saved = config;
        saved.udp_port = 36692;
        saved.enable_ble = false;
        let rewritten = toml::to_string_pretty(&saved).unwrap();

        let reloaded: TapAuthConfig = toml::from_str(&rewritten).unwrap();
        assert_eq!(
            reloaded.pam_refused_services,
            vec![
                "sshd".to_string(),
                "sshd-session".to_string(),
                "sshd-renamed".to_string()
            ],
            "SaveConfig must not delete the configured refused services"
        );
        assert!(rewritten.contains("sshd-renamed"));
    }
}
