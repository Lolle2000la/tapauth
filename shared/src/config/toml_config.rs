//! TOML configuration file handling for TapAuth.
//!
//! Reads system-wide configuration from `/etc/tapauth/config.toml` with sensible defaults.
//! This file contains settings that affect runtime behavior but are not considered
//! persistent state (which is stored in `/var/lib/tapauth`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Default configuration path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tapauth/config.toml";

/// Default PAM authentication session timeout in seconds
const DEFAULT_PAM_TIMEOUT_SECS: u64 = 120;

/// Default PAM authentication timeout for GUI contexts without a usable
/// conversation (e.g. the KDE lock screen), in seconds. Mirrors the default
/// in the PAM module's `PamConfig` (client-pam).
const DEFAULT_PAM_GUI_TIMEOUT_SECS: u64 = 30;

/// Default UDP port for authentication
const DEFAULT_UDP_PORT: u16 = 36692;

/// Marker file shipped by the optional `tapauth-fprintd-emulation` package
/// (world-readable, fixed path).
///
/// Its presence is what makes the virtual fprintd D-Bus bridge default to
/// enabled when `enable_fprintd_bridge` is left unset. The base packages do
/// NOT ship it, so a base install leaves the `net.reactivated.Fprint` bus name
/// to a real local fprintd unless the user opts in explicitly.
pub const FPRINTD_EMULATION_MARKER_PATH: &str = "/usr/share/tapauth/fprintd-emulation.enabled";

/// Resolve the tri-state `enable_fprintd_bridge` setting into an effective
/// boolean.
///
/// - An explicit value (`Some`) always wins (user override).
/// - When unset (`None`), the bridge is enabled iff `marker_exists`, i.e. the
///   optional `tapauth-fprintd-emulation` package installed its marker file.
///
/// Pure so the policy is unit-testable without touching the filesystem.
pub fn resolve_enable_fprintd_bridge(explicit: Option<bool>, marker_exists: bool) -> bool {
    explicit.unwrap_or(marker_exists)
}

/// Whether [`FPRINTD_EMULATION_MARKER_PATH`] exists on this system.
pub fn fprintd_emulation_marker_exists() -> bool {
    Path::new(FPRINTD_EMULATION_MARKER_PATH).exists()
}

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

    /// Authentication timeout for graphical PAM contexts that cannot collect a
    /// password while TapAuth waits (e.g. the KDE lock screen).
    /// Default: 30 seconds
    ///
    /// In those contexts the TapAuth wait is capped at this duration before
    /// falling through to password entry. The PAM module additionally clamps
    /// this to `pam_operation_timeout_secs`.
    ///
    /// This field must exist here (not only in the PAM module's own parser)
    /// because the daemon rewrites the whole config file on SaveConfig; a
    /// missing field would silently delete the user's setting.
    pub pam_gui_timeout_secs: u64,

    /// UDP port for authentication (default: 36692)
    pub udp_port: u16,

    /// Whether the Local Network (UDP broadcast/multicast) transport may be
    /// used for authentication attempts (default: true).
    ///
    /// When disabled, the daemon will not broadcast authentication requests
    /// over UDP and will not open the firewall port for them.
    pub enable_network: bool,

    /// Whether the Bluetooth Low Energy (BLE) transport may be used for
    /// authentication attempts (default: true).
    ///
    /// Only effective when the daemon is compiled with the `ble` feature.
    /// When disabled, the daemon will not advertise over BLE during
    /// authentication.
    pub enable_ble: bool,

    /// Whether the virtual fprintd D-Bus bridge is enabled.
    ///
    /// Tri-state:
    /// - unset (`None`): enabled only when the optional
    ///   `tapauth-fprintd-emulation` package has installed
    ///   [`FPRINTD_EMULATION_MARKER_PATH`]
    ///   (`/usr/share/tapauth/fprintd-emulation.enabled`). This is the base
    ///   install default, so the bus name stays with a real local fprintd.
    /// - `Some(true)`: always enabled (explicit user override).
    /// - `Some(false)`: always disabled (explicit user override; wins over the
    ///   marker).
    ///
    /// When enabled, the daemon exposes the `net.reactivated.Fprint` D-Bus
    /// interface, allowing desktop environments like GNOME Shell to query and
    /// trigger TapAuth biometrics seamlessly. Requires a daemon restart to
    /// acquire or release the D-Bus bus name.
    ///
    /// Use [`TapAuthConfig::fprintd_bridge_enabled`] for the effective value
    /// rather than reading this field directly.
    pub enable_fprintd_bridge: Option<bool>,

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
            udp_port: DEFAULT_UDP_PORT,
            enable_network: DEFAULT_TRANSPORT_ENABLED,
            enable_ble: DEFAULT_TRANSPORT_ENABLED,
            enable_fprintd_bridge: None,
            #[cfg(feature = "tpm")]
            use_tpm: false,
            #[cfg(feature = "tpm")]
            tpm_pcr_policy: TpmPcrPolicy::default(),
        }
    }
}

impl TapAuthConfig {
    /// Effective value of the virtual fprintd D-Bus bridge toggle.
    ///
    /// Resolves the tri-state [`TapAuthConfig::enable_fprintd_bridge`] against
    /// the presence of the `tapauth-fprintd-emulation` marker file. Callers
    /// that decide whether to claim the `net.reactivated.Fprint` bus name must
    /// use this rather than reading the raw field.
    pub fn fprintd_bridge_enabled(&self) -> bool {
        resolve_enable_fprintd_bridge(
            self.enable_fprintd_bridge,
            fprintd_emulation_marker_exists(),
        )
    }

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
        assert_eq!(config.udp_port, 36692);
        assert!(config.enable_network);
        assert!(config.enable_ble);
        // Tri-state default: unset, resolved against the emulation marker.
        assert_eq!(config.enable_fprintd_bridge, None);
        #[cfg(feature = "tpm")]
        {
            assert!(!config.use_tpm);
            assert_eq!(config.tpm_pcr_policy, TpmPcrPolicy::Standard);
        }
    }

    #[test]
    fn test_parse_valid_toml() {
        #[cfg(feature = "tpm")]
        let toml = r#"
            pam_operation_timeout_secs = 5
            pam_gui_timeout_secs = 15
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
            udp_port = 12345
            enable_network = false
            enable_ble = false
        "#;

        let config: TapAuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 5);
        assert_eq!(config.pam_gui_timeout_secs, 15);
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
            udp_port: 54321,
            enable_network: false,
            enable_ble: true,
            enable_fprintd_bridge: Some(true),
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
        assert_eq!(parsed.udp_port, config.udp_port);
        assert_eq!(parsed.enable_network, config.enable_network);
        assert_eq!(parsed.enable_ble, config.enable_ble);
        assert_eq!(parsed.enable_fprintd_bridge, config.enable_fprintd_bridge);
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

    /// The tri-state resolution: explicit values always win; when unset the
    /// bridge follows the `tapauth-fprintd-emulation` marker file.
    #[test]
    fn test_resolve_enable_fprintd_bridge() {
        // Explicit override wins in both directions, regardless of the marker.
        assert!(resolve_enable_fprintd_bridge(Some(true), false));
        assert!(resolve_enable_fprintd_bridge(Some(true), true));
        assert!(!resolve_enable_fprintd_bridge(Some(false), false));
        assert!(!resolve_enable_fprintd_bridge(Some(false), true));

        // Unset: base install (no marker) is off, emulation package (marker) on.
        assert!(!resolve_enable_fprintd_bridge(None, false));
        assert!(resolve_enable_fprintd_bridge(None, true));
    }

    /// Serde compatibility: existing configs containing an explicit boolean
    /// still parse (as an override), and an absent key stays `None`.
    #[test]
    fn test_parse_fprintd_bridge_presence() {
        let unset: TapAuthConfig = toml::from_str("udp_port = 36692").unwrap();
        assert_eq!(unset.enable_fprintd_bridge, None);

        let enabled: TapAuthConfig = toml::from_str("enable_fprintd_bridge = true").unwrap();
        assert_eq!(enabled.enable_fprintd_bridge, Some(true));

        let disabled: TapAuthConfig = toml::from_str("enable_fprintd_bridge = false").unwrap();
        assert_eq!(disabled.enable_fprintd_bridge, Some(false));
    }

    /// An unset bridge must serialize without an `enable_fprintd_bridge` key so
    /// the daemon's whole-file SaveConfig rewrite does not turn "auto" into an
    /// explicit value. Explicit overrides must survive.
    #[test]
    fn test_serialize_fprintd_bridge_tristate() {
        let mut config = TapAuthConfig::default();
        let unset = toml::to_string_pretty(&config).unwrap();
        assert!(!unset.contains("enable_fprintd_bridge"));

        config.enable_fprintd_bridge = Some(false);
        let disabled = toml::to_string_pretty(&config).unwrap();
        assert!(disabled.contains("enable_fprintd_bridge = false"));

        config.enable_fprintd_bridge = Some(true);
        let enabled = toml::to_string_pretty(&config).unwrap();
        assert!(enabled.contains("enable_fprintd_bridge = true"));
    }
}
