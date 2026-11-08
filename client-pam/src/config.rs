//! Configuration file handling for TapAuth PAM module.
//!
//! Reads configuration from `/etc/tapauth/config.toml` with sensible defaults.
//! Focuses on timeout settings to prevent user lockouts while maintaining security.

use serde::Deserialize;
use std::fs;
use std::path::Path;

const DEFAULT_CONFIG_PATH: &str = "/etc/tapauth/config.toml";
const DEFAULT_PAM_TIMEOUT_SECS: u64 = 120;
const DEFAULT_PAM_GUI_TIMEOUT_SECS: u64 = 30;

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
    /// Authentication timeout for GUI contexts without a usable conversation.
    /// Default: 30 seconds
    ///
    /// Sequential graphical PAM hosts (any host the rule table in `policy.rs`
    /// does not name) cannot have their conversation function driven while
    /// TapAuth waits for the phone, so no concurrent password entry is possible
    /// there (see `mechanism::sequential`). To keep the lock screen
    /// responsive, the TapAuth wait in those contexts is capped at this
    /// duration before falling through to password authentication. It is
    /// additionally clamped to `pam_operation_timeout_secs`.
    pub pam_gui_timeout_secs: u64,
    /// Additional PAM service names the module must refuse to take part in.
    ///
    /// The built-ins (`shared::config::DEFAULT_PAM_REFUSED_SERVICES`) are always
    /// refused. Entries here are *added* to them: a deployment that renames
    /// OpenSSH's `PAMServiceName` lists its new name, and the module refuses it
    /// exactly as it refuses `sshd`. Invalid entries are dropped with a warning;
    /// see `PamConfig::effective_refused_services`.
    pub pam_refused_services: Vec<String>,
}

impl Default for PamConfig {
    fn default() -> Self {
        Self {
            pam_operation_timeout_secs: DEFAULT_PAM_TIMEOUT_SECS,
            pam_gui_timeout_secs: DEFAULT_PAM_GUI_TIMEOUT_SECS,
            pam_refused_services: shared::config::DEFAULT_PAM_REFUSED_SERVICES
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }
}

/// Whether `name` can be a `pam.d` service name.
///
/// After trimming, a service name must be non-empty pure ASCII, contain no `/`
/// and no whitespace or control character, and fit in 255 bytes: `PAM_SERVICE`
/// is a file name under `/etc/pam.d`, so it has to fit `NAME_MAX`.
fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.is_ascii()
        && !name.contains('/')
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl PamConfig {
    /// The service names the module must refuse to take part in: the built-ins
    /// plus every valid configured entry.
    ///
    /// The built-ins are always present — config can add a name, never remove
    /// one of them. Entries are trimmed and deduplicated ASCII
    /// case-insensitively (a `pam.d` file name cannot distinguish `SSHD` from
    /// `sshd`, so keeping both would only make the list harder to read). An
    /// entry that cannot be a service name is dropped with a warning: silently
    /// ignoring a misspelled rename would leave the deployment treating the
    /// stack as local, which is exactly the false negative this setting exists
    /// to close.
    pub(crate) fn effective_refused_services(&self) -> Vec<String> {
        let mut effective: Vec<String> = shared::config::DEFAULT_PAM_REFUSED_SERVICES
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        for entry in &self.pam_refused_services {
            let name = entry.trim();
            if !valid_service_name(name) {
                tracing::warn!(
                    "Ignoring invalid pam_refused_services entry {:?}: a PAM service name must \
                     be non-empty ASCII with no '/' or whitespace and at most 255 bytes",
                    entry
                );
                continue;
            }
            if !effective
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(name))
            {
                effective.push(name.to_owned());
            }
        }
        effective
    }

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
                    "Loaded PAM config from {:?}: operation_timeout={}s gui_timeout={}s",
                    path,
                    config.pam_operation_timeout_secs,
                    config.pam_gui_timeout_secs
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
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PamConfig::default();
        assert_eq!(config.pam_operation_timeout_secs, 120);
        assert_eq!(config.pam_gui_timeout_secs, 30);
        assert_eq!(
            config.pam_refused_services,
            vec!["sshd".to_string(), "sshd-session".to_string()]
        );
        assert_eq!(
            config.effective_refused_services(),
            vec!["sshd".to_string(), "sshd-session".to_string()]
        );
    }

    /// A configured entry is *added* to the built-ins, never a replacement.
    ///
    /// The defect this catches: `effective_refused_services` returning only the
    /// configured list, so declaring a rename silently un-refused `sshd` itself.
    #[test]
    fn configured_refused_service_is_added_to_the_built_ins() {
        let config = PamConfig {
            pam_refused_services: vec!["sshd-renamed".to_string()],
            ..PamConfig::default()
        };
        assert_eq!(
            config.effective_refused_services(),
            vec![
                "sshd".to_string(),
                "sshd-session".to_string(),
                "sshd-renamed".to_string()
            ]
        );
    }

    /// The built-ins stand even when the configured list omits them entirely.
    ///
    /// The defect this catches: the built-ins being taken from the configured
    /// list, so a `pam_refused_services = []` (or a list that names only a
    /// rename) removed `sshd` from the refusal.
    #[test]
    fn built_ins_survive_an_empty_configured_list() {
        let config = PamConfig {
            pam_refused_services: vec![],
            ..PamConfig::default()
        };
        assert_eq!(
            config.effective_refused_services(),
            vec!["sshd".to_string(), "sshd-session".to_string()]
        );
    }

    /// Dedup is ASCII case-insensitive, so a spelling variant does not double
    /// the list.
    ///
    /// The defect this catches: a case-sensitive dedup, which would leave
    /// `["sshd", "SSHD"]` in the list and make it unclear which entry the
    /// refusal came from.
    #[test]
    fn refused_services_are_deduplicated_case_insensitively() {
        let config = PamConfig {
            pam_refused_services: vec![
                "SSHD".to_string(),
                "sshd-renamed".to_string(),
                "SSHD-RENAMED".to_string(),
            ],
            ..PamConfig::default()
        };
        assert_eq!(
            config.effective_refused_services(),
            vec![
                "sshd".to_string(),
                "sshd-session".to_string(),
                "sshd-renamed".to_string()
            ]
        );
    }

    /// Invalid entries are dropped, valid ones survive, and the built-ins stay.
    ///
    /// The defect this catches: a malformed entry reaching the matcher (the
    /// empty string would match an unresolved/empty service) or a parser that
    /// rejects the whole list because of one bad name.
    #[test]
    fn invalid_refused_services_are_dropped_without_losing_valid_ones() {
        let config = PamConfig {
            pam_refused_services: vec![
                String::new(),
                "   ".to_string(),
                "sshd/x".to_string(),
                "ssh d".to_string(),
                "sshd\u{0}".to_string(),
                "sshd\u{e9}".to_string(),
                "x".repeat(256),
                " sshd-renamed ".to_string(),
            ],
            ..PamConfig::default()
        };
        assert_eq!(
            config.effective_refused_services(),
            vec![
                "sshd".to_string(),
                "sshd-session".to_string(),
                "sshd-renamed".to_string()
            ],
            "only the trimmed, valid entry is added; the built-ins remain"
        );
    }

    #[test]
    fn test_parse_refused_services_from_toml() {
        let toml = r#"
            pam_operation_timeout_secs = 5
            pam_refused_services = ["sshd", "sshd-renamed"]
        "#;
        let config: PamConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 5);
        assert_eq!(
            config.pam_refused_services,
            vec!["sshd".to_string(), "sshd-renamed".to_string()]
        );
        assert_eq!(
            config.effective_refused_services(),
            vec![
                "sshd".to_string(),
                "sshd-session".to_string(),
                "sshd-renamed".to_string()
            ]
        );
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
