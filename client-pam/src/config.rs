//! The module's slice of `/etc/tapauth/config.toml` — the PAM timeouts and the
//! `pam.d` service names to refuse — with a default for every field, so a
//! missing or unparsable file leaves the module usable.

use serde::Deserialize;
use std::fs;
use std::path::Path;

const DEFAULT_CONFIG_PATH: &str = "/etc/tapauth/config.toml";
const DEFAULT_PAM_TIMEOUT_SECS: u64 = 120;
const DEFAULT_PAM_GUI_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PamConfig {
    /// How long the module waits for the daemon to conclude an attempt
    /// (discovery, exchange and the phone tap included), default 120 s. Past
    /// the deadline it falls through to the next stack entry, typically the
    /// password. Must be at least the transport timeout, or the daemon can
    /// never finish in time.
    pub pam_operation_timeout_secs: u64,
    /// The wait cap for a sequential GUI host — one the rule table
    /// (`policy/table.rs`) does not classify as threaded — whose conversation is
    /// never driven, so no concurrent password entry exists. Default 30 s,
    /// additionally clamped to `pam_operation_timeout_secs`.
    pub pam_gui_timeout_secs: u64,
    /// Extra `pam.d` service names to refuse, *added* to the built-ins
    /// (`shared::config::DEFAULT_PAM_REFUSED_SERVICES`), never replacing them:
    /// this is how a deployment that renames OpenSSH's `PAMServiceName` keeps
    /// the refusal. Invalid entries are dropped with a warning; see
    /// `PamConfig::effective_refused_services`.
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

/// Whether `name` can be a `pam.d` service name. The 255-byte cap is `NAME_MAX`:
/// `PAM_SERVICE` names a file under `/etc/pam.d`.
fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.is_ascii()
        && !name.contains('/')
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl PamConfig {
    /// The built-ins plus every valid configured entry: config can add a name,
    /// never remove one.
    ///
    /// Entries are trimmed and deduplicated ASCII case-insensitively (`pam.d`
    /// cannot distinguish `SSHD` from `sshd`). An invalid entry is dropped with a
    /// warning: silently ignoring a misspelled rename would leave the deployment
    /// treating the stack as local, the false negative this setting exists to
    /// close.
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

    pub fn load() -> Self {
        Self::load_from_path(DEFAULT_CONFIG_PATH)
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();

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

        match toml::from_str::<PamConfig>(&contents) {
            Ok(config) => {
                tracing::info!(
                    "Loaded PAM config from {:?}: pam_operation_timeout_secs={}s \
                     pam_gui_timeout_secs={}s pam_refused_services={:?}",
                    path,
                    config.pam_operation_timeout_secs,
                    config.pam_gui_timeout_secs,
                    config.pam_refused_services
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

    /// The defect this catches: a case-sensitive dedup, leaving `SSHD` beside
    /// `sshd` in the list.
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

    /// The defect this catches: a malformed entry reaching the matcher (the empty
    /// string would match an unresolved service), or a parser that rejects the
    /// whole list over one bad name.
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
        let toml = "";
        let config: PamConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pam_operation_timeout_secs, 120);
    }
}
