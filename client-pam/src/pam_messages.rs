//! Localized user-facing messages for the PAM module.
//!
//! Uses the same Fluent (FTL) localization engine as the GUI, matching its
//! locale detection (LC_ALL → LC_MESSAGES → LANG) and embedding FTL strings
//! at compile time via `include_str!()`.  All keys are resolved at construction
//! time so accessors return `&str` with zero runtime cost.

use fluent::{FluentBundle, FluentResource};
use std::sync::Arc;
use unic_langid::LanguageIdentifier;

pub struct PamMessages {
    waiting_for_tap_skip: String,
    waiting_for_tap: String,
    cannot_connect: String,
    communication_error: String,
    connection_lost: String,
    timed_out: String,
    skipped: String,
    auth_successful: String,
    auth_denied: String,
    error_prefix: String,
}

fn tr(bundle: &FluentBundle<Arc<FluentResource>>, key: &str) -> String {
    if let Some(msg) = bundle.get_message(key) {
        if let Some(pattern) = msg.value() {
            let mut errors = vec![];
            return bundle
                .format_pattern(pattern, None, &mut errors)
                .to_string();
        }
    }
    format!("??{}??", key)
}

impl PamMessages {
    pub fn new(locale: &str) -> Self {
        let ftl_str = match locale {
            "de" => include_str!("../locales/de/main.ftl"),
            "ja" => include_str!("../locales/ja/main.ftl"),
            _ => include_str!("../locales/en/main.ftl"),
        };

        let res = FluentResource::try_new(ftl_str.to_string())
            .expect("Failed to parse embedded PAM FTL file");
        let lang_id: LanguageIdentifier = locale.parse().unwrap_or_else(|_| "en".parse().unwrap());
        let mut bundle = FluentBundle::new(vec![lang_id]);
        bundle
            .add_resource(Arc::new(res))
            .expect("Failed to add FTL resource to PAM bundle");
        bundle.set_use_isolating(false);

        Self {
            waiting_for_tap_skip: tr(&bundle, "pam-waiting-tap-skip"),
            waiting_for_tap: tr(&bundle, "pam-waiting-tap"),
            cannot_connect: tr(&bundle, "pam-cannot-connect"),
            communication_error: tr(&bundle, "pam-communication-error"),
            connection_lost: tr(&bundle, "pam-connection-lost"),
            timed_out: tr(&bundle, "pam-timed-out"),
            skipped: tr(&bundle, "pam-skipped"),
            auth_successful: tr(&bundle, "pam-auth-successful"),
            auth_denied: tr(&bundle, "pam-auth-denied"),
            error_prefix: tr(&bundle, "pam-error-prefix"),
        }
    }

    pub fn waiting_for_tap_skip(&self) -> &str {
        &self.waiting_for_tap_skip
    }
    pub fn waiting_for_tap(&self) -> &str {
        &self.waiting_for_tap
    }
    pub fn cannot_connect(&self) -> &str {
        &self.cannot_connect
    }
    pub fn communication_error(&self) -> &str {
        &self.communication_error
    }
    pub fn connection_lost(&self) -> &str {
        &self.connection_lost
    }
    pub fn timed_out(&self) -> &str {
        &self.timed_out
    }
    pub fn skipped(&self) -> &str {
        &self.skipped
    }
    pub fn auth_successful(&self) -> &str {
        &self.auth_successful
    }
    pub fn auth_denied(&self) -> &str {
        &self.auth_denied
    }

    /// Build an error message by concatenating the localized prefix with the detail string.
    pub fn error(&self, detail: &str) -> String {
        format!("{}{}", self.error_prefix, detail)
    }
}

/// Detect locale from POSIX environment variables.
/// Mirrors the GUI's `detect_locale()` logic.
pub fn detect_locale() -> &'static str {
    for var in &["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            let val_lower = val.to_lowercase();
            if val_lower.starts_with("de") {
                return "de";
            }
            if val_lower.starts_with("ja") {
                return "ja";
            }
        }
    }
    "en"
}

pub fn load() -> PamMessages {
    PamMessages::new(detect_locale())
}
