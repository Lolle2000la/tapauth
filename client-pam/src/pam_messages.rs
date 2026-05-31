//! Localized user-facing messages for the PAM module.
//!
//! Uses the same Fluent (FTL) localization engine as the GUI, matching its
//! locale detection (LC_ALL → LC_MESSAGES → LANG) and embedding FTL strings
//! at compile time via `include_str!()`.  All keys are resolved at construction
//! time so accessors return `&str` with zero runtime cost.
//!
//! When a key is missing in a non-English locale, the English bundle is used
//! as a fallback — matching the GUI's Fluent Bundle fallback behaviour.

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

fn tr(
    bundle: &FluentBundle<Arc<FluentResource>>,
    fallback: Option<&FluentBundle<Arc<FluentResource>>>,
    key: &str,
) -> String {
    if let Some(msg) = bundle.get_message(key) {
        if let Some(pattern) = msg.value() {
            let mut errors = vec![];
            return bundle
                .format_pattern(pattern, None, &mut errors)
                .to_string();
        }
    }
    if let Some(fb) = fallback {
        if let Some(msg) = fb.get_message(key) {
            if let Some(pattern) = msg.value() {
                let mut errors = vec![];
                return fb.format_pattern(pattern, None, &mut errors).to_string();
            }
        }
    }
    format!("??{}??", key)
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
fn load_bundle(ftl_str: &str, lang_id: LanguageIdentifier) -> FluentBundle<Arc<FluentResource>> {
    let res = FluentResource::try_new(ftl_str.to_string())
        .expect("Failed to parse embedded PAM FTL file");
    let mut bundle = FluentBundle::new(vec![lang_id]);
    bundle
        .add_resource(Arc::new(res))
        .expect("Failed to add FTL resource to PAM bundle");
    bundle.set_use_isolating(false);
    bundle
}

impl PamMessages {
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    pub fn new(locale: &str) -> Self {
        let en_str = include_str!("../locales/en/main.ftl");
        let en_bundle = {
            let en_lang: LanguageIdentifier = "en".parse().unwrap();
            load_bundle(en_str, en_lang)
        };

        let (bundle, fallback) = match locale {
            "en" => (en_bundle, None),
            other => {
                let ftl_str = match other {
                    "de" => include_str!("../locales/de/main.ftl"),
                    "ja" => include_str!("../locales/ja/main.ftl"),
                    _ => en_str,
                };
                if std::ptr::eq(ftl_str, en_str) {
                    (en_bundle, None)
                } else {
                    let lang_id: LanguageIdentifier =
                        other.parse().unwrap_or_else(|_| "en".parse().unwrap());
                    (load_bundle(ftl_str, lang_id), Some(en_bundle))
                }
            }
        };

        let tr_val = |key: &str| tr(&bundle, fallback.as_ref(), key);

        Self {
            waiting_for_tap_skip: tr_val("pam-waiting-tap-skip"),
            waiting_for_tap: tr_val("pam-waiting-tap"),
            cannot_connect: tr_val("pam-cannot-connect"),
            communication_error: tr_val("pam-communication-error"),
            connection_lost: tr_val("pam-connection-lost"),
            timed_out: tr_val("pam-timed-out"),
            skipped: tr_val("pam-skipped"),
            auth_successful: tr_val("pam-auth-successful"),
            auth_denied: tr_val("pam-auth-denied"),
            error_prefix: tr_val("pam-error-prefix"),
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
