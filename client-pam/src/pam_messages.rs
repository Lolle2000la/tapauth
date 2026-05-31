//! Localized user-facing messages for the PAM module.
//!
//! Uses the same Fluent (FTL) localization engine as the GUI, matching its
//! locale detection (LC_ALL → LC_MESSAGES → LANG) and embedding FTL strings
//! at compile time via `include_str!()`.  All keys are resolved at construction
//! time so accessors return `&str` with zero runtime cost.
//!
//! When a key is missing in a non-English locale, the English bundle is used
//! as a fallback.  Fluent parse / resource errors are logged and recovered
//! from gracefully — PAM modules must never panic.

use fluent::{FluentBundle, FluentResource};
use std::sync::Arc;
use unic_langid::LanguageIdentifier;

mod locales_codegen {
    include!(concat!(env!("OUT_DIR"), "/locales_codegen.rs"));
}

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

fn load_bundle(ftl_str: &str, lang_id: LanguageIdentifier) -> FluentBundle<Arc<FluentResource>> {
    let res = match FluentResource::try_new(ftl_str.to_string()) {
        Ok(r) => r,
        Err((r, errs)) => {
            for err in errs {
                tracing::error!("Fluent parse error in PAM FTL: {:?}", err);
            }
            r
        }
    };
    let mut bundle = FluentBundle::new(vec![lang_id]);
    if let Err(errs) = bundle.add_resource(Arc::new(res)) {
        for err in errs {
            tracing::error!("Failed to add FTL resource to PAM bundle: {:?}", err);
        }
    }
    bundle.set_use_isolating(false);
    bundle
}

impl PamMessages {
    pub fn new(locale: &str) -> Self {
        let en_ftl = include_str!("../locales/en/main.ftl");
        let en_lang: LanguageIdentifier = "en".parse().unwrap_or_default();
        let en_bundle = load_bundle(en_ftl, en_lang);

        let (bundle, fallback) = if locale == "en" {
            (en_bundle, None)
        } else if let Some(ftl) = locales_codegen::load_ftl(locale) {
            let lang_id: LanguageIdentifier = locale.parse().unwrap_or_default();
            (load_bundle(ftl, lang_id), Some(en_bundle))
        } else {
            (en_bundle, None)
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
        format!("{} {}", self.error_prefix, detail)
    }
}

/// Detect locale from POSIX environment variables.
/// Mirrors the GUI's `detect_locale()` logic.
pub fn detect_locale() -> &'static str {
    shared::l10n::detect_locale(locales_codegen::AVAILABLE_LOCALES)
}

/// Resolve the effective locale for a user, respecting the GUI's persisted
/// preference if available.
fn resolve_locale(username: &str) -> String {
    if let Some(loc) = load_user_locale(username) {
        return loc;
    }
    detect_locale().to_string()
}

fn load_user_locale(username: &str) -> Option<String> {
    let home = nix::unistd::User::from_name(username)
        .ok()
        .flatten()
        .map(|u| u.dir.to_path_buf())?;
    let path = home.join(".config/tapauth/locale");
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| locales_codegen::AVAILABLE_LOCALES.contains(&s.as_str()))
}

/// Load PAM messages for the given username, respecting any persisted
/// locale preference from ~/.config/tapauth/locale.
pub fn load_for_user(username: &str) -> PamMessages {
    PamMessages::new(&resolve_locale(username))
}
