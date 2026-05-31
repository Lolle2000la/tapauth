use fluent::{FluentArgs, FluentBundle, FluentResource};
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;
use unic_langid::LanguageIdentifier;

mod locales_codegen {
    include!(concat!(env!("OUT_DIR"), "/locales_codegen.rs"));
}
pub use locales_codegen::locale_display_name;

pub const AVAILABLE_LOCALES: &[&str] = locales_codegen::AVAILABLE_LOCALES;

#[derive(Clone)]
pub struct L10n {
    locale: String,
    bundle: Rc<FluentBundle<Arc<FluentResource>>>,
}

// Manual implementation to allow Screen structs to derive Debug seamlessly
impl fmt::Debug for L10n {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L10n").finish_non_exhaustive()
    }
}

impl L10n {
    pub fn new(locale: &str) -> Self {
        let ftl_str =
            locales_codegen::load_ftl(locale).unwrap_or(include_str!("../locales/en/main.ftl"));

        let res = FluentResource::try_new(ftl_str.to_string())
            .expect("Failed to parse static FTL string.");

        let lang_id: LanguageIdentifier = locale.parse().unwrap_or_else(|_| "en".parse().unwrap());
        let mut bundle = FluentBundle::new(vec![lang_id]);

        bundle
            .add_resource(Arc::new(res))
            .expect("Failed to add FTL resource to bundle.");

        // Disables Unicode isolation marks (prevents rendering unexpected control characters in simple UIs)
        bundle.set_use_isolating(false);

        Self {
            locale: locale.to_string(),
            bundle: Rc::new(bundle),
        }
    }

    pub fn locale(&self) -> &str {
        &self.locale
    }

    pub fn tr(&self, key: &str) -> String {
        if let Some(msg) = self.bundle.get_message(key) {
            if let Some(pattern) = msg.value() {
                let mut errors = vec![];
                let value = self.bundle.format_pattern(pattern, None, &mut errors);
                return value.to_string();
            }
        }
        format!("??{}??", key)
    }

    pub fn tr_args(&self, key: &str, args: &[(&str, &str)]) -> String {
        if let Some(msg) = self.bundle.get_message(key) {
            if let Some(pattern) = msg.value() {
                let mut fluent_args = FluentArgs::new();
                for (k, v) in args {
                    if let Ok(num) = v.parse::<i64>() {
                        fluent_args.set(*k, num);
                    } else if let Ok(float) = v.parse::<f64>() {
                        fluent_args.set(*k, float);
                    } else {
                        fluent_args.set(*k, *v);
                    }
                }
                let mut errors = vec![];
                let value = self
                    .bundle
                    .format_pattern(pattern, Some(&fluent_args), &mut errors);
                return value.to_string();
            }
        }
        format!("??{}??", key)
    }
}

/// Detect system locale respecting POSIX priority rules (LC_ALL > LC_MESSAGES > LANG)
pub fn detect_locale() -> &'static str {
    shared::l10n::detect_locale(AVAILABLE_LOCALES)
}

fn is_valid_locale(code: &str) -> bool {
    AVAILABLE_LOCALES.contains(&code)
}

/// Resolve the effective locale with this precedence:
/// 1. CLI override (--locale flag, survives pkexec)
/// 2. Per-user persisted preference (~/.config/tapauth/locale)
/// 3. System locale detection (LANG/LC_ALL/LC_MESSAGES)
pub fn resolve_locale(cli_override: Option<&str>, username: &str) -> String {
    if let Some(loc) = cli_override {
        if is_valid_locale(loc) {
            return loc.to_string();
        }
    }
    if let Some(loc) = load_user_locale(username) {
        return loc;
    }
    detect_locale().to_string()
}

/// Save the user's locale preference to ~/.config/tapauth/locale
pub fn save_user_locale(username: &str, locale: &str) {
    let path = user_locale_path(username);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, locale.as_bytes()) {
        tracing::warn!("Failed to persist locale preference for user {username}: {e}");
    }
}

/// Load the user's persisted locale preference, if any
fn load_user_locale(username: &str) -> Option<String> {
    let path = user_locale_path(username);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| is_valid_locale(s))
}

fn user_locale_path(username: &str) -> std::path::PathBuf {
    let home = nix::unistd::User::from_name(username)
        .ok()
        .flatten()
        .map(|u| u.dir.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    home.join(".config/tapauth/locale")
}
