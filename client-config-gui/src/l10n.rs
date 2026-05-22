use fluent::{FluentArgs, FluentBundle, FluentResource};
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;
use unic_langid::LanguageIdentifier;

#[derive(Clone)]
pub struct L10n {
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
        let ftl_str = match locale {
            "de" => include_str!("../locales/de/main.ftl"),
            "ja" => include_str!("../locales/ja/main.ftl"),
            _ => include_str!("../locales/en/main.ftl"),
        };

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
            bundle: Rc::new(bundle),
        }
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
                    fluent_args.set(*k, *v);
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
