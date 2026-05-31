//! Shared locale detection utilities.

/// Detect locale from POSIX environment variables.
///
/// Checks `LC_ALL`, `LC_MESSAGES`, and `LANG` in that order,
/// returning a `&str` locale code for the first match.
///
/// `available_locales` should be the list of supported locale codes discovered
/// at build time.
pub fn detect_locale(available_locales: &[&'static str]) -> &'static str {
    for var in &["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            let val_lower = val.to_ascii_lowercase();
            for &lang in available_locales {
                if locale_matches(&val_lower, lang) {
                    return lang;
                }
            }
        }
    }
    "en"
}

fn locale_matches(val: &str, lang: &str) -> bool {
    let lang_norm = lang.to_ascii_lowercase().replace('_', "-");
    let val_norm = val.replace('_', "-");
    val_norm == lang_norm
        || val_norm
            .strip_prefix(&lang_norm)
            .is_some_and(|rest| rest.starts_with(['-', '.', '@']))
}
