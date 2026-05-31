//! Shared locale detection utilities.

/// Detect locale from POSIX environment variables.
///
/// Checks `LC_ALL`, `LC_MESSAGES`, and `LANG` in that order,
/// returning a `&str` locale code for the first match.
///
/// Uses two-pass matching so regional variants (e.g. "en-us") are preferred
/// over shorter prefixes (e.g. "en").
///
/// `available_locales` should be the list of supported locale codes discovered
/// at build time.
pub fn detect_locale(available_locales: &[&'static str]) -> &'static str {
    for var in &["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            let val_lower = val.to_ascii_lowercase();
            let val_norm = val_lower.replace('_', "-");

            // Pass 1: exact match (e.g. "en-us" matches "en-us")
            for &lang in available_locales {
                let lang_norm = lang.to_ascii_lowercase().replace('_', "-");
                if val_norm == lang_norm {
                    return lang;
                }
            }

            // Pass 2: prefix match (e.g. "en-us.utf-8" matches "en")
            for &lang in available_locales {
                let lang_norm = lang.to_ascii_lowercase().replace('_', "-");
                if val_norm
                    .strip_prefix(&lang_norm)
                    .is_some_and(|rest| rest.starts_with(['-', '.', '@']))
                {
                    return lang;
                }
            }
        }
    }
    "en"
}
