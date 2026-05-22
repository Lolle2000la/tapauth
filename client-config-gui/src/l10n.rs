use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct L10n {
    messages: HashMap<String, String>,
}

impl L10n {
    pub fn new(locale: &str) -> Self {
        let ftl_str = match locale {
            "de" => include_str!("../locales/de/main.ftl"),
            "ja" => include_str!("../locales/ja/main.ftl"),
            _ => include_str!("../locales/en/main.ftl"),
        };

        let mut messages = HashMap::new();
        for line in ftl_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim().to_string();
                let value = line[eq_pos + 1..].trim().to_string();
                messages.insert(key, value);
            }
        }

        Self { messages }
    }

    pub fn tr(&self, key: &str) -> String {
        self.messages
            .get(key)
            .cloned()
            .unwrap_or_else(|| format!("??{}??", key))
    }

    pub fn tr_args(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut result = self.tr(key);
        for (name, value) in args {
            result = result.replace(&format!("{{${}}}", name), value);
        }
        result
    }
}

/// Detect system locale from environment variables (LANG, LC_ALL)
pub fn detect_locale() -> &'static str {
    for var in &["LANG", "LC_ALL", "LC_MESSAGES"] {
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
