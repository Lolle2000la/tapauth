//! Compile-time localized user-facing messages for the PAM module.
//!
//! The PAM module runs as a lightweight cdylib loaded by the PAM stack.
//! To avoid pulling in Fluent or doing file I/O, all translated strings
//! are embedded as Rust constants. Locale detection uses the standard
//! POSIX environment variables (LC_ALL, LC_MESSAGES, LANG).

pub struct PamMessages {
    pub waiting_for_tap_skip: &'static str,
    pub waiting_for_tap: &'static str,
    pub cannot_connect: &'static str,
    pub communication_error: &'static str,
    pub connection_lost: &'static str,
    pub timed_out: &'static str,
    pub skipped: &'static str,
    pub auth_successful: &'static str,
    pub auth_denied: &'static str,
    pub error_prefix: &'static str,
}

impl PamMessages {
    pub fn error(&self, detail: &str) -> String {
        format!("{}{}", self.error_prefix, detail)
    }
}

mod strings {
    use super::PamMessages;

    pub const EN: PamMessages = PamMessages {
        waiting_for_tap_skip: "TapAuth: Waiting for phone tap (press Enter to skip)...",
        waiting_for_tap: "TapAuth: Waiting for phone tap...",
        cannot_connect: "TapAuth: Cannot connect to daemon, trying password...",
        communication_error: "TapAuth: Communication error, trying password...",
        connection_lost: "TapAuth: Connection lost, trying password...",
        timed_out: "TapAuth: Timed out, trying password...",
        skipped: "TapAuth: Skipped, trying password...",
        auth_successful: "TapAuth: Authentication successful!",
        auth_denied: "TapAuth: Authentication denied by server",
        error_prefix: "TapAuth: Error - ",
    };

    pub const DE: PamMessages = PamMessages {
        waiting_for_tap_skip: "TapAuth: Warte auf Tippen am Telefon (Enter zum Überspringen)...",
        waiting_for_tap: "TapAuth: Warte auf Tippen am Telefon...",
        cannot_connect: "TapAuth: Keine Verbindung zum Daemon, versuche Passwort...",
        communication_error: "TapAuth: Kommunikationsfehler, versuche Passwort...",
        connection_lost: "TapAuth: Verbindung verloren, versuche Passwort...",
        timed_out: "TapAuth: Zeitüberschreitung, versuche Passwort...",
        skipped: "TapAuth: Übersprungen, versuche Passwort...",
        auth_successful: "TapAuth: Authentifizierung erfolgreich!",
        auth_denied: "TapAuth: Authentifizierung vom Server abgelehnt",
        error_prefix: "TapAuth: Fehler - ",
    };

    pub const JA: PamMessages = PamMessages {
        waiting_for_tap_skip: "TapAuth: スマートフォンのタップを待機中（Enterでスキップ）...",
        waiting_for_tap: "TapAuth: スマートフォンのタップを待機中...",
        cannot_connect: "TapAuth: デーモンに接続できません、パスワードを試します...",
        communication_error: "TapAuth: 通信エラー、パスワードを試します...",
        connection_lost: "TapAuth: 接続が失われました、パスワードを試します...",
        timed_out: "TapAuth: タイムアウト、パスワードを試します...",
        skipped: "TapAuth: スキップしました、パスワードを試します...",
        auth_successful: "TapAuth: 認証成功！",
        auth_denied: "TapAuth: サーバーによって認証が拒否されました",
        error_prefix: "TapAuth: エラー - ",
    };
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

/// Load the PAM messages for the detected locale.
/// Returns a reference to compile-time embedded strings — zero allocation.
pub fn load() -> &'static PamMessages {
    match detect_locale() {
        "de" => &strings::DE,
        "ja" => &strings::JA,
        _ => &strings::EN,
    }
}
