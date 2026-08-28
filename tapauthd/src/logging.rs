//! Logging configuration for tapauthd
//!
//! Logs go to journald (via `tracing-journald`).  When running outside
//! systemd (e.g. manual `cargo run`), a stdout layer is added for
//! terminal visibility.  Under systemd the stdout layer is skipped
//! because systemd already forwards stdout to the journal, avoiding
//! duplicate entries.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stdout log level (default: info)
//! - `TAPAUTH_JOURNALD_LOG_LEVEL`: Controls journald log level (default: info)

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

fn make_stdout_layer() -> impl Layer<tracing_subscriber::Registry> {
    let filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout)
        .with_filter(filter)
}

pub fn init_logging() {
    let stdout_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    if std::env::var("JOURNAL_STREAM").is_ok() {
        let journald_level =
            std::env::var("TAPAUTH_JOURNALD_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        if let Ok(journald_layer) = tracing_journald::layer() {
            let filter =
                EnvFilter::try_new(&journald_level).unwrap_or_else(|_| EnvFilter::new("info"));
            tracing_subscriber::registry()
                .with(journald_layer.with_filter(filter))
                .init();
            return;
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(stdout_filter)
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();
}
