//! Logging configuration for client-pam
//!
//! Logs go to journald (via `tracing-journald`).  When running outside
//! systemd, a stderr layer is added for terminal visibility.  Under
//! systemd the stderr layer is skipped because systemd already forwards
//! stderr to the journal, avoiding duplicate entries.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stderr log level (default: warn)

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

fn make_stderr_layer() -> impl Layer<tracing_subscriber::Registry> {
    let filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));
    tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(filter)
}

pub fn init_logging() {
    if let Ok(journald_layer) = tracing_journald::layer() {
        if std::env::var("JOURNAL_STREAM").is_ok() {
            let _ = tracing_subscriber::registry()
                .with(journald_layer)
                .try_init();
        } else {
            let _ = tracing_subscriber::registry()
                .with(make_stderr_layer())
                .with(journald_layer)
                .try_init();
        }
    } else {
        let _ = tracing_subscriber::registry()
            .with(make_stderr_layer())
            .try_init();
    }
}
