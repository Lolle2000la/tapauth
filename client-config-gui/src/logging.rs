//! Logging configuration for client-config-gui
//!
//! Logs are written to both stdout (for terminal visibility) and journald.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stdout log level (default: warn, only warnings and errors shown)
//! - `TAPAUTH_JOURNALD_LOG_LEVEL`: Controls journald log level (default: info)

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize logging for tapauth-config GUI
///
/// Sets up dual logging:
/// - stdout: warn level by default (only warnings/errors), configurable via TAPAUTH_LOG_LEVEL
/// - journald: info level by default, configurable via TAPAUTH_JOURNALD_LOG_LEVEL
pub fn init_logging() {
    let stdout_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout)
        .with_filter(stdout_filter);

    let journald_filter = std::env::var("TAPAUTH_JOURNALD_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    if let Ok(journald_layer) = tracing_journald::layer() {
        let journald_layer = journald_layer.with_filter(journald_filter);

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(journald_layer)
            .init();
    } else {
        tracing_subscriber::registry().with(stdout_layer).init();
    }
}
