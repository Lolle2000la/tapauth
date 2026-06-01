//! Logging configuration for client-pam
//!
//! Logs are written to both stderr and journald.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stderr log level (default: warn, only warnings and errors shown)
//! - `TAPAUTH_JOURNALD_LOG_LEVEL`: Controls journald log level (default: info)

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize logging for PAM module
///
/// Sets up dual logging:
/// - stderr: warn level by default (only warnings/errors), configurable via TAPAUTH_LOG_LEVEL
/// - journald: info level by default, configurable via TAPAUTH_JOURNALD_LOG_LEVEL
pub fn init_logging() {
    let stderr_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(stderr_filter);

    let journald_filter = std::env::var("TAPAUTH_JOURNALD_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    if let Ok(journald_layer) = tracing_journald::layer() {
        let journald_layer = journald_layer.with_filter(journald_filter);

        let _ = tracing_subscriber::registry()
            .with(stderr_layer)
            .with(journald_layer)
            .try_init();
    } else {
        let _ = tracing_subscriber::registry().with(stderr_layer).try_init();
    }
}
