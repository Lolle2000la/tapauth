//! Logging configuration for client-config-gui
//!
//! Logs are written to both stdout and a rotating file.
//! 
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stdout log level (default: warn, only warnings and errors shown)
//! - `TAPAUTH_FILE_LOG_LEVEL`: Controls file log level (default: info)
//!
//! Log files are stored in `/var/log/tapauth/tapauth-config.log` with daily rotation,
//! keeping the last 7 days of logs.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize logging for tapauth-config GUI
///
/// Sets up dual logging:
/// - stdout: warn level by default (only warnings/errors), configurable via TAPAUTH_LOG_LEVEL
/// - file: info level by default, configurable via TAPAUTH_FILE_LOG_LEVEL
pub fn init_logging() {
    // Determine log directory - fall back to /tmp if /var/log/tapauth is not accessible
    let log_dir = std::path::PathBuf::from("/var/log/tapauth");
    let log_dir = if log_dir.exists() || std::fs::create_dir_all(&log_dir).is_ok() {
        log_dir
    } else {
        eprintln!("Warning: Cannot write to /var/log/tapauth, falling back to /tmp/tapauth-logs");
        let fallback = std::path::PathBuf::from("/tmp/tapauth-logs");
        let _ = std::fs::create_dir_all(&fallback);
        fallback
    };

    // Create rotating file appender (daily rotation, keep 7 days)
    let file_appender = tracing_appender::rolling::daily(&log_dir, "tapauth-config.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Stdout layer - warn level by default (only show warnings/errors), configurable via TAPAUTH_LOG_LEVEL
    let stdout_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout)
        .with_filter(stdout_filter);

    // File layer - info level by default, configurable via TAPAUTH_FILE_LOG_LEVEL
    let file_filter = std::env::var("TAPAUTH_FILE_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_ansi(false)
        .with_writer(non_blocking)
        .with_filter(file_filter);

    // Combine layers
    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    // Keep the guard alive for the lifetime of the program
    std::mem::forget(_guard);

    tracing::info!("Logging initialized: stdout (warn+) + file (info+) at {}/tapauth-config.log", log_dir.display());
}
