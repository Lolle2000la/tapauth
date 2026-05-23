//! Logging configuration for tapauthd
//!
//! Logs are written to both stdout (for journalctl) and a rotating file.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stdout log level (default: info, can be overridden to debug, trace, etc.)
//! - `TAPAUTH_FILE_LOG_LEVEL`: Controls file log level (default: info)
//!
//! Log files are stored in `/var/log/tapauth/tapauthd.log` with daily rotation,
//! keeping the last 7 days of logs.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize logging for tapauthd
///
/// Sets up dual logging:
/// - stdout: info level by default (for journalctl), configurable via TAPAUTH_LOG_LEVEL
/// - file: info level by default, configurable via TAPAUTH_FILE_LOG_LEVEL
pub fn init_logging() {
    // Stdout layer - info level by default, configurable via TAPAUTH_LOG_LEVEL
    let stdout_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout)
        .with_filter(stdout_filter);

    // Try to set up file logging, but don't panic if it fails
    // Use catch_unwind because tracing_appender::rolling::daily can panic
    let file_layer_result =
        std::panic::catch_unwind(|| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
            // Determine log directory - fall back to /tmp if /var/log/tapauth is not accessible
            let log_dir = std::path::PathBuf::from("/var/log/tapauth");
            let log_dir = if log_dir.exists()
                && std::fs::metadata(&log_dir)
                    .map(|m| !m.permissions().readonly())
                    .unwrap_or(false)
            {
                log_dir
            } else {
                if !log_dir.exists() {
                    std::fs::create_dir_all(&log_dir)?;
                }
                // Test if we can write to it by creating a test file
                let test_file = log_dir.join(".write_test");
                std::fs::write(&test_file, b"test")?;
                std::fs::remove_file(test_file)?;
                log_dir
            };

            // Create rotating file appender (daily rotation, keep 7 days)
            let file_appender = tracing_appender::rolling::daily(&log_dir, "tapauthd.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

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

            // Keep the guard alive for the lifetime of the program
            std::mem::forget(guard);

            Ok((file_layer, log_dir))
        })
        .ok()
        .and_then(|r| r.ok());

    // Combine layers - file layer is optional
    match file_layer_result {
        Some((file_layer, log_dir)) => {
            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(file_layer)
                .init();
            tracing::info!(
                "Logging initialized: stdout + file at {}/tapauthd.log",
                log_dir.display()
            );
        }
        None => {
            tracing_subscriber::registry().with(stdout_layer).init();
            tracing::warn!("Logging initialized: stdout only (file logging unavailable)");
        }
    }
}
