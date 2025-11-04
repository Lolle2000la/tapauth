//! Logging configuration for client-pam
//!
//! Logs are written to both stderr and a rotating file.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stderr log level (default: warn, only warnings and errors shown)
//! - `TAPAUTH_FILE_LOG_LEVEL`: Controls file log level (default: info)
//!
//! Log files are stored in `/var/log/tapauth/tapauth-pam.log` with daily rotation,
//! keeping the last 7 days of logs. The log directory will fall back to a user-specific
//! directory if /var/log/tapauth is not accessible (for non-root users).

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize logging for PAM module
///
/// Sets up dual logging:
/// - stderr: warn level by default (only warnings/errors), configurable via TAPAUTH_LOG_LEVEL
/// - file: info level by default, configurable via TAPAUTH_FILE_LOG_LEVEL
///
/// The log directory varies based on user permissions:
/// - Root: /var/log/tapauth/tapauth-pam.log
/// - Non-root: $HOME/.local/state/tapauth/tapauth-pam.log or /tmp/tapauth-logs-$USER/tapauth-pam.log
pub fn init_logging() {
    // Determine log directory based on user permissions
    let log_dir = if nix::unistd::geteuid().is_root() {
        // Running as root - use system log directory
        let dir = std::path::PathBuf::from("/var/log/tapauth");
        if dir.exists() || std::fs::create_dir_all(&dir).is_ok() {
            dir
        } else {
            // Fall back to /tmp if we can't create /var/log/tapauth
            let fallback = std::path::PathBuf::from("/tmp/tapauth-logs");
            let _ = std::fs::create_dir_all(&fallback);
            fallback
        }
    } else {
        // Running as regular user - use user-specific directory
        if let Ok(home) = std::env::var("HOME") {
            let dir = std::path::PathBuf::from(home).join(".local/state/tapauth");
            if dir.exists() || std::fs::create_dir_all(&dir).is_ok() {
                dir
            } else {
                // Fall back to /tmp with username
                let username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
                let fallback = std::path::PathBuf::from(format!("/tmp/tapauth-logs-{}", username));
                let _ = std::fs::create_dir_all(&fallback);
                fallback
            }
        } else {
            // No HOME - use /tmp
            let username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
            let fallback = std::path::PathBuf::from(format!("/tmp/tapauth-logs-{}", username));
            let _ = std::fs::create_dir_all(&fallback);
            fallback
        }
    };

    // Create rotating file appender (daily rotation, keep 7 days)
    let file_appender = tracing_appender::rolling::daily(&log_dir, "tapauth-pam.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Stderr layer - warn level by default (only show warnings/errors), configurable via TAPAUTH_LOG_LEVEL
    let stderr_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(stderr_filter);

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
    let _ = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .try_init();

    // Keep the guard alive for the lifetime of the program
    std::mem::forget(_guard);

    tracing::info!(
        "PAM logging initialized: stderr (warn+) + file (info+) at {}/tapauth-pam.log",
        log_dir.display()
    );
}
