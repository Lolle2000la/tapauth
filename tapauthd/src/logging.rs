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

fn is_dir_writable(path: &std::path::Path) -> bool {
    use nix::unistd::{getegid, geteuid};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    if !meta.is_dir() {
        return false;
    }

    let mode = meta.permissions().mode();
    let euid = geteuid().as_raw();
    let egid = getegid().as_raw();

    // Check write+execute permission (both needed to create files in a directory)
    let has_rwx = if euid == 0 || euid == meta.uid() {
        (mode & 0o300) == 0o300
    } else {
        // Check supplementary groups
        let in_group = egid == 0
            || egid == meta.gid()
            || nix::unistd::getgroups()
                .unwrap_or_default()
                .iter()
                .any(|g| g.as_raw() == meta.gid());
        if in_group {
            (mode & 0o030) == 0o030
        } else {
            (mode & 0o003) == 0o003
        }
    };

    has_rwx
}

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

    // Try file logging only if /var/log/tapauth is writable by the running user.
    // Otherwise fall back to stdout-only (common in test/container environments).
    let log_dir = std::path::PathBuf::from("/var/log/tapauth");
    let log_dir = if is_dir_writable(&log_dir) {
        log_dir
    } else if !log_dir.exists() {
        if std::fs::create_dir_all(&log_dir).is_ok() && is_dir_writable(&log_dir) {
            log_dir
        } else {
            let fallback = std::path::PathBuf::from("/tmp/tapauthd-logs");
            let _ = std::fs::create_dir_all(&fallback);
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o700));
            }
            fallback
        }
    } else {
        let fallback = std::path::PathBuf::from("/tmp/tapauthd-logs");
        let _ = std::fs::create_dir_all(&fallback);
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o700));
        }
        fallback
    };

    match std::panic::catch_unwind(|| {
        let file_appender = tracing_appender::rolling::daily(&log_dir, "tapauthd.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let file_filter = std::env::var("TAPAUTH_FILE_LOG_LEVEL")
            .ok()
            .and_then(|level| EnvFilter::try_new(&level).ok())
            .unwrap_or_else(|| EnvFilter::new("info"));
        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_ansi(false)
            .with_writer(non_blocking)
            .with_filter(file_filter);
        std::mem::forget(guard);
        (file_layer, log_dir)
    }) {
        Ok((file_layer, log_dir)) => {
            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(file_layer)
                .init();
            tracing::info!(
                "Logging initialized: stdout + file at {}/tapauthd.log",
                log_dir.display()
            );
        }
        Err(_) => {
            tracing_subscriber::registry().with(stdout_layer).init();
            tracing::warn!("Logging initialized: stdout only (file logging unavailable)");
        }
    }
}
