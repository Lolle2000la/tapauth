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

use nix::unistd::{getegid, geteuid};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

fn is_dir_writable(path: &std::path::Path) -> bool {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    if meta.file_type().is_symlink() {
        return false;
    }

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
/// Sets up dual logging when possible:
/// - stdout: info level by default (for journalctl), configurable via TAPAUTH_LOG_LEVEL
/// - file: info level by default, configurable via TAPAUTH_FILE_LOG_LEVEL
///
/// File logging requires `/var/log/tapauth` to be writable (or safely creatable).
/// If neither that nor the `/tmp/tapauthd-logs` fallback (symlink+owner checked) is
/// usable, logs go to stdout only.
pub fn init_logging() {
    let stdout_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout)
        .with_filter(stdout_filter);

    let log_dir = resolve_log_dir();

    let subscriber = tracing_subscriber::registry().with(stdout_layer);

    if let Some(ref dir) = log_dir {
        subscriber
            .with({
                let file_appender = tracing_appender::rolling::daily(dir, "tapauthd.log");
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
                file_layer
            })
            .init();
    } else {
        subscriber.init();
    }
}

fn resolve_log_dir() -> Option<std::path::PathBuf> {
    let primary = std::path::PathBuf::from("/var/log/tapauth");

    if is_dir_writable(&primary) {
        return Some(primary);
    }

    if !primary.exists() {
        if create_safe_dir(&primary) && is_dir_writable(&primary) {
            return Some(primary);
        }
    } else {
        // Primary exists but not writable — try fallback immediately
    }

    let fallback = std::path::PathBuf::from("/tmp/tapauthd-logs");
    if create_safe_dir(&fallback) && is_dir_writable(&fallback) {
        return Some(fallback);
    }

    eprintln!(
        "tapauthd: Cannot write to /var/log/tapauth and /tmp/tapauthd-logs is unsafe, \
         logging to stdout only"
    );
    None
}

fn create_safe_dir(path: &std::path::Path) -> bool {
    if path.exists() {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return false,
        };
        if meta.file_type().is_symlink() {
            return false;
        }
        if meta.is_dir() && meta.uid() == geteuid().as_raw() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
            return is_dir_writable(path);
        }
    }
    if std::fs::create_dir_all(path).is_err() {
        return false;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).is_ok()
}
