//! Logging configuration for client-config-gui
//!
//! Logs are written to both stdout and a rotating file.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stdout log level (default: warn, only warnings and errors shown)
//! - `TAPAUTH_FILE_LOG_LEVEL`: Controls file log level (default: info)
//!
//! Log files are stored in `/var/log/tapauth/tapauth-config.log` with daily rotation
//! when running as root.  Unprivileged runs fall back to `/tmp/tapauth-logs`.

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

fn create_safe_tmp_dir(path: &std::path::Path) -> bool {
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

/// Initialize logging for tapauth-config GUI
///
/// Sets up dual logging when possible:
/// - stdout: warn level by default (only warnings/errors), configurable via TAPAUTH_LOG_LEVEL
/// - file: info level by default, configurable via TAPAUTH_FILE_LOG_LEVEL
///
/// File logging requires `/var/log/tapauth` to be writable.  If it's not,
/// the `/tmp/tapauth-logs` fallback is tried with symlink+owner validation.
/// If neither is usable, logs go to stdout only.
pub fn init_logging() {
    let log_dir = resolve_log_dir();

    let stdout_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout)
        .with_filter(stdout_filter);

    let subscriber = tracing_subscriber::registry().with(stdout_layer);

    if let Some(ref dir) = log_dir {
        let file_appender = tracing_appender::rolling::daily(dir, "tapauth-config.log");
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
        subscriber.with(file_layer).init();
        tracing::info!(
            "Logging initialized: stdout (warn+) + file (info+) at {}/tapauth-config.log",
            dir.display()
        );
    } else {
        subscriber.init();
        eprintln!("tapauth-config: no writable log directory, using stdout only");
    }
}

fn resolve_log_dir() -> Option<std::path::PathBuf> {
    let primary = std::path::PathBuf::from("/var/log/tapauth");
    if is_dir_writable(&primary) {
        return Some(primary);
    }

    if !primary.exists() && create_safe_tmp_dir(&primary) && is_dir_writable(&primary) {
        return Some(primary);
    }

    let fallback = std::path::PathBuf::from("/tmp/tapauth-logs");
    if create_safe_tmp_dir(&fallback) && is_dir_writable(&fallback) {
        return Some(fallback);
    }

    eprintln!(
        "tapauth-config: /var/log/tapauth not writable and /tmp/tapauth-logs is unsafe, \
         using stdout only"
    );
    None
}
