//! The on-disk posture of a secret: where the state directory is, and how a file in
//! it is written and read.
//!
//! The four file and directory primitives below are re-exported from the parent module
//! at their original visibility. Everything else here is reachable only through
//! [`super::ClientConfigManager`]: the 0700 directory and 0600 file modes, the
//! `tapauthd:tapauthd` chown, and the owner and mode a read accepts. What a config *is*
//! lives in `super`.

use super::{ConfigError, CONFIG_DIR};
use nix::unistd::{geteuid, User};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Get active state/config directory (allows override via TAPAUTH_STATE_DIR in development/testing)
pub fn get_config_dir() -> PathBuf {
    #[cfg(any(feature = "dev-state-override", test))]
    if let Ok(dir) = std::env::var("TAPAUTH_STATE_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(CONFIG_DIR)
}

/// Resolve the system user "tapauthd" to its UID (cached best-effort).
fn tapauthd_uid() -> Option<u32> {
    // If NSS lookup fails or user does not exist yet (during install), we return None
    // and default to accepting only root-owned files. Callers must handle None.
    User::from_name("tapauthd")
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
}

/// Whether the effective UID is the tapauthd user.
fn is_euid_tapauthd() -> bool {
    match tapauthd_uid() {
        Some(uid) => geteuid().as_raw() == uid,
        None => false,
    }
}

/// Whether the effective UID is privileged for writes (tapauthd, root, or custom TAPAUTH_STATE_DIR)
fn is_euid_privileged_for_writes() -> bool {
    #[cfg(any(feature = "dev-state-override", test))]
    if std::env::var("TAPAUTH_STATE_DIR").is_ok() {
        return true;
    }
    is_euid_tapauthd() || nix::unistd::geteuid().as_raw() == 0
}

/// Chown a path to tapauthd:tapauthd when running as root
/// If tapauthd user doesn't exist (e.g., during development), skip chown silently
fn chown_to_tapauthd(path: &Path) -> Result<(), ConfigError> {
    #[cfg(any(feature = "dev-state-override", test))]
    if std::env::var("TAPAUTH_STATE_DIR").is_ok() {
        return Ok(());
    }
    // Only attempt when running as root
    if nix::unistd::geteuid().as_raw() != 0 {
        return Ok(());
    }
    let user = match User::from_name("tapauthd").ok().flatten() {
        Some(u) => u,
        None => {
            // tapauthd user doesn't exist (development mode or pre-install) - skip chown
            tracing::debug!("tapauthd user not found, skipping chown (development mode)");
            return Ok(());
        }
    };
    let uid = user.uid.as_raw();
    let gid = user.gid.as_raw();
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

/// Ensure configuration directory exists with strict permissions (700)
pub fn ensure_secure_directory(path: &Path) -> Result<(), ConfigError> {
    // Only tapauthd or root may create/modify; if root, we will chown to tapauthd
    if !is_euid_privileged_for_writes() {
        return Err(ConfigError::InsufficientPermissions);
    }

    if !path.exists() {
        fs::create_dir_all(path)?;
    }

    // Set permissions to 700 (rwx for owner only)
    let metadata = fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;

    // Ensure ownership is tapauthd:tapauthd when invoked as root
    if !is_euid_tapauthd() {
        chown_to_tapauthd(path)?;
    }

    Ok(())
}

/// Write data to a file with strict owner-only permissions (600)
pub fn write_secure_file(path: &Path, data: &[u8]) -> Result<(), ConfigError> {
    // Only tapauthd or root may write; if root, we will chown to tapauthd
    if !is_euid_privileged_for_writes() {
        tracing::error!("write_secure_file: insufficient permissions");
        return Err(ConfigError::InsufficientPermissions);
    }

    tracing::debug!(
        "write_secure_file: writing {} bytes to {:?}",
        data.len(),
        path
    );
    fs::write(path, data)?;
    tracing::debug!("write_secure_file: write complete");

    // Set permissions to 600 (rw for owner only)
    let metadata = fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    tracing::debug!("write_secure_file: permissions set to 0600");

    // Ensure ownership is tapauthd:tapauthd when invoked as root
    if !is_euid_tapauthd() {
        tracing::debug!("write_secure_file: attempting chown to tapauthd");
        chown_to_tapauthd(path)?;
        tracing::debug!("write_secure_file: chown complete");
    }

    Ok(())
}

/// Read data from a secure file
pub fn read_secure_file(path: &Path) -> Result<Vec<u8>, ConfigError> {
    // Verify file permissions
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // Check ownership: accept root:root, tapauthd:tapauthd, or current user when TAPAUTH_STATE_DIR is active
    let owner_uid = metadata.uid();
    let current_euid = nix::unistd::geteuid().as_raw();
    let tap_uid = tapauthd_uid();
    #[cfg(any(feature = "dev-state-override", test))]
    let is_dev_dir = std::env::var("TAPAUTH_STATE_DIR").is_ok();
    #[cfg(not(any(feature = "dev-state-override", test)))]
    let is_dev_dir = false;

    let owner_ok = owner_uid == 0
        || tap_uid.map(|u| owner_uid == u).unwrap_or(false)
        || (is_dev_dir && owner_uid == current_euid);
    if !owner_ok {
        return Err(ConfigError::InsufficientPermissions);
    }

    // Check group/other permissions
    let mode = permissions.mode() & 0o777;

    // For simplicity and safety, enforce 0600 or 0400 for all files (keys and config)
    if mode != 0o600 && mode != 0o400 {
        return Err(ConfigError::InsufficientPermissions);
    }

    Ok(fs::read(path)?)
}
