//! Privilege elevation utilities for the TapAuth configuration GUI.
//!
//! Provides root privilege checking and elevation via `pkexec` or `sudo`,
//! preserving environment variables needed for GUI display (Wayland/X11).

use nix::unistd::{setgid, setuid, Gid, Uid, User};
use std::env;
use std::process::Command;

/// Check if the current process is running as root.
///
/// ## Returns
///
/// `true` if the effective user ID is 0 (root), `false` otherwise.
///
/// ## Safety
///
/// Calls `libc::geteuid()` which is safe to call from any context.
/// The function has no preconditions and does not modify any state.
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Get the original user who invoked the program (before any elevation)
pub fn get_original_user() -> String {
    // Check environment variable we set during elevation
    if let Ok(user) = env::var("TAPAUTH_ORIGINAL_USER") {
        return user;
    }

    // Check if running via pkexec (preserves PKEXEC_UID)
    if let Ok(uid_str) = env::var("PKEXEC_UID") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            if let Ok(username) = get_username_from_uid(uid) {
                return username;
            }
        }
    }

    // Check SUDO_USER (when run with sudo)
    if let Ok(user) = env::var("SUDO_USER") {
        return user;
    }

    // Fallback to current USER
    env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

/// Public wrapper to get original user for other modules
/// This is the recommended way to get the username in the application
pub fn get_username() -> String {
    get_original_user()
}

/// Get username from UID using libc.
///
/// ## Safety
///
/// Calls `libc::getpwuid()` which:
/// - Returns a pointer to a static `passwd` struct or NULL on failure
/// - The returned pointer is valid until the next NSS call (not thread-safe)
/// - The `pw_name` field points to a null-terminated C string
/// - Must not be freed by the caller
///
/// This function immediately copies the username string, so the transient
/// pointer lifetime is safe.
fn get_username_from_uid(uid: u32) -> Result<String, ()> {
    unsafe {
        let passwd = libc::getpwuid(uid);
        if passwd.is_null() {
            return Err(());
        }

        let name_ptr = (*passwd).pw_name;
        if name_ptr.is_null() {
            return Err(());
        }

        let c_str = std::ffi::CStr::from_ptr(name_ptr);
        Ok(c_str.to_string_lossy().into_owned())
    }
}

/// Attempt to elevate privileges using pkexec or sudo.
///
/// Preserves environment variables needed for GUI display (X11/Wayland).
/// This function does not return if elevation succeeds.
///
/// ## Panics
///
/// Never panics. Exits the process with status code 1 if elevation fails.
pub fn attempt_privilege_elevation(original_user: &str) -> ! {
    tracing::info!(
        "Attempting privilege escalation for user: {}",
        original_user
    );

    let current_exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("ERROR: Failed to get current executable path: {}", e);
            eprintln!("Please run with: sudo tapauth-config");
            std::process::exit(1);
        }
    };

    let mut env_vars = vec![("TAPAUTH_ORIGINAL_USER", original_user.to_string())];

    if let Ok(display) = env::var("DISPLAY") {
        env_vars.push(("DISPLAY", display));
    }
    if let Ok(wayland_display) = env::var("WAYLAND_DISPLAY") {
        env_vars.push(("WAYLAND_DISPLAY", wayland_display));
    }
    if let Ok(wayland_socket) = env::var("WAYLAND_SOCKET") {
        env_vars.push(("WAYLAND_SOCKET", wayland_socket));
    }
    if let Ok(xauthority) = env::var("XAUTHORITY") {
        env_vars.push(("XAUTHORITY", xauthority));
    }
    if let Ok(xdg_runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        env_vars.push(("XDG_RUNTIME_DIR", xdg_runtime_dir));
    }
    if let Ok(dbus_session) = env::var("DBUS_SESSION_BUS_ADDRESS") {
        env_vars.push(("DBUS_SESSION_BUS_ADDRESS", dbus_session));
    }

    tracing::debug!("Trying pkexec elevation...");
    let mut pkexec_cmd = Command::new("pkexec");

    for (key, value) in &env_vars {
        pkexec_cmd.env(key, value);
    }

    let pkexec_result = pkexec_cmd
        .arg("env")
        .args(env_vars.iter().map(|(k, v)| format!("{}={}", k, v)))
        .arg(&current_exe)
        .args(env::args().skip(1))
        .status();

    match pkexec_result {
        Ok(status) => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            tracing::warn!("pkexec failed: {}", e);
        }
    }

    tracing::debug!("Trying sudo elevation...");
    let mut sudo_cmd = Command::new("sudo");
    sudo_cmd.arg("-E");

    for (key, value) in &env_vars {
        sudo_cmd.env(key, value);
    }

    let sudo_result = sudo_cmd
        .arg(&current_exe)
        .args(env::args().skip(1))
        .status();

    match sudo_result {
        Ok(status) => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            tracing::warn!("sudo failed: {}", e);
        }
    }

    eprintln!("\n╔════════════════════════════════════════════════════════════╗");
    eprintln!("║  ERROR: This application requires root privileges         ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
    eprintln!();
    eprintln!("TapAuth Configuration needs root access to manage system-wide");
    eprintln!("authentication pairings.");
    eprintln!();
    eprintln!("Please run with one of:");
    eprintln!("  • pkexec tapauth-config");
    eprintln!("  • sudo -E tapauth-config");
    eprintln!();

    std::process::exit(1);
}

/// Drop privileges from root to the specified target system user.
///
/// Returns Ok(()) if privilege drop succeeded or if already running as the target user.
/// Returns Err(()) if the target user cannot be resolved or setuid/setgid fails.
pub fn drop_privileges_to_user(target_user: &str) -> Result<(), ()> {
    // If we're not root, do nothing
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(());
    }

    // Resolve target user via NSS
    let user = User::from_name(target_user).map_err(|_| ())?.ok_or(())?;
    let target_uid = Uid::from_raw(user.uid.as_raw());
    let target_gid = Gid::from_raw(user.gid.as_raw());

    // Set group first, then user
    setgid(target_gid).map_err(|e| {
        tracing::error!(
            "Failed to setgid to {} (gid {}): {}",
            target_user,
            target_gid.as_raw(),
            e
        );
    })?;
    setuid(target_uid).map_err(|e| {
        tracing::error!(
            "Failed to setuid to {} (uid {}): {}",
            target_user,
            target_uid.as_raw(),
            e
        );
    })?;

    Ok(())
}
