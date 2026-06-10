//! TapAuth PAM module.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(clashing_extern_declarations)]
//!
//! Linux PAM authentication module that enables phone-tap-based authentication.
//! Integrates with the system authentication stack to provide passwordless login
//! via paired Android devices.
//!
//! ## PAM Integration
//!
//! Provides all required PAM entry points:
//! - `pam_sm_authenticate`: Core authentication via BLE/UDP to paired devices
//! - `pam_sm_setcred`: Credential management (no-op, returns success)
//! - `pam_sm_acct_mgmt`: Account management (no-op, returns success)
//! - `pam_sm_open_session`/`pam_sm_close_session`: Session management (no-ops)
//! - `pam_sm_chauthtok`: Password change (no-op)
//!
//! ## Behavior
//!
//! Returns `PAM_IGNORE` (not `PAM_AUTH_ERR`) on failure to allow password fallback.
//! Only returns `PAM_SUCCESS` when phone tap authentication succeeds.
//!
//! ## Requirements
//!
//! Must run as root to access `/etc/tapauth` configuration files.

mod config;
mod error;
mod ipc_client;
mod logging;
mod pam_logic;
mod pam_messages;
mod pam_sys;

pub use error::PamError;
pub use ipc_client::*;

use std::os::raw::c_int;
use std::panic::catch_unwind;
// Internal panic guard: returns PAM_IGNORE if the inner closure panics.
fn guard<F>(f: F) -> c_int
where
    F: FnOnce() -> c_int + std::panic::UnwindSafe,
{
    match catch_unwind(f) {
        Ok(code) => code,
        Err(_) => {
            let _ = catch_unwind(|| {
                tracing::error!(
                    "TapAuth PAM: panic caught in guarded section; returning PAM_IGNORE"
                );
            });
            pam_sys::PAM_IGNORE
        }
    }
}

/// PAM service module entry point for authentication
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    // Guard against panics: PAM modules must never unwind into the host process
    guard(|| pam_logic::authenticate(pamh))
}

/// PAM service module entry point for establishing/deleting user credentials
/// Required by PAM specification for authentication modules.
/// We don't manage credentials ourselves, so this is a no-op.
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for account management
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for session management
#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for closing session
#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for password change
#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn guard_returns_ignore_on_panic() {
        let code = guard(|| panic!("boom"));
        assert_eq!(code, crate::pam_sys::PAM_IGNORE);
    }
}
