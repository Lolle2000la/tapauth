//! TapAuth PAM module.
//!
//! Linux PAM authentication module that enables phone-tap-based authentication.
//! Integrates with the system authentication stack to provide passwordless login
//! via paired Android devices.
//!
//! ## PAM Integration
//!
//! Provides all required PAM entry points:
//! - `pam_sm_authenticate`: Core authentication via BLE/UDP to paired devices
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

mod auth_client;
mod pam_logic;
mod pam_sys;
mod transport;

pub use auth_client::*;
pub use transport::*;

use std::os::raw::c_int;

/// PAM service module entry point for authentication
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_logic::authenticate(pamh)
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
