mod auth_client;
mod ble_advertiser;
mod pam_logic;
mod pam_sys;

pub use auth_client::*;
pub use ble_advertiser::*;

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
