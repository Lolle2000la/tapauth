mod auth_client;
mod ble_advertiser;
mod pam_logic;

pub use auth_client::*;
pub use ble_advertiser::*;

use pam::{constants::{PamFlag, PamResultCode}, module::PamHandle};
use std::ffi::CStr;

/// PAM service module entry point for authentication
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: &mut PamHandle,
    flags: PamFlag,
    args: Vec<&CStr>,
) -> PamResultCode {
    pam_logic::authenticate(pamh, args, flags)
}

/// PAM service module entry point for account management
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: &mut PamHandle,
    _flags: PamFlag,
    _args: Vec<&CStr>,
) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}

/// PAM service module entry point for session management
#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    _pamh: &mut PamHandle,
    _flags: PamFlag,
    _args: Vec<&CStr>,
) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}

/// PAM service module entry point for closing session
#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: &mut PamHandle,
    _flags: PamFlag,
    _args: Vec<&CStr>,
) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}

/// PAM service module entry point for password change
#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: &mut PamHandle,
    _flags: PamFlag,
    _args: Vec<&CStr>,
) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}
