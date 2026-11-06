//! TapAuth PAM module.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
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
//! Every path produces one `outcome::Outcome`, and `Outcome::to_pam` is the only
//! conversion from a verdict to a code — `authenticate` maps the two arms of the
//! transaction's result (`Finished::Concluded` and `Finished::Unrecorded`), and
//! nothing else in the crate produces a `PAM_*` value except the six constant
//! ABI sites named below:
//!
//! - `PAM_SUCCESS` — this call's daemon response was a phone tap, or a duplicate
//!   answered from this process's 500 ms reuse record (a replay, which emits no
//!   message)
//! - `PAM_PERM_DENIED` — the phone explicitly denied the request
//! - `PAM_AUTHINFO_UNAVAIL` — the service could not be consulted: no paired
//!   device, the user skipped, the daemon timed out or was unreachable, the
//!   conversation could not be driven, a display-manager login or a remote
//!   caller was skipped, or a pre-collected host's own token was handed on
//! - `PAM_AUTH_ERR` — a processing failure: the daemon reported an internal
//!   error, the conversation lookup failed, the request id could not be
//!   generated, or a local resource (pipe, thread) could not be created
//! - `PAM_USER_UNKNOWN` — the username lookup failed
//!
//! The ABI surface is the exception, and it is exempt by name: `pam_sm_setcred`,
//! `pam_sm_acct_mgmt`, `pam_sm_open_session`, `pam_sm_close_session` and
//! `pam_sm_chauthtok` answer a non-authentication entry point with
//! `PAM_SUCCESS`, and `guard`'s panic arm answers `PAM_AUTH_ERR`; none of them
//! converts a verdict or sees an `Outcome`.
//! (`only_outcome_rs_returns_pam_constants` asserts both halves.)
//!
//! It never returns `PAM_IGNORE`, which protects the
//! `required` stack shape: there `PAM_IGNORE` is explicitly `ignore` while
//! `PAM_AUTHINFO_UNAVAIL` is `bad`. On a `sufficient` line both codes are
//! `ignore`, so a following `optional pam_permit` grants either way and only
//! the stack's configuration prevents it. Password fallback still works on that
//! `sufficient` line, whose default action for any non-success is `ignore`.
//!
//! ## Requirements
//!
//! Must run as root to access `/etc/tapauth` configuration files.

mod config;
mod context;
mod ipc_client;
mod logging;
mod mechanism;
mod outcome;
mod pam_logic;
mod pam_messages;
mod pam_sys;
mod plan;
mod policy;
mod transaction;

pub use ipc_client::*;

use std::os::raw::c_int;
use std::panic::catch_unwind;
// Internal panic guard: returns PAM_AUTH_ERR if the inner closure panics.
fn guard<F>(f: F) -> c_int
where
    F: FnOnce() -> c_int + std::panic::UnwindSafe,
{
    match catch_unwind(f) {
        Ok(code) => code,
        Err(_) => {
            let _ = catch_unwind(|| {
                tracing::error!(
                    "TapAuth PAM: panic caught in guarded section; returning PAM_AUTH_ERR"
                );
            });
            pam_sys::PAM_AUTH_ERR
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
    fn guard_returns_auth_err_on_panic() {
        let code = guard(|| panic!("boom"));
        assert_eq!(code, crate::pam_sys::PAM_AUTH_ERR);
    }
}
