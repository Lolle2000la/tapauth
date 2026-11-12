//! TapAuth PAM module: libpam loads this cdylib to authenticate a Linux login
//! through a paired phone, which it reaches through tapauthd's Unix socket.
//!
//! The ABI is the six symbols libpam resolves. The five non-authentication ones
//! are no-ops:
//!
//! - `pam_sm_authenticate` — the only entry point that reaches a verdict
//! - `pam_sm_setcred`, `pam_sm_acct_mgmt`, `pam_sm_open_session`,
//!   `pam_sm_close_session`, `pam_sm_chauthtok` — answer `PAM_SUCCESS`
//!
//! `Outcome::into_pam` is the only conversion from a verdict to a code; the ABI
//! sites are exempt by name (those five stubs and `guard`'s panic arm), and
//! `source_guards::only_outcome_rs_returns_pam_constants` asserts both halves.
//!
//! It never returns `PAM_IGNORE`: on a `required` stack that code is `ignore`,
//! so a following `optional pam_permit` would grant a failed authentication.
//! Behaviour and the per-host conversation rules are in
//! `docs/design-documents/pam-conversation-policy.md`.
//!
//! Test placement: unit tests are an inline `mod tests` at the bottom of the file
//! they cover — including `policy`'s decision corpus, which reads the private
//! `RuleId`/`RULES` there — while `pam_logic` and `transaction` keep a corpus in a
//! `src/**/tests/` submodule, and the crate-wide scans live in `source_guards.rs`.
//! There is no `tests/*.rs` integration suite, because the crate is cdylib-only;
//! the walker test asserts which files carry `#[cfg(test)]`.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod conclusion_cache;
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

use std::os::raw::c_int;
use std::panic::catch_unwind;

// PAM entry points must never unwind into the host process. The logging call is
// guarded too: it must not panic on the path that is already unwinding.
fn guard<F>(f: F) -> c_int
where
    F: FnOnce() -> c_int + std::panic::UnwindSafe,
{
    match catch_unwind(f) {
        Ok(code) => code,
        Err(_) => {
            let _ = catch_unwind(|| {
                tracing::error!(
                    "TapAuth: panic caught in the PAM entry point; returning PAM_AUTH_ERR"
                );
            });
            pam_sys::PAM_AUTH_ERR
        }
    }
}

/// PAM service module entry point for authentication.
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    guard(|| pam_logic::authenticate(pamh))
}

/// PAM service module entry point for credentials (required by the PAM
/// specification; this module has none to manage).
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for account management.
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for session management.
#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for closing a session.
#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

/// PAM service module entry point for password change.
#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod source_guards;

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
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
