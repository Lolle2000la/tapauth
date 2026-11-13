//! TapAuth PAM module: libpam loads this cdylib to authenticate a Linux login
//! through a paired phone, which it reaches through tapauthd's Unix socket.
//!
//! It never returns `PAM_IGNORE`: on a `required` stack that code is `ignore`, so
//! a following `optional pam_permit` would grant a failed authentication.
//! `Outcome::into_pam` is the only conversion from a verdict to a code — the ABI
//! stubs and `guard`'s panic arm are exempt by name, and
//! `source_guards::only_outcome_rs_returns_pam_constants` asserts both halves.
//! Behaviour and the per-host conversation rules are in
//! `docs/design-documents/pam-conversation-policy.md`.
//!
//! # Module map
//!
//! One line per file under `client-pam/src`; `source_guards.rs` is test-only.
//!
//! | Module | Owns |
//! | :--- | :--- |
//! | `lib.rs` | the `pam_sm_*` ABI stubs, and `guard`, which turns a panic into `PAM_AUTH_ERR` |
//! | `pam_logic.rs` | the order of one call: capture, classify, config, identity/conversation/messages, reuse lookup, plan, transaction, `into_pam` |
//! | `pam_logic/wiring.rs` | the production effects that order binds: the `/dev/tty` probe, connect, send, the fresh-connection cancel |
//! | `context.rs` | the caller facts classification reads, captured once: service name, process identity, GDM reauth flag |
//! | `policy.rs` | the classification taxonomy and the first-match engine; `policy/table.rs` is the rule table as data, `policy/refine.rs` the config-dependent second phase |
//! | `plan.rs` | deadline, announcement and terminal use for one conversation |
//! | `transaction.rs` | one request's lifecycle: the armed→concluded state machine, the driver, the host I/O with its single emission site |
//! | `conclusion_cache.rs` | the 500 ms verdict-reuse record, its gates, the `atfork` child handler |
//! | `mechanism.rs` | the three conversation bodies (threaded, sequential, pre-collected) around the exit type they share |
//! | `outcome.rs` | the verdict taxonomy and `into_pam` |
//! | `config.rs` | the module's slice of `/etc/tapauth/config.toml`: timeouts, refused services |
//! | `ipc_client.rs` | length-prefixed protobuf IPC over the daemon socket |
//! | `pam_sys.rs` | the Linux-PAM FFI bindings and their safe wrappers |
//! | `pam_messages.rs` | localized user-facing messages |
//! | `logging.rs` | `tracing` initialisation: journald, stderr fallback |
//! | `source_guards.rs` | the test-only source scans named below |
//!
//! # Dependency rule
//!
//! Imports run one way, from the ABI stubs down to the leaves. `pam_logic.rs`
//! is the only module that may name every layer below it; `transaction.rs`
//! drives `mechanism.rs`, `plan.rs`, `conclusion_cache.rs`, `outcome.rs` and
//! the leaves; `policy.rs`, `plan.rs` and `outcome.rs` build on `context.rs` and
//! on leaves; `config.rs`, `ipc_client.rs`, `pam_sys.rs`, `pam_messages.rs` and
//! `logging.rs` name nothing else in the crate.
//!
//! Two references run back up and are type-only: `mechanism/*` names `Armed` and
//! `HostIo` from `transaction`, and `conclusion_cache` names `Concluded` and
//! `Via`; neither calls into `transaction`, so the call direction stays one-way.
//!
//! Two invariants hold the design together:
//!
//! * **Only `outcome.rs` produces a `PAM_*` code.** `Outcome::into_pam` is the
//!   single conversion; `guard`'s panic arm and the constant ABI stubs are
//!   exempt by name, and `PAM_AUTHTOK` is an argument, not a code.
//!   `source_guards::only_outcome_rs_returns_pam_constants` asserts both
//!   halves.
//! * **Only `conclusion_cache.rs` touches the stored conclusion.** No other
//!   module names the record, its lock or its guard;
//!   `source_guards::cache_owner_is_local` asserts it, and the record's
//!   `pub(crate)` surface hands out values, never the lock or the stored struct.
//!
//! `source_guards.rs` also pins the single call sites: the service name is read
//! only in `context.rs`, and `policy::refine` is called only from `pam_logic.rs`.
//!
//! # Adding a rule or a flow
//!
//! A host is a predicate, a rule-table row and an audit record in
//! `policy/table.rs`, plus a corpus row in `client-pam/tests/fixtures/callers.csv`.
//! The doc comment on `RULES` is the checklist and the authority for the full
//! edit list: read it there rather than from a copy here. A flow is a
//! `Conversation` variant, a `plan.rs` row per terminal shape, a body under
//! `mechanism/` with its dispatch in `transaction/run.rs`, and an entry in the
//! production list in `source_guards.rs`.
//!
//! The one step nothing fails loudly on is the rule id's `ALL` list together
//! with the `rules_are_process_disjoint` key set: a rule missing from both `ALL`
//! and `RULES` stays green. The audit arm fails to compile, a stale evidence
//! citation trips `evidence_citations_resolve`, and a corpus row that disagrees
//! with the table trips `corpus_characterises_the_decision_table`.
//!
//! Tests are an inline `mod tests` at the bottom of the file they cover, or a
//! `src/**/tests/` submodule for a corpus, and the crate-wide scans live in
//! `source_guards.rs`. There is no `tests/*.rs` suite, because the crate is
//! cdylib-only.
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

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    guard(|| pam_logic::authenticate(pamh))
}

/// Required by the PAM specification; this module has no credentials to manage.
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const std::os::raw::c_char,
) -> c_int {
    pam_sys::PAM_SUCCESS
}

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
