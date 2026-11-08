//! PAM authentication logic for TapAuth: the orchestration policy.
//!
//! Implements the core authentication flow that integrates with Linux PAM.
//! Supports both terminal (with skip detection via Enter key) and GUI contexts
//! (e.g., Polkit dialogs).
//!
//! ## Layout
//!
//! This file is the orchestration *policy*. [`authenticate`] is the entry point
//! and the one place a [`Finished`] becomes a `PAM_*` code; [`orchestrate`] fixes
//! the order of the effects (classify → config → refine → username →
//! conversation → messages → `transaction::run`); [`OrchestrationIo`] is the
//! injectable seam that makes that order observable. The `wiring` submodule
//! holds the platform values behind the transaction's `Effects`;
//! [`OrchestrationIo::production`] builds the PAM-side seam beside it.
//!
//! ## Flow
//!
//! 1. Capture the caller facts and classify them against the rule table
//! 2. For a participant, load the config and refine the classification with the
//!    configured refused service names
//! 3. Resolve the username, the PAM conversation and the messages
//! 4. Hand the participation to `transaction::run`, which sends one IPC request
//!    to `tapauthd` and waits for the daemon's answer
//! 5. Map the resulting verdict to a `PAM_*` code: `PAM_SUCCESS` on a phone tap,
//!    `PAM_PERM_DENIED` on an explicit denial, `PAM_AUTHINFO_UNAVAIL` when the
//!    service could not be consulted and `PAM_AUTH_ERR` on a processing failure,
//!    never `PAM_IGNORE` (Linux-PAM records no failure for it, so a later
//!    `optional` module voting success, e.g. `pam_permit`, would grant the stack)
//!
//! ## Threading
//!
//! The module sends one IPC request and waits for it on the calling thread; it
//! starts no runtime and owns no daemon transport. The only thread it ever
//! creates is the threaded mechanism's password worker. The sequential mechanism
//! polls the daemon socket on the calling thread (and `/dev/tty` when the plan
//! gave it a terminal) and never drives the conversation.
//!
//! ## Return-code mapping
//!
//! | Transition | Code |
//! | :--- | :--- |
//! | Phone approved the request | `PAM_SUCCESS` |
//! | Phone explicitly denied | `PAM_PERM_DENIED` |
//! | Timeout, dialog dismissed, IPC error, no paired device, skip, DM bypass | `PAM_AUTHINFO_UNAVAIL` |
//! | Daemon reported an internal error, or a local failure (conversation lookup, RNG, pipe/thread spawn) | `PAM_AUTH_ERR` |
//! | Username lookup failed | `PAM_USER_UNKNOWN` |

use crate::config::PamConfig;
use crate::context::{CallerContext, ServiceName};
use crate::ipc_client::IpcResponseReader;
use crate::logging;
use crate::outcome::Outcome;
use crate::pam_messages;
use crate::pam_sys;
use crate::policy;
use crate::transaction::{Effects, Finished, HostIo};
use std::os::raw::c_int;
use std::time::Instant;
use wiring::{cancel_on_fresh_connection, connect, probe_tty, send_authenticate_request};

mod wiring;

/// Main PAM authentication entry point.
///
/// ## Returns
///
/// The orchestration returns a [`Finished`], whose two arms both carry an
/// [`Outcome`]; `Outcome::into_pam` is the only conversion, and the `match` below
/// is its only caller. Which reasons reach which code is the table in
/// `Outcome::into_pam` / `Outcome::notice`, not a per-call decision here:
///
/// - `PAM_SUCCESS`: this call's daemon response was a phone tap, or a duplicate
///   answered from this process's 500 ms reuse record (a replay, which records
///   nothing and shows nothing)
/// - `PAM_PERM_DENIED`: The user explicitly denied the request on the phone
/// - `PAM_AUTHINFO_UNAVAIL`: The authentication service could not be consulted —
///   no paired devices, the user skipped, the daemon is unreachable, the
///   attempt timed out, a display-manager login or a remote caller was skipped,
///   or a pre-collected host's token was handed on. On a `sufficient` line
///   (which expands to
///   `[success=done new_authtok_reqd=done default=ignore]`) this still falls
///   through to the next module, so password fallback is preserved
/// - `PAM_AUTH_ERR`: This attempt failed while being processed — the daemon
///   reported an internal error, the conversation lookup failed, the request id
///   could not be generated, or a local resource could not be created
/// - `PAM_USER_UNKNOWN`: Failed to retrieve username from PAM
///
/// `PAM_IGNORE` is deliberately never returned.  Linux-PAM records no failure
/// for it, so a later `optional` module that votes success (e.g. `pam_permit`)
/// turns the whole stack into `PAM_SUCCESS` — an authentication bypass.  That is
/// a `required`-line hazard, and it is the shape this protects: there
/// `PAM_IGNORE` is explicitly `ignore` while `PAM_AUTHINFO_UNAVAIL` is `bad`.
/// On a `sufficient` line both codes are `ignore` and a following
/// `optional pam_permit` grants either way, so there the stack's own
/// configuration, not the return code, is what prevents the grant.
pub fn authenticate(pamh: *mut pam_sys::PamHandle) -> c_int {
    logging::init_logging();
    tracing::info!("TapAuth PAM module called (custom bindings)");

    // The caller facts are read once, here, and every consumer reads the
    // captured values — the policy, the log line in `capture`, the verdict
    // cache's key and the skip's decision. No second resolution exists.
    let ctx = unsafe { CallerContext::capture(pamh) };
    // The orchestration returns the verdict, never a code. This is the one
    // place a `PAM_*` value is produced from it: `into_pam` is exhaustive, so an
    // arm cannot be forgotten and a code cannot travel beside the verdict. A
    // conclusion is recorded here — after the body returned, which is what
    // anchors the 500 ms reuse window to *this module's return* — and `record`
    // hands the verdict back so it becomes a code exactly once. Neither arm
    // emits: `run` already emitted its outcome's one notice.
    //
    // The outside world this call asks for, as one value: the `/dev/tty` probe,
    // the nonblocking daemon dial, the authenticate request and the
    // fresh-connection cancel — all four bound from `wiring`, so this file names
    // none of the platform calls. Each function is bound to a local first so the
    // struct borrows a named place rather than a temporary.
    let mut probe = probe_tty;
    let mut connect = connect;
    let mut send = send_authenticate_request;
    let cancel = cancel_on_fresh_connection;
    let mut effects = Effects {
        probe_tty: &mut probe,
        connect: &mut connect,
        send: &mut send,
        cancel: &cancel,
    };
    match orchestrate(pamh, &ctx, &OrchestrationIo::production(), &mut effects) {
        Finished::Concluded(concluded) => {
            crate::conclusion_cache::record(concluded, Instant::now()).into_pam()
        }
        Finished::Unrecorded(outcome) => outcome.into_pam(),
    }
}

/// The four side-effecting calls `classify` must precede, injected so they can
/// be counted without a PAM handle.
///
/// `classify_before_side_effects` drives `orchestrate` with this table replaced
/// by counting wrappers and asserts every counter reads zero on a `Skip`. The
/// context is passed in already captured, so the test can hand `orchestrate` a
/// `CallerContext::from_parts` directly.
pub(crate) struct OrchestrationIo {
    pub load_config: fn() -> PamConfig,
    pub get_user: unsafe fn(*mut pam_sys::PamHandle) -> Result<String, c_int>,
    pub new_conversation:
        unsafe fn(*mut pam_sys::PamHandle) -> Result<pam_sys::PamConversation<'static>, c_int>,
    pub load_messages: fn(&str) -> pam_messages::PamMessages,
    /// The pre-collected handoff's token read. Injected here as well as on
    /// `HostIo` so a test that drives `orchestrate` end to end can count the
    /// read, which is the only observable the handoff has.
    pub read_authtok: pam_sys::ReadAuthtok,
}

impl OrchestrationIo {
    /// The real functions. The only constructor production uses.
    pub(crate) fn production() -> Self {
        OrchestrationIo {
            load_config: PamConfig::load,
            get_user: pam_sys::get_user,
            new_conversation: pam_sys::PamConversation::new,
            load_messages: pam_messages::load_for_user,
            read_authtok: pam_sys::read_authtok_for_handoff,
        }
    }
}

/// Run one authentication: capture the caller facts, classify, resolve the
/// inputs a participation needs, and hand the transaction to
/// [`crate::transaction::run`].
///
/// The body decides and acts; recording is the caller's (`authenticate`), so the
/// 500 ms reuse window stays anchored to *this module's return* rather than to
/// the moment the transaction concluded.
///
/// The order is load-bearing and is asserted by `classify_before_side_effects`:
/// `classify` runs **before** `PamConfig::load`, `get_user`,
/// `PamConversation::new` and `PamMessages::load_for_user`, so a `Skip` (a
/// display-manager login, a remote caller) pays none of them. `HostIo` is built
/// after those four calls and borrows what they produced, so it cannot exist on
/// a skip path.
///
/// `effects` is the transaction's outside world — the `/dev/tty` probe, the
/// daemon dial, the request on the wire and the cancel, the same seam
/// [`Armed::open`](crate::transaction::Armed::open) has. Production passes
/// [`connect`](wiring::connect), [`send_authenticate_request`](wiring::send_authenticate_request)
/// and [`cancel_on_fresh_connection`](wiring::cancel_on_fresh_connection) (built
/// by [`authenticate`]), and a test passes counting closures or failures, so
/// "the skip never reaches the daemon", "a connect failure records nothing" and
/// "a timeout cancels nothing" are assertions rather than promises.
fn orchestrate<T: IpcResponseReader>(
    pamh: *mut pam_sys::PamHandle,
    ctx: &CallerContext,
    io: &OrchestrationIo,
    effects: &mut Effects<'_, T>,
) -> Finished {
    // The conversation policy is decided from the caller facts `capture` read,
    // and it is decided *first*: a `Skip` returns before the config read, the
    // username lookup, the conversation and the messages, which is the order
    // the display-manager bypass has always had. `classify_before_side_effects`
    // counts those four calls, because nothing in the types stops a later edit
    // from moving the decision below them.
    let (_rule, classification) = policy::classify(ctx);

    // The built-in skips — R1's service names and R2's display managers — return
    // here, before the config read. A skip is a static policy decision about the
    // caller, not a conclusion about credentials: it never reaches
    // `Armed::open`, never touches the recorded conclusion, and must not clobber
    // the last real one. `skip_finished` is the one return for either phase's
    // skip.
    if let policy::Classification::Skip(skip) = &classification {
        return skip_finished(ctx, *skip);
    }

    // Load configuration for timeouts
    let config = (io.load_config)();
    tracing::debug!(
        "PAM operation timeout: {}s",
        config.pam_operation_timeout_secs
    );

    // The second decision phase. `classify` sees only the built-in refused
    // names, so a deployment that renames OpenSSH's `PAMServiceName` arrives
    // here as a participating call; `policy::refine` is the one entry point for
    // the configured half of R1. It runs immediately after the config read and
    // before the username lookup, the conversation, the messages and the
    // transaction, and it can only add a skip: the participation it returns
    // unchanged is the one `classify` produced, mechanism and deadline
    // included.
    let participation = match policy::refine(
        classification,
        ctx.service(),
        &config.effective_refused_services(),
    ) {
        policy::Classification::Participate(participation) => participation,
        policy::Classification::Skip(skip) => return skip_finished(ctx, skip),
    };

    let username = unsafe {
        match (io.get_user)(pamh) {
            Ok(user) => {
                tracing::info!("Got username from PAM: {}", user);
                user
            }
            Err(code) => {
                tracing::error!("Failed to get username, PAM error code: {}", code);
                return Finished::Unrecorded(Outcome::UserUnknown);
            }
        }
    };

    tracing::info!("TapAuth: Authenticating user: {}", username);

    let pam_conv = unsafe {
        match (io.new_conversation)(pamh) {
            Ok(conv) => conv,
            Err(e) => {
                tracing::error!("Failed to get PAM conversation function: {}", e);
                return Finished::Unrecorded(Outcome::Error(
                    crate::outcome::ErrorReason::ConversationLookup,
                ));
            }
        }
    };

    // No explicit root check here; shared config enforces file ownership/permissions.

    let msgs = (io.load_messages)(&username);

    let mut host = HostIo::new(pamh, &pam_conv, &msgs, io.read_authtok);
    crate::transaction::run(
        ctx.service(),
        &username,
        &participation,
        &mut host,
        &config,
        effects,
    )
}

/// The one return for a skip, whichever of the two decision phases produced it.
///
/// `Skip` is a static decision about the caller, not a conclusion about
/// credentials: it returns before `Armed::open`, so it is never recorded, and
/// `Outcome::from_skip` is the only mapping of a `SkipPolicy` to a verdict. The
/// two log lines are the ones the module has always written for R1 and R2.
fn skip_finished(ctx: &CallerContext, skip: policy::SkipPolicy) -> Finished {
    let service = ctx.service().map(ServiceName::original).unwrap_or_default();
    match skip {
        policy::SkipPolicy::KeyringNeedsAuthtok => tracing::info!(
            "TapAuth: Service '{}' is a primary display manager. \
             Skipping to avoid breaking keyring auto-unlock.",
            service
        ),
        policy::SkipPolicy::RemoteAuthentication => tracing::info!(
            "TapAuth: Service '{}' authenticates a remote caller. \
             Skipping: this module does not take part in remote authentication.",
            service
        ),
    }
    Finished::Unrecorded(Outcome::from_skip(skip))
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests;
