//! The orchestration policy: the order of the effects between PAM and the transaction, and
//! [`authenticate`], the single place a verdict becomes a PAM code — by calling
//! `Outcome::into_pam`.
//!
//! [`orchestrate`] fixes that order; which verdict maps to which code is `Outcome::into_pam`'s
//! table in `outcome.rs`, not a decision taken here. It sends at most one IPC request — none on
//! a handoff or a reuse hit — and waits for it on the calling thread. The sequential mechanism
//! never drives the conversation: on those hosts a reply posted from another thread deadlocks
//! their event loop.

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

/// PAM's authenticate entry point: capture the caller facts, orchestrate, and convert the one
/// resulting verdict to a code.
///
/// The verdict→code table is `Outcome::into_pam` in `outcome.rs`, not a decision taken here.
/// Never returns `PAM_IGNORE` — on a `required` line it is `ignore` while
/// `PAM_AUTHINFO_UNAVAIL` is `bad`, so a later `optional pam_permit` would grant the whole
/// stack.
pub fn authenticate(pamh: *mut pam_sys::PamHandle) -> c_int {
    logging::init_logging();
    tracing::info!("TapAuth: pam_sm_authenticate called");

    // The caller facts are read once; every consumer reads these captured values, so no second
    // resolution exists.
    let ctx = unsafe { CallerContext::capture(pamh) };
    // The conclusion is recorded here, after `into_pam`'s inputs are fixed, which anchors the
    // 500 ms reuse window to *this module's return* (see `conclusion_cache`); `record` hands the
    // verdict back so it becomes a code exactly once. Neither arm emits: `run` already emitted
    // its outcome's one notice.
    //
    // The four platform calls are bound to locals first so the struct borrows a named place
    // rather than a temporary; `Effects` is what lets the transaction run without a PAM handle.
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

/// The side-effecting calls `orchestrate` makes, injected so an end-to-end test can count them
/// without a PAM handle; `orchestrate`'s doc says which of them a skip must never reach.
pub(crate) struct OrchestrationIo {
    pub load_config: fn() -> PamConfig,
    pub get_user: unsafe fn(*mut pam_sys::PamHandle) -> Result<String, c_int>,
    pub new_conversation:
        unsafe fn(*mut pam_sys::PamHandle) -> Result<pam_sys::PamConversation<'static>, c_int>,
    pub load_messages: fn(&str) -> pam_messages::PamMessages,
    /// The handoff's token read. Also on `HostIo`, which is where the handoff actually reads;
    /// injected here so a test can count it, since the read is the handoff's only observable.
    pub read_authtok: pam_sys::ReadAuthtok,
}

impl OrchestrationIo {
    /// The real functions.
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

/// Run one authentication for an already captured context: classify, resolve what a
/// participation needs, and hand the transaction to [`crate::transaction::run`].
///
/// The order is load-bearing: `classify` runs **before** `PamConfig::load`, `get_user`,
/// `PamConversation::new` and `PamMessages::load_for_user`, so a `Skip` pays none of them, and
/// `HostIo` — built after those four — cannot exist on a skip path. Recording is the caller's
/// job, which keeps the 500 ms reuse window anchored to the module's return (`conclusion_cache`).
fn orchestrate<T: IpcResponseReader>(
    pamh: *mut pam_sys::PamHandle,
    ctx: &CallerContext,
    io: &OrchestrationIo,
    effects: &mut Effects<'_, T>,
) -> Finished {
    // The policy is decided *first*: a `Skip` returns before the config read, the username
    // lookup, the conversation and the messages. `classify_before_side_effects` counts those
    // four, because nothing in the types stops a later edit from moving the decision below them.
    // The id it also returns is a fixture label; production reads only the classification.
    let (_rule, classification) = policy::classify(ctx);

    // A skip is a static decision about the caller, not a conclusion about credentials: it never
    // reaches `Armed::open`, never touches the recorded conclusion, and must not clobber the last
    // real one.
    if let policy::Classification::Skip(skip) = &classification {
        return skip_finished(ctx, *skip);
    }

    let config = (io.load_config)();
    tracing::debug!(
        "PAM operation timeout: {}s",
        config.pam_operation_timeout_secs
    );

    // The second decision phase. `classify` sees only the built-in refused names, so a deployment
    // that renames OpenSSH's `PAMServiceName` arrives here as a participating call. It runs right
    // after the config read and can only add a skip; the participation it returns unchanged is
    // `classify`'s own, mechanism and deadline included.
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

    let msgs = (io.load_messages)(&username);

    let mut host = HostIo::new(pamh, Some(&pam_conv), &msgs, io.read_authtok);
    crate::transaction::run(
        ctx.service(),
        ctx.process().name().unwrap_or_default(),
        &username,
        &participation,
        &mut host,
        &config,
        effects,
    )
}

/// The one return for a skip, whichever of the two decision phases produced it.
///
/// `Outcome::from_skip` is the only mapping of a `SkipPolicy` to a verdict, and a skip is never
/// recorded (it returns before `Armed::open`).
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
