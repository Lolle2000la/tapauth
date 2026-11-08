//! The transaction driver, and the seam it takes.
//!
//! [`run`] is the transaction itself: it takes the classification the policy
//! produced, dispatches the pre-collected handoff, answers a duplicate, plans
//! the wait, puts the request on the wire, and hands the wait to one of the
//! three mechanisms. It is the only place that emits a user-visible message, and
//! the only place that resolves the configured deadline.
//!
//! [`Effects`] is everything it asks the outside world for; `HostIo` is the PAM
//! side and lives in [`crate::transaction::HostIo`].

use super::host_io::finish;
use super::{Armed, Finished, HostIo, StartError};
use crate::conclusion_cache::replay_for;
use crate::config::PamConfig;
use crate::context::ServiceName;
use crate::ipc_client::{IpcError, IpcResponseReader};
use crate::mechanism::{handoff, sequential, threaded};
use crate::outcome::{ErrorReason, Notice, NoticeStyle, Outcome, UnavailableReason};
use crate::plan::{Announcement, Plannable, TtyUse};
use crate::policy::{Conversation, FailureDirection, Participation};
use std::borrow::Cow;
use std::fs::File;
use std::time::{Duration, Instant};

/// What the transaction puts on the wire.
///
/// Handed to the injected `send` closure so that closure sees exactly the four
/// request facts and nothing else — no plan, no cache, no caller context.
pub(crate) struct SendParams<'a> {
    pub(crate) username: &'a str,
    pub(crate) has_tty: bool,
    pub(crate) timeout_secs: u32,
    pub(crate) request_id: &'a str,
}

/// The four things a transaction asks the platform to do.
///
/// `HostIo` is the PAM conversation surface; this is the outside world: probe a
/// terminal, dial the daemon, put the request on the wire, cancel it. Production
/// passes the module's own functions; tests substitute one field at a time.
///
/// `cancel` is a shared `dyn Fn` rather than a function pointer so a test can
/// count the calls: the mechanisms take any `X: Fn(&str, &str)`, and a captured
/// counter satisfies that bound without a second seam.
pub(crate) struct Effects<'a, T> {
    pub(crate) probe_tty: &'a mut dyn FnMut() -> Option<File>,
    pub(crate) connect: &'a mut dyn FnMut() -> Result<T, IpcError>,
    pub(crate) send: &'a mut dyn for<'p> FnMut(&mut T, &SendParams<'p>) -> Result<(), IpcError>,
    pub(crate) cancel: &'a dyn Fn(&str, &str),
}

/// One authentication transaction, from the classification to the conclusion.
///
/// It takes the participant, not the caller's captured identity: the only
/// caller fact it needs is the service name the reuse record keys on, so it
/// cannot re-branch on identity and a mechanism selected by the policy cannot be
/// overridden here.
///
/// Everything that happens *before* a request is on the wire returns
/// `Finished::Unrecorded`: the pre-collected handoff, a failed request id, a
/// failed connect or send. Recording one of those would answer a later
/// duplicate with a verdict the daemon never reached.
///
/// Everything after [`Armed::open`] returns `Finished::Concluded`, with
/// `Via::Daemon` for this call's own request and `Via::Replay` for a duplicate
/// answered from the reuse record.
///
/// Every return emits its verdict's one message through `host` before returning
/// — all of them through [`finish`] — so a message can be neither lost by an
/// early return nor doubled; a replayed conclusion is silent because [`finish`]
/// sees its [`Via::Replay`](super::Via::Replay), not because its return happens
/// to be early. The paths that return before a conversation exists carry
/// outcomes whose notice is `None` by construction
/// (`outcomes_that_precede_the_conversation_are_silent`). The mechanisms
/// themselves emit nothing.
///
/// `effects` is the transaction's whole outside world — see [`Effects`]:
/// production passes `pam_logic::wiring`'s `probe_tty`, `connect`,
/// `send_authenticate_request` and `cancel_on_fresh_connection`, and a
/// test substitutes one field at a time with a counter, a failure or a
/// recorder, so "the skip never reaches the daemon", "a connect failure
/// records nothing" and "a timeout cancels nothing" are assertions rather
/// than promises.
pub(crate) fn run<T: IpcResponseReader>(
    service: Option<&ServiceName>,
    username: &str,
    participation: &Participation,
    host: &mut HostIo<'_>,
    cfg: &PamConfig,
    effects: &mut Effects<'_, T>,
) -> Finished {
    // `PreCollected` has no plan at all: its handoff is the last thing that
    // happens before the transaction machinery, and it returns before a probe,
    // a `Plan` or a cache lookup exists — which is why `plan::Plannable` has no
    // `PreCollected` variant to excuse.
    //
    // The same match produces the carrier for the probe, the plan and the
    // mechanism, so a `PreCollected` participation cannot reach any of them.
    let plannable = match participation.conversation {
        Conversation::Threaded => Plannable::Threaded,
        Conversation::Sequential => Plannable::Sequential,
        Conversation::PreCollected => {
            let outcome = handoff::perform(host).into();
            return finish(host, Finished::Unrecorded(outcome));
        }
    };

    // First, answer a duplicate: the lock-screen duplicate is queued while the
    // first transaction is still running, so replaying the code this process
    // just concluded is the correct answer to a retry no user could have
    // initiated.
    //
    // The paths above deliberately record nothing. The pre-collected handoff
    // never contacts the daemon, so there is no transaction to suppress: storing
    // its `PAM_AUTHINFO_UNAVAIL` would only let a duplicate skip
    // `pam_get_authtok`, leaving `PAM_AUTHTOK` unset for `pam_unix` on that
    // handle. None of them may clobber the last real conclusion.
    // The captured service name keys the cache: `None` means the service is
    // unknown, which disables the cache for this call rather than collapsing
    // every such call into one key.
    if let Some(service_name) = service {
        // A hit is a conclusion — an earlier call's — so it is `Concluded`,
        // with `Via::Replay` saying it must not be recorded again: that would
        // refresh the timestamp, so the window stays anchored to the original
        // verdict no matter how many duplicates arrive. It is not a sliding
        // window. The hit's own log line (with its age) belongs to the cache,
        // which is the only place that knows it.
        if let Some(concluded) = replay_for(username, service_name.original(), Instant::now()) {
            return finish(host, Finished::Concluded(concluded));
        }
    }

    // The `/dev/tty` probe, gated by `Plannable::tty_use` — a function of the
    // carrier alone — so `conversation == Sequential` is not tested a second
    // time here. It runs *after* the reuse lookup: a duplicate answered from the
    // record must not open the terminal at all.
    //
    // A host whose conversation we drive from a worker thread must not take the
    // terminal branch either: it would start polling `/dev/tty` on this thread
    // and steal the stdin the host expects for its own dialog.
    let tty_file = if plannable.tty_use() == TtyUse::PollForKey {
        (effects.probe_tty)()
    } else {
        None
    };
    let has_tty = tty_file.is_some();
    let plan = plannable.plan(has_tty);

    // This is where the class first meets the plan (§3.3.2, §3.6 step 4): the
    // failure direction is a table cell copied onto the participation, so the
    // one relation it makes about the conversation is checked at the point the
    // two values meet. `NeverRing` is the pre-collected handoff, which returned
    // above and so can never produce a `Plannable`; `AlwaysRing` means the host
    // can answer while we wait, which is the threaded conversation. A rule whose
    // class and conversation drift apart fails here in a debug build and in
    // `class_agrees_with_conversation` in every build.
    debug_assert!(
        !matches!(
            (participation.failure_direction, plannable),
            (FailureDirection::NeverRing, _)
                | (FailureDirection::AlwaysRing, Plannable::Sequential)
        ),
        "class {:?} cannot be planned as {plannable:?}",
        participation.failure_direction
    );

    // Announce the wait. Each call is a single non-blocking `PAM_TEXT_INFO`
    // (one conversation round trip that carries no input and never waits for
    // the user). The terminal and threaded paths get theirs here, before the
    // wait starts; a no-terminal sequential host gets `WaitThenPassword`
    // further down, right before the module begins blocking, because such hosts
    // only reveal their password entry once a PAM message arrives.
    match plan.announcement {
        Announcement::WaitSkipHint => host.emit(Some(Notice {
            style: NoticeStyle::Info,
            text: Cow::Borrowed(host.msgs.waiting_for_tap_skip()),
        })),
        Announcement::Wait => host.emit(Some(Notice {
            style: NoticeStyle::Info,
            text: Cow::Borrowed(host.msgs.waiting_for_tap()),
        })),
        // Emitted after the request is on the wire, just below.
        Announcement::WaitThenPassword => {}
    }

    // Generate a per-request id to correlate cancellation (shared by auth and skip branches)
    let mut rid_bytes = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut rid_bytes) {
        tracing::warn!("Failed to generate random request ID: {}, skipping...", e);
        return finish(
            host,
            Finished::Unrecorded(Outcome::Error(ErrorReason::RequestId)),
        );
    }
    let request_id = hex::encode(rid_bytes);
    // The deadline, resolved once from the plan and anchored *before* the
    // request is on the wire, so a stalled connect or write consumes budget
    // instead of running past it. The daemon gets the same number of seconds,
    // so the two deadlines stay in sync. This is the only site the clamp has.
    let timeout_secs = plan.deadline.resolve(cfg);
    let deadline_at = Instant::now() + Duration::from_secs(u64::from(timeout_secs));
    let context = match (plannable, plan.tty_use) {
        (Plannable::Threaded, _) => "gui-threaded",
        (Plannable::Sequential, TtyUse::PollForKey) => "terminal",
        (Plannable::Sequential, TtyUse::DoNotOpen) => "gui-sequential",
    };
    tracing::debug!(
        "Authentication deadline: {}s (context: {})",
        timeout_secs,
        context
    );

    // Establish nonblocking IPC connection and send authenticate request.
    //
    // `Armed::open` produces the `Armed` only when the request is actually on
    // the wire — i.e. after both the connect and the send succeeded — and it is
    // the only way to reach a conclusion, so a local IPC failure cannot record
    // one. Recording a failure would let a later duplicate inherit that
    // `PAM_AUTHINFO_UNAVAIL` without ever asking, and a genuine retry must dial
    // the socket again.
    let request = SendParams {
        username,
        has_tty,
        timeout_secs,
        request_id: &request_id,
    };
    // The id is cloned into the `Armed` because `SendParams` borrows it and the
    // closure that consumes it runs inside `open`, after the `Armed` exists.
    let mut armed = match Armed::open(
        &mut *effects.connect,
        &mut |ipc: &mut T| (effects.send)(ipc, &request),
        request_id.clone().into_boxed_str(),
    ) {
        Ok(armed) => armed,
        // The two pre-arm IPC failures: no request reached the daemon, so the
        // verdict is unrecorded, and each names its own message
        // (`cannot_connect` vs `communication_error`).
        Err(StartError::Connect(e)) => {
            tracing::error!("Failed to connect to tapauthd: {}", e);
            let outcome = Outcome::Unavailable(UnavailableReason::DaemonUnreachable);
            return finish(host, Finished::Unrecorded(outcome));
        }
        Err(StartError::Send(e)) => {
            tracing::error!("Failed to send authenticate request: {}", e);
            let outcome = Outcome::Unavailable(UnavailableReason::DaemonSendFailed);
            return finish(host, Finished::Unrecorded(outcome));
        }
    };

    // GUI contexts whose conversation must be left to the host wait for the
    // daemon on this thread and never *drive* the conversation. Password
    // fallback happens after this returns, when the next PAM module runs its
    // own conversation.
    //
    // Announce the wait now that the request is on the wire and the module is
    // about to block. Event-loop hosts (GDM's auth prompt, KDE's
    // kscreenlocker_worker) only reveal their password entry once a PAM module
    // sends a query or a `PAM_TEXT_INFO`, so this is what gives the user a
    // visible password route while we wait.
    if plan.announcement == Announcement::WaitThenPassword {
        host.emit(Some(Notice {
            style: NoticeStyle::Info,
            text: Cow::Borrowed(host.msgs.waiting_for_tap_password()),
        }));
    }

    // The mechanism owns the wait; it returns an exit, never a verdict, so the
    // daemon's answer becomes an `Outcome` exactly once, in `conclude`.
    let end = match plannable {
        Plannable::Threaded => {
            threaded::drive(&mut armed, &plan, deadline_at, host.pamh(), effects.cancel)
        }
        Plannable::Sequential => {
            sequential::drive(&mut armed, &plan, deadline_at, tty_file, effects.cancel)
        }
    };

    let concluded = armed.conclude(end, username, service.cloned());
    finish(host, Finished::Concluded(concluded))
}
