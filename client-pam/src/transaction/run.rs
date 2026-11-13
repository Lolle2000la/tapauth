//! The transaction driver, and the seam it takes.
//!
//! [`run`] is the only caller of `plan.rs`'s deadline resolution and of [`finish`], and the only
//! thing that asks the outside world for anything — through [`Effects`].

use super::host_io::finish;
use super::{Armed, Finished, HostIo, StartError};
use crate::conclusion_cache::replay_for;
use crate::config::PamConfig;
use crate::context::ServiceName;
use crate::ipc_client::{IpcError, IpcResponseReader};
use crate::mechanism::{handoff, sequential, threaded};
use crate::outcome::{ErrorReason, Notice, NoticeStyle, Outcome, UnavailableReason};
use crate::plan::{Announcement, Plannable, TtyUse};
use crate::policy::{class_permits, Conversation, Participation};
use std::borrow::Cow;
use std::fs::File;
use std::time::{Duration, Instant};

/// What the transaction puts on the wire.
///
/// The send closure sees exactly these six request facts — no plan, no cache, no caller
/// context. `pam_service` and `process_name` are the caller's context projected onto the wire
/// (empty when the context has none); the context itself stays out, so nothing here can
/// re-branch on it.
pub(crate) struct SendParams<'a> {
    pub(crate) username: &'a str,
    pub(crate) has_tty: bool,
    pub(crate) timeout_secs: u32,
    pub(crate) request_id: &'a str,
    pub(crate) pam_service: &'a str,
    pub(crate) process_name: &'a str,
}

/// The four things a transaction asks the platform to do.
///
/// Production passes the module's own functions; a test substitutes one field at a time with a
/// counter, a failure or a recorder, which is how the transaction is driven without a PAM
/// handle.
///
/// `cancel` is a shared `dyn Fn` rather than a function pointer so a test can count the calls:
/// the mechanisms take any `X: Fn(&str, &str)`, and a captured counter satisfies that bound
/// without a second seam.
pub(crate) struct Effects<'a, T> {
    pub(crate) probe_tty: &'a mut dyn FnMut() -> Option<File>,
    pub(crate) connect: &'a mut dyn FnMut() -> Result<T, IpcError>,
    pub(crate) send: &'a mut dyn for<'p> FnMut(&mut T, &SendParams<'p>) -> Result<(), IpcError>,
    pub(crate) cancel: &'a dyn Fn(&str, &str),
}

/// One authentication transaction, from the classification to the conclusion.
///
/// It takes the participation, not the caller's captured identity: the caller facts it
/// needs — the service name the reuse record keys on, and the process name it forwards to the
/// daemon — arrive as plain values, so it cannot re-branch on identity and a mechanism selected
/// by the policy cannot be overridden here. A missing service forwards an empty `pam_service`,
/// which is the wire's "not known".
///
/// Everything before the request is on the wire — the pre-collected handoff, a failed request
/// id, a failed connect or send — returns `Finished::Unrecorded`: recording one would answer a
/// later duplicate with a verdict the daemon never reached. Everything after [`Armed::open`]
/// returns `Finished::Concluded`; see [`finish`] for what each return shows.
pub(crate) fn run<T: IpcResponseReader>(
    service: Option<&ServiceName>,
    process_name: &str,
    username: &str,
    participation: &Participation,
    host: &mut HostIo<'_>,
    cfg: &PamConfig,
    effects: &mut Effects<'_, T>,
) -> Finished {
    // `PreCollected` has no plan at all: its handoff returns before a probe, a `Plan` or a
    // cache lookup exists, which is why `plan::Plannable` has no `PreCollected` variant. This
    // one match produces the carrier for the probe, the plan and the mechanism, so a
    // `PreCollected` participation cannot reach any of them.
    let plannable = match participation.conversation {
        Conversation::Threaded => Plannable::Threaded,
        Conversation::Sequential => Plannable::Sequential,
        Conversation::PreCollected => {
            let outcome = handoff::perform(host).into();
            return finish(host, Finished::Unrecorded(outcome));
        }
    };

    // Answer a duplicate first: the lock screen queues it while the first transaction is still
    // running (see `conclusion_cache`), so replaying the code this process just concluded is the
    // correct answer to a retry no user could have initiated.
    //
    // The handoff path above deliberately records nothing: storing its `PAM_AUTHINFO_UNAVAIL`
    // would let a duplicate skip `pam_get_authtok`, leaving `PAM_AUTHTOK` unset for `pam_unix`
    // on that handle, and it must not clobber the last real conclusion either. `None` means the
    // service is unknown, which disables the cache for this call rather than collapsing every
    // such call into one key.
    if let Some(service_name) = service {
        // A hit is a `Concluded` with `Via::Replay`, which is what keeps it from being recorded
        // again: a re-record would refresh the timestamp and turn the fixed window into a
        // sliding one. The hit's own log line (with its age) belongs to the cache.
        if let Some(concluded) = replay_for(username, service_name.original(), Instant::now()) {
            return finish(host, Finished::Concluded(concluded));
        }
    }

    // The probe is gated by `Plannable::tty_use` — a function of the carrier alone — so
    // `conversation == Sequential` is not tested a second time here. It runs *after* the reuse
    // lookup: a duplicate answered from the record must not open the terminal at all.
    //
    // A threaded host must not take the terminal branch either: it would start polling
    // `/dev/tty` on this thread and steal the stdin the host expects for its own dialog.
    let tty_file = if plannable.tty_use() == TtyUse::PollForKey {
        (effects.probe_tty)()
    } else {
        None
    };
    let has_tty = tty_file.is_some();
    let plan = plannable.plan(has_tty);

    // This is where the class first meets the plan. The pairing rule is `policy::class_permits`'s
    // — one total function over `FailureDirection × Conversation`, no wildcard, walked cell by
    // cell and over every rule and corpus row by the policy's own tests — so it is not restated
    // here, and release builds drop this check entirely.
    debug_assert!(
        class_permits(participation.failure_direction, participation.conversation),
        "class {:?} cannot be answered with a {:?} conversation",
        participation.failure_direction,
        participation.conversation
    );

    // One non-blocking `PAM_TEXT_INFO` per call: no input, and it never waits for the user. The
    // terminal and threaded paths announce here, before the wait starts; a no-terminal
    // sequential host gets `WaitThenPassword` further down — after the request, because such
    // hosts only reveal their password entry once a PAM message arrives.
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

    // A per-request id, so a cancel can be matched to this request.
    let mut rid_bytes = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut rid_bytes) {
        tracing::warn!("Failed to generate random request ID: {}, skipping...", e);
        return finish(
            host,
            Finished::Unrecorded(Outcome::Error(ErrorReason::RequestId)),
        );
    }
    let request_id = hex::encode(rid_bytes);
    // Resolved once from the plan and anchored *before* the request is on the wire, so a stalled
    // connect or write consumes budget instead of running past it; the daemon is given the same
    // number of seconds, so the two deadlines stay in sync. `Deadline::resolve` owns the clamp.
    let timeout_secs = plan.deadline.resolve(cfg);
    let deadline_at = Instant::now() + Duration::from_secs(u64::from(timeout_secs));
    let label = match (plannable, plan.tty_use) {
        (Plannable::Threaded, _) => "gui-threaded",
        (Plannable::Sequential, TtyUse::PollForKey) => "terminal",
        (Plannable::Sequential, TtyUse::DoNotOpen) => "gui-sequential",
    };
    tracing::debug!(
        "Authentication deadline: {}s (context: {})",
        timeout_secs,
        label
    );

    // Only `Armed::open` can arm the record — it yields an `Armed` once both the connect and the
    // send succeeded — so neither failure below can be recorded.
    let request = SendParams {
        username,
        has_tty,
        timeout_secs,
        request_id: &request_id,
        // The caller's context, projected onto the wire: the service as libpam spelled it, and
        // the process name when `/proc` resolved one.
        pam_service: service.map(ServiceName::original).unwrap_or_default(),
        process_name,
    };
    // Cloned because `SendParams` borrows the id and the closure that consumes it runs inside
    // `open`, after the `Armed` exists.
    let mut armed = match Armed::open(
        &mut *effects.connect,
        &mut |ipc: &mut T| (effects.send)(ipc, &request),
        request_id.clone().into_boxed_str(),
    ) {
        Ok(armed) => armed,
        // No request reached the daemon, so the verdict is unrecorded; each arm names its own
        // message (`cannot_connect` vs `communication_error`).
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

    // Announced only once the request is on the wire and the module is about to block: an
    // event-loop host reveals its password entry only when a PAM message arrives, and it must
    // already be blocked when one does (see `plan::Announcement::WaitThenPassword`).
    if plan.announcement == Announcement::WaitThenPassword {
        host.emit(Some(Notice {
            style: NoticeStyle::Info,
            text: Cow::Borrowed(host.msgs.waiting_for_tap_password()),
        }));
    }

    // The mechanism returns an exit, never a verdict.
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
