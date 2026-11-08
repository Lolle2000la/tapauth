//! What one authentication transaction produced.
//!
//! The two arms of [`Finished`] are the whole contract between the
//! orchestration and its caller. `Finished::Concluded` carries a [`Concluded`] —
//! the verdict, the subject, the service and how the verdict was reached — and
//! only that arm may be recorded in the 500 ms reuse record.
//! `Finished::Unrecorded` carries an [`Outcome`] that was reached before a
//! request was on the wire (a skip, a missing username, a pre-collected
//! handoff, a connect failure), so recording it could only answer a later
//! duplicate with a verdict the daemon never reached.
//!
//! A fresh [`Concluded`] has exactly one producer, [`Armed::conclude`], and an
//! [`Armed`] exists only when a request is on the wire, so a conclusion cannot
//! be minted without one. [`Concluded::replay`] is the only producer of
//! [`Via::Replay`], and
//! [`ConclusionCache::record`](crate::conclusion_cache::ConclusionCache::record)
//! refuses it — which is what keeps the fixed 500 ms window fixed.
//!
//! [`Concluded::outcome`] is the only way the orchestration's caller reads a
//! verdict out of this type in a test build, and `Outcome::to_pam` the only way
//! it becomes a `PAM_*` code, so a code cannot travel beside the verdict.
//!
//! [`run`] is the transaction itself: it takes the classification the policy
//! produced, dispatches the pre-collected handoff, answers a duplicate, plans
//! the wait, puts the request on the wire, and hands the wait to one of the
//! three mechanisms. It is the only place that emits a user-visible message, and
//! the only place that resolves the configured deadline.

use crate::conclusion_cache::replay_for;
use crate::config::PamConfig;
use crate::context::{CallerContext, ServiceName};
use crate::ipc_client::{IpcClient, IpcError, IpcResponseReader};
use crate::mechanism::{handoff, sequential, threaded};
use crate::outcome::{ErrorReason, Notice, NoticeStyle, Outcome, UnavailableReason};
use crate::pam_messages::PamMessages;
use crate::pam_sys::{PamConversation, PamHandle, ReadAuthtok};
use crate::plan::{Announcement, Plannable, TtyUse};
use crate::policy::{Conversation, FailureDirection, Participation};
use std::borrow::Cow;
use std::fs::File;
use std::os::raw::{c_char, c_int};
use std::time::{Duration, Instant};

/// The result of one authentication transaction.
pub(crate) enum Finished {
    /// A conclusion was reached, with the provenance needed to decide whether
    /// it may be recorded.
    Concluded(Concluded),
    /// No conclusion: the call ended before a request could be put on the wire.
    Unrecorded(Outcome),
}

/// A conclusion, and how it was reached.
///
/// The fields are private to this module: `username`, `service` and `via` are
/// the recording gate's inputs, and the cache owner reads them only through
/// [`Concluded::into_parts`]. There is deliberately no constructor that a
/// caller outside this module can reach except [`Armed::conclude`] and
/// [`Concluded::replay`].
pub(crate) struct Concluded {
    outcome: Outcome,
    username: String,
    service: Option<ServiceName>,
    via: Via,
}

/// How a conclusion was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// This call's own request reached the daemon.
    Daemon,
    /// A copy of a conclusion this process recorded earlier, inside the reuse
    /// window. Never re-recorded.
    Replay,
}

impl Finished {
    /// The verdict this result carries, whatever the arm.
    ///
    /// Test-only: production reads the arm it matched and records through
    /// [`record`], so nothing outside a test needs the verdict detached from
    /// the provenance.
    #[cfg(test)]
    pub(crate) fn outcome(&self) -> &Outcome {
        match self {
            Finished::Concluded(concluded) => concluded.outcome(),
            Finished::Unrecorded(outcome) => outcome,
        }
    }
}

impl Concluded {
    /// The verdict.
    #[cfg(test)]
    pub(crate) fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// How the conclusion was reached.
    #[cfg(test)]
    pub(crate) fn via(&self) -> Via {
        self.via
    }

    /// The recording gate's inputs, moved out for the cache owner.
    ///
    /// The fields stay private so only this module can build a `Concluded`; the
    /// cache (`crate::conclusion_cache`) is the one reader outside it, and it
    /// applies the gate and stores the record with these four values.
    pub(crate) fn into_parts(self) -> (Outcome, String, Option<ServiceName>, Via) {
        (self.outcome, self.username, self.service, self.via)
    }

    /// The replay constructor, and the only producer of [`Via::Replay`].
    ///
    /// It takes the *recorded* `Outcome` — a value [`Armed::conclude`] produced
    /// earlier in this process — copies it through `Outcome::replayed`, and
    /// marks the token `Via::Replay`, which
    /// [`ConclusionCache::record`](crate::conclusion_cache::ConclusionCache::record)
    /// refuses. Its production caller is the cache hit in
    /// [`replay_for`](crate::conclusion_cache::replay_for); a test may build one
    /// directly, which is how `a_from_cache_verdict_is_not_recorded` pins that
    /// the marker — not a local flag — is what refuses the re-record.
    pub(crate) fn replay(recorded: Outcome, username: Box<str>, service: ServiceName) -> Concluded {
        Concluded {
            outcome: Outcome::replayed(&recorded),
            username: username.into(),
            service: Some(service),
            via: Via::Replay,
        }
    }
}

/// Why a transaction never reached the daemon.
///
/// The two arms keep their own notices: the caller maps
/// `Connect` to `Unavailable(DaemonUnreachable)` (`cannot_connect`) and `Send`
/// to `Unavailable(DaemonSendFailed)` (`communication_error`), so a reader can
/// tell a missing socket from a failed write.
pub(crate) enum StartError {
    Connect(IpcError),
    Send(IpcError),
}

/// A request that is on the wire, with the client and the request id the
/// mechanism needs.
///
/// [`Armed::open`] is the only producer: it runs the injected `connect` and
/// then `send`, and it returns `Armed` only when *both* succeeded. A local IPC
/// failure is not a verdict about the phone, so it can neither arm the record
/// nor produce a conclusion.
pub(crate) struct Armed<I: IpcResponseReader = IpcClient> {
    ipc: I,
    request_id: Box<str>,
}

impl<I: IpcResponseReader> Armed<I> {
    /// Connect, put the authenticate request on the wire, and only then produce
    /// the `Armed`.
    ///
    /// The ordering is the point: the record exists so a duplicate
    /// `pam_authenticate` can replay a conclusion *the daemon* reached, so it
    /// must not be armed by a local IPC failure. A missing socket or a failed
    /// write says nothing about the phone — arming there would let a later
    /// duplicate inherit that `PAM_AUTHINFO_UNAVAIL` without ever asking, and a
    /// genuine retry must dial the socket again instead of being answered from
    /// the record.
    ///
    /// `connect` and `send` are parameters so both failure paths are testable
    /// without a daemon (`verdict_reuse_tests`); production passes
    /// `IpcClient::connect_nonblocking` and [`crate::pam_logic`]'s
    /// `send_authenticate_request` closure.
    pub(crate) fn open<C, S>(connect: C, send: S, request_id: Box<str>) -> Result<Self, StartError>
    where
        C: FnOnce() -> Result<I, IpcError>,
        S: FnOnce(&mut I) -> Result<(), IpcError>,
    {
        let mut ipc = connect().map_err(StartError::Connect)?;
        send(&mut ipc).map_err(StartError::Send)?;
        // The request is on the wire, so a daemon conclusion is now possible.
        // Nothing above this line can produce one.
        Ok(Armed { ipc, request_id })
    }

    /// The conclusion this request reached.
    ///
    /// Consumes the `Armed`, so a conclusion cannot outlive the fact that a
    /// request was on the wire, and consumes the mechanism's [`MechanismEnd`],
    /// so the daemon's answer is mapped to a verdict here and nowhere else: a
    /// mechanism cannot mint a `Granted` or a `Denied` of its own (§3.5.2
    /// layer 4).
    pub(crate) fn conclude(
        self,
        end: MechanismEnd,
        username: &str,
        service: Option<ServiceName>,
    ) -> Concluded {
        Concluded {
            outcome: end.into_outcome(),
            username: username.to_owned(),
            service,
            via: Via::Daemon,
        }
    }

    /// The client and the request id, for the mechanism that drives the wait.
    ///
    /// One call rather than two accessors, so a caller cannot hold the client's
    /// mutable borrow and the id's shared borrow separately.
    pub(crate) fn parts(&mut self) -> (&mut I, &str) {
        (&mut self.ipc, &self.request_id)
    }
}

/// A mechanism's exit.
///
/// It carries the daemon's response, an unavailability reason, or a local error
/// reason — never an [`Outcome`]: only [`Armed::conclude`] may turn one into a
/// conclusion, so a mechanism cannot mint one of its own. `Error` exists for the
/// two local-resource failures the threaded mechanism owns (`pipe2`,
/// `pthread_create`), which must keep returning `PAM_AUTH_ERR` and must keep
/// being recorded. The response is owned, because a mechanism cannot return a
/// borrow of its own local.
#[derive(Debug)]
pub(crate) enum MechanismEnd {
    Response(shared::ipc::pb::PamAuthenticateResponse),
    Reason(UnavailableReason),
    Error(ErrorReason),
}

impl MechanismEnd {
    /// The verdict this exit names.
    ///
    /// The one mapping from an exit to an outcome, used by [`Armed::conclude`]
    /// for a transaction that reached the daemon and by [`run`]'s handoff arm,
    /// which has no request to conclude.
    fn into_outcome(self) -> Outcome {
        match self {
            MechanismEnd::Response(resp) => Outcome::from_daemon(resp),
            MechanismEnd::Reason(reason) => Outcome::Unavailable(reason),
            MechanismEnd::Error(reason) => Outcome::Error(reason),
        }
    }
}

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

/// One thing [`HostIo::emit`] was asked to show, with the style it was shown in.
///
/// The recording sink's entry: the text alone would let an `Error`-style
/// message be asserted where an `Info` one belongs, which is exactly the
/// distinction `Outcome::notice` exists to keep.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Emitted {
    pub(crate) style: NoticeStyle,
    pub(crate) text: String,
}

/// The PAM handle and the messages the orchestration built, plus — in
/// production only — the conversation they belong to.
///
/// `new` is the only production constructor and always passes `Some`; `for_test`
/// is its `#[cfg(test)]` counterpart and passes `None`, which makes [`emit`] a
/// no-op, so a test never opens a real PAM handle. A test that needs to *see*
/// the emission order uses `for_test_recording`, which records text and style
/// instead.
///
/// The type deliberately owns no terminal: the `/dev/tty` file is `run`'s local
/// and is consumed by the sequential mechanism.
pub(crate) struct HostIo<'a> {
    pamh: *mut PamHandle,
    conv: Option<&'a PamConversation<'a>>,
    msgs: &'a PamMessages,
    /// The handoff's one handle read, injected like the other effects so a test
    /// can count it: production passes
    /// [`crate::pam_sys::read_authtok_for_handoff`].
    read_authtok: ReadAuthtok,
    /// Test-only record of what [`emit`] was asked to show.
    #[cfg(test)]
    emitted: Option<&'a std::cell::RefCell<Vec<Emitted>>>,
}

impl<'a> HostIo<'a> {
    pub(crate) fn new(
        pamh: *mut PamHandle,
        conv: &'a PamConversation<'a>,
        msgs: &'a PamMessages,
        read_authtok: ReadAuthtok,
    ) -> Self {
        HostIo {
            pamh,
            conv: Some(conv),
            msgs,
            read_authtok,
            #[cfg(test)]
            emitted: None,
        }
    }

    /// The handle a mechanism needs for its one conversation call, if any.
    pub(crate) fn pamh(&self) -> *mut PamHandle {
        self.pamh
    }

    /// Read the host's pre-collected token, through the injected reader.
    pub(crate) fn read_authtok(&self) -> (c_int, *const c_char) {
        // SAFETY: the reader is the caller's `pam_get_authtok` wrapper, which
        // takes the live handle this host carries; the conversation belongs to
        // this thread.
        unsafe { (self.read_authtok)(self.pamh) }
    }

    /// Show one notice, if there is one.
    ///
    /// The one emission site in the crate: `try_info`/`try_error` swallow a
    /// failing conversation, so a broken host conversation cannot change the
    /// verdict, and the style comes from the notice's reason rather than from
    /// the site that observed the failure.
    pub(crate) fn emit(&self, notice: Option<Notice<'_>>) {
        let Some(notice) = notice else {
            return;
        };
        #[cfg(test)]
        if let Some(log) = self.emitted {
            log.borrow_mut().push(Emitted {
                style: notice.style,
                text: notice.text.to_string(),
            });
        }
        let Some(conv) = self.conv else {
            return;
        };
        match notice.style {
            NoticeStyle::Info => conv.try_info(&notice.text),
            NoticeStyle::Error => conv.try_error(&notice.text),
        }
    }

    /// A host with no conversation: every emission is a no-op.
    #[cfg(test)]
    pub(crate) fn for_test(
        pamh: *mut PamHandle,
        conv: Option<&'a PamConversation<'a>>,
        msgs: &'a PamMessages,
        read_authtok: ReadAuthtok,
    ) -> Self {
        HostIo {
            pamh,
            conv,
            msgs,
            read_authtok,
            emitted: None,
        }
    }

    /// A host that records what it was asked to show, in order, with styles.
    ///
    /// The only way an ordering or a message assertion can see what the
    /// transaction emitted without a real PAM handle, which is what
    /// `announcement_order_matches_today` and `unrecorded_paths_emit_their_notice`
    /// need.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn for_test_recording(
        pamh: *mut PamHandle,
        msgs: &'a PamMessages,
        emitted: &'a std::cell::RefCell<Vec<Emitted>>,
        read_authtok: ReadAuthtok,
    ) -> Self {
        HostIo {
            pamh,
            conv: None,
            msgs,
            read_authtok,
            emitted: Some(emitted),
        }
    }
}

/// The transaction's one emission site: show `finished`'s message through
/// `host`, then hand it back.
///
/// Every return in [`run`] goes through here, so the message is decided by the
/// verdict *and by how it was reached*, never by the site that produced it.
/// `Concluded`'s [`Via`] is what suppresses it: a replay is a copy of a
/// conclusion this process already announced when it first reached it, so it
/// must say nothing — and it must say nothing because of its provenance, not
/// because the cache-hit arm happens to return early, so a restructure that
/// routed a replayed `Unavailable(..)` or `Error(..)` through an ordinary
/// return still could not speak.
fn finish(host: &HostIo<'_>, finished: Finished) -> Finished {
    let notice = match &finished {
        Finished::Concluded(concluded) if concluded.via == Via::Replay => None,
        Finished::Concluded(concluded) => concluded.outcome.notice(host.msgs),
        Finished::Unrecorded(outcome) => outcome.notice(host.msgs),
    };
    host.emit(notice);
    finished
}

/// One authentication transaction, from the classification to the conclusion.
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
/// sees its [`Via::Replay`], not because its return happens to be early. The
/// paths that return before a conversation exists carry outcomes whose notice is
/// `None` by construction (`outcomes_that_precede_the_conversation_are_silent`).
/// The mechanisms themselves emit nothing.
///
/// `probe_tty`, `connect`, `send` and `cancel` are the transaction's four
/// injected effects: production passes the real `/dev/tty` open,
/// `IpcClient::connect_nonblocking`, the `send_authenticate_start` closure and
/// the fresh-connection cancel, and a test passes counters, failures or a
/// recording cancel, so "the skip never reaches the daemon", "a connect failure
/// records nothing" and "a timeout cancels nothing" are assertions rather than
/// promises.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run<T, C, S, X>(
    ctx: &CallerContext,
    username: &str,
    participation: &Participation,
    host: &mut HostIo<'_>,
    cfg: &PamConfig,
    probe_tty: impl FnOnce() -> Option<File>,
    connect: C,
    send: S,
    cancel: X,
) -> Finished
where
    T: IpcResponseReader,
    C: FnOnce() -> Result<T, IpcError>,
    S: FnOnce(&mut T, &SendParams<'_>) -> Result<(), IpcError>,
    X: Fn(&str, &str),
{
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
            let outcome = handoff::perform(host).into_outcome();
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
    if let Some(service_name) = ctx.service() {
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
        probe_tty()
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
        connect,
        |ipc| send(ipc, &request),
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
            threaded::drive(&mut armed, &plan, deadline_at, host.pamh(), &cancel)
        }
        Plannable::Sequential => {
            sequential::drive(&mut armed, &plan, deadline_at, tty_file, &cancel)
        }
    };

    let concluded = armed.conclude(end, username, ctx.service().cloned());
    finish(host, Finished::Concluded(concluded))
}

/// The test carrier over a fake reader; no test opens a real daemon socket.
#[cfg(test)]
pub(crate) fn armed_for_test<I: IpcResponseReader>(ipc: I, request_id: &str) -> Armed<I> {
    Armed {
        ipc,
        request_id: request_id.into(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
pub(crate) mod tests {
    use super::*;
    use crate::conclusion_cache::tests::take_slot;
    use crate::conclusion_cache::{record, replay_for};
    use crate::outcome::{GrantVia, UnavailableReason};

    /// An `IpcResponseReader` that carries nothing: enough to build an `Armed`
    /// for the paths that never touch the transport.
    struct UnusedIpc;

    impl IpcResponseReader for UnusedIpc {
        fn fd(&self) -> std::os::fd::RawFd {
            -1
        }

        fn try_read_response_nonblocking(
            &mut self,
        ) -> Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error> {
            Ok(None)
        }

        fn send_cancel(&mut self, _reason: &str, _request_id: &str) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    fn concluded(outcome: Outcome, via: Via) -> Concluded {
        Concluded {
            outcome,
            username: "alice".to_owned(),
            service: Some(ServiceName::new("sudo")),
            via,
        }
    }

    // ------------------------------------------------------------------
    // Driving `run`: the transport doubles and the harness the moved tests
    // share. No test opens a daemon socket.
    // ------------------------------------------------------------------

    /// An `IpcResponseReader` that carries nothing: enough to satisfy the
    /// transport bound for a path that fails before either end is used.
    pub(crate) struct NullIpc;

    impl IpcResponseReader for NullIpc {
        fn fd(&self) -> std::os::fd::RawFd {
            -1
        }

        fn try_read_response_nonblocking(
            &mut self,
        ) -> Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error> {
            Ok(None)
        }

        fn send_cancel(&mut self, _reason: &str, _request_id: &str) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    /// A connect that fails the way a missing socket does, for the paths whose
    /// call counts are the assertion.
    pub(crate) fn no_daemon() -> IpcError {
        IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "no daemon socket",
        ))
    }

    /// The exit every daemon grant arrives as: a `Success` response.
    fn success_end() -> MechanismEnd {
        let mut resp = shared::ipc::pb::PamAuthenticateResponse::default();
        resp.set_outcome(shared::ipc::pb::PamOutcome::Success);
        MechanismEnd::Response(resp)
    }

    /// Timeouts of zero, so a path that gets as far as the mechanism returns
    /// without waiting: these tests assert call counts and orderings, not
    /// waiting.
    fn zero_timeouts() -> PamConfig {
        PamConfig {
            pam_operation_timeout_secs: 0,
            pam_gui_timeout_secs: 0,
            ..PamConfig::default()
        }
    }

    /// A caller context from already-resolved facts.
    fn context(service: Option<&str>, process: Option<&str>) -> CallerContext {
        let process = match process {
            Some(name) => crate::context::ProcessIdentity::Exe(name.into()),
            None => crate::context::ProcessIdentity::Unknown,
        };
        CallerContext::from_parts(service, process, crate::context::GdmReauth::Absent)
    }

    /// The participation `classify` produces for `ctx`.
    ///
    /// `run` is downstream of the policy — it receives a participation and never
    /// re-branches on identity — so a test that drives `run` directly has to
    /// name the one the context classifies to.
    fn participation_for(ctx: &CallerContext) -> Participation {
        match crate::policy::classify(ctx) {
            crate::policy::Classification::Participate(participation) => participation,
            crate::policy::Classification::Skip(skip) => {
                panic!("expected a participation, got the skip {skip:?}")
            }
        }
    }

    /// A handoff reader that reads nothing, for the tests whose paths never
    /// reach the pre-collected handoff.
    ///
    /// `skip_never_hands_off` injects a counting reader instead, which is where
    /// the read is the assertion.
    pub(crate) unsafe fn unused_authtok(_pamh: *mut PamHandle) -> (c_int, *const c_char) {
        (crate::pam_sys::PAM_SUCCESS, std::ptr::null())
    }

    /// Drive `run` with a context, a tty probe and the two injected IPC effects,
    /// and report its result plus how many times the probe ran.
    fn run_with_probe<T, C, S>(
        ctx: &CallerContext,
        tty: Option<&str>,
        connect: C,
        send: S,
    ) -> (Finished, usize)
    where
        T: IpcResponseReader,
        C: FnOnce() -> Result<T, IpcError>,
        S: FnOnce(&mut T, &SendParams<'_>) -> Result<(), IpcError>,
    {
        let msgs = PamMessages::new("en");
        let mut host = HostIo::for_test(std::ptr::null_mut(), None, &msgs, unused_authtok);
        let participation = participation_for(ctx);
        let mut probes = 0usize;
        let finished = run(
            ctx,
            "tty-probe-test-user",
            &participation,
            &mut host,
            &zero_timeouts(),
            || {
                probes += 1;
                tty.and_then(|path| std::fs::File::open(path).ok())
            },
            connect,
            send,
            |_, _| {},
        );
        (finished, probes)
    }

    /// Record `outcome` for `(username, service)` at `at`, through the same
    /// `Armed`-conclude-record path `authenticate` uses.
    pub(crate) fn record_conclusion(username: &str, service: &str, outcome: Outcome, at: Instant) {
        let end = match outcome {
            Outcome::Granted(_) => success_end(),
            Outcome::Unavailable(reason) => MechanismEnd::Reason(reason),
            other => unreachable!("these tests record a grant or an unavailability, not {other:?}"),
        };
        let concluded = armed_for_test(NullIpc, "pam-logic-test-request").conclude(
            end,
            username,
            Some(ServiceName::new(service)),
        );
        let _ = record(concluded, at);
    }

    /// Both arms report the verdict they carry, and a `Concluded` keeps its
    /// provenance.
    ///
    /// The defect this catches: a `Finished` accessor that reads only one arm
    /// (so a caller mapping `outcome()` would silently turn an unrecorded
    /// connect failure into something else), and a provenance field that cannot
    /// distinguish a fresh conclusion from a replay — which is what `record`
    /// refuses.
    #[test]
    fn finished_reports_its_outcome_and_provenance() {
        let grant = Outcome::granted_from_daemon();
        let finished = Finished::Concluded(concluded(grant.clone(), Via::Daemon));
        assert_eq!(finished.outcome(), &grant);
        assert_eq!(
            finished.outcome().clone().to_pam(),
            crate::pam_sys::PAM_SUCCESS
        );

        let unreachable = Outcome::Unavailable(UnavailableReason::DaemonUnreachable);
        let unrecorded = Finished::Unrecorded(unreachable.clone());
        assert_eq!(unrecorded.outcome(), &unreachable);
        assert_eq!(
            unrecorded.outcome().clone().to_pam(),
            crate::pam_sys::PAM_AUTHINFO_UNAVAIL
        );

        let replay = Outcome::replayed(&grant);
        let replayed = concluded(replay.clone(), Via::Replay);
        assert_eq!(replayed.outcome(), &replay);
        assert_eq!(replayed.via, Via::Replay);
        assert_eq!(replayed.username, "alice");
        assert_eq!(
            replayed.service.as_ref().map(ServiceName::original),
            Some("sudo")
        );
        assert_eq!(grant, Outcome::Granted(GrantVia::PhoneTap));
    }

    /// An `Armed` exists only when the connect *and* the send succeeded.
    ///
    /// The defect this catches: a failed `send` (or a failed `connect`) still
    /// yielding an `Armed`, which would let the caller record a conclusion the
    /// daemon never had a chance to reach and answer the duplicate from it. The
    /// assertion is on the arm, not on "is an error": a `connect` failure
    /// reported as `Send` would send `communication_error` where `cannot_connect`
    /// belongs.
    #[test]
    fn armed_requires_both_connect_and_send() {
        let refused = || {
            Err::<UnusedIpc, _>(IpcError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "no daemon socket",
            )))
        };

        let no_connect = Armed::open(refused, |_: &mut UnusedIpc| Ok(()), "rid".into());
        assert!(
            matches!(no_connect, Err(StartError::Connect(_))),
            "a refused connect must surface as a connect failure, not as a send \
             failure and not as an armed request"
        );

        let mut sent = false;
        let bad_send = Armed::open(
            || Ok(UnusedIpc),
            |_: &mut UnusedIpc| {
                sent = true;
                Err(IpcError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "daemon closed the socket",
                )))
            },
            "rid".into(),
        );
        assert!(
            matches!(bad_send, Err(StartError::Send(_))),
            "a failed write must surface as a send failure and must not arm"
        );
        assert!(sent, "the send closure is what failed, so it must have run");

        let Ok(armed) = Armed::open(|| Ok(UnusedIpc), |_: &mut UnusedIpc| Ok(()), "rid".into())
        else {
            panic!("both effects succeeded, so the request is on the wire");
        };
        let concluded = armed.conclude(
            MechanismEnd::Reason(UnavailableReason::TimedOut),
            "alice",
            Some(ServiceName::new("sudo")),
        );
        assert_eq!(
            concluded.via,
            Via::Daemon,
            "a conclusion minted by `conclude` is this call's own request"
        );
    }

    /// A replayed conclusion shows no message.
    ///
    /// The defect this catches: `notice` on a replayed grant or denial returning
    /// the phone-tap text, so a cache hit either re-shows `auth_successful` /
    /// `auth_denied` (a duplicate the user never made) or, worse, re-enters the
    /// emission path with a verdict the daemon already answered. The
    /// total-emission rule reaches `notice` on a replay, so this is what keeps
    /// the cache hit silent.
    #[test]
    fn replay_notice_is_silent() {
        let msgs = crate::pam_messages::PamMessages::new("en");
        let service = ServiceName::new("silent-replay-service");

        let replay = Concluded::replay(
            Outcome::granted_from_daemon(),
            "alice".into(),
            service.clone(),
        );
        assert_eq!(replay.via, Via::Replay);
        assert!(
            replay.outcome.notice(&msgs).is_none(),
            "a replayed grant must show nothing: the successful tap was announced \
             when it was first reached"
        );

        let replay = Concluded::replay(
            Outcome::Denied(crate::outcome::DenyVia::PhoneDenial),
            "alice".into(),
            service,
        );
        assert_eq!(replay.via, Via::Replay);
        assert!(
            replay.outcome.notice(&msgs).is_none(),
            "a replayed denial must show nothing either: re-announcing it would \
             answer a duplicate the user never made"
        );

        // The control: the same verdicts, not replayed, do have their messages,
        // so the assertion above is about the replay marker and not about the
        // message being missing for these codes.
        assert!(
            Outcome::granted_from_daemon().notice(&msgs).is_some(),
            "a fresh grant shows auth_successful"
        );
        assert!(
            Outcome::Denied(crate::outcome::DenyVia::PhoneDenial)
                .notice(&msgs)
                .is_some(),
            "a fresh denial shows auth_denied"
        );
    }

    // ------------------------------------------------------------------
    // The transaction's own behaviour, moved with `run` when the mechanisms
    // became modules. Assertions unchanged.
    // ------------------------------------------------------------------

    /// `/dev/tty` is opened once, and only for the conversation that polls it.
    ///
    /// The defect this catches: the probe moved to the top of `run` (or gated on
    /// `conversation == Sequential` a second time, next to the plan), so a
    /// threaded host polls the terminal and steals the stdin its own dialog
    /// needs — or a plan maker and the probe disagree about whether a terminal
    /// exists.
    #[test]
    fn tty_probe_only_for_sequential() {
        let threaded = context(Some("probe-threaded"), Some("hyprlock"));
        let (finished, probes) = run_with_probe(
            &threaded,
            Some("/dev/null"),
            || Err::<NullIpc, _>(no_daemon()),
            |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
        );
        assert_eq!(
            (finished.outcome().clone().to_pam(), probes),
            (crate::pam_sys::PAM_AUTHINFO_UNAVAIL, 0),
            "a threaded conversation must not open /dev/tty"
        );

        let sequential_tty = context(Some("probe-tty"), Some("xfce4-screensaver-dialog"));
        let (finished, probes) = run_with_probe(
            &sequential_tty,
            Some("/dev/null"),
            || Err::<NullIpc, _>(no_daemon()),
            |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
        );
        assert_eq!(
            (finished.outcome().clone().to_pam(), probes),
            (crate::pam_sys::PAM_AUTHINFO_UNAVAIL, 1),
            "a sequential conversation probes /dev/tty exactly once"
        );

        let sequential_no_tty = context(Some("probe-no-tty"), Some("xfce4-screensaver-dialog"));
        let (finished, probes) = run_with_probe(
            &sequential_no_tty,
            None,
            || Err::<NullIpc, _>(no_daemon()),
            |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
        );
        assert_eq!(
            (finished.outcome().clone().to_pam(), probes),
            (crate::pam_sys::PAM_AUTHINFO_UNAVAIL, 1),
            "a sequential conversation probes once even when there is no terminal"
        );
    }

    /// A duplicate answered from the reuse record does not open `/dev/tty`.
    ///
    /// The defect this catches: the probe left *before* the reuse lookup, where
    /// it used to be, so every hit opened the terminal for a transaction it
    /// never starts. The recorded conclusion is a success, so the returned code
    /// also proves the hit was taken rather than the probe merely being skipped
    /// on an early return.
    ///
    /// The reuse record is one process-wide slot that other tests in this binary
    /// also write, and the module's lookup happens after the injected
    /// `load_messages`, so the record is re-taken whenever a concurrent test
    /// replaced it. The assertion itself is never relaxed: it is only evaluated
    /// once a hit actually happened, which the returned code proves.
    #[test]
    fn cache_hit_does_not_open_tty() {
        let _slot = take_slot();

        let service = "cache-hit-service";
        let ctx = context(Some(service), Some("xfce4-screensaver-dialog"));
        let conclusion = crate::outcome::Outcome::granted_from_daemon();
        let conclusion_code = conclusion.clone().to_pam();

        for _ in 0..64 {
            record_conclusion(
                "tty-probe-test-user",
                service,
                conclusion.clone(),
                Instant::now(),
            );
            let (finished, probes) = run_with_probe(
                &ctx,
                Some("/dev/null"),
                || Err::<NullIpc, _>(no_daemon()),
                |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
            );
            if finished.outcome().clone().to_pam() != conclusion_code {
                // A concurrent test replaced the single record before the
                // lookup; nothing was proved about the ordering, so re-take it.
                continue;
            }
            assert_eq!(
                probes, 0,
                "a cache hit must replay the conclusion and never open /dev/tty"
            );
            return;
        }
        panic!(
            "the reuse record was replaced by a concurrent test before every one of 64 \
             attempts, so the cache-hit path was never observed"
        );
    }

    /// The two pre-arm IPC failures *emit* their own message, and neither is
    /// recorded.
    ///
    /// The defect this catches: the `host.emit` call deleted from the
    /// connect-failure or send-failure return, so the user is told nothing on
    /// the one path where the daemon could not be reached at all — and a
    /// restructure that emitted only inside the `Concluded` arm, which leaves
    /// both of these `Unrecorded` and silent. It also pins the mapping: a
    /// connect failure reported as `DaemonSendFailed` would show
    /// `communication_error` where `cannot_connect` belongs. The recorded
    /// emission is the assertion, not `notice(&msgs)` re-derived in the test,
    /// because a re-derived notice passes with every `emit` call deleted.
    #[test]
    fn unrecorded_paths_emit_their_notice() {
        let msgs = PamMessages::new("en");
        let ctx = context(Some("unrecorded-paths"), Some("totally-unknown"));

        let (connect_failed, shown) = shown_while_running(
            &ctx,
            "unrecorded-emit-user",
            || Err::<NullIpc, _>(no_daemon()),
            |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
        );
        assert!(
            matches!(
                &connect_failed,
                Finished::Unrecorded(Outcome::Unavailable(UnavailableReason::DaemonUnreachable))
            ),
            "a refused connect is an unrecorded DaemonUnreachable"
        );
        assert_eq!(
            connect_failed.outcome().clone().to_pam(),
            crate::pam_sys::PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(
            shown,
            vec![Emitted {
                style: NoticeStyle::Error,
                text: msgs.cannot_connect().to_owned(),
            }],
            "the connect failure must have emitted cannot_connect, as an error, \
             and nothing else"
        );

        let (send_failed, shown) = shown_while_running(
            &ctx,
            "unrecorded-emit-user",
            || Ok(NullIpc),
            |_: &mut NullIpc, _: &SendParams<'_>| Err(no_daemon()),
        );
        assert!(
            matches!(
                &send_failed,
                Finished::Unrecorded(Outcome::Unavailable(UnavailableReason::DaemonSendFailed))
            ),
            "a failed write is an unrecorded DaemonSendFailed"
        );
        assert_eq!(
            send_failed.outcome().clone().to_pam(),
            crate::pam_sys::PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(
            shown,
            vec![Emitted {
                style: NoticeStyle::Error,
                text: msgs.communication_error().to_owned(),
            }],
            "the send failure must have emitted communication_error, as an error, \
             and nothing else"
        );
    }

    /// A duplicate answered from the record is a `Via::Replay` conclusion.
    ///
    /// The defect this catches: a cache hit reported as `Via::Daemon`, which
    /// `record` accepts — so the duplicate would re-record the verdict and turn
    /// the fixed 500 ms window into a sliding one — and a replay that keeps the
    /// original provenance, which re-emits the message the first call already
    /// showed.
    #[test]
    fn a_cache_hit_is_a_replay_conclusion() {
        let _slot = take_slot();

        let service = "replay-provenance-service";
        let ctx = context(Some(service), Some("xfce4-screensaver-dialog"));
        let recorded = Outcome::granted_from_daemon();

        for _ in 0..64 {
            record_conclusion(
                "tty-probe-test-user",
                service,
                recorded.clone(),
                Instant::now(),
            );
            let (finished, _) = run_with_probe(
                &ctx,
                Some("/dev/null"),
                || Err::<NullIpc, _>(no_daemon()),
                |_, _| Ok(()),
            );

            let Finished::Concluded(concluded) = finished else {
                // A concurrent test replaced the single record before the
                // lookup; nothing was proved about the provenance.
                continue;
            };
            assert_eq!(
                concluded.via(),
                crate::transaction::Via::Replay,
                "a cache hit must be marked as a replay"
            );
            assert_eq!(
                concluded.outcome(),
                &Outcome::replayed(&recorded),
                "a replay must carry the recorded verdict, marked as replayed"
            );
            // The replay marker is what refuses the re-record (today's
            // `from_cache`): recording the conclusion hands its verdict back
            // and must leave the slot exactly as the first call recorded it.
            assert_eq!(
                crate::conclusion_cache::record(concluded, Instant::now()),
                Outcome::replayed(&recorded),
                "a cache hit must not be recorded again: it would slide the window"
            );
            assert_eq!(
                replay_for(
                    "tty-probe-test-user",
                    service,
                    Instant::now()
                )
                .map(|c| c.outcome().clone()),
                Some(Outcome::replayed(&recorded)),
                "the slot must still hold the verdict the first call recorded, not                  the replay that tried to overwrite it"
            );
            return;
        }
        panic!(
            "the reuse record was replaced by a concurrent test before every one of 64 \
             attempts, so the cache-hit path was never observed"
        );
    }

    /// A replayed *failure* emits nothing, and its silence is a property of its
    /// provenance.
    ///
    /// The defect this catches: the cache-hit return being silent only because
    /// it returns early, so a later restructure that emitted
    /// `outcome.notice(..)` on the way out re-shows `communication_error` for a
    /// duplicate the user never made. The recorded verdict is an unavailability
    /// that *does* have a message — `Outcome::replayed` keeps the reason — so
    /// the outcome alone cannot explain the silence: `Via::Replay` must, which
    /// is what [`finish`] keys on.
    #[test]
    fn a_replayed_failure_emits_nothing() {
        let _slot = take_slot();

        let service = "replay-emit-service";
        let ctx = context(Some(service), Some("xfce4-screensaver-dialog"));
        let recorded = Outcome::Unavailable(UnavailableReason::DaemonSendFailed);
        let msgs = PamMessages::new("en");

        for _ in 0..64 {
            record_conclusion(
                "replay-emit-user",
                service,
                recorded.clone(),
                Instant::now(),
            );
            let (finished, shown) = shown_while_running(
                &ctx,
                "replay-emit-user",
                || Err::<NullIpc, _>(no_daemon()),
                |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
            );
            let Finished::Concluded(concluded) = finished else {
                // A concurrent test replaced the single record before the
                // lookup; nothing was proved about the emission.
                continue;
            };
            assert_eq!(
                concluded.via,
                Via::Replay,
                "a duplicate answered from the record is a replay"
            );
            assert!(
                concluded.outcome.notice(&msgs).is_some(),
                "control: the recorded failure has a message \
                 (`communication_error`), so only the replay marker can make \
                 the emission silent"
            );
            assert_eq!(
                shown,
                Vec::new(),
                "a replay must emit nothing: the message was shown when the \
                 conclusion was first reached"
            );
            return;
        }
        panic!(
            "the reuse record was replaced by a concurrent test before every one of 64 \
             attempts, so the cache-hit path was never observed"
        );
    }
    // ------------------------------------------------------------------
    // The transaction's own ordering guarantees: the announcements and the
    // pre-collected arm.
    // ------------------------------------------------------------------

    /// The marker `shown_order` puts in the log where the request went on the
    /// wire: one entry of the same log as the emissions, so its position is the
    /// request's position.
    const OPEN_MARKER: &str = "Armed::open";

    /// A log entry that is not a message.
    fn marker(text: &str) -> Emitted {
        Emitted {
            style: NoticeStyle::Info,
            text: text.to_owned(),
        }
    }

    /// What `run` showed, in order, with the point the request went on the wire
    /// marked.
    ///
    /// The recording host is the only way an announcement can be observed
    /// without a real PAM handle; `send` runs inside `Armed::open`, so its mark
    /// is the request's position in the same log.
    fn shown_order(ctx: &CallerContext, tty: Option<&str>) -> Vec<Emitted> {
        let msgs = PamMessages::new("en");
        let log: std::cell::RefCell<Vec<Emitted>> = std::cell::RefCell::new(Vec::new());
        let mut host =
            HostIo::for_test_recording(std::ptr::null_mut(), &msgs, &log, unused_authtok);
        let participation = participation_for(ctx);
        let _finished = run(
            ctx,
            "announcement-order-user",
            &participation,
            &mut host,
            &zero_timeouts(),
            || tty.and_then(|path| std::fs::File::open(path).ok()),
            || Ok(NullIpc),
            |_: &mut NullIpc, _: &SendParams<'_>| {
                log.borrow_mut().push(marker(OPEN_MARKER));
                Ok(())
            },
            |_, _| {},
        );
        log.into_inner()
    }

    /// Drive `run` through a recording host with no terminal and report what it
    /// showed, in order.
    ///
    /// The transaction's own emissions are the assertion in the tests that use
    /// it, so a test can never re-derive the message from the outcome. The
    /// participation comes from `ctx`, so the path under test is the one
    /// `classify` really picks.
    fn shown_while_running<T, C, S>(
        ctx: &CallerContext,
        username: &str,
        connect: C,
        send: S,
    ) -> (Finished, Vec<Emitted>)
    where
        T: IpcResponseReader,
        C: FnOnce() -> Result<T, IpcError>,
        S: FnOnce(&mut T, &SendParams<'_>) -> Result<(), IpcError>,
    {
        let msgs = PamMessages::new("en");
        let log: std::cell::RefCell<Vec<Emitted>> = std::cell::RefCell::new(Vec::new());
        let mut host =
            HostIo::for_test_recording(std::ptr::null_mut(), &msgs, &log, unused_authtok);
        let participation = participation_for(ctx);
        let finished = run(
            ctx,
            username,
            &participation,
            &mut host,
            &zero_timeouts(),
            || None::<File>,
            connect,
            send,
            |_, _| {},
        );
        (finished, log.into_inner())
    }

    /// The position of the message `needle` in `log`, which must appear exactly
    /// once.
    fn once(log: &[Emitted], needle: &str) -> usize {
        let hits: Vec<usize> = log
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.text == needle)
            .map(|(at, _)| at)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "{needle:?} must be shown exactly once: {log:?}"
        );
        hits.first().copied().unwrap_or_default()
    }

    /// The three announcements keep the ordering they have today.
    ///
    /// The defect this catches: `Wait`/`WaitSkipHint` emitted *after* the
    /// request — so a host whose conversation has to reveal the password entry
    /// before it can answer never sees the message in time — or
    /// `WaitThenPassword` emitted *before* it, which is the opposite failure on
    /// the one host shape that needs it after: an event-loop host must already
    /// be blocked when the message arrives, which is why today's code emits it
    /// between the send and the blocking wait. This replaces `S4`
    /// (`test_sequential_wait_is_announced_before_it_blocks`), which could only
    /// compare two source byte offsets and had to name a call that no longer
    /// exists.
    #[test]
    fn announcement_order_matches_today() {
        let msgs = PamMessages::new("en");

        // Threaded: `waiting_for_tap` before the request.
        let log = shown_order(&context(Some("order-threaded"), Some("hyprlock")), None);
        assert!(
            once(&log, msgs.waiting_for_tap()) < once(&log, OPEN_MARKER),
            "the threaded wait is announced before the request: {log:?}"
        );

        // Terminal: `waiting_for_tap_skip` before the request.
        let log = shown_order(
            &context(Some("order-terminal"), Some("xfce4-screensaver-dialog")),
            Some("/dev/null"),
        );
        assert!(
            once(&log, msgs.waiting_for_tap_skip()) < once(&log, OPEN_MARKER),
            "the terminal wait is announced before the request: {log:?}"
        );

        // No-terminal sequential: `waiting_for_tap_password` *after* it.
        let log = shown_order(
            &context(
                Some("order-gui-sequential"),
                Some("xfce4-screensaver-dialog"),
            ),
            None,
        );
        assert!(
            once(&log, msgs.waiting_for_tap_password()) > once(&log, OPEN_MARKER),
            "the password-route announcement follows the request, once the \
             module is about to block: {log:?}"
        );
    }

    /// A pre-collected participation neither probes nor plans.
    ///
    /// The defect this catches: the handoff placed after the probe, the cache
    /// lookup or the request — which would open `/dev/tty` for a host that never
    /// uses it, consult the reuse record for a transaction that never happened,
    /// or, worst, ring the phone for a user who already chose the password
    /// route. The probe would return a terminal here, so a probe count of zero
    /// is a real assertion rather than a check that the file was missing.
    #[test]
    fn precollected_never_plans() {
        let ctx = context(Some("swaylock"), Some("swaylock"));
        let participation = participation_for(&ctx);
        assert_eq!(
            participation.conversation,
            Conversation::PreCollected,
            "swaylock is the pre-collected rule's host"
        );

        let msgs = PamMessages::new("en");
        let mut host = HostIo::for_test(std::ptr::null_mut(), None, &msgs, unused_authtok);
        let mut probes = 0usize;
        let connects = std::cell::Cell::new(0usize);
        let finished = run(
            &ctx,
            "precollected-user",
            &participation,
            &mut host,
            &zero_timeouts(),
            || {
                probes += 1;
                std::fs::File::open("/dev/null").ok()
            },
            || {
                connects.set(connects.get() + 1);
                Err::<NullIpc, _>(no_daemon())
            },
            |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
            |_, _| {},
        );

        assert_eq!(probes, 0, "a pre-collected host must not open /dev/tty");
        assert_eq!(connects.get(), 0, "a pre-collected host must not dial");
        assert!(
            matches!(
                &finished,
                Finished::Unrecorded(Outcome::Unavailable(UnavailableReason::PasswordHandoff))
            ),
            "the handoff is an unrecorded PasswordHandoff verdict"
        );
        assert_eq!(
            finished.outcome().clone().to_pam(),
            crate::pam_sys::PAM_AUTHINFO_UNAVAIL
        );
    }
}
