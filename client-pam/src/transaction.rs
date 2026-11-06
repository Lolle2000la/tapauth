//! What one authentication transaction produced, and the one owner of the
//! process's reuse record.
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
//! [`Via::Replay`], and [`ConclusionCache::record`] refuses it — which is what
//! keeps the fixed 500 ms window fixed.
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

use crate::config::PamConfig;
use crate::context::{CallerContext, ServiceName};
use crate::ipc_client::{IpcClient, IpcError, IpcResponseReader};
use crate::mechanism::{handoff, sequential, threaded};
use crate::outcome::{ErrorReason, Notice, NoticeStyle, Outcome, UnavailableReason};
use crate::pam_messages::PamMessages;
use crate::pam_sys::{PamConversation, PamHandle};
use crate::plan::{Announcement, Plannable, TtyUse};
use crate::policy::{Conversation, Participation};
use std::borrow::Cow;
use std::fs::File;
use std::sync::Mutex;
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
/// the recording gate's inputs and are read by [`ConclusionCache::record`], and
/// there is deliberately no constructor that a caller outside this module can
/// reach except [`Armed::conclude`] and [`Concluded::replay`].
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

    /// The replay constructor, and the only producer of [`Via::Replay`].
    ///
    /// It takes the *recorded* `Outcome` — a value [`Armed::conclude`] produced
    /// earlier in this process — copies it through `Outcome::replayed`, and
    /// marks the token `Via::Replay`, which [`ConclusionCache::record`] refuses.
    /// Its production caller is the cache hit in [`replay_for`]; a test may
    /// build one directly, which is how `a_from_cache_verdict_is_not_recorded`
    /// pins that the marker — not a local flag — is what refuses the re-record.
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

/// The PAM handle and the messages the orchestration built, plus — in
/// production only — the conversation they belong to.
///
/// `new` is the only production constructor and always passes `Some`; `for_test`
/// is its `#[cfg(test)]` counterpart and passes `None`, which makes [`emit`] a
/// no-op, so a test never opens a real PAM handle. A test that needs to *see*
/// the emission order uses `for_test_recording`, which records the text instead.
///
/// The type deliberately owns no terminal: the `/dev/tty` file is `run`'s local
/// and is consumed by the sequential mechanism.
pub(crate) struct HostIo<'a> {
    pamh: *mut PamHandle,
    conv: Option<&'a PamConversation<'a>>,
    msgs: &'a PamMessages,
    /// Test-only record of what [`emit`] was asked to show.
    #[cfg(test)]
    emitted: Option<&'a std::cell::RefCell<Vec<String>>>,
}

impl<'a> HostIo<'a> {
    pub(crate) fn new(
        pamh: *mut PamHandle,
        conv: &'a PamConversation<'a>,
        msgs: &'a PamMessages,
    ) -> Self {
        HostIo {
            pamh,
            conv: Some(conv),
            msgs,
            #[cfg(test)]
            emitted: None,
        }
    }

    /// The handle a mechanism needs for its one conversation call, if any.
    pub(crate) fn pamh(&self) -> *mut PamHandle {
        self.pamh
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
            log.borrow_mut().push(notice.text.to_string());
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
    ) -> Self {
        HostIo {
            pamh,
            conv,
            msgs,
            emitted: None,
        }
    }

    /// A host that records what it was asked to show, in order.
    ///
    /// The only way an ordering assertion can see an announcement without a real
    /// PAM handle, which is what `announcement_order_matches_today` needs.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn for_test_recording(
        pamh: *mut PamHandle,
        msgs: &'a PamMessages,
        emitted: &'a std::cell::RefCell<Vec<String>>,
    ) -> Self {
        HostIo {
            pamh,
            conv: None,
            msgs,
            emitted: Some(emitted),
        }
    }
}

/// Window during which the verdict this process just concluded may be
/// replayed instead of starting a second authentication transaction.
///
/// What it guards: a duplicate transaction some lock screens issue right after
/// a transaction concludes.  kscreenlocker ≥ 6.8 queues the duplicate
/// `Authenticate()` about a second into the first transaction — while it is
/// still running — and dispatches it the moment the first call returns,
/// whatever its outcome, because its `PamAuthenticator::promptInternal()`
/// clears the busy guard before the heartbeat's request can be observed and
/// dropped.  The real fix is the upstream busy-guard change; until then the
/// duplicate is answered here.  Without it the second call is a full
/// transaction: a new request id, a new daemon challenge, and a second ring of
/// the phone (or a second full timeout) for a single unlock.
///
/// Why replay *any* concluded code, not just `Success`: the duplicate was
/// queued while the first transaction was still running, so no user could have
/// initiated it.  Re-asking the phone about a request the user never made is
/// wrong in both directions — a success would ring twice, and a failure
/// (`PAM_AUTHINFO_UNAVAIL` for a phone timeout or an unpaired device, or
/// `PAM_PERM_DENIED`) would ring again and wait out another full timeout for a
/// question that was just answered.
///
/// Why 500 ms: the observed duplicate gap is 0.37 ms, so 500 ms absorbs
/// scheduling jitter on a loaded host, while a human re-lock or a second login
/// as the same user takes seconds — no human-initiated retry can fall inside
/// the window, which is what keeps a genuine second attempt from being
/// answered by a cached failure.
///
/// Where the window starts: at this module's **return**.  `authenticate` records
/// the conclusion only after `orchestrate` has handed it back, so the 500 ms
/// runs from the end of the `pam_authenticate` call, not from the moment the
/// transaction concluded.  That is what matches the host behaviour it exists
/// for (the duplicate is dispatched the instant the first call returns), but it
/// also bounds the suppression: a module *after* `pam_tapauth.so` in the same
/// stack that blocks for longer than 500 ms pushes the host's duplicate outside
/// the window, and that duplicate rings the phone again.  Suppression is a
/// heuristic for a host that re-enters immediately, not a guarantee that a
/// second `pam_authenticate` in the same process is always answered locally.
const VERDICT_REUSE_WINDOW: Duration = Duration::from_millis(500);

/// The conclusion this process recorded last, with the user and service it
/// belongs to.
///
/// Process-wide because the duplicate transaction comes from the same host
/// process.  Keyed on `(username, service)` because the duplicate is the same
/// user against the same PAM service, so a different user *or* a different
/// service takes the normal path and rings the phone.  The remaining assumption
/// is that no legitimate host performs an *independent* authentication for the
/// same user and service within 500 ms of a concluded one: the key cannot tell
/// such a request apart from a duplicate.  A new process always misses, because
/// `pam_end` unloads the module and the cache dies with it.
struct LastConclusion {
    concluded_at: Instant,
    username: String,
    service: String,
    outcome: Outcome,
}

/// The last conclusion of this process, replayed for
/// [`VERDICT_REUSE_WINDOW`] only.
///
/// `std::sync::Mutex` is const-constructible on stable, so no lazy initializer
/// (and no `once_cell`) is needed.  The lock is an optimisation, never a
/// credential: a poisoned lock is ignored rather than fatal, so losing the
/// cache only costs one duplicate request.
///
/// The static is private to this module and is named by no other file:
/// [`record`] and [`replay_for`] are the only way to reach the record, which is
/// what keeps a change to its representation (an `atfork` reinit, an atomic
/// cell, or removing it) inside this type.
static LAST_CONCLUSION: Mutex<Option<LastConclusion>> = Mutex::new(None);

/// The 500 ms reuse record and its lock, owned by exactly one type.
///
/// The type is zero-sized: the state is the private static above. It exists so
/// the record has an owner to hang `lookup` and `record` on, and so no other
/// module can name the lock — `mechanism/*`, `Plan` and `Outcome` cannot touch
/// it, and `pam_logic` reaches it through [`record`] and [`replay_for`] only.
pub(crate) struct ConclusionCache {
    /// No state of its own; the record lives in `LAST_CONCLUSION`.
    _private: (),
}

/// The process's one cache. Zero-sized; the state is `LAST_CONCLUSION`.
const CACHE: ConclusionCache = ConclusionCache { _private: () };

/// Whether `prev` may be replayed for `username` against `service` at `now` —
/// any code, not just a success.
///
/// Pure so the window can be tested without touching the process-wide cache.
/// `Instant` is `CLOCK_MONOTONIC` and never steps backwards, so the subtraction
/// can only be unavailable when the recorded instant came from another clock
/// origin (or is a later `Instant` constructed in a test); saturating reads
/// that as "no time passed" instead of panicking.
fn reusable_conclusion(
    prev: &LastConclusion,
    username: &str,
    service: &str,
    now: Instant,
) -> Option<Outcome> {
    if prev.username == username
        && prev.service == service
        && now.saturating_duration_since(prev.concluded_at) < VERDICT_REUSE_WINDOW
    {
        return Some(prev.outcome.clone());
    }
    None
}

/// The replayable record inside `slot` at `now`, with its age.
///
/// The age is the distance from the recorded instant to `now` — i.e. measured
/// from this module's return, which is where `authenticate` records it.
fn recorded_in(
    slot: &Option<LastConclusion>,
    username: &str,
    service: &str,
    now: Instant,
) -> Option<(Outcome, Duration)> {
    slot.as_ref().and_then(|prev| {
        reusable_conclusion(prev, username, service, now)
            .map(|outcome| (outcome, now.saturating_duration_since(prev.concluded_at)))
    })
}

impl ConclusionCache {
    /// The cached verdict for `(username, service)` at `now`, together with how
    /// long ago it was recorded, if it may be replayed.
    ///
    /// A poisoned lock returns `None`: the cache is an optimisation, so
    /// ignoring it is always a correct answer.
    fn lookup(&self, username: &str, service: &str, now: Instant) -> Option<(Outcome, Duration)> {
        let Ok(guard) = LAST_CONCLUSION.lock() else {
            return None;
        };
        recorded_in(&guard, username, service, now)
    }

    /// The cache hit for `(username, service)` as a conclusion that must not be
    /// recorded.
    ///
    /// The hit log lives here rather than at the call site: it is the cache's
    /// own event, and it carries the age the record knows.
    fn replay_for(&self, username: &str, service: &str, now: Instant) -> Option<Concluded> {
        let (recorded, age) = self.lookup(username, service, now)?;
        tracing::debug!(
            username = %username,
            service = %service,
            outcome = ?recorded,
            age_ms = age.as_millis(),
            "Replaying the concluded verdict for a duplicate transaction"
        );
        Some(Concluded::replay(
            recorded,
            username.into(),
            ServiceName::new(service),
        ))
    }

    /// Remember `concluded` as this process's last conclusion, and hand its
    /// verdict back.
    ///
    /// The token is taken **by value**, so one conclusion cannot be recorded
    /// twice, and both existing gates are inside: a conclusion whose service
    /// never resolved records nothing (it would collapse unrelated services
    /// into the empty key), and a [`Via::Replay`] one records nothing (that
    /// would refresh the timestamp and turn the fixed window into a sliding
    /// one). It is the *last* conclusion, so a non-success verdict overwrites an
    /// earlier success: a later denial must invalidate the cached grant, never
    /// sit behind it. The record holds the `Outcome`, not a code, so a replay
    /// cannot re-enter the code path.
    ///
    /// `at` is the moment the module returned to the host, which is the anchor
    /// of [`VERDICT_REUSE_WINDOW`] — not the moment the transaction concluded.
    fn record(&self, concluded: Concluded, at: Instant) -> Outcome {
        let Concluded {
            outcome,
            username,
            service,
            via,
        } = concluded;
        if via == Via::Daemon {
            if let Some(service) = service {
                if let Ok(mut guard) = LAST_CONCLUSION.lock() {
                    *guard = Some(LastConclusion {
                        concluded_at: at,
                        username,
                        service: service.original().to_owned(),
                        outcome: outcome.clone(),
                    });
                }
            }
        }
        outcome
    }

    /// Today's test seam, kept so the poisoned-lock test can poison its own
    /// mutex instead of the process-wide one: a poisoned lock is a miss, not a
    /// panic.
    #[cfg(test)]
    fn lookup_in(
        lock: &Mutex<Option<LastConclusion>>,
        username: &str,
        service: &str,
        now: Instant,
    ) -> Option<(Outcome, Duration)> {
        let Ok(guard) = lock.lock() else {
            return None;
        };
        recorded_in(&guard, username, service, now)
    }
}

/// Record `concluded` as this process's last conclusion and hand its verdict
/// back — the only way to write the reuse record.
pub(crate) fn record(concluded: Concluded, at: Instant) -> Outcome {
    CACHE.record(concluded, at)
}

/// This process's replayable conclusion for `(username, service)` at `now` —
/// the only way to read the reuse record.
pub(crate) fn replay_for(username: &str, service: &str, now: Instant) -> Option<Concluded> {
    CACHE.replay_for(username, service, now)
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
/// Every return emits its verdict's one message through `host` before returning,
/// so a message can be neither lost by an early return nor doubled; the paths
/// that return before a conversation exists carry outcomes whose notice is
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
            host.emit(outcome.notice(host.msgs));
            return Finished::Unrecorded(outcome);
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
            return Finished::Concluded(concluded);
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
        return Finished::Unrecorded(Outcome::Error(ErrorReason::RequestId));
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
            host.emit(outcome.notice(host.msgs));
            return Finished::Unrecorded(outcome);
        }
        Err(StartError::Send(e)) => {
            tracing::error!("Failed to send authenticate request: {}", e);
            let outcome = Outcome::Unavailable(UnavailableReason::DaemonSendFailed);
            host.emit(outcome.notice(host.msgs));
            return Finished::Unrecorded(outcome);
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
        Plannable::Threaded => threaded::drive(&mut armed, &plan, deadline_at, host.pamh()),
        Plannable::Sequential => {
            sequential::drive(&mut armed, &plan, deadline_at, tty_file, cancel)
        }
    };

    let concluded = armed.conclude(end, username, ctx.service().cloned());
    host.emit(concluded.outcome.notice(host.msgs));
    Finished::Concluded(concluded)
}

/// The test carrier over a fake reader; no test opens a real daemon socket.
#[cfg(test)]
pub(crate) fn armed_for_test<I: IpcResponseReader>(ipc: I, request_id: &str) -> Armed<I> {
    Armed {
        ipc,
        request_id: request_id.into(),
    }
}

/// Serialises the tests that drive the process-wide reuse slot from a record to
/// a lookup.
///
/// The record is one slot for the whole process, so two tests that each record
/// and then look up would otherwise overwrite each other between the two steps
/// and read a miss. It lives here, beside the slot it serialises, and it is
/// `#[cfg(test)]` code — the source scan that keeps the lock local exempts it
/// explicitly.
#[cfg(test)]
pub(crate) static CACHE_SLOT_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
pub(crate) mod tests {
    use super::*;
    use crate::outcome::{GrantVia, UnavailableReason};
    use std::sync::atomic::{AtomicBool, Ordering};

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

    fn take_slot() -> std::sync::MutexGuard<'static, ()> {
        CACHE_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// An `Armed` over a transport nothing will use: the request is "on the
    /// wire" as far as the types are concerned.
    fn armed() -> Armed<UnusedIpc> {
        armed_for_test(UnusedIpc, "transaction-test-request")
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
        let mut host = HostIo::for_test(std::ptr::null_mut(), None, &msgs);
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
    fn record_conclusion(username: &str, service: &str, outcome: Outcome, at: Instant) {
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

    /// The record is keyed on the service name's original bytes, so `sudo` and
    /// `SUDO` are different keys.
    ///
    /// The defect this catches: keying on an ASCII-lowercased service, which
    /// would let a conclusion recorded for `sudo` answer a `SUDO` stack —
    /// the corpus's `service_case_*` rows only prove that `classify` sees both
    /// spellings alike, not that the cache keeps them apart.
    #[test]
    fn reuse_key_is_case_sensitive() {
        let _slot = take_slot();
        let user = "case-key-user";
        let now = Instant::now();

        let recorded = armed().conclude(success_end(), user, Some(ServiceName::new("sudo")));
        record(recorded, now);

        assert!(
            replay_for(user, "sudo", now).is_some(),
            "the recorded spelling must hit"
        );
        assert!(
            replay_for(user, "SUDO", now).is_none(),
            "`SUDO` is a different key: folding the service would answer another \
             stack from this process's record"
        );

        // And the other direction, so neither spelling is privileged.
        let recorded =
            armed().conclude(success_end(), user, Some(ServiceName::new("KScreenLocker")));
        record(recorded, now);
        assert!(replay_for(user, "KScreenLocker", now).is_some());
        assert!(
            replay_for(user, "kscreenlocker", now).is_none(),
            "a case-folded key would answer the lowercase spelling from the \
             mixed-case entry"
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

    /// A poisoned lock reads as a cache miss.
    ///
    /// Moved here from `pam_logic::verdict_reuse_tests` when the record did: its
    /// seam (`lookup_in`, which takes the lock as a parameter) is private to the
    /// cache's module, so the test follows it. Same scenario, same assertion.
    ///
    /// The defect this catches: a poisoned lock unwrapped or panicked on, or
    /// read as a hit — either way a `PAM_SUCCESS` that is otherwise inside the
    /// window would be returned after another thread panicked.
    #[test]
    fn a_poisoned_lock_reads_as_a_cache_miss() {
        let local: Mutex<Option<LastConclusion>> = Mutex::new(Some(LastConclusion {
            concluded_at: Instant::now(),
            username: "alice".to_owned(),
            service: "tapauth-test".to_owned(),
            outcome: Outcome::granted_from_daemon(),
        }));

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = local.lock().expect("a fresh mutex is not poisoned");
            panic!("poison the local lock while holding it");
        }));
        assert!(
            poisoned.is_err(),
            "the helper closure was supposed to panic"
        );

        assert_eq!(
            ConclusionCache::lookup_in(&local, "alice", "tapauth-test", Instant::now()),
            None,
            "a poisoned lock must read as a cache miss: a `PAM_SUCCESS` that is \
             otherwise inside the window must not be returned, and the path must \
             not unwrap or panic"
        );
    }

    /// The cache survives a fork taken while another thread holds its lock.
    ///
    /// The defect this catches (D4): `LAST_CONCLUSION` has no `pthread_atfork`
    /// handler, so a fork taken while another thread holds the lock leaves the
    /// child blocked forever on its first `pam_authenticate` — the lock's owner
    /// does not exist in the child — and the child also inherits the recorded
    /// conclusion itself, so a lookup there can replay a verdict this process
    /// reached before the fork.
    ///
    /// This asserts the *fixed* behaviour, so it fails against the tree as it
    /// stands and ships `#[ignore]`d. The three candidate fixes it tells apart
    /// are (i) `pthread_atfork` to reinitialise the lock in the child, (ii)
    /// replacing `Mutex<Option<..>>` with an atomic/seqlock cell, and (iii)
    /// dropping the cache altogether (F1); (i) and (ii) keep the inherited
    /// record and (iii) removes it, which is the decision the fix has to make.
    /// Whichever lands removes the attribute and this test becomes its
    /// acceptance test.
    ///
    /// The gate is glibc only today: no musl target exists in CI and the module
    /// links libpam dynamically, so "built for both, run on both" is a
    /// requirement rather than a present fact.
    #[test]
    #[ignore = "known latent defect (D4): a fork while another thread holds LAST_CONCLUSION leaves the \
                child blocked, and the child inherits the recorded conclusion. The three candidate fixes \
                are (i) a pthread_atfork reinit of the lock, (ii) an atomic/seqlock cell instead of the \
                Mutex, and (iii) dropping the cache (F1). This test is the acceptance test for whichever \
                of them lands"]
    fn conclusion_cache_survives_fork() {
        static HELD: AtomicBool = AtomicBool::new(false);
        static RELEASE: AtomicBool = AtomicBool::new(false);

        let holder = std::thread::spawn(|| {
            let _guard = LAST_CONCLUSION
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            HELD.store(true, Ordering::SeqCst);
            // Hold until the parent has forked: the fork must happen while a
            // thread that will not exist in the child owns the lock.
            while !RELEASE.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
        });

        while !HELD.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child. Only async-signal-safe work: an `alarm` so a blocked lock
            // cannot hang the suite, the lock attempt itself, and `_exit` — not
            // `exit`, so no atexit handler or Rust destructor runs on the
            // forked copy of the parent's state.
            unsafe {
                libc::alarm(5);
                let _guard = LAST_CONCLUSION.lock();
                libc::_exit(0);
            }
        }
        assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());

        RELEASE.store(true, Ordering::SeqCst);
        holder.join().expect("the lock holder must be reaped");

        let mut status: libc::c_int = 0;
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(reaped, pid, "waitpid must reap the child");
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the child could not take the cache lock after the parent forked \
             while another thread held it (wait status {status}): a blocked \
             child is killed by its own alarm, so this is the D4 defect"
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

    /// The two pre-arm IPC failures keep their own messages, and neither is
    /// recorded.
    ///
    /// The defect this catches: a connect failure mapped onto
    /// `DaemonSendFailed` (so the user sees `communication_error` where
    /// `cannot_connect` belongs, see `Outcome::notice`), and either failure
    /// treated as a conclusion — arming the record would let a duplicate replay
    /// a verdict the daemon never reached. The emission itself is not
    /// observable through a dummy conversation, so what is pinned here is the
    /// reason each path returns, which is where the text comes from.
    #[test]
    fn unrecorded_paths_name_their_notice() {
        let msgs = crate::pam_messages::load_for_user("unrecorded-test-user");
        let ctx = context(Some("unrecorded-paths"), Some("totally-unknown"));

        let (connect_failed, _) = run_with_probe(
            &ctx,
            None,
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
        let notice = connect_failed.outcome().notice(&msgs);
        assert_eq!(
            notice.map(|n| (n.style, n.text.into_owned())),
            Some((
                crate::outcome::NoticeStyle::Error,
                msgs.cannot_connect().to_owned()
            )),
            "the connect failure must still show cannot_connect, as an error"
        );

        let (send_failed, _) = run_with_probe(
            &ctx,
            None,
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
        let notice = send_failed.outcome().notice(&msgs);
        assert_eq!(
            notice.map(|n| (n.style, n.text.into_owned())),
            Some((
                crate::outcome::NoticeStyle::Error,
                msgs.communication_error().to_owned()
            )),
            "the send failure must still show communication_error, as an error"
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
                crate::transaction::record(concluded, Instant::now()),
                Outcome::replayed(&recorded),
                "a cache hit must not be recorded again: it would slide the window"
            );
            assert_eq!(
                crate::transaction::replay_for(
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
    // ------------------------------------------------------------------
    // The transaction's own ordering guarantees: the announcements and the
    // pre-collected arm.
    // ------------------------------------------------------------------

    /// What `run` showed, in order, with the point the request went on the wire
    /// marked.
    ///
    /// The recording host is the only way an announcement can be observed
    /// without a real PAM handle; `send` runs inside `Armed::open`, so its mark
    /// is the request's position in the same log.
    fn shown_order(ctx: &CallerContext, tty: Option<&str>) -> Vec<String> {
        const OPEN: &str = "Armed::open";
        let msgs = PamMessages::new("en");
        let log: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
        let mut host = HostIo::for_test_recording(std::ptr::null_mut(), &msgs, &log);
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
                log.borrow_mut().push(OPEN.to_owned());
                Ok(())
            },
            |_, _| {},
        );
        log.into_inner()
    }

    /// The position of `needle` in `log`, which must appear exactly once.
    fn once(log: &[String], needle: &str) -> usize {
        let hits: Vec<usize> = log
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.as_str() == needle)
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
        const OPEN: &str = "Armed::open";
        let msgs = PamMessages::new("en");

        // Threaded: `waiting_for_tap` before the request.
        let log = shown_order(&context(Some("order-threaded"), Some("hyprlock")), None);
        assert!(
            once(&log, msgs.waiting_for_tap()) < once(&log, OPEN),
            "the threaded wait is announced before the request: {log:?}"
        );

        // Terminal: `waiting_for_tap_skip` before the request.
        let log = shown_order(
            &context(Some("order-terminal"), Some("xfce4-screensaver-dialog")),
            Some("/dev/null"),
        );
        assert!(
            once(&log, msgs.waiting_for_tap_skip()) < once(&log, OPEN),
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
            once(&log, msgs.waiting_for_tap_password()) > once(&log, OPEN),
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
        let mut host = HostIo::for_test(std::ptr::null_mut(), None, &msgs);
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
