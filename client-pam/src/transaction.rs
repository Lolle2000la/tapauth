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

use crate::context::ServiceName;
use crate::ipc_client::{IpcClient, IpcError, IpcResponseReader};
use crate::outcome::Outcome;
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
    /// request was on the wire. At this step the mechanisms still return an
    /// [`Outcome`] (`MechanismEnd` arrives in step 6); step 6 narrows the
    /// parameter to `MechanismEnd` and moves the `from_daemon` call inside this
    /// function, so the daemon's answer is mapped where the conclusion is
    /// minted.
    pub(crate) fn conclude(
        self,
        outcome: Outcome,
        username: &str,
        service: Option<ServiceName>,
    ) -> Concluded {
        Concluded {
            outcome,
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
mod tests {
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
            Outcome::Unavailable(UnavailableReason::TimedOut),
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

        let recorded = armed().conclude(
            Outcome::granted_from_daemon(),
            user,
            Some(ServiceName::new("sudo")),
        );
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
        let recorded = armed().conclude(
            Outcome::granted_from_daemon(),
            user,
            Some(ServiceName::new("KScreenLocker")),
        );
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
}
