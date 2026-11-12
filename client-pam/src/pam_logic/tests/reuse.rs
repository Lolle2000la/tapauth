//! The 500 ms reuse corpus: the window, its `(username, service)` key, and the two gates that
//! decide what may be recorded.
//!
//! Every case drives the real `conclusion_cache::record` / `conclusion_cache::replay_for` pair,
//! so the assertions are about the record `authenticate` writes and reads and not about a
//! parallel copy of its logic. Each case holds `conclusion_cache::CACHE_SLOT_LOCK` for its
//! whole body, because the record is one slot for the process.

// `super::super` is `pam_logic` itself: the names these cases share with the module that
// records (`Outcome`, `ServiceName`, …) come from its imports.
use super::super::*;
use crate::conclusion_cache::{record, replay_for};
use crate::outcome::{DenyVia, UnavailableReason};
use crate::transaction::tests::{no_daemon, NullIpc};
use crate::transaction::{Armed, Concluded, StartError, Via};
use std::time::{Duration, Instant};

const SERVICE: &str = "tapauth-test";

/// The three verdicts these tests replay: a grant, an unavailable service and an explicit
/// denial — the three the daemon can reach.
fn granted() -> Outcome {
    Outcome::granted_from_daemon()
}

fn unavailable() -> Outcome {
    Outcome::Unavailable(UnavailableReason::TimedOut)
}

fn denied() -> Outcome {
    Outcome::Denied(DenyVia::PhoneDenial)
}

/// The mechanism exit a recorded verdict arrives as.
///
/// `Armed::conclude` takes a `MechanismEnd` — a mechanism never mints an `Outcome` — so a test
/// that records one of the three verdicts has to name the exit that produces it.
fn end_of(outcome: &Outcome) -> crate::mechanism::MechanismEnd {
    use crate::mechanism::MechanismEnd;
    match outcome {
        Outcome::Granted(_) => {
            let mut resp = shared::ipc::pb::PamAuthenticateResponse::default();
            resp.set_outcome(shared::ipc::pb::PamOutcome::Success);
            MechanismEnd::Response(resp)
        }
        Outcome::Denied(_) => {
            let mut resp = shared::ipc::pb::PamAuthenticateResponse::default();
            resp.set_outcome(shared::ipc::pb::PamOutcome::Denied);
            MechanismEnd::Response(resp)
        }
        Outcome::Unavailable(reason) => MechanismEnd::Reason(*reason),
        other => {
            unreachable!("the daemon reaches a grant, a denial or an unavailability, not {other:?}")
        }
    }
}

/// The single process-wide slot, held for the whole case.
fn slot() -> std::sync::MutexGuard<'static, ()> {
    crate::conclusion_cache::CACHE_SLOT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Record `outcome` for `(user, service)` as if it had concluded `ms_ago`, through the same
/// `Armed` — conclude — record path `authenticate` uses, and hand back the instant the lookup
/// should use.
fn record_ago(ms_ago: u64, user: &str, service: Option<&str>, outcome: Outcome) -> Instant {
    let now = Instant::now();
    let concluded = crate::transaction::armed_for_test(NullIpc, "reuse-test-request").conclude(
        end_of(&outcome),
        user,
        service.map(ServiceName::new),
    );
    let _ = record(concluded, now - Duration::from_millis(ms_ago));
    now
}

/// The verdict a lookup returns for `(user, service)` at `now`.
///
/// A hit is `Outcome::replayed(..)` of what was recorded: the marker is the provenance this
/// step adds, and `record` is what refuses it.
fn replayable(user: &str, service: &str, now: Instant) -> Option<Outcome> {
    replay_for(user, service, now).map(|concluded| concluded.outcome().clone())
}

#[test]
fn a_success_inside_the_window_is_reused() {
    let _slot = slot();
    let now = record_ago(400, "alice", Some(SERVICE), granted());
    assert_eq!(
        replayable("alice", SERVICE, now),
        Some(Outcome::replayed(&granted())),
        "a success 400 ms old must still be replayable inside the 500 ms window"
    );
}

#[test]
fn a_success_after_the_window_is_not_reused() {
    let _slot = slot();
    let now = record_ago(600, "alice", Some(SERVICE), granted());
    assert_eq!(
        replayable("alice", SERVICE, now),
        None,
        "a success 600 ms old is outside the window and must start a new transaction"
    );
}

#[test]
fn an_unavailability_inside_the_window_is_reused() {
    let _slot = slot();
    let now = record_ago(400, "alice", Some(SERVICE), unavailable());
    assert_eq!(
        replayable("alice", SERVICE, now),
        Some(Outcome::replayed(&unavailable())),
        "the duplicate is queued while the first transaction runs, so the \
         unavailability it just reached must be replayed instead of ringing \
         the phone for a second full timeout"
    );
}

#[test]
fn a_denial_inside_the_window_is_reused() {
    let _slot = slot();
    let now = record_ago(400, "alice", Some(SERVICE), denied());
    assert_eq!(
        replayable("alice", SERVICE, now),
        Some(Outcome::replayed(&denied())),
        "a concluded denial must be replayed for the duplicate, not re-asked"
    );
}

#[test]
fn an_unavailability_after_the_window_is_not_reused() {
    let _slot = slot();
    let now = record_ago(600, "alice", Some(SERVICE), unavailable());
    assert_eq!(
        replayable("alice", SERVICE, now),
        None,
        "outside the window a failure must be re-derived: this is what keeps a \
         human retry from being answered by a stale verdict"
    );
}

#[test]
fn another_users_conclusion_is_never_reused() {
    let _slot = slot();
    for outcome in [granted(), unavailable(), denied()] {
        let code = outcome.clone().into_pam();
        let now = record_ago(1, "alice", Some(SERVICE), outcome);
        assert_eq!(
            replayable("bob", SERVICE, now),
            None,
            "code {code} recorded for alice must never answer for bob"
        );
    }
}

#[test]
fn another_services_conclusion_is_never_reused() {
    let _slot = slot();
    for outcome in [granted(), unavailable(), denied()] {
        let code = outcome.clone().into_pam();
        let now = record_ago(1, "alice", Some("kscreenlocker"), outcome);
        assert_eq!(
            replayable("alice", "polkit-1", now),
            None,
            "code {code} recorded for one service must never answer a \
             different service: only the transaction the host is retrying may \
             be replayed, every other stack must ring the phone"
        );
    }
}

#[test]
fn recording_a_failure_replaces_the_cached_success() {
    let _slot = slot();
    let now = Instant::now();

    let recorded = crate::transaction::armed_for_test(NullIpc, "replace-success-request").conclude(
        end_of(&granted()),
        "alice",
        Some(ServiceName::new(SERVICE)),
    );
    record(recorded, now);
    assert_eq!(
        replayable("alice", SERVICE, now),
        Some(Outcome::replayed(&granted()))
    );

    let recorded = crate::transaction::armed_for_test(NullIpc, "replace-failure-request").conclude(
        end_of(&unavailable()),
        "alice",
        Some(ServiceName::new(SERVICE)),
    );
    record(recorded, now);
    assert_eq!(
        replayable("alice", SERVICE, now),
        Some(Outcome::replayed(&unavailable())),
        "the record holds the *last* conclusion, so a later failure must \
         overwrite the earlier success"
    );
}

/// A connect failure says nothing about the phone, so it must leave the process-wide record
/// unarmed — and a retry must therefore be able to start a real transaction instead of
/// replaying a verdict that never existed.
///
/// The key is unique to this test: the record is process-wide and other tests in this module
/// write to it in parallel.
///
/// Not covered here: a *caller* that records before opening a request — `record` takes a
/// `Concluded` by value and `Armed::conclude` is its only fresh producer, so that shape is a
/// move error rather than something a test has to look for.
#[test]
fn a_failed_connect_records_nothing_and_the_retry_dials_again() {
    let _slot = slot();

    const USER: &str = "failed-connect-user";
    const UNIQUE_SERVICE: &str = "failed-connect-service";
    let now = Instant::now();

    let first = Armed::<NullIpc>::open(
        &mut || Err(no_daemon()),
        &mut |_: &mut NullIpc| Ok(()),
        "failed-connect-request".into(),
    );
    assert!(
        matches!(first, Err(StartError::Connect(_))),
        "a refused connect must surface as a connect failure"
    );
    assert!(
        replayable(USER, UNIQUE_SERVICE, now).is_none(),
        "a local IPC failure is not a verdict about the phone: recording one \
         would let the duplicate inherit PAM_AUTHINFO_UNAVAIL without the \
         phone ever being asked"
    );

    // The retry: with nothing recorded it must dial again and arm a real transaction, whose
    // conclusion *is* recorded.
    let Ok(armed) = Armed::<NullIpc>::open(
        &mut || Ok(NullIpc),
        &mut |_: &mut NullIpc| Ok(()),
        "retry-request".into(),
    ) else {
        panic!("the retry must be able to connect after the failed attempt");
    };
    let concluded = armed.conclude(
        end_of(&unavailable()),
        USER,
        Some(ServiceName::new(UNIQUE_SERVICE)),
    );
    assert_eq!(
        concluded.via(),
        Via::Daemon,
        "the armed request is this call's own, so `record` must accept its conclusion"
    );
    assert_eq!(record(concluded, now), unavailable());
    assert_eq!(
        replayable(USER, UNIQUE_SERVICE, now),
        Some(Outcome::replayed(&unavailable())),
        "the retry's conclusion must be recorded, unlike the failed connect"
    );
}

/// A verdict replayed from the record must not be recorded again: that would refresh the
/// timestamp and turn the fixed 500 ms window into a sliding one.
#[test]
fn a_from_cache_verdict_is_not_recorded() {
    let _slot = slot();

    const USER: &str = "from-cache-user";
    const UNIQUE_SERVICE: &str = "from-cache-service";
    let now = Instant::now();

    let recorded = crate::transaction::armed_for_test(NullIpc, "original-request").conclude(
        end_of(&denied()),
        USER,
        Some(ServiceName::new(UNIQUE_SERVICE)),
    );
    record(recorded, now);

    // A replay carrying a *different* verdict, recorded again on purpose: if `record` accepted
    // it, the slot would hold the grant instead of the denial and the assertion below would see
    // it.
    let replay = Concluded::replay(granted(), USER.into(), ServiceName::new(UNIQUE_SERVICE));
    assert_eq!(record(replay, now), Outcome::replayed(&granted()));
    assert_eq!(
        replayable(USER, UNIQUE_SERVICE, now),
        Some(Outcome::replayed(&denied())),
        "a cache hit must not be re-recorded: it would overwrite the original \
         code and refresh the timestamp, making the window sliding"
    );
}

/// An unresolved service is never cached: the empty string would collapse every such call into
/// one key.
#[test]
fn an_unresolved_service_is_not_recorded() {
    let _slot = slot();

    const USER: &str = "unresolved-service-user";
    let now = Instant::now();

    let recorded = crate::transaction::armed_for_test(NullIpc, "unresolved-service-request")
        .conclude(end_of(&unavailable()), USER, None);
    assert_eq!(record(recorded, now), unavailable());
    assert!(
        replayable(USER, "", now).is_none(),
        "a call without a service name must record nothing: an empty string \
         would merge unrelated services into one key"
    );
}

#[test]
fn a_future_timestamp_does_not_panic() {
    let _slot = slot();
    let now = Instant::now();

    let recorded = crate::transaction::armed_for_test(NullIpc, "future-timestamp-request")
        .conclude(
            end_of(&unavailable()),
            "alice",
            Some(ServiceName::new(SERVICE)),
        );
    record(recorded, now + Duration::from_millis(50));
    // `saturating_duration_since` reads a clock anomaly as "no time has passed", so the
    // conclusion still counts as fresh. The point of the test is that it must not panic.
    assert_eq!(
        replayable("alice", SERVICE, now),
        Some(Outcome::replayed(&unavailable())),
        "a record stamped in the future must read as fresh, not panic"
    );
}
