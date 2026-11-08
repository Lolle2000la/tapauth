//! The transaction's own behaviour: the armed→concluded state machine, the
//! pre-arm IPC failures and their notices, the reuse replay, and the
//! announcements' order. Declared (and allowed) by `transaction/mod.rs`.

use super::*;
use crate::conclusion_cache::tests::take_slot;
use crate::conclusion_cache::{record, replay_for};
use crate::config::PamConfig;
use crate::context::{CallerContext, ServiceName};
use crate::ipc_client::{IpcError, IpcResponseReader};
use crate::mechanism::MechanismEnd;
use crate::outcome::{GrantVia, NoticeStyle, Outcome, UnavailableReason};
use crate::pam_messages::PamMessages;
use crate::pam_sys::PamHandle;
use crate::policy::{Conversation, Participation};
use std::fs::File;
use std::os::raw::{c_char, c_int};
use std::time::Instant;

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
    match crate::policy::classify(ctx).1 {
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
fn run_with_probe<T: IpcResponseReader>(
    ctx: &CallerContext,
    tty: Option<&str>,
    connect: &mut dyn FnMut() -> Result<T, IpcError>,
    send: &mut dyn for<'p> FnMut(&mut T, &SendParams<'p>) -> Result<(), IpcError>,
) -> (Finished, usize) {
    let msgs = PamMessages::new("en");
    let mut host = HostIo::for_test(std::ptr::null_mut(), None, &msgs, unused_authtok);
    let participation = participation_for(ctx);
    let mut probes = 0usize;
    let mut probe = || {
        probes += 1;
        tty.and_then(|path| std::fs::File::open(path).ok())
    };
    let finished = run(
        ctx,
        "tty-probe-test-user",
        &participation,
        &mut host,
        &zero_timeouts(),
        &mut Effects {
            probe_tty: &mut probe,
            connect,
            send,
            cancel: |_, _| {},
        },
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
        finished.outcome().clone().into_pam(),
        crate::pam_sys::PAM_SUCCESS
    );

    let unreachable = Outcome::Unavailable(UnavailableReason::DaemonUnreachable);
    let unrecorded = Finished::Unrecorded(unreachable.clone());
    assert_eq!(unrecorded.outcome(), &unreachable);
    assert_eq!(
        unrecorded.outcome().clone().into_pam(),
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
    let mut refused = || {
        Err::<UnusedIpc, _>(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "no daemon socket",
        )))
    };

    let no_connect = Armed::open(&mut refused, &mut |_: &mut UnusedIpc| Ok(()), "rid".into());
    assert!(
        matches!(no_connect, Err(StartError::Connect(_))),
        "a refused connect must surface as a connect failure, not as a send \
         failure and not as an armed request"
    );

    let mut sent = false;
    let bad_send = Armed::open(
        &mut || Ok(UnusedIpc),
        &mut |_: &mut UnusedIpc| {
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

    let Ok(armed) = Armed::open(
        &mut || Ok(UnusedIpc),
        &mut |_: &mut UnusedIpc| Ok(()),
        "rid".into(),
    ) else {
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
        &mut || Err::<NullIpc, _>(no_daemon()),
        &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
    );
    assert_eq!(
        (finished.outcome().clone().into_pam(), probes),
        (crate::pam_sys::PAM_AUTHINFO_UNAVAIL, 0),
        "a threaded conversation must not open /dev/tty"
    );

    let sequential_tty = context(Some("probe-tty"), Some("xfce4-screensaver-dialog"));
    let (finished, probes) = run_with_probe(
        &sequential_tty,
        Some("/dev/null"),
        &mut || Err::<NullIpc, _>(no_daemon()),
        &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
    );
    assert_eq!(
        (finished.outcome().clone().into_pam(), probes),
        (crate::pam_sys::PAM_AUTHINFO_UNAVAIL, 1),
        "a sequential conversation probes /dev/tty exactly once"
    );

    let sequential_no_tty = context(Some("probe-no-tty"), Some("xfce4-screensaver-dialog"));
    let (finished, probes) = run_with_probe(
        &sequential_no_tty,
        None,
        &mut || Err::<NullIpc, _>(no_daemon()),
        &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
    );
    assert_eq!(
        (finished.outcome().clone().into_pam(), probes),
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
    let conclusion_code = conclusion.clone().into_pam();

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
            &mut || Err::<NullIpc, _>(no_daemon()),
            &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
        );
        if finished.outcome().clone().into_pam() != conclusion_code {
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
        &mut || Err::<NullIpc, _>(no_daemon()),
        &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
    );
    assert!(
        matches!(
            &connect_failed,
            Finished::Unrecorded(Outcome::Unavailable(UnavailableReason::DaemonUnreachable))
        ),
        "a refused connect is an unrecorded DaemonUnreachable"
    );
    assert_eq!(
        connect_failed.outcome().clone().into_pam(),
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
        &mut || Ok(NullIpc),
        &mut |_: &mut NullIpc, _: &SendParams<'_>| Err(no_daemon()),
    );
    assert!(
        matches!(
            &send_failed,
            Finished::Unrecorded(Outcome::Unavailable(UnavailableReason::DaemonSendFailed))
        ),
        "a failed write is an unrecorded DaemonSendFailed"
    );
    assert_eq!(
        send_failed.outcome().clone().into_pam(),
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
            &mut || Err::<NullIpc, _>(no_daemon()),
            &mut |_, _| Ok(()),
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
/// is what [`finish`](super::host_io::finish) keys on.
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
            &mut || Err::<NullIpc, _>(no_daemon()),
            &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
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
    let mut host = HostIo::for_test_recording(std::ptr::null_mut(), &msgs, &log, unused_authtok);
    let participation = participation_for(ctx);
    let _finished = run(
        ctx,
        "announcement-order-user",
        &participation,
        &mut host,
        &zero_timeouts(),
        &mut Effects {
            probe_tty: &mut || tty.and_then(|path| std::fs::File::open(path).ok()),
            connect: &mut || Ok(NullIpc),
            send: &mut |_: &mut NullIpc, _: &SendParams<'_>| {
                log.borrow_mut().push(marker(OPEN_MARKER));
                Ok(())
            },
            cancel: |_, _| {},
        },
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
fn shown_while_running<T: IpcResponseReader>(
    ctx: &CallerContext,
    username: &str,
    connect: &mut dyn FnMut() -> Result<T, IpcError>,
    send: &mut dyn for<'p> FnMut(&mut T, &SendParams<'p>) -> Result<(), IpcError>,
) -> (Finished, Vec<Emitted>) {
    let msgs = PamMessages::new("en");
    let log: std::cell::RefCell<Vec<Emitted>> = std::cell::RefCell::new(Vec::new());
    let mut host = HostIo::for_test_recording(std::ptr::null_mut(), &msgs, &log, unused_authtok);
    let participation = participation_for(ctx);
    let finished = run(
        ctx,
        username,
        &participation,
        &mut host,
        &zero_timeouts(),
        &mut Effects {
            probe_tty: &mut || None::<File>,
            connect,
            send,
            cancel: |_, _| {},
        },
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
        &mut Effects {
            probe_tty: &mut || {
                probes += 1;
                std::fs::File::open("/dev/null").ok()
            },
            connect: &mut || {
                connects.set(connects.get() + 1);
                Err::<NullIpc, _>(no_daemon())
            },
            send: &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
            cancel: |_, _| {},
        },
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
        finished.outcome().clone().into_pam(),
        crate::pam_sys::PAM_AUTHINFO_UNAVAIL
    );
}
