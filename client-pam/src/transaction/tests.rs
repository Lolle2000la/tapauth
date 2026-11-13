//! The transaction's own behaviour: the armed→concluded state machine, the pre-arm IPC failures
//! and their notices, the reuse replay, and the announcements' order.

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

/// The crate's transport double: a reader that carries nothing, for paths that never use it.
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

fn concluded(outcome: Outcome, via: Via) -> Concluded {
    Concluded {
        outcome,
        username: "alice".to_owned(),
        service: Some(ServiceName::new("sudo")),
        via,
    }
}

// ------------------------------------------------------------------
// The harness the `run` tests share. No test opens a daemon socket.
// ------------------------------------------------------------------

/// A connect that fails the way a missing socket does.
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

/// Timeouts of zero: these tests assert call counts and orderings, not waiting.
fn zero_timeouts() -> PamConfig {
    PamConfig {
        pam_operation_timeout_secs: 0,
        pam_gui_timeout_secs: 0,
        ..PamConfig::default()
    }
}

fn context(service: Option<&str>, process: Option<&str>) -> CallerContext {
    let process = match process {
        Some(name) => crate::context::ProcessIdentity::Exe(name.into()),
        None => crate::context::ProcessIdentity::Unknown,
    };
    CallerContext::from_parts(service, process, crate::context::GdmReauth::Absent)
}

/// The participation `classify` produces for `ctx`, since `run` never re-branches on identity.
fn participation_for(ctx: &CallerContext) -> Participation {
    match crate::policy::classify(ctx).1 {
        crate::policy::Classification::Participate(participation) => participation,
        crate::policy::Classification::Skip(skip) => {
            panic!("expected a participation, got the skip {skip:?}")
        }
    }
}

/// A handoff reader that reads nothing, for the tests whose paths never reach the pre-collected
/// handoff.
pub(crate) unsafe fn unused_authtok(_pamh: *mut PamHandle) -> (c_int, *const c_char) {
    (crate::pam_sys::PAM_SUCCESS, std::ptr::null())
}

fn run_with_probe<T: IpcResponseReader>(
    ctx: &CallerContext,
    tty: Option<&str>,
    connect: &mut dyn FnMut() -> Result<T, IpcError>,
    send: &mut dyn for<'p> FnMut(&mut T, &SendParams<'p>) -> Result<(), IpcError>,
) -> (Finished, usize) {
    let msgs = PamMessages::new("en");
    let mut host = HostIo::new(std::ptr::null_mut(), None, &msgs, unused_authtok);
    let participation = participation_for(ctx);
    let mut probes = 0usize;
    let mut probe = || {
        probes += 1;
        tty.and_then(|path| std::fs::File::open(path).ok())
    };
    let finished = run(
        ctx.service(),
        "tty-probe-test-user",
        &participation,
        &mut host,
        &zero_timeouts(),
        &mut Effects {
            probe_tty: &mut probe,
            connect,
            send,
            cancel: &|_, _| {},
        },
    );
    (finished, probes)
}

/// Record `outcome` for `(username, service)` at `at`, through the same `Armed`-conclude-record
/// path `authenticate` uses.
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

/// Both arms report the verdict they carry, and a `Concluded` keeps its provenance.
///
/// Catches an accessor that reads only one arm, and a provenance field that cannot tell a fresh
/// conclusion from a replay — which is what `record` refuses.
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
/// Catches a failed connect or send still yielding an `Armed`, which would let the caller record
/// a conclusion the daemon never reached; the assertion is on the arm, so a connect failure
/// reported as `Send` also fails (`communication_error` where `cannot_connect` belongs).
#[test]
fn armed_requires_both_connect_and_send() {
    let mut refused = || {
        Err::<NullIpc, _>(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "no daemon socket",
        )))
    };

    let no_connect = Armed::open(&mut refused, &mut |_: &mut NullIpc| Ok(()), "rid".into());
    assert!(
        matches!(no_connect, Err(StartError::Connect(_))),
        "a refused connect must surface as a connect failure, not as a send \
         failure and not as an armed request"
    );

    let mut sent = false;
    let bad_send = Armed::open(
        &mut || Ok(NullIpc),
        &mut |_: &mut NullIpc| {
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
        &mut || Ok(NullIpc),
        &mut |_: &mut NullIpc| Ok(()),
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
/// Catches a replayed grant or denial returning the phone-tap text, so a cache hit re-shows
/// `auth_successful` / `auth_denied` for a duplicate the user never made.
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

    // The control: the same verdicts, not replayed, do have their messages.
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
// The tty probe, the pre-arm failures and the reuse record.
// ------------------------------------------------------------------

/// `/dev/tty` is opened once, and only for the conversation that polls it.
///
/// Catches the probe moved above the plan (or gated on the conversation a second time), so a
/// threaded host polls the terminal and steals the stdin its own dialog needs, or a probe and a
/// plan disagree about whether a terminal exists.
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

/// Catches the probe placed *before* the reuse lookup, so every hit opened the terminal for a
/// transaction it never starts. The recorded conclusion is a success, so the returned code also
/// proves the hit was taken rather than the probe merely skipped on an early return.
///
/// The record is one process-wide slot other tests also write, so an attempt whose returned code
/// is not the recorded one proved nothing about the ordering and is retried; the assertion
/// itself is never relaxed.
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
            // A concurrent test replaced the single record before the lookup; nothing was
            // proved about the ordering, so re-take it.
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

/// The two pre-arm IPC failures *emit* their own message, and neither is recorded.
///
/// Catches the `finish` call deleted from either return, which tells the user nothing on the one
/// path where the daemon could not be reached at all, and pins the mapping: a connect failure
/// reported as `DaemonSendFailed` would show `communication_error` where `cannot_connect`
/// belongs. The recorded emission is the assertion, because `notice(&msgs)` re-derived in the
/// test would pass with every `emit` call deleted.
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

/// Catches a cache hit reported as `Via::Daemon`, which `record` accepts — the duplicate would
/// re-record the verdict and turn the fixed 500 ms window into a sliding one — or a replay that
/// loses the recorded verdict.
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
            // A concurrent test replaced the single record before the lookup; nothing was
            // proved about the provenance.
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
        // The replay marker is what refuses the re-record: `record` hands the verdict back and
        // must leave the slot exactly as the first call recorded it.
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
            "the slot must still hold the verdict the first call recorded, not the replay that tried to overwrite it"
        );
        return;
    }
    panic!(
        "the reuse record was replaced by a concurrent test before every one of 64 \
         attempts, so the cache-hit path was never observed"
    );
}

/// Catches the cache-hit return being silent only because it returns early, so a later
/// restructure that emitted `outcome.notice(..)` on the way out re-shows `communication_error`
/// for a duplicate the user never made. The recorded verdict is an unavailability that *does*
/// have a message — `Outcome::replayed` keeps the reason — so only `Via::Replay`, which
/// [`finish`](super::host_io::finish) keys on, can explain the silence.
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
            // A concurrent test replaced the single record before the lookup; nothing was
            // proved about the emission.
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
// The transaction's own ordering guarantees: the announcements and the pre-collected arm.
// ------------------------------------------------------------------

/// The marker `shown_order` puts in the log at the point the request went on the wire.
const OPEN_MARKER: &str = "Armed::open";

fn marker(text: &str) -> Emitted {
    Emitted {
        style: NoticeStyle::Info,
        text: text.to_owned(),
    }
}

/// What `run` showed, in order, with the point the request went on the wire marked, and how
/// many times it asked for a cancellation.
///
/// `send` runs inside `Armed::open`, so its mark is the request's position in the same log. The
/// cancel count makes the `Effects` seam's last field observable: with the zero-second budget
/// these tests use, no path reaches a cancel.
fn shown_order(ctx: &CallerContext, tty: Option<&str>) -> (Vec<Emitted>, usize) {
    let msgs = PamMessages::new("en");
    let log: std::cell::RefCell<Vec<Emitted>> = std::cell::RefCell::new(Vec::new());
    let mut host = HostIo::for_test_recording(std::ptr::null_mut(), &msgs, &log, unused_authtok);
    let participation = participation_for(ctx);
    let cancels = std::cell::Cell::new(0usize);
    let _finished = run(
        ctx.service(),
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
            cancel: &|_, _| cancels.set(cancels.get() + 1),
        },
    );
    (log.into_inner(), cancels.get())
}

/// Drive `run` through a recording host with no terminal and report what it showed, in order.
///
/// The emissions are the assertion, so a test never re-derives the message from the outcome.
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
        ctx.service(),
        username,
        &participation,
        &mut host,
        &zero_timeouts(),
        &mut Effects {
            probe_tty: &mut || None::<File>,
            connect,
            send,
            cancel: &|_, _| {},
        },
    );
    (finished, log.into_inner())
}

/// The position of the message `needle` in `log`, which must appear exactly once.
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

/// Catches `Wait`/`WaitSkipHint` emitted *after* the request, so a host whose conversation has
/// to reveal the password entry before it can answer never sees the message in time, and
/// `WaitThenPassword` emitted *before* it, which is the opposite failure on the one host shape
/// that needs it after: an event-loop host must already be blocked when the message arrives.
#[test]
fn announcement_order_matches_today() {
    let msgs = PamMessages::new("en");

    let (log, cancels) = shown_order(&context(Some("order-threaded"), Some("hyprlock")), None);
    assert!(
        once(&log, msgs.waiting_for_tap()) < once(&log, OPEN_MARKER),
        "the threaded wait is announced before the request: {log:?}"
    );
    assert_eq!(
        cancels, 0,
        "the zero-second budget ends the threaded wait as a timeout, and a \
         timeout cancels nothing"
    );

    let (log, cancels) = shown_order(
        &context(Some("order-terminal"), Some("xfce4-screensaver-dialog")),
        Some("/dev/null"),
    );
    assert!(
        once(&log, msgs.waiting_for_tap_skip()) < once(&log, OPEN_MARKER),
        "the terminal wait is announced before the request: {log:?}"
    );
    assert_eq!(
        cancels, 0,
        "the terminal timeout must not cancel: the daemon holds the same \
         deadline and multicasts its own cancel"
    );

    let (log, cancels) = shown_order(
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
    assert_eq!(
        cancels, 0,
        "the no-terminal sequential timeout must not open a fresh connection \
         for a cancellation the daemon already decided"
    );
}

/// A reader whose socket is already hung up: `poll` reports it readable and at end-of-file,
/// which is the no-terminal `gui-ipc-error` shape.
struct HangupIpc {
    stream: std::os::unix::net::UnixStream,
}

impl HangupIpc {
    fn new() -> Self {
        let (live, peer) =
            std::os::unix::net::UnixStream::pair().expect("the test can make a socket pair");
        drop(peer);
        HangupIpc { stream: live }
    }
}

impl IpcResponseReader for HangupIpc {
    fn fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.stream)
    }

    fn try_read_response_nonblocking(
        &mut self,
    ) -> Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error> {
        // A hung-up peer yields no frame: the loop's own `POLLHUP` handling is what classifies
        // the event, so the reader never has to read.
        Ok(None)
    }

    fn send_cancel(&mut self, _reason: &str, _request_id: &str) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// Catches `run` handing the mechanism a different closure than `effects.cancel` — a local
/// no-op, or a copy that is never invoked — so the phone keeps buzzing for a request the host
/// already abandoned. Every other transaction test asserts `cancels == 0`, so only a positive
/// count here proves the seam is wired; the assertion is on the effect `run` was given, never on
/// the mechanism's own test double.
#[test]
fn gui_ipc_error_cancels_through_the_effects_seam() {
    let ctx = context(
        Some("cancel-seam-service"),
        Some("xfce4-screensaver-dialog"),
    );
    let participation = participation_for(&ctx);
    assert_eq!(
        participation.conversation,
        Conversation::Sequential,
        "the no-terminal sequential shape is the one that cancels on an IPC error"
    );
    let msgs = PamMessages::new("en");
    let mut host = HostIo::new(std::ptr::null_mut(), None, &msgs, unused_authtok);
    let cancels: std::cell::RefCell<Vec<(String, String)>> = std::cell::RefCell::new(Vec::new());
    let cfg = PamConfig {
        pam_operation_timeout_secs: 5,
        pam_gui_timeout_secs: 5,
        ..PamConfig::default()
    };
    let finished = run(
        ctx.service(),
        "cancel-seam-user",
        &participation,
        &mut host,
        &cfg,
        &mut Effects {
            probe_tty: &mut || None::<File>,
            connect: &mut || Ok(HangupIpc::new()),
            send: &mut |_: &mut HangupIpc, _: &SendParams<'_>| Ok(()),
            cancel: &|reason, request_id| {
                cancels
                    .borrow_mut()
                    .push((reason.to_owned(), request_id.to_owned()));
            },
        },
    );

    let recorded = cancels.into_inner();
    assert_eq!(
        recorded.len(),
        1,
        "the hung-up no-terminal wait cancels exactly once: {recorded:?}"
    );
    assert_eq!(
        recorded.first().map(|(reason, _)| reason.as_str()),
        Some("gui-ipc-error"),
        "the cancel carries the exit's own reason: {recorded:?}"
    );
    assert_eq!(
        recorded.first().map(|(_, request_id)| request_id.len()),
        Some(32),
        "the cancel carries the request id `run` put on the wire: {recorded:?}"
    );
    assert_eq!(
        finished.outcome().clone().into_pam(),
        crate::pam_sys::PAM_AUTHINFO_UNAVAIL,
        "the cancelled no-terminal wait is an unavailability, not a grant"
    );
    assert!(
        matches!(
            finished.outcome(),
            Outcome::Unavailable(UnavailableReason::IpcError)
        ),
        "the no-terminal IPC failure is named `IpcError`: {:?}",
        finished.outcome()
    );
}

/// Catches the handoff placed after the probe, the cache lookup or the request — which would
/// open `/dev/tty` for a host that never uses it, consult the reuse record for a transaction
/// that never happened, or ring the phone for a user who already chose the password route. The
/// probe would find a terminal here, so a probe count of zero is a real assertion.
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
    let mut host = HostIo::new(std::ptr::null_mut(), None, &msgs, unused_authtok);
    let mut probes = 0usize;
    let connects = std::cell::Cell::new(0usize);
    let finished = run(
        ctx.service(),
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
            cancel: &|_, _| {},
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
