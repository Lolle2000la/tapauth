//! The sequential conversation: the host's own event loop owns the dialogue, so
//! this module only waits for the daemon on the calling thread.
//!
//! Such a host typically implements the conversation as a synchronous
//! round-trip that can only be answered by the event loop running on the very
//! thread that called `pam_authenticate` (kscreenlocker ≤ 6.7, for instance,
//! posts the answer back to that thread). For those hosts:
//!
//! 1. collecting the password from a background thread deadlocks: the
//!    conversation reply is queued for the blocked host event loop and can
//!    never be dispatched, so password entry stops working entirely, and
//! 2. `pthread_cancel`-ing that background thread (as the threaded flow does)
//!    would force-unwind through the host's non-Rust frames, which can
//!    `abort()` the host process and take the lock screen down with it.
//!
//! The safe pattern is to never drive the conversation from this thread: no
//! query is sent and no input is read, and the conversation is not touched at
//! all while the module waits. It blocks on the daemon IPC socket on the
//! calling thread, returns the result, and lets the PAM stack fall through to
//! the password module afterwards (whose own conversation then runs on the
//! host's terms). The one exception is a single non-blocking `PAM_TEXT_INFO`
//! announcement emitted immediately before this module is entered: it carries
//! no input and hosts need it in order to reveal their password entry. Because
//! nothing is consumed here, a typed password only counts once the *following*
//! module prompts for it, after the (shorter) GUI timeout — which is why
//! `pam_gui_timeout_secs` exists.
//!
//! This module emits nothing and names no conversation type: it never touches
//! `pam_conv`, so a host whose conversation is broken still cannot change the
//! verdict. It returns a [`MechanismEnd`], and the injected `cancel` closure is
//! the only way it can ask for a cancellation.
//!
//! # One loop, one profile
//!
//! The terminal and the no-terminal shape answer the *same* events differently:
//! the no-terminal path collapses every IPC failure into one reason and cancels
//! on it, the terminal path distinguishes a hangup from a read error, logs a
//! poll error and keeps waiting, and never cancels on an IPC failure. Holding
//! that check order twice is the maintenance hazard this module exists to
//! remove, so the difference is data ([`Profile`]) and the order is written once:
//!
//! 1. the deadline first, at the top of every iteration;
//! 2. one `poll` over `[ipc]` or `[ipc, tty]`, with the IPC fd always index 0;
//! 3. EINTR swallowed, every other poll error a profile decision;
//! 4. `revents` tested before `read`, and a readable IPC socket decoded before
//!    `POLLHUP`/`POLLERR` is interpreted ("POLLIN can arrive with POLLHUP");
//! 5. the IPC fd examined before the tty;
//! 6. the conversation untouched — no `pam_conv`, no message;
//! 7. only `Armed::conclude` mints an outcome, so the profile selects a
//!    *reason*, never a code;
//! 8. no client-side cancel on timeout, on either path: the daemon holds the
//!    same deadline and multicasts its own cancel;
//! 9. cancellation is a property of the exit — the tty Enter skip (`tty-skip`)
//!    and the no-tty IPC error (`gui-ipc-error`) — through the injected
//!    `cancel` closure, which production wires to a *fresh* short-timeout
//!    connection.

use super::{IpcFault, MechanismEnd};
use crate::ipc_client::IpcResponseReader;
use crate::outcome::UnavailableReason;
use crate::plan::{Plan, TtyUse};
use crate::transaction::Armed;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

/// Everything that differs between the terminal and no-terminal paths.
///
/// The loop reads it; nothing else in the module branches on the tty.
struct Profile {
    /// The probe's file; `None` ⇒ the no-terminal shape.
    tty: Option<File>,
    /// How an IPC failure is named.
    ipc_failure: IpcFailureMap,
    /// Whether a non-EINTR `poll` error ends the wait (no-terminal) or is logged
    /// while the terminal shape keeps waiting.
    poll_error_stops: bool,
}

/// Which reason set an IPC failure maps to.
///
/// `Collapse` is today's no-terminal loop: hangup, `Ok(None)` plus a hangup, a
/// decode error and a poll error are all one `IpcError`, shown as an error, with
/// a `gui-ipc-error` cancel. `Distinguish` is today's terminal loop: a hangup is
/// `IpcConnectionLost`, a decode error `IpcLoopError`, a poll error is logged
/// and the loop continues, and nothing is cancelled.
#[derive(Clone, Copy)]
enum IpcFailureMap {
    Collapse,
    Distinguish,
}

/// Which event produced the IPC failure, for the profiles that distinguish them.
#[derive(Clone, Copy)]
enum IpcFailure {
    /// The peer closed the connection, with or without a partial frame.
    Hangup,
    /// A read on the socket failed.
    DecodeError,
    /// `poll` failed with something other than `EINTR`.
    PollError,
}

impl Profile {
    /// The profile the plan and the probe produce.
    ///
    /// `plan.tty_use` is the single source of "does this shape poll a terminal",
    /// so the branch is not a second copy of the conversation test. The `File` is
    /// data: `run` only probes when the plan says `PollForKey`, and drops it
    /// otherwise.
    fn of(plan: &Plan, tty: Option<File>) -> Profile {
        match plan.tty_use {
            TtyUse::PollForKey => Profile {
                tty,
                ipc_failure: IpcFailureMap::Distinguish,
                poll_error_stops: false,
            },
            TtyUse::DoNotOpen => Profile {
                tty: None,
                ipc_failure: IpcFailureMap::Collapse,
                poll_error_stops: true,
            },
        }
    }
}

/// Wait for the daemon in the shape the plan chose.
///
/// `tty` is the file `run`'s probe produced and it is `Some` exactly when the
/// plan says `PollForKey`. The plan itself is not otherwise read: `run` already
/// resolved it into `deadline_at`, so the clamp keeps its single site and this
/// module never sees the configuration.
pub(crate) fn drive<T: IpcResponseReader, X: Fn(&str, &str)>(
    armed: &mut Armed<T>,
    plan: &Plan,
    deadline_at: Instant,
    tty: Option<File>,
    cancel: X,
) -> MechanismEnd {
    let profile = Profile::of(plan, tty);
    let (ipc, request_id) = armed.parts();
    run_loop(
        ipc,
        request_id,
        deadline_at,
        profile,
        &cancel,
        production_poll,
    )
}

/// The `poll` the loop calls, as a value.
///
/// It is a parameter rather than a direct call so the non-`EINTR` error cell —
/// which the profiles answer differently — can be reached from a test with a
/// mock. Production passes exactly [`nix::poll::poll`] (through
/// [`production_poll`], which only widens its `c_int` count to `usize`); the
/// error is forwarded unchanged, so the loop's mapping is unaffected.
type PollFn = fn(&mut [PollFd<'_>], PollTimeout) -> Result<usize, nix::errno::Errno>;

/// [`nix::poll::poll`] behind the seam's signature.
///
/// The only difference is the ready-count type: `poll` answers `c_int`, and on
/// success that value is never negative, so the widening is exact. The
/// `Err(Errno)` arm is passed through untouched — no errno is translated here.
fn production_poll(
    fds: &mut [PollFd<'_>],
    timeout: PollTimeout,
) -> Result<usize, nix::errno::Errno> {
    poll(fds, timeout).map(|ready| usize::try_from(ready).unwrap_or(usize::MAX))
}

/// The one loop both shapes run.
fn run_loop<T: IpcResponseReader, X: Fn(&str, &str)>(
    ipc: &mut T,
    request_id: &str,
    deadline_at: Instant,
    mut profile: Profile,
    cancel: &X,
    poll_fn: PollFn,
) -> MechanismEnd {
    // Set the tty nonblocking once, up front, so a `read` after a readable poll
    // cannot block unexpectedly.
    if let Some(tty) = profile.tty.as_ref() {
        if let Ok(cur) = fcntl(tty, FcntlArg::F_GETFL) {
            let mut flags = OFlag::from_bits_truncate(cur);
            flags.insert(OFlag::O_NONBLOCK);
            let _ = fcntl(tty, FcntlArg::F_SETFL(flags));
        }
    }

    // The tty stops being polled on EOF, a read error or a hangup; the daemon
    // socket keeps being waited on either way.
    let mut poll_tty = profile.tty.is_some();
    let mut kb = [0u8; 4];
    loop {
        // (1) The deadline first, at the top of every iteration. No
        // client-side cancel: the daemon runs on the same deadline and
        // multicasts its own AuthenticationCancel, so a cancel here would be a
        // second message for a decision the daemon already made.
        let now = Instant::now();
        if now >= deadline_at {
            return MechanismEnd::Reason(UnavailableReason::TimedOut);
        }
        let remain = deadline_at
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        let timeout = PollTimeout::try_from(remain).unwrap_or(PollTimeout::MAX);

        // (2) One poll, the IPC fd always at index 0. The second slot is a
        // placeholder until a tty is polled, so the slice never carries an
        // invalid descriptor.
        let ipc_fd = unsafe { BorrowedFd::borrow_raw(ipc.fd()) };
        let mut fds = [
            PollFd::new(ipc_fd, PollFlags::POLLIN),
            PollFd::new(ipc_fd, PollFlags::POLLIN),
        ];
        if poll_tty {
            if let Some(tty) = profile.tty.as_ref() {
                fds[1] = PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(tty.as_raw_fd()) },
                    PollFlags::POLLIN,
                );
            }
        }
        // The no-terminal shape polls one fd, so a tty that stopped being
        // polled is not carried as an invalid descriptor.
        let ready = if poll_tty {
            poll_fn(&mut fds, timeout)
        } else {
            poll_fn(&mut fds[..1], timeout)
        };

        match ready {
            Ok(0) => {}
            Ok(_) => {
                // (4)+(5) The IPC fd first, `revents` before `read`, and a
                // readable socket decoded before a hangup is interpreted.
                if let Some(rev) = fds[0].revents() {
                    if rev.contains(PollFlags::POLLIN) {
                        match ipc.try_read_response_nonblocking() {
                            Ok(Some(resp)) => return MechanismEnd::Response(resp),
                            Ok(None) => {
                                // No complete frame yet. A hangup in the same
                                // `revents` is the hangup case, not a retry.
                                if rev.contains(PollFlags::POLLHUP)
                                    || rev.contains(PollFlags::POLLERR)
                                {
                                    tracing::error!(
                                        "Daemon closed connection before sending response"
                                    );
                                    return ipc_failure(
                                        profile.ipc_failure,
                                        request_id,
                                        cancel,
                                        IpcFailure::Hangup,
                                    );
                                }
                                // Otherwise fall through to the tty: a partial
                                // frame must not stop a key from being read.
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {}", e);
                                return ipc_failure(
                                    profile.ipc_failure,
                                    request_id,
                                    cancel,
                                    IpcFailure::DecodeError,
                                );
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        // Hangup/error without any data available.
                        tracing::error!("Daemon closed connection or error detected");
                        return ipc_failure(
                            profile.ipc_failure,
                            request_id,
                            cancel,
                            IpcFailure::Hangup,
                        );
                    }
                }

                // The tty: read one byte; Enter skips, any other key is
                // consumed and discarded.
                if poll_tty {
                    if let Some(rev) = fds[1].revents() {
                        if rev.contains(PollFlags::POLLIN) {
                            if let Some(tty) = profile.tty.as_mut() {
                                match tty.read(&mut kb[..1]) {
                                    Ok(1) => {
                                        let b = kb[0];
                                        if b == b'\n' || b == b'\r' {
                                            tracing::info!("User pressed Enter to skip");
                                            // The request may still be in
                                            // flight daemon-side, so the phone
                                            // would keep buzzing: cancel
                                            // through the injected seam (a fresh
                                            // short-timeout connection in
                                            // production, because the live fd is
                                            // not the one the user gave up on).
                                            cancel("tty-skip", request_id);
                                            return MechanismEnd::Reason(
                                                UnavailableReason::Skipped,
                                            );
                                        }
                                        // Non-Enter key: consume and ignore.
                                    }
                                    Ok(0) => {
                                        // EOF: stop polling the tty rather than
                                        // spinning on a permanently ready fd.
                                        poll_tty = false;
                                    }
                                    Ok(_) => {
                                        unreachable!("read into 1-byte buffer cannot exceed 1")
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                    Err(_) => poll_tty = false,
                                }
                            }
                        } else if rev.contains(PollFlags::POLLHUP)
                            || rev.contains(PollFlags::POLLERR)
                        {
                            poll_tty = false;
                        }
                    }
                }
            }
            // (3) EINTR is swallowed; every other poll error is a profile
            // decision.
            Err(e) => {
                if e != nix::errno::Errno::EINTR {
                    tracing::warn!("poll error: {}", e);
                    if profile.poll_error_stops {
                        return ipc_failure(
                            profile.ipc_failure,
                            request_id,
                            cancel,
                            IpcFailure::PollError,
                        );
                    }
                }
            }
        }
    }
}

/// The one mapping from an IPC failure to the module's exit.
///
/// `Collapse` names every failure `IpcError` and cancels with `gui-ipc-error`;
/// the live fd is precisely the one that just failed, so production's fresh
/// connection is what makes the cancel reach the daemon at all. `Distinguish`
/// keeps the hangup/loop-error split and sends no cancel: a terminal host has
/// already stopped waiting, and adding a message there would be a new network
/// act on a path this refactor preserves.
fn ipc_failure<X: Fn(&str, &str)>(
    map: IpcFailureMap,
    request_id: &str,
    cancel: &X,
    kind: IpcFailure,
) -> MechanismEnd {
    match map {
        IpcFailureMap::Collapse => {
            cancel("gui-ipc-error", request_id);
            MechanismEnd::Reason(UnavailableReason::IpcError)
        }
        IpcFailureMap::Distinguish => MechanismEnd::Reason(match kind {
            IpcFailure::Hangup => IpcFault::Hangup.reason(),
            IpcFailure::DecodeError => IpcFault::DecodeError.reason(),
            // A non-EINTR poll error only reaches this function on the
            // collapsing profile (`poll_error_stops`), so this arm is
            // unreachable; it is not a panic path because a shipped `cdylib`
            // compiles panics out. It is also the arm that keeps the poll-error
            // cell local instead of in `IpcFault`: the threaded loop answers the
            // same event with `IpcLoopError`.
            IpcFailure::PollError => UnavailableReason::IpcConnectionLost,
        }),
    }
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::plan::Plannable;
    use crate::transaction::armed_for_test;
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    /// The request id every case drives, so a cancel log reads as
    /// `"<reason>:<id>"`.
    const RID: &str = "sequential-loop-request";

    struct MockIpcReader {
        stream: UnixStream,
        /// The far end, held open for the cases that need an *idle* socket: a
        /// dropped peer would make the descriptor report `POLLHUP`, which is a
        /// different cell of the mapping than "no data yet". Never read — the
        /// field exists to keep the descriptor open.
        _peer: Option<UnixStream>,
        next_response:
            Option<Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error>>,
    }

    impl MockIpcReader {
        fn idle() -> Self {
            let (peer, client) = UnixStream::pair().unwrap();
            MockIpcReader {
                stream: client,
                _peer: Some(peer),
                next_response: None,
            }
        }

        /// A socket whose peer is still open and whose next read is `next`.
        fn answering(
            next: Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error>,
        ) -> Self {
            let (mut peer, client) = UnixStream::pair().unwrap();
            // One byte is enough to make the descriptor report POLLIN; the
            // reader below never parses it.
            peer.write_all(&[1]).unwrap();
            MockIpcReader {
                stream: client,
                _peer: Some(peer),
                next_response: Some(next),
            }
        }

        /// A socket whose peer has closed without answering.
        fn hung_up(
            next: Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error>,
        ) -> Self {
            let (peer, client) = UnixStream::pair().unwrap();
            std::mem::drop(peer);
            MockIpcReader {
                stream: client,
                _peer: None,
                next_response: Some(next),
            }
        }
    }

    impl IpcResponseReader for MockIpcReader {
        fn fd(&self) -> RawFd {
            AsRawFd::as_raw_fd(&self.stream)
        }

        fn try_read_response_nonblocking(
            &mut self,
        ) -> Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error> {
            self.next_response.take().unwrap_or(Ok(None))
        }

        fn send_cancel(&mut self, _reason: &str, _request_id: &str) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    /// A pipe standing in for `/dev/tty`: the returned `File` is the read end,
    /// and `write` feeds it the bytes a user would type.
    fn tty_pipe() -> (File, RawFd) {
        let mut fds: [RawFd; 2] = [-1, -1];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2 failed"
        );
        let read_end = unsafe { File::from_raw_fd(fds[0]) };
        (read_end, fds[1])
    }

    /// Write one byte into the test pipe, as a terminal would on a keystroke.
    fn type_byte(fd: RawFd, byte: u8) {
        let written = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
        assert_eq!(written, 1, "the test pipe accepted one byte");
    }

    /// A `Plannable::Sequential` plan for a host with (or without) a terminal.
    fn plan(has_tty: bool) -> Plan {
        Plannable::Sequential.plan(has_tty)
    }

    /// Drive the mechanism over `ipc`, recording every `(reason, id)` the loop
    /// asks to cancel.
    fn drive_recording(
        ipc: MockIpcReader,
        tty: Option<File>,
        deadline_at: Instant,
    ) -> (MechanismEnd, Vec<String>) {
        let log: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let mut armed = armed_for_test(ipc, RID);
        let end = drive(
            &mut armed,
            &plan(tty.is_some()),
            deadline_at,
            tty,
            |reason: &str, request_id: &str| {
                log.borrow_mut().push(format!("{reason}:{request_id}"));
            },
        );
        (end, log.into_inner())
    }

    fn shortly() -> Instant {
        Instant::now() + Duration::from_millis(100)
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// Drive the one loop with a caller-supplied `poll`, so the non-`EINTR`
    /// error cell can be reached. Production never takes this path: `drive`
    /// always passes `production_poll` (`nix::poll::poll`).
    fn run_loop_recording(
        ipc: MockIpcReader,
        tty: Option<File>,
        deadline_at: Instant,
        poll_fn: PollFn,
    ) -> (MechanismEnd, Vec<String>) {
        let log: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let mut armed = armed_for_test(ipc, RID);
        let profile = Profile::of(&plan(tty.is_some()), tty);
        let (ipc, request_id) = armed.parts();
        let end = run_loop(
            ipc,
            request_id,
            deadline_at,
            profile,
            &|reason: &str, request_id: &str| {
                log.borrow_mut().push(format!("{reason}:{request_id}"));
            },
            poll_fn,
        );
        (end, log.into_inner())
    }

    // How many times the mock `poll` below ran on this thread. Thread-local, so
    // the two poll-error cases share one mock without racing each other or any
    // other test in this binary.
    thread_local! {
        static POLL_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    fn poll_calls() -> usize {
        POLL_CALLS.with(Cell::get)
    }

    fn reset_poll_calls() {
        POLL_CALLS.with(|calls| calls.set(0));
    }

    /// A `poll` that always fails with `EIO` — an error that is *not* `EINTR`,
    /// so it reaches the profile decision instead of being swallowed. The 1 ms
    /// pause keeps the continuing profile at about a hundred iterations over the
    /// 100 ms deadline rather than a hot spin.
    fn failing_poll(
        _fds: &mut [PollFd<'_>],
        _timeout: PollTimeout,
    ) -> Result<usize, nix::errno::Errno> {
        POLL_CALLS.with(|calls| calls.set(calls.get() + 1));
        std::thread::sleep(Duration::from_millis(1));
        Err(nix::errno::Errno::EIO)
    }

    /// Enter skips; every other key is consumed and the wait continues.
    ///
    /// The defect this catches: a merged loop that treats *any* readable tty as
    /// the skip (so a keystroke ends the authentication), or one that forgets
    /// `\r` — the two keys a terminal maps Enter to. The `Ok(1)` arm is where
    /// both live, and the positive half (`\n`, `\r` skip) makes the negative
    /// half (`a` does not) meaningful.
    #[test]
    fn enter_skips_other_keys_do_not() {
        // A non-Enter key is consumed: the loop keeps waiting until the deadline.
        let (tty, write_end) = tty_pipe();
        type_byte(write_end, b'a');
        let (end, cancelled) = drive_recording(MockIpcReader::idle(), Some(tty), shortly());
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::TimedOut)),
            "a non-Enter key must not end the wait: {end:?}"
        );
        assert!(cancelled.is_empty(), "a consumed key cancels nothing");
        unsafe { libc::close(write_end) };

        // Enter skips, in both spellings.
        for key in *b"\n\r" {
            let (tty, write_end) = tty_pipe();
            type_byte(write_end, key);
            let (end, cancelled) = drive_recording(MockIpcReader::idle(), Some(tty), later());
            assert!(
                matches!(end, MechanismEnd::Reason(UnavailableReason::Skipped)),
                "{key:?} must skip"
            );
            assert_eq!(cancelled, vec![format!("tty-skip:{RID}")]);
            unsafe { libc::close(write_end) };
        }
    }

    /// The no-terminal shape ends at its deadline.
    ///
    /// Same scenario and same assertion as the pre-merge `S1`
    /// (`test_sequential_loop_immediate_timeout`), retargeted onto the one loop:
    /// the exit is a `MechanismEnd` now, not a loop-local exit code, because the
    /// loop no longer reports a reason the caller maps.
    #[test]
    fn test_sequential_loop_immediate_timeout() {
        let expired = Instant::now() - Duration::from_secs(1);
        let (end, cancelled) = drive_recording(MockIpcReader::idle(), None, expired);
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::TimedOut)),
            "a passed deadline ends the wait as a timeout"
        );
        assert!(cancelled.is_empty());
    }

    /// The no-terminal shape returns the daemon's frame.
    ///
    /// Same scenario as the pre-merge `S2`
    /// (`test_sequential_loop_receives_response`).
    #[test]
    fn test_sequential_loop_receives_response() {
        let mut expected = shared::ipc::pb::PamAuthenticateResponse::default();
        expected.set_outcome(shared::ipc::pb::PamOutcome::Success);
        let (end, cancelled) =
            drive_recording(MockIpcReader::answering(Ok(Some(expected))), None, later());
        match end {
            MechanismEnd::Response(resp) => assert_eq!(
                resp.outcome(),
                shared::ipc::pb::PamOutcome::Success,
                "the frame the daemon sent is the one the mechanism returns"
            ),
            other => panic!("a decoded frame must end the wait with a response: {other:?}"),
        }
        assert!(cancelled.is_empty());
    }

    /// The no-terminal shape collapses a bare hangup into `IpcError`.
    ///
    /// Same scenario as the pre-merge `S3`
    /// (`test_sequential_loop_daemon_hangup`).
    #[test]
    fn test_sequential_loop_daemon_hangup() {
        let (end, cancelled) = drive_recording(MockIpcReader::hung_up(Ok(None)), None, later());
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::IpcError)),
            "a hangup on the collapsing profile is one IpcError"
        );
        assert_eq!(cancelled, vec![format!("gui-ipc-error:{RID}")]);
    }

    /// A tty at EOF stops being polled; the daemon socket keeps being waited on.
    ///
    /// The defect this catches: a merged loop that turns a tty EOF, read error
    /// or hangup into the call's exit (an `IpcConnectionLost` or an error) — the
    /// terminal shape must instead drop the tty from the poll set and let the
    /// daemon answer, because the host may simply have closed the terminal
    /// while the phone was still being asked.
    #[test]
    fn tty_eof_stops_polling_not_waiting() {
        // EOF with an idle daemon: the deadline still ends the wait, and the
        // exit is the timeout, not a tty-derived failure.
        let (tty, write_end) = tty_pipe();
        unsafe { libc::close(write_end) };
        let (end, cancelled) = drive_recording(MockIpcReader::idle(), Some(tty), shortly());
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::TimedOut)),
            "a tty at EOF must not end the call: the daemon is still being waited on"
        );
        assert!(cancelled.is_empty());

        // EOF with an answer available: the daemon's response still wins.
        let (tty, write_end) = tty_pipe();
        unsafe { libc::close(write_end) };
        let mut resp = shared::ipc::pb::PamAuthenticateResponse::default();
        resp.set_outcome(shared::ipc::pb::PamOutcome::Success);
        let (end, cancelled) =
            drive_recording(MockIpcReader::answering(Ok(Some(resp))), Some(tty), later());
        match end {
            MechanismEnd::Response(resp) => {
                assert_eq!(resp.outcome(), shared::ipc::pb::PamOutcome::Success);
            }
            other => panic!("a finished frame must win over a tty EOF: {other:?}"),
        }
        assert!(cancelled.is_empty(), "a response cancels nothing");
    }

    /// The deadline ends the wait without a cancel, on both shapes.
    ///
    /// The defect this catches: a merged loop that copies the *skip* path's
    /// cancel onto the timeout path. The daemon holds the same deadline and
    /// multicasts its own cancel, so a client cancel there is a second message
    /// for a decision already made — and on the no-terminal shape it would be a
    /// fresh connection opened for nothing.
    #[test]
    fn timeout_does_not_cancel() {
        let expired = Instant::now() - Duration::from_secs(1);
        for tty in [None, Some(tty_pipe().0)] {
            let shape = if tty.is_some() { "terminal" } else { "no tty" };
            let (end, cancelled) = drive_recording(MockIpcReader::idle(), tty, expired);
            assert!(
                matches!(end, MechanismEnd::Reason(UnavailableReason::TimedOut)),
                "{shape}: the deadline must end the wait"
            );
            assert!(
                cancelled.is_empty(),
                "{shape}: a timeout must not cancel: {cancelled:?}"
            );
        }
    }

    /// A readable socket that closes with a partial frame is a hangup.
    ///
    /// The defect this catches: the "read data first" rule applied one step too
    /// far — a loop that sees POLLIN, reads `Ok(None)` and retries, instead of
    /// treating the `POLLHUP` in the same `revents` as the terminal shape's
    /// `connection_lost`. It is the cell that differs from the no-tty shape,
    /// which collapses the same event into `IpcError`.
    #[test]
    fn partial_frame_with_hangup_is_connection_lost() {
        // A partial frame (fewer than the four length bytes) followed by the
        // peer closing: POLLIN and POLLHUP arrive together.
        let (mut server, client) = UnixStream::pair().unwrap();
        server.write_all(&[1, 2, 3]).unwrap();
        std::mem::drop(server);
        let ipc = MockIpcReader {
            stream: client,
            _peer: None,
            next_response: Some(Ok(None)),
        };

        let (tty, write_end) = tty_pipe();
        let (end, cancelled) = drive_recording(ipc, Some(tty), later());
        assert!(
            matches!(
                end,
                MechanismEnd::Reason(UnavailableReason::IpcConnectionLost)
            ),
            "a partial frame plus a hangup is a lost connection, not a retry"
        );
        assert!(
            cancelled.is_empty(),
            "the terminal shape does not cancel on an IPC failure"
        );
        unsafe { libc::close(write_end) };
    }

    /// A failed read is `IpcLoopError` on the terminal shape and `IpcError` on
    /// the other.
    ///
    /// The defect this catches: one reason for both shapes, which changes the
    /// message *and* its style (the collapsing path shows `communication_error`
    /// as an error, the terminal path shows it as information) — and the
    /// missing cancel on the collapsing path, where the request is still in
    /// flight daemon-side.
    #[test]
    fn read_error_maps_to_ipc_error() {
        let boom = || std::io::Error::other("read failed");

        let (tty, write_end) = tty_pipe();
        let (end, cancelled) =
            drive_recording(MockIpcReader::answering(Err(boom())), Some(tty), later());
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::IpcLoopError)),
            "the terminal shape names a read error IpcLoopError"
        );
        assert!(cancelled.is_empty());
        unsafe { libc::close(write_end) };

        let (end, cancelled) =
            drive_recording(MockIpcReader::answering(Err(boom())), None, later());
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::IpcError)),
            "the no-terminal shape collapses a read error into IpcError"
        );
        assert_eq!(cancelled, vec![format!("gui-ipc-error:{RID}")]);
    }

    /// The Enter skip cancels with `tty-skip` and nothing else.
    ///
    /// The defect this catches: the skip returning without a cancel, so the
    /// phone keeps buzzing until the daemon's own deadline for a request the
    /// user already abandoned — or a skip that cancels with the IPC-error
    /// reason, which would be a different event in the daemon's log.
    #[test]
    fn skip_cancels_with_tty_skip() {
        let (tty, write_end) = tty_pipe();
        type_byte(write_end, b'\n');
        let (end, cancelled) = drive_recording(MockIpcReader::idle(), Some(tty), later());
        assert!(matches!(
            end,
            MechanismEnd::Reason(UnavailableReason::Skipped)
        ));
        assert_eq!(
            cancelled,
            vec![format!("tty-skip:{RID}")],
            "the skip cancels with its own reason, exactly once"
        );
        unsafe { libc::close(write_end) };
    }

    /// An IPC failure cancels only on the no-terminal shape.
    ///
    /// The defect this catches: the asymmetry "fixed" in either direction — a
    /// merged loop that cancels on both (a new network message on the terminal
    /// path, which today sends none) or on neither (the phone keeps buzzing on
    /// the no-terminal shape). The two halves run the *same* event so only the
    /// profile differs.
    #[test]
    fn ipc_error_cancels_only_without_tty() {
        let (tty, write_end) = tty_pipe();
        let (end, cancelled) =
            drive_recording(MockIpcReader::hung_up(Ok(None)), Some(tty), later());
        assert!(
            matches!(
                end,
                MechanismEnd::Reason(UnavailableReason::IpcConnectionLost)
            ),
            "the terminal shape distinguishes a hangup"
        );
        assert!(
            cancelled.is_empty(),
            "the terminal shape must not cancel on an IPC failure: {cancelled:?}"
        );
        unsafe { libc::close(write_end) };

        let (end, cancelled) = drive_recording(MockIpcReader::hung_up(Ok(None)), None, later());
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::IpcError)),
            "the no-terminal shape collapses a hangup into IpcError"
        );
        assert_eq!(
            cancelled,
            vec![format!("gui-ipc-error:{RID}")],
            "the no-terminal shape cancels so the phone stops buzzing"
        );
    }

    /// A non-`EINTR` `poll` error ends the no-terminal wait at once.
    ///
    /// The defect this catches: the `Collapse` half of the poll-error cell
    /// (`Profile::poll_error_stops`) ignored — a loop that logs the error and
    /// keeps polling, so a broken IPC socket waits out the whole GUI timeout
    /// while the phone keeps buzzing instead of being cancelled immediately. The
    /// call count is the other half: the loop must *end*, not retry.
    #[test]
    fn poll_error_stops_the_no_terminal_wait() {
        reset_poll_calls();
        let (end, cancelled) =
            run_loop_recording(MockIpcReader::idle(), None, later(), failing_poll);
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::IpcError)),
            "the collapsing profile names a poll error IpcError: {end:?}"
        );
        assert_eq!(
            cancelled,
            vec![format!("gui-ipc-error:{RID}")],
            "the collapsing profile cancels so the phone stops buzzing"
        );
        assert_eq!(
            poll_calls(),
            1,
            "a poll error ends the no-terminal loop: it must not be polled again"
        );
    }

    /// The same error on the terminal profile is logged and the wait continues.
    ///
    /// The defect this catches: the `Distinguish` half of the cell — a merged
    /// loop that treats a non-`EINTR` poll error as an IPC failure on the
    /// terminal shape too, ending the call with `IpcConnectionLost` (a different
    /// message and style) for a transient error it must simply retry. The call
    /// count is what distinguishes "continue" from "return a reason": one
    /// iteration would mean the loop ended on the first error.
    #[test]
    fn poll_error_is_logged_and_the_terminal_wait_continues() {
        reset_poll_calls();
        let (tty, write_end) = tty_pipe();
        // A 500 ms budget, not `shortly()`'s 100 ms: under high parallelism a
        // scheduling stall of a few tens of ms could otherwise end the wait
        // before the loop's second poll, failing the `> 1` assertion below for a
        // reason unrelated to the behaviour under test.
        let (end, cancelled) = run_loop_recording(
            MockIpcReader::idle(),
            Some(tty),
            Instant::now() + Duration::from_millis(500),
            failing_poll,
        );
        unsafe { libc::close(write_end) };
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::TimedOut)),
            "the terminal profile keeps waiting until its deadline: {end:?}"
        );
        assert!(
            cancelled.is_empty(),
            "the terminal shape does not cancel on an IPC failure"
        );
        assert!(
            poll_calls() > 1,
            "a poll error must not end the terminal wait: poll ran {} time(s)",
            poll_calls()
        );
    }
}
