//! The sequential conversation: the host's own event loop owns the dialogue, so
//! this module only waits for the daemon on the calling thread.
//!
//! These hosts answer the conversation synchronously on the thread that called
//! `pam_authenticate` (kscreenlocker ≤ 6.7 posts the answer back to that
//! thread), so two things are forbidden here. Collecting the password from a
//! worker thread deadlocks: the reply is queued for an event loop that cannot run
//! while it waits. And `pthread_cancel`-ing that thread as the threaded flow does
//! would force-unwind through the host's non-Rust frames, which can `abort()` the
//! host and take the lock screen down with it. So no query is sent and no password
//! collected: the module blocks on the daemon socket, returns, and lets the PAM
//! stack fall through to the password module, whose own conversation then runs on
//! the host's terms. On the terminal shape this loop reads and drops keypresses
//! until Enter skips; on the no-terminal one nothing is consumed, so a typed
//! password only counts once the *following* module prompts it, after the
//! (shorter) GUI timeout — which is why `pam_gui_timeout_secs` exists.
//!
//! It never touches `pam_conv` — a broken host conversation cannot change the
//! verdict — and emits nothing; its only outgoing act is the injected `cancel`.
//!
//! # One loop, one profile
//!
//! The two shapes answer the *same* events differently, so the check order is
//! written once and the difference is data ([`Profile`], [`IpcFailureMap`]):
//!
//! 1. the deadline first, at the top of every iteration;
//! 2. one `poll` over `[ipc]` or `[ipc, tty]`, the IPC fd always index 0;
//! 3. EINTR swallowed, every other poll error a profile decision;
//! 4. `revents` before `read`, and a readable IPC socket decoded before
//!    `POLLHUP`/`POLLERR` is interpreted ("POLLIN can arrive with POLLHUP");
//! 5. the IPC fd before the tty, and the conversation untouched (no `pam_conv`);
//! 6. only `Armed::conclude` mints an outcome: a profile selects a *reason*,
//!    never a code;
//! 7. no client-side cancel on timeout: the daemon holds the same deadline;
//! 8. cancellation is a property of the exit (`tty-skip`, `gui-ipc-error`), through
//!    the injected `cancel` — a *fresh* short-timeout connection in production.

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

/// Everything that differs between the terminal and no-terminal shapes; the loop
/// reads it, and nothing outside the loop branches on the tty.
struct Profile {
    /// The probe's file; `None` ⇒ the no-terminal shape.
    tty: Option<File>,
    ipc_failure: IpcFailureMap,
    /// A non-`EINTR` `poll` error: ends the wait on the no-terminal shape, only
    /// logged on the terminal one.
    poll_error_stops: bool,
}

/// Which reason set an IPC failure maps to.
///
/// `Collapse` (no terminal) turns a hangup, `Ok(None)` plus a hangup, a decode
/// error and a poll error into one `IpcError`, shown as an error, with a
/// `gui-ipc-error` cancel. `Distinguish` (terminal) splits a hangup from a decode
/// error, logs a poll error and keeps waiting, and cancels nothing.
#[derive(Clone, Copy)]
enum IpcFailureMap {
    Collapse,
    Distinguish,
}

/// The observed event, for the profiles that distinguish them.
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
    /// `plan.tty_use` is the single source of "does this shape poll a terminal",
    /// so this branch is not a second copy of the conversation test.
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
/// `tty` is `run`'s probe file, `Some` exactly when the plan says `PollForKey`;
/// the plan is otherwise unread — `run` resolved it into `deadline_at`, so the
/// clamp keeps its single site.
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

/// The `poll` the loop calls, as a value: a parameter so a test can reach the
/// non-`EINTR` error cell, which production (through [`production_poll`]) does
/// not.
type PollFn = fn(&mut [PollFd<'_>], PollTimeout) -> Result<usize, nix::errno::Errno>;

/// [`nix::poll::poll`] behind the seam: on success its `c_int` count is never
/// negative, so the widening is exact; the `Err` arm is passed through untouched.
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
        // (1) The deadline first, at the top of every iteration. No client-side
        // cancel: the daemon runs on the same deadline and multicasts its own
        // AuthenticationCancel, so a cancel here would be a second message.
        let now = Instant::now();
        if now >= deadline_at {
            return MechanismEnd::Reason(UnavailableReason::TimedOut);
        }
        let remain = deadline_at
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        let timeout = PollTimeout::try_from(remain).unwrap_or(PollTimeout::MAX);

        // (2) One poll, the IPC fd always index 0; until a tty is polled the
        // second slot repeats that fd deliberately, because every `PollFd` must
        // hold a valid descriptor and an uninitialised or bogus one would invite
        // a "cleanup" into a bad fd.
        // SAFETY: `Armed` owns this reader (the live `IpcClient` in production),
        // so its fd stays open as long as the loop borrows it.
        let ipc_fd = unsafe { BorrowedFd::borrow_raw(ipc.fd()) };
        let mut fds = [
            PollFd::new(ipc_fd, PollFlags::POLLIN),
            PollFd::new(ipc_fd, PollFlags::POLLIN),
        ];
        if poll_tty {
            if let Some(tty) = profile.tty.as_ref() {
                // SAFETY: `profile.tty` owns the `File`, which outlives every
                // poll of this `BorrowedFd`.
                fds[1] = PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(tty.as_raw_fd()) },
                    PollFlags::POLLIN,
                );
            }
        }
        // The no-terminal shape polls one fd.
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
                        tracing::error!("Daemon closed connection or error detected");
                        return ipc_failure(
                            profile.ipc_failure,
                            request_id,
                            cancel,
                            IpcFailure::Hangup,
                        );
                    }
                }

                // The tty: read one byte; Enter skips, anything else is dropped.
                if poll_tty {
                    if let Some(rev) = fds[1].revents() {
                        if rev.contains(PollFlags::POLLIN) {
                            if let Some(tty) = profile.tty.as_mut() {
                                match tty.read(&mut kb[..1]) {
                                    Ok(1) => {
                                        let b = kb[0];
                                        if b == b'\n' || b == b'\r' {
                                            tracing::info!("User pressed Enter to skip");
                                            // The request may still be in flight
                                            // daemon-side, so cancel through the
                                            // injected seam (a fresh connection in
                                            // production, not the fd given up on).
                                            cancel("tty-skip", request_id);
                                            return MechanismEnd::Reason(
                                                UnavailableReason::Skipped,
                                            );
                                        }
                                    }
                                    Ok(0) => {
                                        // EOF: stop polling the tty rather than
                                        // spinning on a permanently ready fd.
                                        poll_tty = false;
                                    }
                                    Ok(_) => {
                                        // The target is one byte, so `read` cannot
                                        // report more than 1.
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
            // (3) EINTR is swallowed; every other poll error is a profile decision.
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
/// `Collapse` cancels on production's *fresh* connection, the live fd being the
/// one that just failed; `Distinguish` sends no cancel.
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
            // `Profile::of` pairs `poll_error_stops` with `Collapse` alone, so
            // `Distinguish` never receives this event; the arm exists because
            // the two arguments are independent.
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

    /// The request id every case drives, so a cancel log reads `<reason>:<id>`.
    const RID: &str = "sequential-loop-request";

    struct MockIpcReader {
        stream: UnixStream,
        /// The far end: held open so an idle socket does not report `POLLHUP`,
        /// which is a different cell of the mapping than "no data yet".
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

    /// Drive the one loop with a caller-supplied `poll`, which production never
    /// does: `drive` always passes `production_poll`.
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

    // How many times the mock `poll` below ran on this thread; thread-local, so
    // the two poll-error cases cannot race each other.
    thread_local! {
        static POLL_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    fn poll_calls() -> usize {
        POLL_CALLS.with(Cell::get)
    }

    fn reset_poll_calls() {
        POLL_CALLS.with(|calls| calls.set(0));
    }

    /// A `poll` that always fails with `EIO`, an error that is not `EINTR`, so it
    /// reaches the profile decision. The 1 ms pause keeps the continuing profile
    /// at about a hundred iterations, not a hot spin.
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
    /// The defect this catches: a loop that treats *any* readable tty as the
    /// skip, or one that forgets `\r`, the other key a terminal maps Enter to.
    #[test]
    fn enter_skips_other_keys_do_not() {
        let (tty, write_end) = tty_pipe();
        type_byte(write_end, b'a');
        let (end, cancelled) = drive_recording(MockIpcReader::idle(), Some(tty), shortly());
        assert!(
            matches!(end, MechanismEnd::Reason(UnavailableReason::TimedOut)),
            "a non-Enter key must not end the wait: {end:?}"
        );
        assert!(cancelled.is_empty(), "a consumed key cancels nothing");
        unsafe { libc::close(write_end) };

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

    /// The no-terminal shape ends at its deadline, as a `MechanismEnd` the
    /// caller concludes with.
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
    /// The defect this catches: a loop that turns a tty EOF, read error or hangup
    /// into the call's exit instead of dropping the tty from the poll set — the
    /// host may have closed the terminal while the phone was still being asked.
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
    /// The defect this catches: a loop that copies the *skip* path's cancel onto
    /// the timeout path, a second message for a decision the daemon already made
    /// — and on the no-terminal shape a fresh connection opened for nothing.
    #[test]
    fn timeout_does_not_cancel() {
        let expired = Instant::now() - Duration::from_secs(1);
        // Both pipe ends are owned here: the read end travels into the loop as the
        // `Some` and is closed when the loop drops it, the write end is closed below.
        let (tty, write_end) = tty_pipe();
        for (shape, tty) in [("terminal", Some(tty)), ("no tty", None)] {
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
        unsafe { libc::close(write_end) };
    }

    /// A readable socket that closes with a partial frame is a hangup.
    ///
    /// The defect this catches: the "read data first" rule applied one step too
    /// far — a loop that sees POLLIN, reads `Ok(None)` and retries instead of
    /// treating the `POLLHUP` in the same `revents` as a hangup.
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
    /// message *and* its style — and the missing cancel on the collapsing path,
    /// where the request is still in flight daemon-side.
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
    /// The defect this catches: the skip returning without a cancel, so the phone
    /// keeps buzzing for a request the user already abandoned, or one that
    /// cancels with the IPC-error reason, a different event in the daemon's log.
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
    /// loop that cancels on both (a new network message on the terminal path) or
    /// on neither (the phone keeps buzzing on the no-terminal shape).
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
    /// ignored — a loop that logs the error and keeps polling, so a broken socket
    /// waits out the whole GUI timeout while the phone keeps buzzing. The call
    /// count is the other half: the loop must *end*, not retry.
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
    /// The defect this catches: the `Distinguish` half of the cell — a loop that
    /// treats a non-`EINTR` poll error as an IPC failure on the terminal shape
    /// too, ending the call with `IpcConnectionLost` for a transient error it
    /// must simply retry. More than one call is what separates "continue" from
    /// "return a reason".
    #[test]
    fn poll_error_is_logged_and_the_terminal_wait_continues() {
        reset_poll_calls();
        let (tty, write_end) = tty_pipe();
        // A 500 ms budget, not `shortly()`'s 100 ms: under high parallelism a
        // scheduling stall could otherwise end the wait before the loop's second
        // poll and fail the `> 1` assertion for an unrelated reason.
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
