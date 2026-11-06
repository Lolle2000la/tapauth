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

use super::ExitReason;
use crate::ipc_client::IpcResponseReader;
use crate::outcome::UnavailableReason;
use crate::plan::Plan;
use crate::transaction::{Armed, MechanismEnd};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

/// Wait for the daemon in the shape the plan chose.
///
/// `tty` is the file `run`'s probe produced and it is `Some` exactly when the
/// plan says `PollForKey`, so the shape is decided once, by
/// `Plannable::tty_use`, and not a second time here.
///
/// The plan itself is not read: `run` already resolved it into `deadline_at`, so
/// the clamp keeps its single site and this module never sees the configuration.
pub(crate) fn drive<T: IpcResponseReader, X: Fn(&str, &str)>(
    armed: &mut Armed<T>,
    _plan: &Plan,
    deadline_at: Instant,
    tty: Option<File>,
    cancel: X,
) -> MechanismEnd {
    let (ipc, request_id) = armed.parts();
    match tty {
        Some(tty) => drive_terminal(ipc, tty, deadline_at, request_id, &cancel),
        None => drive_no_tty(ipc, deadline_at, request_id, &cancel),
    }
}

/// Event loop for GUI contexts whose conversation function must not be driven
/// while TapAuth waits for the phone.
///
/// This is the default for every host that `policy` does not allowlist. It
/// blocks on the daemon IPC socket on the calling thread, returns the reason it
/// stopped, and lets the PAM stack fall through to the password module
/// afterwards.
///
/// Returns the exit reason plus the daemon response, if one was received.
fn run_sequential_event_loop<T: IpcResponseReader>(
    ipc: &mut T,
    deadline: Instant,
) -> (ExitReason, Option<shared::ipc::pb::PamAuthenticateResponse>) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return (ExitReason::Timeout, None);
        }

        let remain = deadline
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        let timeout = PollTimeout::try_from(remain).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(
            unsafe { BorrowedFd::borrow_raw(ipc.fd()) },
            PollFlags::POLLIN,
        )];

        match poll(&mut fds, timeout) {
            Ok(0) => continue,
            Ok(_) => {
                let Some(rev) = fds[0].revents() else {
                    continue;
                };

                // Read data first: POLLIN can arrive together with POLLHUP.
                if rev.contains(PollFlags::POLLIN) {
                    match ipc.try_read_response_nonblocking() {
                        Ok(Some(resp)) => {
                            return (ExitReason::IpcResponseReceived, Some(resp));
                        }
                        Ok(None) => {
                            // No complete frame yet; check for hangup.
                            if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR)
                            {
                                tracing::error!("Daemon closed connection before sending response");
                                return (ExitReason::IpcError, None);
                            }
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("IPC read failed: {e}");
                            return (ExitReason::IpcError, None);
                        }
                    }
                } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                    tracing::error!("Daemon closed connection or error detected");
                    return (ExitReason::IpcError, None);
                }
            }
            Err(e) => {
                if e != nix::errno::Errno::EINTR {
                    tracing::warn!("poll error: {e}");
                    return (ExitReason::IpcError, None);
                }
            }
        }
    }
}

/// The no-terminal shape: wait on the IPC socket alone.
///
/// The verdict comes from the loop's exit, never from the loop itself, so the
/// text and the style of a failure are decided once by `Outcome::notice`.
fn drive_no_tty<T: IpcResponseReader, X: Fn(&str, &str)>(
    ipc: &mut T,
    deadline_at: Instant,
    request_id: &str,
    cancel: &X,
) -> MechanismEnd {
    let (exit_reason, auth_response) = run_sequential_event_loop(ipc, deadline_at);

    match exit_reason {
        // `IpcResponseReceived` without a payload cannot happen (the loop
        // returns it only with `Some`), so it fails closed without a message
        // rather than inventing one.
        ExitReason::IpcResponseReceived => match auth_response {
            Some(resp) => MechanismEnd::Response(resp),
            None => MechanismEnd::Reason(UnavailableReason::ProtocolError),
        },
        ExitReason::Timeout => {
            // The daemon runs on the same deadline and multicasts its own
            // AuthenticationCancel, so no client-side cancel is needed.
            MechanismEnd::Reason(UnavailableReason::TimedOut)
        }
        _ => {
            // IPC error: the request may still be in flight daemon-side.
            // Best-effort cancel through the injected seam, which production
            // wires to a *fresh* short-timeout connection — the live fd is the
            // one that just failed, so a write on it would be a guaranteed
            // no-op and the phone would keep buzzing.
            cancel("gui-ipc-error", request_id);
            // This is the one path that shows its IPC text as an error, so it
            // maps to `IpcError` rather than to the hangup/loop reasons the
            // other two mechanisms use.
            MechanismEnd::Reason(UnavailableReason::IpcError)
        }
    }
}

/// The terminal flow: poll the daemon socket and `/dev/tty` together, and let
/// Enter skip.
///
/// The only mechanism with a terminal to read: a `\n`/`\r` cancels the request
/// on a fresh short connection and ends the wait, any other key is consumed and
/// discarded, and a tty that reaches EOF, errors or hangs up simply stops being
/// polled while the daemon socket keeps waiting.
///
/// Every exit here — response, hangup, read error, skip, deadline — is a
/// reason, and `Outcome::notice` decides the one message it shows.
fn drive_terminal<T: IpcResponseReader, X: Fn(&str, &str)>(
    ipc: &mut T,
    mut tty: File,
    deadline_at: Instant,
    request_id: &str,
    cancel: &X,
) -> MechanismEnd {
    // Set tty nonblocking to avoid read(1) blocking unexpectedly
    {
        if let Ok(cur) = fcntl(&tty, FcntlArg::F_GETFL) {
            let mut flags = OFlag::from_bits_truncate(cur);
            flags.insert(OFlag::O_NONBLOCK);
            let _ = fcntl(&tty, FcntlArg::F_SETFL(flags));
        }
    }

    let mut poll_tty = true;
    let mut kb = [0u8; 4];
    loop {
        let now = Instant::now();
        if now >= deadline_at {
            break;
        }
        let remain = deadline_at
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        let timeout = PollTimeout::try_from(remain).unwrap_or(PollTimeout::MAX);
        let mut fds = [
            PollFd::new(
                unsafe { BorrowedFd::borrow_raw(ipc.fd()) },
                PollFlags::POLLIN,
            ),
            PollFd::new(
                unsafe { BorrowedFd::borrow_raw(tty.as_raw_fd()) },
                PollFlags::POLLIN,
            ),
        ];

        let fds_slice = if poll_tty {
            &mut fds[..2]
        } else {
            &mut fds[..1]
        };

        match poll(fds_slice, timeout) {
            Ok(0) => {}
            Ok(_) => {
                // IPC
                if let Some(rev) = fds[0].revents() {
                    // Read data first if available (POLLIN can be set with POLLHUP)
                    if rev.contains(PollFlags::POLLIN) {
                        match ipc.try_read_response_nonblocking() {
                            Ok(Some(resp)) => return MechanismEnd::Response(resp),
                            Ok(None) => {
                                // No complete frame yet, check for errors
                                if rev.contains(PollFlags::POLLHUP)
                                    || rev.contains(PollFlags::POLLERR)
                                {
                                    tracing::error!(
                                        "Daemon closed connection before sending response"
                                    );
                                    return MechanismEnd::Reason(
                                        UnavailableReason::IpcConnectionLost,
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {}", e);
                                return MechanismEnd::Reason(UnavailableReason::IpcLoopError);
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        // Hangup/error without any data available
                        tracing::error!("Daemon closed connection or error detected");
                        return MechanismEnd::Reason(UnavailableReason::IpcConnectionLost);
                    }
                }
                // TTY - read one byte; skip on Enter, discard other keys
                if poll_tty {
                    if let Some(rev) = fds[1].revents() {
                        if rev.contains(PollFlags::POLLIN) {
                            match tty.read(&mut kb[..1]) {
                                Ok(1) => {
                                    let b = kb[0];
                                    if b == b'\n' || b == b'\r' {
                                        tracing::info!("User pressed Enter to skip");
                                        // Best-effort cancel through the
                                        // injected seam (a fresh short-timeout
                                        // connection in production) so the skip
                                        // is not blocked by an unresponsive
                                        // daemon.
                                        cancel("tty-skip", request_id);
                                        return MechanismEnd::Reason(UnavailableReason::Skipped);
                                    }
                                    // Non-Enter key: consume and ignore
                                }
                                Ok(0) => {
                                    // EOF reached, stop polling TTY to avoid busy loop
                                    poll_tty = false;
                                }
                                Ok(_) => unreachable!("read into 1-byte buffer cannot exceed 1"),
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                Err(_) => {
                                    // Other error, stop polling TTY
                                    poll_tty = false;
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
            Err(e) => {
                if e != nix::errno::Errno::EINTR {
                    tracing::warn!("poll error: {}", e);
                }
            }
        }
    }

    MechanismEnd::Reason(UnavailableReason::TimedOut)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod sequential_loop_tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    struct MockIpcReader {
        stream: UnixStream,
        next_response:
            Option<Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error>>,
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

    #[test]
    fn test_sequential_loop_immediate_timeout() {
        let (_server, client) = UnixStream::pair().unwrap();
        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: None,
        };

        let deadline = Instant::now() - Duration::from_secs(1);
        let (reason, auth_response) = run_sequential_event_loop(&mut mock_ipc, deadline);

        assert_eq!(reason, ExitReason::Timeout);
        assert!(auth_response.is_none());
    }

    #[test]
    fn test_sequential_loop_receives_response() {
        let (mut server, client) = UnixStream::pair().unwrap();

        let mut expected_resp = shared::ipc::pb::PamAuthenticateResponse::default();
        expected_resp.set_outcome(shared::ipc::pb::PamOutcome::Success);

        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: Some(Ok(Some(expected_resp))),
        };

        server.write_all(&[1]).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let (reason, auth_response) = run_sequential_event_loop(&mut mock_ipc, deadline);

        assert_eq!(reason, ExitReason::IpcResponseReceived);
        assert_eq!(
            auth_response.map(|r| r.outcome()),
            Some(shared::ipc::pb::PamOutcome::Success)
        );
    }

    #[test]
    fn test_sequential_loop_daemon_hangup() {
        let (server, client) = UnixStream::pair().unwrap();
        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: Some(Ok(None)),
        };

        std::mem::drop(server);

        let deadline = Instant::now() + Duration::from_secs(5);
        let (reason, auth_response) = run_sequential_event_loop(&mut mock_ipc, deadline);

        assert_eq!(reason, ExitReason::IpcError);
        assert!(auth_response.is_none());
    }
}
