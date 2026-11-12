//! The threaded conversation: a worker thread collects the password while the
//! calling thread multiplexes the daemon socket and a self-pipe.
//!
//! For the hosts whose conversation stays answerable while this thread blocks
//! (see `policy`). This module owns both local-resource failures — `pipe2` and
//! `pthread_create`, with their best-effort cancels, the only non-daemon errors a
//! mechanism may report — and emits nothing: the caller decides the reason's text.

use super::{IpcFault, MechanismEnd};
use crate::ipc_client::IpcResponseReader;
use crate::outcome::{ErrorReason, UnavailableReason};
use crate::pam_sys;
use crate::plan::Plan;
use crate::transaction::Armed;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Context passed to the raw POSIX worker thread: it lives on the main thread's
/// stack and is joined before that frame goes out of scope.
struct ThreadContext {
    pamh: *mut pam_sys::PamHandle,
    password_entered: AtomicBool,
    /// Write end of the self-pipe: one byte on any exit unblocks the main loop.
    pipe_write_fd: std::os::raw::c_int,
}

/// Raw background worker, `C-unwind` so glibc's forced unwind
/// (`abi::__forced_unwind`) from `pthread_cancel` can pass through this frame
/// without aborting the process. On natural completion it always writes the
/// self-pipe; a cancel intercepts it inside `pam_get_authtok` and the write is
/// bypassed. Nothing with a `Drop` lives on this frame, so that unwind is sound.
///
/// # Safety
///
/// `arg` must point to a `ThreadContext` that outlives this call: the main thread
/// holds it and joins before its frame goes out of scope. Its `pipe_write_fd`
/// must be an open write end owned by that thread until the join, and `pamh` must
/// be the handle the conversation is running on.
unsafe extern "C-unwind" fn native_password_worker(
    arg: *mut std::os::raw::c_void,
) -> *mut std::os::raw::c_void {
    // SAFETY: `arg` points at the caller's `ThreadContext`, which it keeps alive
    // until the join — see this function's `# Safety`.
    let ctx = unsafe { &*(arg as *const ThreadContext) };
    let mut authtok: *const std::os::raw::c_char = std::ptr::null();

    // SAFETY: `ctx.pamh` is the handle this conversation is running on.
    let res = unsafe {
        pam_sys::pam_get_authtok(
            ctx.pamh,
            pam_sys::PAM_AUTHTOK,
            &mut authtok,
            std::ptr::null(),
        )
    };

    if res == pam_sys::PAM_SUCCESS && !authtok.is_null() {
        ctx.password_entered.store(true, Ordering::Release);
    }

    // Unconditional write: notifies the main thread that the worker exited,
    // password or not, so a cancel cannot force the full timeout. The bare
    // `write` syscall, not a `write` binding: glibc's wrapper is a cancellation
    // point, so a cancel delivered inside it would unwind through this frame, and
    // the `C-unwind` re-declaration that would need is what rustc's
    // `invalid_runtime_symbol_definitions` rejects (and would be UB).
    let dummy: [u8; 1] = [1];
    loop {
        // SAFETY: `ctx.pipe_write_fd` is an open write end owned by the main
        // thread until the join, and `dummy` outlives this call.
        let written = unsafe {
            libc::syscall(
                libc::SYS_write,
                ctx.pipe_write_fd,
                dummy.as_ptr() as *const std::os::raw::c_void,
                1usize,
            ) as isize
        };
        if written >= 0 {
            break;
        }
        let err = std::io::Error::last_os_error().raw_os_error();
        if err != Some(libc::EINTR) {
            break;
        }
    }

    std::ptr::null_mut()
}

/// The worker entry point the spawn operation must accept: `C-unwind` is what
/// lets glibc's forced unwind pass through the worker frame without aborting.
type WorkerStart =
    unsafe extern "C-unwind" fn(*mut std::os::raw::c_void) -> *mut std::os::raw::c_void;

// The hand-declared `pthread_create`, so a `C-unwind` start routine is passed
// as-is: transmuting it to the `extern "C"` signature would be UB.
extern "C" {
    #[link_name = "pthread_create"]
    fn pthread_create_unwind(
        thread: *mut libc::pthread_t,
        attr: *const libc::pthread_attr_t,
        start_routine: WorkerStart,
        arg: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int;
}

/// Cancel (optionally) and reap the native password worker.
///
/// The join is load-bearing twice over: `ThreadContext` lives on the caller's
/// stack, so the worker must be gone before that frame is popped; and `pamh` is
/// a plain, unlocked struct whose process-global libpam state (`caller_is`) the
/// worker reads inside `pam_get_authtok`, so re-entering libpam — another `conv`
/// call, a `pam_get_item`, the return from `pam_authenticate` — while it runs
/// would race unsynchronised state. The join is what orders them, so it runs on
/// every non-panicking path, including those where the worker has already exited.
///
/// A panic between `pthread_create` and this join unwinds past the frame holding
/// `ThreadContext` without reaping the worker: a pre-existing gap that would need
/// a drop guard, which `guard()` (`lib.rs`) does not close.
///
/// # Safety
///
/// `pthread_id` must be the live, joinable thread created by [`drive_with`], and
/// this must be its only join.
unsafe fn cancel_and_join(pthread_id: libc::pthread_t, cancel: bool) {
    // NOTE: `pthread_cancel` can deadlock the host if the signal arrives while
    // the worker holds an internal libc lock (a malloc arena entered inside
    // `pam_get_authtok`, say). Accepted trade-off: isolating the conversation
    // would need a helper process, as Howdy does.
    if cancel {
        // SAFETY: the same live, joinable `pthread_id` the join below reaps.
        let cancel_res = unsafe { libc::pthread_cancel(pthread_id) };
        // ESRCH is benign: the thread exited naturally, racing the phone tap.
        if cancel_res != 0 && cancel_res != libc::ESRCH {
            let err = std::io::Error::from_raw_os_error(cancel_res);
            tracing::error!("pthread_cancel failed: {err}; worker may not have terminated");
        }
    }

    // SAFETY: if `pthread_join` fails the worker may still be running with a
    // dangling reference into the caller's stack frame; aborting is the only
    // safe response.
    let join_res = unsafe { libc::pthread_join(pthread_id, std::ptr::null_mut()) };
    if join_res != 0 {
        let err = std::io::Error::from_raw_os_error(join_res);
        tracing::error!(
            "pthread_join failed: {err}; aborting because the worker must not outlive its \
             stack frame"
        );
        std::process::abort();
    }
}

/// Why the GUI event loop stopped waiting: threaded's vocabulary, not a verdict.
#[derive(Debug, PartialEq, Eq)]
enum LoopExit {
    Timeout,
    IpcResponseReceived,
    IpcError,
    PasswordEntered,
    PasswordFailed,
}

/// Central event loop for the graphical authentication flow: it polls the daemon
/// socket and the self-pipe together. The out-parameter is a *reason*, not a
/// message, so the loop cannot pick a different string from the terminal loop.
fn run_gui_event_loop<T: IpcResponseReader>(
    ipc: &mut T,
    pipe_read: libc::c_int,
    deadline: Instant,
    ctx: &ThreadContext,
    request_id: &str,
    auth_response: &mut Option<shared::ipc::pb::PamAuthenticateResponse>,
    pending: &mut Option<UnavailableReason>,
) -> LoopExit {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return LoopExit::Timeout;
        }

        let remain = deadline
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        let timeout = PollTimeout::try_from(remain).unwrap_or(PollTimeout::MAX);
        // SAFETY: `Armed` owns this reader and `drive_with` owns the pipe until
        // the join, so both fds outlive this poll set.
        let mut fds = [
            PollFd::new(
                unsafe { BorrowedFd::borrow_raw(ipc.fd()) },
                PollFlags::POLLIN,
            ),
            PollFd::new(
                unsafe { BorrowedFd::borrow_raw(pipe_read) },
                PollFlags::POLLIN,
            ),
        ];

        match poll(&mut fds, timeout) {
            Ok(0) => continue,
            Ok(_) => {
                // Priority: a submitted password beats any concurrent daemon
                // response, so the user is never locked out of the fallback.
                if ctx.password_entered.load(Ordering::Acquire) {
                    tracing::info!("Password submitted; cancelling the TapAuth wait.");
                    let _ = ipc.send_cancel("gui-password-skip", request_id);
                    return LoopExit::PasswordEntered;
                }

                if let Some(rev) = fds[0].revents() {
                    if rev.contains(PollFlags::POLLIN) {
                        match ipc.try_read_response_nonblocking() {
                            Ok(Some(resp)) => {
                                *auth_response = Some(resp);
                                return LoopExit::IpcResponseReceived;
                            }
                            Ok(None) => {
                                if rev.contains(PollFlags::POLLHUP)
                                    || rev.contains(PollFlags::POLLERR)
                                {
                                    tracing::error!(
                                        "Daemon closed connection before sending response"
                                    );
                                    *pending = Some(IpcFault::Hangup.reason());
                                    return LoopExit::IpcError;
                                }
                                continue;
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {e}");
                                *pending = Some(IpcFault::DecodeError.reason());
                                return LoopExit::IpcError;
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        tracing::error!("Daemon closed connection or error detected");
                        *pending = Some(IpcFault::Hangup.reason());
                        return LoopExit::IpcError;
                    }
                }

                // Self-pipe: `password_entered` was checked, so readable = dismissed.
                if let Some(rev) = fds[1].revents() {
                    if rev.contains(PollFlags::POLLIN) {
                        tracing::info!("Password dialog dismissed; cancelling the TapAuth wait.");
                        let _ = ipc.send_cancel("gui-password-failed", request_id);
                        return LoopExit::PasswordFailed;
                    }
                }
            }
            Err(e) => {
                if e != nix::errno::Errno::EINTR {
                    tracing::warn!("poll error: {e}");
                    // Threaded's alone: a poll error stops this loop as an
                    // `IpcLoopError`; sequential answers it per profile.
                    *pending = Some(UnavailableReason::IpcLoopError);
                    return LoopExit::IpcError;
                }
            }
        }
    }
}

/// The threaded GUI flow: a worker thread collects the password while the main
/// thread multiplexes the daemon socket and a self-pipe.
///
/// The plan is unread, arriving for uniformity alone (see `mechanism`); the PAM
/// handle is here only because the password worker needs it. The two
/// local-resource failures are the only errors it can report, and each cancels
/// the in-flight request before returning.
pub(crate) fn drive<T: IpcResponseReader, X: Fn(&str, &str)>(
    armed: &mut Armed<T>,
    _plan: &Plan,
    deadline_at: Instant,
    pamh: *mut pam_sys::PamHandle,
    cancel: X,
) -> MechanismEnd {
    // O_CLOEXEC keeps the pipe fds out of children the long-running privileged
    // host starts (sudo, gdm, polkitd).
    drive_with(
        armed,
        deadline_at,
        pamh,
        cancel,
        // SAFETY: `fds` is the two-element array `drive_with` owns; on success
        // `pipe2` fills both entries with fds this process owns.
        |fds| unsafe { libc::pipe2(fds, libc::O_CLOEXEC) },
        // SAFETY: `thread` points at `drive_with`'s `MaybeUninit` out-param, `attr`
        // is null (defaults) and `arg` at the context it keeps alive until join.
        |thread, attr, start, arg| unsafe { pthread_create_unwind(thread, attr, start, arg) },
    )
}

/// [`drive`] with its two local-resource operations injected: production passes
/// `libc::pipe2` and `pthread_create_unwind`, a test a failing one so each arm
/// and its best-effort cancel are observable. `cancel` is the seam the sequential
/// mechanism uses too — one fresh shorter-timeout connection, never the live fd.
fn drive_with<T, X>(
    armed: &mut Armed<T>,
    deadline_at: Instant,
    pamh: *mut pam_sys::PamHandle,
    cancel: X,
    make_pipe: impl FnOnce(*mut libc::c_int) -> libc::c_int,
    spawn: impl FnOnce(
        *mut libc::pthread_t,
        *const libc::pthread_attr_t,
        WorkerStart,
        *mut std::os::raw::c_void,
    ) -> libc::c_int,
) -> MechanismEnd
where
    T: IpcResponseReader,
    X: Fn(&str, &str),
{
    let (ipc, request_id) = armed.parts();

    let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
    if make_pipe(pipe_fds.as_mut_ptr()) != 0 {
        let err = std::io::Error::last_os_error();
        tracing::error!("Failed to create secure self-pipe: {err}");
        // Best-effort cancel so the phone doesn't keep buzzing.
        cancel("gui-pipe2-fail", request_id);
        return MechanismEnd::Error(ErrorReason::LocalResource);
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    let ctx = ThreadContext {
        pamh,
        password_entered: AtomicBool::new(false),
        pipe_write_fd: pipe_write,
    };

    // SAFETY: `&ctx` lives on this (the main) thread's stack, and every exit path
    // below joins the worker before that frame is popped, so the reference holds
    // for the worker's whole life, cancelled or not.
    let mut pthread_id = std::mem::MaybeUninit::<libc::pthread_t>::uninit();

    let spawn_res = spawn(
        pthread_id.as_mut_ptr(),
        std::ptr::null(),
        native_password_worker,
        &ctx as *const ThreadContext as *mut std::os::raw::c_void,
    );

    if spawn_res != 0 {
        let err = std::io::Error::from_raw_os_error(spawn_res);
        tracing::error!("Failed to create native password thread: {err}");
        cancel("gui-thread-spawn-fail", request_id);
        // SAFETY: `pipe2` returned 0, so both fds are open and ours to close; no
        // worker was spawned that could still use them.
        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
        return MechanismEnd::Error(ErrorReason::LocalResource);
    }

    // SAFETY: the spawn returned 0, so it wrote the `pthread_id` out-param.
    let pthread_id = unsafe { pthread_id.assume_init() };

    let mut auth_response = None;
    let mut pending: Option<UnavailableReason> = None;

    let exit_reason = run_gui_event_loop(
        ipc,
        pipe_read,
        deadline_at,
        &ctx,
        request_id,
        &mut auth_response,
        &mut pending,
    );

    // Cancel unless the worker left `pam_get_authtok` on its own (password
    // entered, dialog dismissed), then always reap it — see `cancel_and_join`
    // for why the join is load-bearing, and the closes for the pipe's owner.
    // SAFETY: `pthread_id` is the thread just spawned and not yet joined, and the
    // two fds are the ones `pipe2` filled; the join happens before this returns.
    unsafe {
        cancel_and_join(
            pthread_id,
            exit_reason != LoopExit::PasswordEntered && exit_reason != LoopExit::PasswordFailed,
        );
        libc::close(pipe_read);
        libc::close(pipe_write);
    }

    // The daemon answered: that is the verdict, whatever the loop exit was.
    if let Some(resp) = auth_response {
        return MechanismEnd::Response(resp);
    }

    // No response, so the service could not be consulted. Every exit is
    // `PAM_AUTHINFO_UNAVAIL` — on a `sufficient` line that is `ignore`, on a
    // `required` line a real failure, and never `PAM_IGNORE`, which records no
    // failure at all. `PasswordEntered` leaves `pam_get_authtok`'s token cached
    // for the next module.
    MechanismEnd::Reason(match exit_reason {
        LoopExit::PasswordEntered => UnavailableReason::PasswordChosen,
        LoopExit::PasswordFailed => UnavailableReason::PasswordDismissed,
        LoopExit::Timeout => UnavailableReason::TimedOut,
        _ => match pending {
            Some(reason) => reason,
            // Every `IpcError` return from the loop records its reason, so this
            // arm cannot be reached; it answers a reason rather than panicking.
            None => UnavailableReason::ProtocolError,
        },
    })
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod gui_loop_tests {
    use super::*;
    use crate::pam_messages;
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

    fn setup_test_pipe_and_ctx() -> (libc::c_int, libc::c_int, ThreadContext) {
        let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
        unsafe {
            let res = libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC);
            assert_eq!(res, 0);
        }
        let ctx = ThreadContext {
            pamh: std::ptr::null_mut(),
            password_entered: AtomicBool::new(false),
            pipe_write_fd: pipe_fds[1],
        };
        (pipe_fds[0], pipe_fds[1], ctx)
    }

    #[test]
    fn test_gui_loop_immediate_timeout() {
        let (_server, client) = UnixStream::pair().unwrap();
        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: None,
        };
        let (pipe_read, pipe_write, ctx) = setup_test_pipe_and_ctx();

        let deadline = Instant::now() - Duration::from_secs(1);
        let mut auth_response = None;
        let mut pending: Option<UnavailableReason> = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &mut auth_response,
            &mut pending,
        );

        assert_eq!(reason, LoopExit::Timeout);
        assert!(auth_response.is_none());
        assert!(pending.is_none());

        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
    }

    #[test]
    fn test_gui_loop_password_entered_breakout() {
        let (_server, client) = UnixStream::pair().unwrap();
        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: None,
        };
        let (pipe_read, pipe_write, ctx) = setup_test_pipe_and_ctx();

        ctx.password_entered.store(true, Ordering::Release);
        let dummy = [1u8];
        unsafe {
            libc::write(pipe_write, dummy.as_ptr() as *const _, 1);
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending: Option<UnavailableReason> = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &mut auth_response,
            &mut pending,
        );

        assert_eq!(reason, LoopExit::PasswordEntered);
        assert!(auth_response.is_none());
        assert!(pending.is_none());

        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
    }

    #[test]
    fn test_gui_loop_password_dialog_failed_breakout() {
        let (_server, client) = UnixStream::pair().unwrap();
        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: None,
        };
        let (pipe_read, pipe_write, ctx) = setup_test_pipe_and_ctx();

        ctx.password_entered.store(false, Ordering::Release);
        let dummy = [1u8];
        unsafe {
            libc::write(pipe_write, dummy.as_ptr() as *const _, 1);
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending: Option<UnavailableReason> = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &mut auth_response,
            &mut pending,
        );

        assert_eq!(reason, LoopExit::PasswordFailed);
        assert!(auth_response.is_none());
        assert!(pending.is_none());

        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
    }

    #[test]
    fn test_gui_loop_successful_phone_tap() {
        let (mut server, client) = UnixStream::pair().unwrap();

        let mut expected_resp = shared::ipc::pb::PamAuthenticateResponse::default();
        expected_resp.set_outcome(shared::ipc::pb::PamOutcome::Success);

        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: Some(Ok(Some(expected_resp))),
        };

        server.write_all(&[1]).unwrap();

        let (pipe_read, pipe_write, ctx) = setup_test_pipe_and_ctx();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending: Option<UnavailableReason> = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &mut auth_response,
            &mut pending,
        );

        assert_eq!(reason, LoopExit::IpcResponseReceived);
        assert_eq!(
            auth_response.unwrap().outcome(),
            shared::ipc::pb::PamOutcome::Success
        );
        assert!(pending.is_none());

        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
    }

    #[test]
    fn test_gui_loop_daemon_hangup() {
        let (server, client) = UnixStream::pair().unwrap();
        let mut mock_ipc = MockIpcReader {
            stream: client,
            next_response: Some(Ok(None)),
        };

        std::mem::drop(server);

        let (pipe_read, pipe_write, ctx) = setup_test_pipe_and_ctx();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending: Option<UnavailableReason> = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &mut auth_response,
            &mut pending,
        );

        assert_eq!(reason, LoopExit::IpcError);
        assert!(auth_response.is_none());
        assert_eq!(pending, Some(UnavailableReason::IpcConnectionLost));

        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
    }

    #[test]
    fn test_wait_announcement_is_single_line() {
        let text = pam_messages::load_for_user("testuser")
            .waiting_for_tap_password()
            .to_string();

        assert!(
            !text.is_empty(),
            "the sequential-wait announcement resolved to an empty string"
        );
        assert!(
            !text.contains("pam-waiting-tap-password"),
            "the sequential-wait announcement is the unresolved '??key??' fallback marker, \
             so the pam-waiting-tap-password key is missing from the loaded locale: {:?}",
            text
        );
        assert!(
            !text.contains('\n') && !text.contains('\r'),
            "the sequential-wait announcement must stay on one line, got {:?}",
            text
        );
    }
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod join_tests {
    use super::*;
    use std::os::raw::c_void;

    static JOIN_TEST_STARTED: AtomicBool = AtomicBool::new(false);

    struct JoinTestCtx {
        pipe_read: libc::c_int,
    }

    /// Blocks in `read(2)`, a cancellation point like `pam_get_authtok`, so
    /// `cancel_and_join` can only return promptly by cancelling the thread;
    /// `C-unwind` lets glibc's forced unwind pass through this frame.
    unsafe extern "C-unwind" fn join_test_worker(arg: *mut c_void) -> *mut c_void {
        let ctx = unsafe { &*(arg as *const JoinTestCtx) };
        JOIN_TEST_STARTED.store(true, Ordering::Release);
        let mut buf = [0u8; 1];
        unsafe {
            libc::read(ctx.pipe_read, buf.as_mut_ptr() as *mut c_void, 1);
        }
        std::ptr::null_mut()
    }

    #[test]
    fn cancel_and_join_reaps_a_worker_blocked_in_a_cancellation_point() {
        let mut fds: [libc::c_int; 2] = [-1, -1];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2 failed"
        );

        // The write end stays open: only a cancel unblocks the worker.
        let ctx = JoinTestCtx { pipe_read: fds[0] };
        let mut tid = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
        let rc = unsafe {
            pthread_create_unwind(
                tid.as_mut_ptr(),
                std::ptr::null(),
                join_test_worker,
                &ctx as *const JoinTestCtx as *mut c_void,
            )
        };
        assert_eq!(rc, 0, "pthread_create failed");
        let tid = unsafe { tid.assume_init() };

        // Watchdog: unblock the worker after 5s so a missing cancel fails this
        // test instead of hanging it.  It owns the write end and closes it.
        let watchdog_write = fds[1];
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            let byte = [1u8];
            unsafe {
                libc::write(watchdog_write, byte.as_ptr() as *const c_void, 1);
                libc::close(watchdog_write);
            }
        });

        let start_deadline = Instant::now() + Duration::from_secs(2);
        while !JOIN_TEST_STARTED.load(Ordering::Acquire) {
            assert!(
                Instant::now() < start_deadline,
                "worker thread never started"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let started = Instant::now();
        unsafe { cancel_and_join(tid, true) };
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "cancel_and_join took {elapsed:?}: the worker was not cancelled and had to be \
             unblocked by the watchdog"
        );

        unsafe { libc::close(fds[0]) };
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
mod local_resource_tests {
    use super::*;
    use crate::transaction::armed_for_test;
    use std::cell::{Cell, RefCell};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    /// An `IpcResponseReader` that is never read: the local-resource arms return
    /// before the event loop.
    struct NullReader {
        stream: UnixStream,
    }

    impl NullReader {
        fn new() -> Self {
            let (_server, stream) = UnixStream::pair().unwrap();
            NullReader { stream }
        }
    }

    impl IpcResponseReader for NullReader {
        fn fd(&self) -> RawFd {
            self.stream.as_raw_fd()
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

    /// A failed `pipe2` returns `Error(LocalResource)`, cancels exactly once on
    /// the request id, and never reaches the spawn operation.
    ///
    /// The defect this catches: the `pipe2` arm returning `Reason(..)`
    /// (`PAM_AUTHINFO_UNAVAIL`) instead of `Error(..)` (`PAM_AUTH_ERR`), or
    /// skipping/multiplying the cancel — the phone keeps buzzing, and a
    /// `sufficient` stack falls through as if the daemon had been unreachable.
    #[test]
    fn pipe2_failure_cancels_once_and_reports_local_resource() {
        let mut armed = armed_for_test(NullReader::new(), "pipe2-fail-request");
        let cancels: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let spawn_called = Cell::new(false);

        let end = drive_with(
            &mut armed,
            Instant::now() + Duration::from_secs(5),
            std::ptr::null_mut(),
            |reason: &str, rid: &str| cancels.borrow_mut().push(format!("{reason}:{rid}")),
            |_fds| -1,
            |_thread, _attr, _start, _arg| {
                spawn_called.set(true);
                0
            },
        );

        assert!(
            matches!(end, MechanismEnd::Error(ErrorReason::LocalResource)),
            "a failed pipe2 must conclude as Error(LocalResource) (PAM_AUTH_ERR), \
             not as a daemon unavailability"
        );
        assert_eq!(
            cancels.borrow().as_slice(),
            ["gui-pipe2-fail:pipe2-fail-request"],
            "the pipe2 failure must cancel exactly once, on its own request id"
        );
        assert!(
            !spawn_called.get(),
            "no worker may be spawned after the self-pipe failed"
        );
    }

    /// A failed `pthread_create` returns `Error(LocalResource)`, cancels
    /// exactly once, and closes both pipe fds.
    ///
    /// The defect this catches: the spawn-failure arm leaking the two
    /// `O_CLOEXEC` fds into the long-running privileged host — invisible in a
    /// passing build because the return code is right either way — or cancelling
    /// with the wrong reason, or not at all.
    ///
    /// The whole sequence runs in a forked child and the parent only asserts the
    /// child's exit status. Checking `fcntl(fd, F_GETFD)` in the test process
    /// after `drive_with` returned races every other test that opens an fd: the
    /// same number can be reused between the close and the check (observed
    /// 6/40 at `--test-threads=16`). The child's fd table is its own, so the
    /// check is exact. `alarm(5)` turns a hang into `SIGALRM`; the child writes
    /// a diagnostic with `write(2)` and `_exit`s — no panics, no stdio locks.
    #[test]
    fn spawn_failure_cancels_once_closes_both_fds_and_reports_local_resource() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe { libc::alarm(5) };
            let code = run_spawn_failure_probe();
            unsafe { libc::_exit(code) };
        }

        let mut status: libc::c_int = 0;
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(reaped, pid, "waitpid must reap the child");
        assert!(
            libc::WIFEXITED(status),
            "the spawn-failure probe did not exit (wait status {status}); SIGALRM \
             means the failing sequence hung"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the failing spawn sequence left an fd open or cancelled wrongly \
             (child exit {})",
            libc::WEXITSTATUS(status)
        );
    }

    /// The child half of
    /// [`spawn_failure_cancels_once_closes_both_fds_and_reports_local_resource`]:
    /// drive the real failing sequence and return an exit code (0 = pass).
    fn run_spawn_failure_probe() -> libc::c_int {
        let mut armed = armed_for_test(NullReader::new(), "spawn-fail-request");
        let cancels: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let seen_fds = Cell::new([-1, -1]);

        let end = drive_with(
            &mut armed,
            Instant::now() + Duration::from_secs(5),
            std::ptr::null_mut(),
            |reason: &str, rid: &str| cancels.borrow_mut().push(format!("{reason}:{rid}")),
            |fds| {
                let rc = unsafe { libc::pipe2(fds, libc::O_CLOEXEC) };
                if rc == 0 {
                    seen_fds.set(unsafe { [*fds, *fds.add(1)] });
                }
                rc
            },
            |_thread, _attr, _start, _arg| libc::EAGAIN,
        );

        if !matches!(end, MechanismEnd::Error(ErrorReason::LocalResource)) {
            return child_diagnostic(b"spawn failure did not conclude Error(LocalResource)\n");
        }
        if cancels.borrow().as_slice() != ["gui-thread-spawn-fail:spawn-fail-request"] {
            return child_diagnostic(
                b"spawn failure did not cancel exactly once as \
                  gui-thread-spawn-fail:spawn-fail-request\n",
            );
        }

        let fds = seen_fds.get();
        if fds == [-1, -1] {
            return child_diagnostic(b"the test pipe was never created\n");
        }
        for fd in fds {
            let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if rc != -1 {
                return child_diagnostic(
                    b"an fd survived the failed pthread_create: the fds leak into \
                      the host\n",
                );
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
                return child_diagnostic(
                    b"an fd was freed but its errno is not EBADF (it was not \
                      ours to close)\n",
                );
            }
        }
        0
    }

    /// Write `message` to stderr and return 1: the only failure channel a forked
    /// child may use — no `panic!` (unwinding on the copied parent state) and no
    /// `eprintln!` (it takes the stdio lock another thread may hold at fork time).
    fn child_diagnostic(message: &[u8]) -> libc::c_int {
        unsafe {
            libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len());
        }
        1
    }

    /// The join-failure abort actually aborts.
    ///
    /// `std::process::abort()` cannot be observed from inside the process, so
    /// this forks: the child joins itself (`pthread_join` on a joinable
    /// `pthread_self()` yields `EDEADLK` on glibc), which drives the defensive
    /// abort, and the parent asserts `SIGABRT`. The `alarm(5)` turns a hung
    /// child into a `SIGALRM` failure rather than a hung suite; a child that
    /// exits `0` (join unexpectedly succeeded) also fails.
    ///
    /// Platform assumption: glibc's `pthread_join` returns `EDEADLK` on a
    /// self-join, and a Linux `fork` that runs the atfork handlers.
    #[test]
    fn join_failure_aborts_the_process() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // Child: no `exit`, so no Rust destructor or atexit handler runs on
            // the forked copy of the parent's state.
            unsafe {
                libc::alarm(5);
                cancel_and_join(libc::pthread_self(), false);
                libc::_exit(0);
            }
        }

        let mut status: libc::c_int = 0;
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(reaped, pid, "waitpid must reap the child");
        assert!(
            libc::WIFSIGNALED(status),
            "the child did not die by signal (wait status {status}): the \
             pthread_join failure returned instead of aborting"
        );
        assert_eq!(
            libc::WTERMSIG(status),
            libc::SIGABRT,
            "a failed pthread_join must abort (SIGABRT), not exit or die of the \
             test's own SIGALRM"
        );
    }
}
