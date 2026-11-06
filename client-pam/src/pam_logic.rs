//! PAM authentication logic for TapAuth.
//!
//! Implements the core authentication flow that integrates with Linux PAM.
//! Supports both terminal (with skip detection via Enter key) and GUI contexts
//! (e.g., Polkit dialogs).
//!
//! ## Flow
//!
//! 1. Load paired devices for the user
//! 2. Send authentication request via BLE/UDP multicast
//! 3. Wait for phone tap or user skip (terminal only)
//! 4. On skip, send IPC cancel to daemon (best effort) plus network cancel
//! 5. Return `PAM_SUCCESS` on authentication; every other outcome returns a
//!    real verdict (`PAM_PERM_DENIED`, `PAM_AUTHINFO_UNAVAIL` or `PAM_AUTH_ERR`),
//!    never `PAM_IGNORE`: Linux-PAM records no failure for that code, so a later
//!    `optional` module voting success (e.g. `pam_permit`) would grant the stack.
//!
//! ## Threading
//!
//! Uses a shared async runtime to avoid the ~100ms overhead of creating a new
//! runtime per authentication attempt. A separate thread monitors `/dev/tty`
//! for skip signals in terminal contexts. TTY-less (GUI) hosts are split into
//! three conversation modes by the policy table in `policy`; only allowlisted hosts get
//! the worker thread, hosts that collect the password before calling into PAM
//! get a synchronous replay and no daemon request at all, and everyone else
//! keeps the conversation on the caller's thread.
//!
//! ## Return-code mapping
//!
//! | Transition | Code |
//! | :--- | :--- |
//! | Phone approved the request | `PAM_SUCCESS` |
//! | Phone explicitly denied | `PAM_PERM_DENIED` |
//! | Timeout, dialog dismissed, IPC error, no paired device, skip, DM bypass | `PAM_AUTHINFO_UNAVAIL` |
//! | Daemon reported an internal error, or a local failure (conversation lookup, RNG, pipe/thread spawn) | `PAM_AUTH_ERR` |
//! | Username lookup failed | `PAM_USER_UNKNOWN` |

use crate::config::PamConfig;
use crate::context::{CallerContext, ServiceName};
use crate::ipc_client::{IpcClient, IpcError, IpcResponseReader};
use crate::logging;
use crate::outcome::{ErrorReason, Outcome, UnavailableReason};
use crate::pam_messages;
use crate::pam_sys;
use crate::plan::{Announcement, Plannable, TtyUse};
use crate::policy;
use crate::transaction::{Armed, Finished, StartError};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// The terminal flow below uses a single-threaded poll loop over the IPC
// socket and /dev/tty.  The GUI flow (no TTY) comes in three variants,
// selected by the policy table (`policy::classify`) — an allowlist of calling
// processes with a sequential default:
//
// * Threaded (`polkit-agent-helper-1`, `kscreenlocker_worker`, `hyprlock`,
//   `authproto_pam`, and GDM's reauthentication worker): the conversation can
//   be driven from another thread.  Polkit's is a plain blocking socket fd fed
//   by the *separate* agent process; kscreenlocker ≥ 6.8 makes it a peer D-Bus
//   answered by Qt's `QDBusConnectionManager` daemon thread, not by the thread
//   that called `pam_authenticate`.  A native POSIX thread collects the
//   password while the main thread waits for the phone, and the main loop
//   multiplexes the IPC socket and a self-pipe (`run_gui_event_loop`).
//
// * PreCollected (`swaylock`, `gtklock`, `i3lock`): the host reads the
//   password *before* calling `pam_authenticate` and its conversation is a
//   synchronous replay of that already-typed password.  The module therefore
//   collects the token on the calling thread with no daemon request at all and
//   immediately hands over to the next PAM module (see the branch in
//   `authenticate`).  Ringing the phone here would be misleading: the user has
//   already chosen the password route, and the wait could only ever time out.
//
// * Sequential (everything else, which includes older kscreenlocker,
//   `xfce4-screensaver-dialog` and `mate-screensaver-dialog`, and every host
//   not explicitly known to be safe): the conversation is a synchronous
//   round-trip that must be dispatched by the host's own event loop on the
//   thread that called `pam_authenticate`.  Blocking that thread (or driving
//   the conversation from a second thread, which older kscreenlocker cannot
//   answer because it posts the reply to the blocked thread) deadlocks the
//   host, so the main thread simply waits for the daemon on its own and never
//   *drives* the conversation (`run_sequential_event_loop`).
//   The one exception is a single non-blocking `PAM_TEXT_INFO` announcement
//   emitted immediately before the wait begins: it is one conversation round
//   trip that carries no input, and host event loops need it in order to
//   reveal the password entry.  Should the host's conversation return an
//   error, `try_info` logs and swallows it, so the verdict is unchanged; a
//   NULL conversation never reaches this point at all, because
//   `PamConversation::new` fails first and the module returns
//   `PAM_AUTH_ERR` as before.
//
// The native password thread used by the threaded variant uses no Drop-bearing
// Rust types so that pthread_cancel is safe.

/// How the PAM conversation of the calling host may be driven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConversationMode {
    /// The conversation may run on a background thread while the calling
    /// thread waits for the daemon.
    Threaded,
    /// The host collected the password before calling `pam_authenticate` and
    /// its conversation only replays it.  The module collects the token on the
    /// calling thread and hands over without contacting the daemon.
    PreCollected,
    /// The conversation must be left to the calling thread/host event loop.
    Sequential,
}

/// Reason the GUI authentication loop exited.  Prevents the "timed out"
/// message from being displayed on top of an explicit IPC error message.
#[derive(Debug, PartialEq, Eq)]
enum ExitReason {
    Timeout,
    IpcResponseReceived,
    IpcError,
    PasswordEntered,
    PasswordFailed,
}

/// Context passed to the raw POSIX worker thread.
///
/// # Safety
///
/// This lives on the main thread's stack.  The main thread strictly blocks on
/// `pthread_join` before the context goes out of scope, so the worker thread's
/// reference to it is valid for the entire worker lifetime.  No `Drop`-bearing
/// types are placed on the worker's stack frame, making `pthread_cancel` safe.
struct ThreadContext {
    pamh: *mut pam_sys::PamHandle,
    password_entered: AtomicBool,
    /// Write end of the self-pipe.  The worker writes a single byte here on
    /// any exit path (success, failure, or dialog dismissal) to instantly
    /// unblock the main loop's poll set.
    pipe_write_fd: std::os::raw::c_int,
}

/// Raw background worker using the `C-unwind` ABI so that glibc's forced
/// stack unwinding (`abi::__forced_unwind`) triggered by `pthread_cancel`
/// can pass through this frame without aborting the process.
///
/// Always writes to the self-pipe on natural completion.  When the thread
/// is cancelled via `pthread_cancel`, the forced unwind intercepts
/// execution inside `pam_get_authtok` and the write is cleanly bypassed.
unsafe extern "C-unwind" fn native_password_worker(
    arg: *mut std::os::raw::c_void,
) -> *mut std::os::raw::c_void {
    let ctx = unsafe { &*(arg as *const ThreadContext) };
    let mut authtok: *const std::os::raw::c_char = std::ptr::null();

    // SAFETY: ctx is valid because the main thread guarantees it outlives
    // this worker via pthread_join.
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

    // Unconditional write: notifies the main thread that the worker exited
    // regardless of whether a password was collected or the dialog was
    // cancelled.  Without this, cancel/poll-hang would force the full
    // timeout.
    //
    // glibc's `write` is a cancellation point, so a `pthread_cancel` delivered
    // inside it would throw `abi::__forced_unwind` through this call frame.
    // `pam_get_authtok` above needs the `C-unwind` ABI for that, but the
    // runtime `write` symbol must keep its canonical `extern "C"` signature:
    // re-declaring it with a different ABI is what rustc's
    // `invalid_runtime_symbol_definitions` rejects, and a mismatched runtime
    // declaration risks UB.  Use the bare `write` syscall instead — the
    // cancellation machinery lives in glibc's `write` wrapper, so the raw
    // syscall is not a cancellation point and cannot unwind.
    let dummy: [u8; 1] = [1];
    loop {
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

/// Cancel (optionally) and reap the native password worker.
///
/// # Why the join is load-bearing
///
/// 1. Stack safety: `ThreadContext` lives on the caller's stack, so the worker
///    must be gone before that frame is popped.
/// 2. libpam ownership: `pamh` is a plain, unlocked struct and the libpam
///    state the conversation depends on (`caller_is`) is process-global.  If
///    the calling thread re-entered libpam — another `conv` call, a
///    `pam_get_item`, or simply the return from `pam_authenticate` — while the
///    worker could still be inside `pam_get_authtok`, the two would race on
///    unsynchronised libpam state.  The join is what orders them, so it runs on
///    every non-panicking path, including the ones where the worker is expected
///    to have exited already.
///
/// A panic between the `pthread_create` and this join unwinds past the frame
/// that holds `ThreadContext` without reaping the worker.  That pre-existing
/// gap is not addressed by this change — closing it would need a drop guard —
/// and `guard()` (`lib.rs`) only converts the panic into `PAM_AUTH_ERR`.
///
/// # Safety
///
/// `pthread_id` must be a live, joinable thread created by this module, and
/// this must be its only join.
unsafe fn cancel_and_join(pthread_id: libc::pthread_t, cancel: bool) {
    // NOTE: pthread_cancel carries a theoretical risk of deadlocking the parent
    // process if the cancellation signal arrives while the worker holds an
    // internal libc lock (e.g. inside a malloc arena entered by
    // pam_get_authtok).  This is an accepted architectural trade-off; fully
    // isolating the conversation pipe would require a separate helper process,
    // as Howdy does with its Python subprocess.
    if cancel {
        let cancel_res = unsafe { libc::pthread_cancel(pthread_id) };
        // ESRCH is benign: the thread already exited naturally during a race
        // between password entry and the phone tap response.
        if cancel_res != 0 && cancel_res != libc::ESRCH {
            let err = std::io::Error::from_raw_os_error(cancel_res);
            tracing::error!("pthread_cancel failed: {err}; worker may not have terminated");
        }
    }

    // SAFETY: if pthread_join fails the worker thread may still be running with
    // a dangling reference into the caller's stack frame.  Aborting is the only
    // safe response.
    let join_res = unsafe { libc::pthread_join(pthread_id, std::ptr::null_mut()) };
    if join_res != 0 {
        let err = std::io::Error::from_raw_os_error(join_res);
        tracing::error!("pthread_join failed: {err}. Aborting to defend stack safety.");
        std::process::abort();
    }
}

/// Central event loop for the graphical authentication flow.
///
/// Polls the daemon IPC socket and the self-pipe simultaneously.  Returns an
/// `ExitReason` plus whichever side-channel data was collected (the daemon
/// response, or the reason the IPC side failed).  Extracted from the main
/// authentication body so the multiplexing logic can be unit-tested
/// independently.
///
/// The out-parameter is a *reason*, not a message: which text and which style
/// the failure shows is decided once, by `Outcome::notice`, so the loop cannot
/// pick a different string from the terminal loop for the same failure.
#[allow(clippy::too_many_arguments)]
fn run_gui_event_loop<T: IpcResponseReader>(
    ipc: &mut T,
    pipe_read: libc::c_int,
    deadline: Instant,
    ctx: &ThreadContext,
    request_id: &str,
    auth_response: &mut Option<shared::ipc::pb::PamAuthenticateResponse>,
    pending: &mut Option<UnavailableReason>,
) -> ExitReason {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return ExitReason::Timeout;
        }

        let remain = deadline
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        let timeout = PollTimeout::try_from(remain).unwrap_or(PollTimeout::MAX);
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
                // Priority: user password submission takes absolute
                // precedence over any concurrent daemon response, so the
                // user is never locked out of the password fallback.
                if ctx.password_entered.load(Ordering::Acquire) {
                    tracing::info!(
                        "Password entered via Polkit agent. Cancelling TapAuth transaction."
                    );
                    let _ = ipc.send_cancel("gui-password-skip", request_id);
                    return ExitReason::PasswordEntered;
                }

                // Daemon IPC connection
                if let Some(rev) = fds[0].revents() {
                    if rev.contains(PollFlags::POLLIN) {
                        match ipc.try_read_response_nonblocking() {
                            Ok(Some(resp)) => {
                                *auth_response = Some(resp);
                                return ExitReason::IpcResponseReceived;
                            }
                            Ok(None) => {
                                if rev.contains(PollFlags::POLLHUP)
                                    || rev.contains(PollFlags::POLLERR)
                                {
                                    tracing::error!(
                                        "Daemon closed connection before sending response"
                                    );
                                    *pending = Some(UnavailableReason::IpcConnectionLost);
                                    return ExitReason::IpcError;
                                }
                                continue;
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {e}");
                                *pending = Some(UnavailableReason::IpcLoopError);
                                return ExitReason::IpcError;
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        tracing::error!("Daemon closed connection or error detected");
                        *pending = Some(UnavailableReason::IpcConnectionLost);
                        return ExitReason::IpcError;
                    }
                }

                // Self-pipe: since password_entered was already checked,
                // readability here means the dialog was dismissed.
                if let Some(rev) = fds[1].revents() {
                    if rev.contains(PollFlags::POLLIN) {
                        tracing::info!("Password dialog dismissed. Releasing transaction.");
                        let _ = ipc.send_cancel("gui-password-failed", request_id);
                        return ExitReason::PasswordFailed;
                    }
                }
            }
            Err(e) => {
                if e != nix::errno::Errno::EINTR {
                    tracing::warn!("poll error: {e}");
                    *pending = Some(UnavailableReason::IpcLoopError);
                    return ExitReason::IpcError;
                }
            }
        }
    }
}

/// Event loop for GUI contexts whose conversation function must not be driven
/// while TapAuth waits for the phone.
///
/// This is the default for every host that `conversation_mode` does not
/// allowlist.  Such a host typically implements the conversation as a
/// synchronous round-trip that can only be answered by the event loop running
/// on the very thread that called `pam_authenticate` (kscreenlocker ≤ 6.7, for
/// instance, posts the answer back to that thread).  For those hosts:
///
/// 1. collecting the password from a background thread deadlocks: the
///    conversation reply is queued for the blocked host event loop and can
///    never be dispatched, so password entry stops working entirely, and
/// 2. `pthread_cancel`-ing that background thread (as the threaded flow does)
///    would force-unwind through the host's non-Rust frames, which can
///    `abort()` the host process and take the lock screen down with it.
///
/// The safe pattern is to never drive the conversation from this thread: no
/// query is sent and no input is read, and the conversation is not touched at
/// all while the module waits.  It blocks on the daemon IPC socket on the
/// calling thread, returns the result, and lets the PAM stack fall through to
/// the password module afterwards (whose own conversation then runs on the
/// host's terms).  The one exception is a single non-blocking `PAM_TEXT_INFO`
/// announcement emitted immediately before this loop starts (see the caller):
/// it carries no input and hosts need it in order to reveal their password
/// entry.  Because nothing is consumed here, a typed password only counts once
/// the *following* module prompts for it, after the (shorter) GUI timeout —
/// which is why `pam_gui_timeout_secs` exists.
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

/// The threaded GUI flow: a worker thread collects the password while the main
/// thread multiplexes the daemon socket and a self-pipe.
///
/// For the hosts whose conversation stays answerable while the calling thread
/// is blocked (see `policy`), blocking credential collection is offloaded to a
/// native background thread so the host can process window events, and the
/// main loop watches both the IPC socket and the self-pipe.
///
/// Returns the verdict, never a code: the caller maps it with `to_pam`
/// (`finish`), so this function cannot produce a `PAM_*` value of its own. The
/// two local-resource failures (`pipe2`, `pthread_create`) are the only errors
/// it can report, and both cancel the in-flight request first.
fn run_threaded<T: IpcResponseReader>(
    pamh: *mut pam_sys::PamHandle,
    ipc: &mut T,
    deadline_at: Instant,
    request_id: &str,
) -> Outcome {
    // O_CLOEXEC prevents the pipe fds from leaking to child processes
    // started by the long-running privileged host (sudo, gdm, polkitd).
    let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        let err = std::io::Error::last_os_error();
        tracing::error!("Failed to create secure self-pipe: {err}");
        // Best-effort cancel so the phone doesn't keep buzzing.
        if let Ok(mut c) = IpcClient::connect(Duration::from_millis(100)) {
            let _ = c.send_cancel("gui-pipe2-fail", request_id);
        }
        return Outcome::Error(ErrorReason::LocalResource);
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    let ctx = ThreadContext {
        pamh,
        password_entered: AtomicBool::new(false),
        pipe_write_fd: pipe_write,
    };

    // SAFETY: &ctx lives on this (the main) thread's stack.  All exit
    // paths below unconditionally call pthread_join, which blocks until
    // the worker has been fully reaped by the kernel.  Therefore the
    // reference passed to the worker remains valid for its entire
    // execution, regardless of whether the worker completes normally or
    // is cancelled via pthread_cancel.
    let mut pthread_id = std::mem::MaybeUninit::<libc::pthread_t>::uninit();

    // Custom FFI binding for pthread_create that accepts the correct
    // `extern "C-unwind"` function signature.  This avoids the undefined
    // behaviour of transmuting between C-unwind and C ABIs.
    extern "C" {
        #[link_name = "pthread_create"]
        fn pthread_create_unwind(
            thread: *mut libc::pthread_t,
            attr: *const libc::pthread_attr_t,
            start_routine: unsafe extern "C-unwind" fn(
                *mut std::os::raw::c_void,
            ) -> *mut std::os::raw::c_void,
            arg: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int;
    }

    let spawn_res = unsafe {
        pthread_create_unwind(
            pthread_id.as_mut_ptr(),
            std::ptr::null(),
            native_password_worker,
            &ctx as *const ThreadContext as *mut std::os::raw::c_void,
        )
    };

    if spawn_res != 0 {
        let err = std::io::Error::from_raw_os_error(spawn_res);
        tracing::error!("Failed to create native password thread: {err}");
        if let Ok(mut c) = IpcClient::connect(Duration::from_millis(100)) {
            let _ = c.send_cancel("gui-thread-spawn-fail", request_id);
        }
        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
        return Outcome::Error(ErrorReason::LocalResource);
    }

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

    // Cancel the worker if it hasn't already exited on its own, then always
    // reap it (see `cancel_and_join` for why the join is load-bearing).
    //
    // Password entry and dialog dismissal both mean the worker has left
    // `pam_get_authtok` on its own, so those paths skip the cancel.
    unsafe {
        cancel_and_join(
            pthread_id,
            exit_reason != ExitReason::PasswordEntered && exit_reason != ExitReason::PasswordFailed,
        );
        libc::close(pipe_read);
        libc::close(pipe_write);
    }

    // The daemon answered: that is the verdict, whatever the loop exit was.
    if let Some(resp) = auth_response {
        return Outcome::from_daemon(resp);
    }

    // No response, so the service could not be consulted. The reason comes
    // from the exit: the user chose the password (`PasswordEntered`, which
    // leaves the token cached by `pam_get_authtok` for the next module),
    // dismissed the dialog (`PasswordFailed`), the daemon went quiet
    // (`Timeout`) or the IPC layer failed (`IpcError`, with the reason the
    // loop recorded). Every one of them is `PAM_AUTHINFO_UNAVAIL`: on a
    // `sufficient` line that is `ignore`, and on a `required` line a real
    // failure — never `PAM_IGNORE`, which records no failure at all.
    match exit_reason {
        ExitReason::PasswordEntered => Outcome::Unavailable(UnavailableReason::PasswordChosen),
        ExitReason::PasswordFailed => Outcome::Unavailable(UnavailableReason::PasswordDismissed),
        ExitReason::Timeout => Outcome::Unavailable(UnavailableReason::TimedOut),
        _ => match pending {
            Some(reason) => Outcome::Unavailable(reason),
            // An `IpcError` always records its reason, so this arm is
            // unreachable; it is not a panic path because a shipped
            // `cdylib` compiles panics out.
            None => Outcome::Unavailable(UnavailableReason::ProtocolError),
        },
    }
}

/// Main PAM authentication entry point.
///
/// ## Returns
///
/// The orchestration returns a [`Finished`], whose two arms both carry an
/// [`Outcome`]; `Outcome::to_pam` is the only conversion, and the `match` below
/// is its only caller. Which reasons reach which code is the table in
/// `Outcome::to_pam` / `Outcome::notice`, not a per-call decision here:
///
/// - `PAM_SUCCESS`: this call's daemon response was a phone tap, or a duplicate
///   answered from this process's 500 ms reuse record (a replay, which records
///   nothing and shows nothing)
/// - `PAM_PERM_DENIED`: The user explicitly denied the request on the phone
/// - `PAM_AUTHINFO_UNAVAIL`: The authentication service could not be consulted —
///   no paired devices, the user skipped, the daemon is unreachable, the
///   attempt timed out, a display-manager login or a remote caller was skipped,
///   or a pre-collected host's token was handed on. On a `sufficient` line
///   (which expands to
///   `[success=done new_authtok_reqd=done default=ignore]`) this still falls
///   through to the next module, so password fallback is preserved
/// - `PAM_AUTH_ERR`: This attempt failed while being processed — the daemon
///   reported an internal error, the conversation lookup failed, the request id
///   could not be generated, or a local resource could not be created
/// - `PAM_USER_UNKNOWN`: Failed to retrieve username from PAM
///
/// `PAM_IGNORE` is deliberately never returned.  Linux-PAM records no failure
/// for it, so a later `optional` module that votes success (e.g. `pam_permit`)
/// turns the whole stack into `PAM_SUCCESS` — an authentication bypass.  That is
/// a `required`-line hazard, and it is the shape this protects: there
/// `PAM_IGNORE` is explicitly `ignore` while `PAM_AUTHINFO_UNAVAIL` is `bad`.
/// On a `sufficient` line both codes are `ignore` and a following
/// `optional pam_permit` grants either way, so there the stack's own
/// configuration, not the return code, is what prevents the grant.
pub fn authenticate(pamh: *mut pam_sys::PamHandle) -> c_int {
    logging::init_logging();
    tracing::info!("TapAuth PAM module called (custom bindings)");

    // The caller facts are read once, here, and every consumer reads the
    // captured values — the policy, the log line in `capture`, the verdict
    // cache's key and the skip's decision. No second resolution exists.
    let ctx = unsafe { CallerContext::capture(pamh) };
    // The orchestration returns the verdict, never a code. This is the one
    // place a `PAM_*` value is produced from it: `to_pam` is exhaustive, so an
    // arm cannot be forgotten and a code cannot travel beside the verdict. A
    // conclusion is recorded here — after the body returned, which is what
    // anchors the 500 ms reuse window to *this module's return* — and `record`
    // hands the verdict back so it becomes a code exactly once. Neither arm
    // emits: `run` already emitted its outcome's one notice.
    match orchestrate(
        pamh,
        &ctx,
        &OrchestrationIo::production(),
        IpcClient::connect_nonblocking,
        send_authenticate_request,
    ) {
        Finished::Concluded(concluded) => {
            crate::transaction::record(concluded, Instant::now()).to_pam()
        }
        Finished::Unrecorded(outcome) => outcome.to_pam(),
    }
}

/// The four side-effecting calls `classify` must precede, injected so they can
/// be counted without a PAM handle.
///
/// `classify_before_side_effects` drives `orchestrate` with this table replaced
/// by counting wrappers and asserts every counter reads zero on a `Skip`. The
/// context is passed in already captured, so the test can hand `orchestrate` a
/// `CallerContext::from_parts` directly.
pub(crate) struct OrchestrationIo {
    pub load_config: fn() -> PamConfig,
    pub get_user: unsafe fn(*mut pam_sys::PamHandle) -> Result<String, c_int>,
    pub new_conversation:
        unsafe fn(*mut pam_sys::PamHandle) -> Result<pam_sys::PamConversation<'static>, c_int>,
    pub load_messages: fn(&str) -> pam_messages::PamMessages,
}

impl OrchestrationIo {
    /// The real functions. The only constructor production uses.
    pub(crate) fn production() -> Self {
        OrchestrationIo {
            load_config: PamConfig::load,
            get_user: pam_sys::get_user,
            new_conversation: pam_sys::PamConversation::new,
            load_messages: pam_messages::load_for_user,
        }
    }
}

/// The module's single `/dev/tty` open.
///
/// Injected into `authenticate_inner` as a closure, the same seam
/// `Armed::open`'s `connect`/`send` have, so tests can count the probe
/// without a terminal.
fn probe_tty() -> Option<std::fs::File> {
    std::fs::File::open("/dev/tty").ok()
}

/// Run one authentication: classify, resolve, plan, arm, drive a mechanism and
/// conclude.
///
/// The body decides and acts; recording is the caller's (`authenticate`), so the
/// 500 ms reuse window stays anchored to *this module's return* rather than to
/// the moment the transaction concluded.
///
/// `connect` and `send` are the transaction's two injected effects, the same
/// seam `Armed::open` has: production passes `IpcClient::connect_nonblocking`
/// and [`send_authenticate_request`], and a test passes counting closures or
/// failures, so "the skip never reaches the daemon" and "a connect failure
/// records nothing" are assertions rather than promises.
fn orchestrate<T, C, S>(
    pamh: *mut pam_sys::PamHandle,
    ctx: &CallerContext,
    io: &OrchestrationIo,
    connect: C,
    send: S,
) -> Finished
where
    T: IpcResponseReader,
    C: FnOnce() -> Result<T, IpcError>,
    S: FnOnce(&mut T, &SendParams<'_>) -> Result<(), IpcError>,
{
    run(pamh, ctx, io, probe_tty, connect, send)
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

/// The production `send`: the authenticate request, on the connected client.
fn send_authenticate_request(
    ipc: &mut IpcClient,
    request: &SendParams<'_>,
) -> Result<(), IpcError> {
    ipc.send_authenticate_start(
        request.username,
        request.has_tty,
        request.timeout_secs,
        request.request_id,
    )
}

/// One authentication transaction.
///
/// Everything that happens *before* a request is on the wire returns
/// `Finished::Unrecorded`: a skip, a missing username, a missing conversation,
/// the pre-collected handoff, a failed request id, a failed connect or send.
/// Recording one of those would answer a later duplicate with a verdict the
/// daemon never reached.
///
/// Everything after `Armed::open` returns `Finished::Concluded`, with
/// `Via::Daemon` for this call's own request and `Via::Replay` for a duplicate
/// answered from the reuse record. The conclusion carries the verdict and its
/// subject; `Outcome::to_pam` is called once, by `authenticate`.
///
/// Every return emits its verdict's one message through [`emit_notice`] before
/// returning, so a message can be neither lost by an early return nor doubled;
/// the paths that return before a conversation exists carry outcomes whose
/// notice is `None` by construction (`outcomes_that_precede_the_conversation_are_silent`).
fn run<T, C, S>(
    pamh: *mut pam_sys::PamHandle,
    ctx: &CallerContext,
    io: &OrchestrationIo,
    probe_tty: impl FnOnce() -> Option<std::fs::File>,
    connect: C,
    send: S,
) -> Finished
where
    T: IpcResponseReader,
    C: FnOnce() -> Result<T, IpcError>,
    S: FnOnce(&mut T, &SendParams<'_>) -> Result<(), IpcError>,
{
    // The conversation policy is decided from the caller facts `capture` read,
    // and it is decided *first*: a `Skip` returns before the config read, the
    // username lookup, the conversation and the messages, which is the order
    // the display-manager bypass has always had. `classify_before_side_effects`
    // counts those four calls, because nothing in the types stops a later edit
    // from moving the decision below them.
    let classification = policy::classify(ctx);

    // The display-manager bypass returns before the username is resolved, so it
    // never reaches `Armed::open` and never touches the recorded conclusion.
    // That is deliberate: it is a static policy decision about the service, not
    // a conclusion about credentials.  Only a daemon-path conclusion is ever
    // recorded, and a pre-IPC path must not clobber the last real one.
    if let Some(outcome) = guard_display_manager_bypass(ctx, &classification) {
        return Finished::Unrecorded(outcome);
    }
    let participation = match classification {
        policy::Classification::Participate(participation) => participation,
        // Every `Skip` returned above.  Repeated here so the match is total
        // without a panic path (`clippy::panic` is denied crate-wide).
        policy::Classification::Skip(skip) => {
            return Finished::Unrecorded(Outcome::from_skip(skip));
        }
    };

    // Load configuration for timeouts
    let config = (io.load_config)();
    tracing::debug!(
        "PAM operation timeout: {}s",
        config.pam_operation_timeout_secs
    );

    let username = unsafe {
        match (io.get_user)(pamh) {
            Ok(user) => {
                tracing::info!("Got username from PAM: {}", user);
                user
            }
            Err(code) => {
                tracing::error!("Failed to get username, PAM error code: {}", code);
                return Finished::Unrecorded(Outcome::UserUnknown);
            }
        }
    };

    tracing::info!("TapAuth: Authenticating user: {}", username);

    let pam_conv = unsafe {
        match (io.new_conversation)(pamh) {
            Ok(conv) => conv,
            Err(e) => {
                tracing::error!("Failed to get PAM conversation function: {}", e);
                return Finished::Unrecorded(Outcome::Error(ErrorReason::ConversationLookup));
            }
        }
    };

    // No explicit root check here; shared config enforces file ownership/permissions.

    let msgs = (io.load_messages)(&username);

    // The conversation mode names the branch this call takes; the `Plannable`
    // carrier and the plan that follows it are what the four timed decisions
    // are made from.
    let mode = match participation.conversation {
        policy::Conversation::Threaded => ConversationMode::Threaded,
        policy::Conversation::Sequential => ConversationMode::Sequential,
        policy::Conversation::PreCollected => ConversationMode::PreCollected,
    };

    // `PreCollected` has no plan at all: its handoff is the last thing that
    // happens before the transaction machinery, and it returns before a probe,
    // a `Plan` or a cache lookup exists — which is why `plan::Plannable` has no
    // `PreCollected` variant to excuse.
    let plannable = match participation.conversation {
        policy::Conversation::Threaded => Plannable::Threaded,
        policy::Conversation::Sequential => Plannable::Sequential,
        // Pre-collected hosts (swaylock, gtklock, i3lock) read the password
        // before they call `pam_authenticate`; their conversation is a
        // synchronous replay of it, so `pam_get_authtok` returns immediately and
        // never waits for the user.  Collect the token on the calling thread — a
        // worker thread would only reintroduce the cross-thread libpam pattern
        // the threaded path has to join around — and let it be cached in
        // `PAM_AUTHTOK`, which is what the next module (`pam_unix` with
        // `try_first_pass`/`use_first_pass`) verifies.
        //
        // This is deliberately a skip, not a wait: the user has already typed
        // the password, so ringing the phone would be misleading and could only
        // ever end in a timeout.  The skip returns `PAM_AUTHINFO_UNAVAIL` (never
        // `PAM_IGNORE`): a `sufficient` line treats that as `ignore`, exactly as
        // `PAM_IGNORE` would, so the next module still runs; a `required` line
        // fails closed.  If the token cannot be read (the host's conversation
        // refused it, or nothing was collected) the next module simply prompts
        // as it would without this module.
        policy::Conversation::PreCollected => {
            let mut authtok: *const std::os::raw::c_char = std::ptr::null();
            // SAFETY: `pamh` is the live handle libpam passed to this call and
            // the conversation belongs to this thread, which is what the host
            // expects.
            let res = unsafe {
                pam_sys::pam_get_authtok(pamh, pam_sys::PAM_AUTHTOK, &mut authtok, std::ptr::null())
            };
            if res != pam_sys::PAM_SUCCESS || authtok.is_null() {
                tracing::warn!(
                    "TapAuth: pre-collected host supplied no password token ({res}); \
                     falling through to the next PAM module"
                );
            } else {
                tracing::info!(
                    "TapAuth: pre-collected password cached for the next PAM module; \
                     the phone is not consulted"
                );
            }
            return Finished::Unrecorded(Outcome::Unavailable(UnavailableReason::PasswordHandoff));
        }
    };

    // First, answer a duplicate: the lock-screen duplicate is queued while the
    // first transaction is still running, so replaying the code this process
    // just concluded is the correct answer to a retry no user could have
    // initiated.
    //
    // The paths above deliberately record nothing.  The display-manager bypass
    // is a static policy decision, not a conclusion about credentials, and the
    // pre-collected skip never contacts the daemon, so there is no transaction
    // to suppress: storing its `PAM_AUTHINFO_UNAVAIL` would only let a
    // duplicate skip `pam_get_authtok`, leaving `PAM_AUTHTOK` unset for
    // `pam_unix` on that handle.  A setup failure above this point (no
    // conversation function) produces no verdict either.  None of them may
    // clobber the last real conclusion.
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
        if let Some(concluded) =
            crate::transaction::replay_for(&username, service_name.original(), Instant::now())
        {
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

    // Announce the wait.  Each call is a single non-blocking `PAM_TEXT_INFO`
    // (one conversation round trip that carries no input and never waits for
    // the user).  The terminal and threaded paths get theirs here, before the
    // wait starts; a no-terminal sequential host gets `WaitThenPassword`
    // further down, right before the module begins blocking, because such hosts
    // only reveal their password entry once a PAM message arrives.
    match plan.announcement {
        Announcement::WaitSkipHint => pam_conv.try_info(msgs.waiting_for_tap_skip()),
        Announcement::Wait => pam_conv.try_info(msgs.waiting_for_tap()),
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
    // so the two deadlines stay in sync.
    let timeout_secs = plan.deadline.resolve(&config);
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
    // one.  Recording a failure would let a later duplicate inherit that
    // `PAM_AUTHINFO_UNAVAIL` without ever asking, and a genuine retry must dial
    // the socket again.  Everything above this point (the display-manager
    // bypass, the pre-collected skip, a missing conversation, a failed RNG) is
    // not a verdict about a transaction attempt either, so it records nothing.
    let request = SendParams {
        username: &username,
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
            return Finished::Unrecorded(emit_notice(
                &pam_conv,
                &msgs,
                Outcome::Unavailable(UnavailableReason::DaemonUnreachable),
            ));
        }
        Err(StartError::Send(e)) => {
            tracing::error!("Failed to send authenticate request: {}", e);
            return Finished::Unrecorded(emit_notice(
                &pam_conv,
                &msgs,
                Outcome::Unavailable(UnavailableReason::DaemonSendFailed),
            ));
        }
    };

    // GUI contexts whose conversation must be left to the host (the sequential
    // mode, e.g. the KDE lock screen before kscreenlocker 6.8): wait for the
    // daemon on this thread and never *drive* the conversation.  Password
    // fallback happens after this returns, when the next PAM module runs its
    // own conversation.
    if !has_tty && mode == ConversationMode::Sequential {
        // Announce the wait now that the request is on the wire and the module
        // is about to block.  Event-loop hosts (GDM's auth prompt, KDE's
        // kscreenlocker_worker) only reveal their password entry once a PAM
        // module sends a query or a `PAM_TEXT_INFO`, so this is what gives the
        // user a visible password route while we wait.  A single non-blocking
        // `PAM_TEXT_INFO` — it never prompts, never reads input and never runs
        // on another thread; a host whose conversation returns `PAM_CONV_ERR`
        // is unaffected because `try_info` swallows the error.
        if plan.announcement == Announcement::WaitThenPassword {
            pam_conv.try_info(msgs.waiting_for_tap_password());
        }
        let outcome = {
            let (ipc, request_id) = armed.parts();
            let (exit_reason, auth_response) = run_sequential_event_loop(ipc, deadline_at);

            // The verdict comes from the loop's exit, never from the loop
            // itself, so the text and the style of a failure are decided once
            // by `Outcome::notice`. `IpcResponseReceived` without a payload
            // cannot happen (the loop returns it only with `Some`), so it fails
            // closed without a message rather than inventing one.
            match exit_reason {
                ExitReason::IpcResponseReceived => match auth_response {
                    Some(resp) => Outcome::from_daemon(resp),
                    None => Outcome::Unavailable(UnavailableReason::ProtocolError),
                },
                ExitReason::Timeout => {
                    // The daemon runs on the same deadline and multicasts its
                    // own AuthenticationCancel, so no client-side cancel is
                    // needed.
                    Outcome::Unavailable(UnavailableReason::TimedOut)
                }
                _ => {
                    // IPC error: the request may still be in flight
                    // daemon-side. Best-effort cancel uses a new blocking
                    // connection with a short timeout so the phone doesn't keep
                    // buzzing.
                    if let Ok(mut c) = IpcClient::connect(Duration::from_millis(100)) {
                        let _ = c.send_cancel("gui-ipc-error", request_id);
                    }
                    // This is the one path that shows its IPC text as an error,
                    // so it maps to `IpcError` rather than to the hangup/loop
                    // reasons the other two mechanisms use.
                    Outcome::Unavailable(UnavailableReason::IpcError)
                }
            }
        };
        let outcome = emit_notice(&pam_conv, &msgs, outcome);
        return Finished::Concluded(armed.conclude(outcome, &username, ctx.service().cloned()));
    }

    // GUI context with a threaded-conversation-capable host (see `policy`):
    // the branch body is `run_threaded`, and its verdict is mapped here — the
    // one place this call site produces a code.
    if !has_tty && mode == ConversationMode::Threaded {
        let outcome = {
            let (ipc, request_id) = armed.parts();
            emit_notice(
                &pam_conv,
                &msgs,
                run_threaded(pamh, ipc, deadline_at, request_id),
            )
        };
        return Finished::Concluded(armed.conclude(outcome, &username, ctx.service().cloned()));
    }

    // Terminal: the branch body is `run_terminal`, and its verdict is concluded
    // here like the other two mechanisms'.
    let outcome = {
        let (ipc, request_id) = armed.parts();
        emit_notice(
            &pam_conv,
            &msgs,
            run_terminal(ipc, tty_file, deadline_at, request_id),
        )
    };
    Finished::Concluded(armed.conclude(outcome, &username, ctx.service().cloned()))
}

/// The terminal flow: poll the daemon socket and `/dev/tty` together, and let
/// Enter skip.
///
/// The only mechanism with a terminal to read: a `\n`/`\r` cancels the request
/// on a fresh short connection and ends the wait, any other key is consumed and
/// discarded, and a tty that reaches EOF, errors or hangs up simply stops being
/// polled while the daemon socket keeps waiting.
///
/// Returns the verdict, never a code: the caller maps it with `to_pam`
/// (`finish`), so every exit here — response, hangup, read error, skip,
/// deadline — is a reason, and `Outcome::notice` decides the one message it
/// shows.
fn run_terminal<T: IpcResponseReader>(
    ipc: &mut T,
    tty: Option<std::fs::File>,
    deadline_at: Instant,
    request_id: &str,
) -> Outcome {
    // `run` probes /dev/tty only when the plan says `PollForKey`, so `tty` is
    // `Some` here. A missing file is still handled without panicking: the host
    // cannot be asked to skip, so the call ends as an unavailability with no
    // message — the code this arm has always returned.
    let Some(mut tty) = tty else {
        return Outcome::Unavailable(UnavailableReason::ProtocolError);
    };

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
                            Ok(Some(resp)) => return Outcome::from_daemon(resp),
                            Ok(None) => {
                                // No complete frame yet, check for errors
                                if rev.contains(PollFlags::POLLHUP)
                                    || rev.contains(PollFlags::POLLERR)
                                {
                                    tracing::error!(
                                        "Daemon closed connection before sending response"
                                    );
                                    return Outcome::Unavailable(
                                        UnavailableReason::IpcConnectionLost,
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {}", e);
                                return Outcome::Unavailable(UnavailableReason::IpcLoopError);
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        // Hangup/error without any data available
                        tracing::error!("Daemon closed connection or error detected");
                        return Outcome::Unavailable(UnavailableReason::IpcConnectionLost);
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
                                        // Best-effort cancel uses a new blocking connection
                                        // with a short timeout so the skip is not blocked
                                        // by an unresponsive daemon.
                                        if let Ok(mut c) =
                                            IpcClient::connect(Duration::from_millis(100))
                                        {
                                            let _ = c.send_cancel("tty-skip", request_id);
                                        }
                                        return Outcome::Unavailable(UnavailableReason::Skipped);
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

    Outcome::Unavailable(UnavailableReason::TimedOut)
}

/// Yield `PAM_AUTHINFO_UNAVAIL` if the calling service is a primary display
/// manager.
///
/// When this module runs as `sufficient` during a GUI desktop login (SDDM, GDM,
/// LightDM, LXDM), a successful phone confirmation authenticates the user but
/// never populates the cleartext password token (`PAM_AUTHTOK`) in the PAM
/// stack. Downstream modules like `pam_kwallet6.so` and `pam_gnome_keyring.so`
/// depend on that token to unlock the local secure keyring/wallet at login-time.
///
/// Bypassing DM services preserves the normal password collection flow so the
/// login manager itself sets `PAM_AUTHTOK` and the keyring unlocks without any
/// secondary prompt. The module still runs for secondary services such as
/// `sudo`, `polkit-1`, and desktop screensavers.
///
/// A **GDM reauthentication** (`gdm-password` with `GDM_SESSION_FOR_REAUTH`
/// set) is exempt: it runs no session/setcred phase
/// (`gdm-session-worker.c:1489,1781`), so the keyring reason for keeping the
/// login sequential does not apply, and the unlock prompt is exactly where the
/// phone should be offered.
///
/// This is a skip, not a verdict, so it returns `PAM_AUTHINFO_UNAVAIL` (never
/// `PAM_IGNORE`, which Linux-PAM does not record as a failure). On a
/// `sufficient` line the stack treats it as `ignore` and still runs the next
/// module; on a `required` line it fails closed.
///
/// R1's remote refusal is the other skip policy, and it takes the same code for
/// the same reason: the module has no business answering that call, so it says
/// "not me" with the code a `required` line reads as a failure.
///
/// The rule name is kept for the display-manager half it was written for; the
/// decision itself is `policy::classify`'s.
///
/// Returns the skip's verdict for any skip, `None` otherwise. The mapping
/// itself is `Outcome::from_skip`, the only place a `SkipPolicy` becomes a
/// verdict.
fn guard_display_manager_bypass(
    ctx: &CallerContext,
    classification: &policy::Classification,
) -> Option<Outcome> {
    let policy::Classification::Skip(skip) = classification else {
        return None;
    };
    let service = ctx.service().map(ServiceName::original).unwrap_or_default();
    match skip {
        policy::SkipPolicy::KeyringNeedsAuthtok => {
            tracing::info!(
                "TapAuth: Service '{}' is a primary display manager. \
                 Skipping to avoid breaking keyring auto-unlock.",
                service
            );
        }
        policy::SkipPolicy::RemoteAuthentication => {
            tracing::info!(
                "TapAuth: Service '{}' authenticates a remote caller. \
                 Skipping: this module does not take part in remote authentication.",
                service
            );
        }
    }
    Some(Outcome::from_skip(*skip))
}

/// Emit an outcome's one message, then hand the outcome back.
///
/// Every return of `run` emits through this, so the message is decided by the
/// verdict and not by the site that produced it, and `to_pam` is called exactly
/// once — by `authenticate`. The emission itself is the two calls the module has
/// always made: `try_info` for information, `try_error` for an error, both of
/// which swallow a failing conversation. A replayed verdict's notice is `None`,
/// which is what keeps a cache hit silent.
fn emit_notice(
    pam_conv: &pam_sys::PamConversation,
    msgs: &pam_messages::PamMessages,
    outcome: Outcome,
) -> Outcome {
    if let Some(notice) = outcome.notice(msgs) {
        match notice.style {
            crate::outcome::NoticeStyle::Info => pam_conv.try_info(&notice.text),
            crate::outcome::NoticeStyle::Error => pam_conv.try_error(&notice.text),
        }
    }
    outcome
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::logging;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_logging_init() {
        logging::init_logging();
        logging::init_logging();
    }

    // ------------------------------------------------------------------
    // The ordering and single-read guarantees of `authenticate`
    // ------------------------------------------------------------------

    /// The four calls `classify` must precede, counted.
    ///
    /// The context is passed to `orchestrate` already captured, so these tests
    /// need no PAM handle and no daemon: whatever the body does after the four
    /// calls, the counters are decided before it.
    static CONFIG_CALLS: AtomicUsize = AtomicUsize::new(0);
    static USER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CONVERSATION_CALLS: AtomicUsize = AtomicUsize::new(0);
    static MESSAGE_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Timeouts of zero, so a path that gets as far as the IPC connect returns
    /// without waiting: these tests assert call counts, not waiting.
    fn zero_timeouts() -> PamConfig {
        PamConfig {
            pam_operation_timeout_secs: 0,
            pam_gui_timeout_secs: 0,
        }
    }

    fn counting_config() -> PamConfig {
        CONFIG_CALLS.fetch_add(1, Ordering::SeqCst);
        zero_timeouts()
    }

    unsafe fn counting_get_user(_pamh: *mut pam_sys::PamHandle) -> Result<String, c_int> {
        USER_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok("classification-test-user".to_owned())
    }

    unsafe fn counting_conversation(
        _pamh: *mut pam_sys::PamHandle,
    ) -> Result<pam_sys::PamConversation<'static>, c_int> {
        CONVERSATION_CALLS.fetch_add(1, Ordering::SeqCst);
        // A conversation over no handle: every emission is a no-op, which is
        // all this test needs.
        Ok(unsafe { pam_sys::PamConversation::dummy() })
    }

    fn counting_messages(_username: &str) -> pam_messages::PamMessages {
        MESSAGE_CALLS.fetch_add(1, Ordering::SeqCst);
        pam_messages::load_for_user("classification-test-user")
    }

    fn counting_io() -> OrchestrationIo {
        OrchestrationIo {
            load_config: counting_config,
            get_user: counting_get_user,
            new_conversation: counting_conversation,
            load_messages: counting_messages,
        }
    }

    fn context(service: Option<&str>, process: Option<&str>) -> CallerContext {
        let process = match process {
            Some(name) => crate::context::ProcessIdentity::Exe(name.into()),
            None => crate::context::ProcessIdentity::Unknown,
        };
        CallerContext::from_parts(service, process, crate::context::GdmReauth::Absent)
    }

    /// An `OrchestrationIo` that counts nothing and needs no PAM handle, for the
    /// tests about the tty probe rather than about call order.
    fn inert_io() -> OrchestrationIo {
        unsafe fn user(_pamh: *mut pam_sys::PamHandle) -> Result<String, c_int> {
            Ok("tty-probe-test-user".to_owned())
        }
        unsafe fn conversation(
            _pamh: *mut pam_sys::PamHandle,
        ) -> Result<pam_sys::PamConversation<'static>, c_int> {
            Ok(unsafe { pam_sys::PamConversation::dummy() })
        }
        OrchestrationIo {
            load_config: zero_timeouts,
            get_user: user,
            new_conversation: conversation,
            load_messages: |_username| pam_messages::load_for_user("tty-probe-test-user"),
        }
    }

    /// Run `authenticate_inner` with an injected tty probe, and report how many
    /// times the probe ran. `tty` is what the probe returns: `Some(path)` opens
    /// that file, `None` reports "no terminal".
    fn tty_probes(ctx: &CallerContext, tty: Option<&str>) -> (c_int, usize) {
        let io = inert_io();
        let mut probes = 0usize;
        let finished = run(
            std::ptr::null_mut(),
            ctx,
            &io,
            || {
                probes += 1;
                tty.and_then(|path| std::fs::File::open(path).ok())
            },
            || Err(no_daemon()),
            |_: &mut IpcClient, _: &SendParams<'_>| Ok(()),
        );
        (finished.outcome().clone().to_pam(), probes)
    }

    /// A connect that fails the way a missing socket does, for the paths whose
    /// call counts are the assertion.
    pub(crate) fn no_daemon() -> IpcError {
        IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "no daemon socket",
        ))
    }

    /// `/dev/tty` is opened once, and only for the conversation that polls it.
    ///
    /// The defect this catches: the probe moved to the top of the function (or
    /// gated on `conversation == Sequential` a second time, next to the plan),
    /// so a threaded host polls the terminal and steals the stdin its own dialog
    /// needs — or a plan maker and the probe disagree about whether a terminal
    /// exists.
    #[test]
    fn tty_probe_only_for_sequential() {
        let threaded = context(Some("probe-threaded"), Some("hyprlock"));
        assert_eq!(
            tty_probes(&threaded, Some("/dev/null")),
            (pam_sys::PAM_AUTHINFO_UNAVAIL, 0),
            "a threaded conversation must not open /dev/tty"
        );

        let sequential_tty = context(Some("probe-tty"), Some("xfce4-screensaver-dialog"));
        assert_eq!(
            tty_probes(&sequential_tty, Some("/dev/null")),
            (pam_sys::PAM_AUTHINFO_UNAVAIL, 1),
            "a sequential conversation probes /dev/tty exactly once"
        );

        let sequential_no_tty = context(Some("probe-no-tty"), Some("xfce4-screensaver-dialog"));
        assert_eq!(
            tty_probes(&sequential_no_tty, None),
            (pam_sys::PAM_AUTHINFO_UNAVAIL, 1),
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
        let _slot = crate::transaction::CACHE_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
            let (code, probes) = tty_probes(&ctx, Some("/dev/null"));
            if code != conclusion_code {
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

    /// An IPC client that never carries anything: enough to satisfy the
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

    /// Drive `run` with a context, a tty probe and the two injected IPC
    /// effects, and report the `Finished` it returned.
    fn run_finished<T: IpcResponseReader, C, S>(
        ctx: &CallerContext,
        tty: Option<&str>,
        connect: C,
        send: S,
    ) -> Finished
    where
        C: FnOnce() -> Result<T, IpcError>,
        S: FnOnce(&mut T, &SendParams<'_>) -> Result<(), IpcError>,
    {
        let io = inert_io();
        run(
            std::ptr::null_mut(),
            ctx,
            &io,
            || tty.and_then(|path| std::fs::File::open(path).ok()),
            connect,
            send,
        )
    }

    /// Record `outcome` for `(username, service)` at `at`, through the same
    /// `Armed`-conclude-record path `authenticate` uses.
    fn record_conclusion(username: &str, service: &str, outcome: Outcome, at: Instant) {
        let concluded = crate::transaction::armed_for_test(NullIpc, "pam-logic-test-request")
            .conclude(outcome, username, Some(ServiceName::new(service)));
        let _ = crate::transaction::record(concluded, at);
    }

    /// R1 refuses a remote call before anything reaches the daemon.
    ///
    /// The defect this catches: a skip decided late enough to dial the socket,
    /// or one that sends the request and only then refuses — the phone must not
    /// be rung for a login nobody is sitting at, and the daemon must not see a
    /// request for it. The counters are the assertion: an outcome equality
    /// cannot tell a refusal that never connected from one that returned the
    /// same code after a full transaction.
    #[test]
    fn remote_skip_never_reaches_the_daemon() {
        for service in ["sshd", "sshd-session"] {
            let connects = AtomicUsize::new(0);
            let sends = AtomicUsize::new(0);
            let ctx = context(Some(service), Some("sshd"));

            let finished = run_finished(
                &ctx,
                None,
                || {
                    connects.fetch_add(1, Ordering::SeqCst);
                    Err::<NullIpc, _>(no_daemon())
                },
                |_: &mut NullIpc, _: &SendParams<'_>| {
                    sends.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            );

            assert_eq!(
                connects.load(Ordering::SeqCst),
                0,
                "service {service}: a remote skip must not dial the daemon"
            );
            assert_eq!(
                sends.load(Ordering::SeqCst),
                0,
                "service {service}: a remote skip must put no request on the wire"
            );
            assert!(
                matches!(
                    &finished,
                    Finished::Unrecorded(Outcome::Unavailable(
                        UnavailableReason::RemoteAuthentication
                    ))
                ),
                "service {service}: R1 is an unrecorded RemoteAuthentication verdict"
            );
            assert_eq!(
                finished.outcome().clone().to_pam(),
                pam_sys::PAM_AUTHINFO_UNAVAIL,
                "service {service}: R1 must report the service as unavailable"
            );
        }
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
        let msgs = pam_messages::load_for_user("unrecorded-test-user");
        let ctx = context(Some("unrecorded-paths"), Some("totally-unknown"));

        let connect_failed = run_finished(
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
            pam_sys::PAM_AUTHINFO_UNAVAIL
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

        let send_failed = run_finished(
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
            pam_sys::PAM_AUTHINFO_UNAVAIL
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

    /// Every verdict `run` can return before a conversation exists is silent.
    ///
    /// The defect this catches: a message added to one of these reasons (say a
    /// `PAM_TEXT_INFO` for the keyring bypass). Those paths return before
    /// `PamConversation::new`, so there is nothing to emit through, and the
    /// message would be dropped silently instead of the omission being a
    /// compile-time or test-time decision.
    #[test]
    fn outcomes_that_precede_the_conversation_are_silent() {
        let msgs = pam_messages::load_for_user("pre-conversation-test-user");
        for outcome in [
            Outcome::from_skip(crate::policy::SkipPolicy::RemoteAuthentication),
            Outcome::from_skip(crate::policy::SkipPolicy::KeyringNeedsAuthtok),
            Outcome::UserUnknown,
            Outcome::Error(ErrorReason::ConversationLookup),
        ] {
            assert!(
                outcome.notice(&msgs).is_none(),
                "{outcome:?} is returned before a conversation exists, so it must show nothing"
            );
        }
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
        let _slot = crate::transaction::CACHE_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
            let finished = run_finished(
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

    /// Run `orchestrate` for `ctx` and return the four call counters in the
    /// order `config, user, conversation, messages`.
    fn side_effects_of(ctx: &CallerContext) -> [usize; 4] {
        CONFIG_CALLS.store(0, Ordering::SeqCst);
        USER_CALLS.store(0, Ordering::SeqCst);
        CONVERSATION_CALLS.store(0, Ordering::SeqCst);
        MESSAGE_CALLS.store(0, Ordering::SeqCst);
        let _finished = orchestrate(
            std::ptr::null_mut(),
            ctx,
            &counting_io(),
            || Err::<IpcClient, _>(no_daemon()),
            |_: &mut IpcClient, _: &SendParams<'_>| Ok(()),
        );
        [
            CONFIG_CALLS.load(Ordering::SeqCst),
            USER_CALLS.load(Ordering::SeqCst),
            CONVERSATION_CALLS.load(Ordering::SeqCst),
            MESSAGE_CALLS.load(Ordering::SeqCst),
        ]
    }

    /// `classify` runs before `PamConfig::load`, `get_user`,
    /// `PamConversation::new` and `PamMessages::load_for_user`, so a skip costs
    /// none of them.
    ///
    /// The defect this catches: moving `classify` below any of the four — the
    /// natural place is "after the config read", where the timeouts are known.
    /// Nothing else fails then: a display-manager login would still return
    /// `PAM_AUTHINFO_UNAVAIL`, it would just pay a config read, two PAM item
    /// lookups, an NSS lookup and a root-side home read first, and a skip on a
    /// null user would come back as `PAM_USER_UNKNOWN` instead.
    #[test]
    fn classify_before_side_effects() {
        // R1: a remote service name is refused before anything is read.
        assert_eq!(
            side_effects_of(&context(Some("sshd"), Some("sshd"))),
            [0, 0, 0, 0],
            "a remote skip must not load config, user, conversation or messages"
        );

        // R2: the display-manager bypass.
        assert_eq!(
            side_effects_of(&context(Some("sddm"), Some("sh"))),
            [0, 0, 0, 0],
            "a display-manager skip must not load config, user, conversation or messages"
        );

        // The control: a `Participate` reaches all four, so the counters above
        // are not zero merely because the harness never increments them.
        assert_eq!(
            side_effects_of(&context(Some("sudo"), Some("totally-unknown"))),
            [1, 1, 1, 1],
            "a participating call must reach every one of the four calls"
        );
    }

    /// `PAM_SERVICE` is read at exactly one call site, in `CallerContext::capture`.
    ///
    /// The defect this catches: a second `pam_sys::get_service_name(pamh)` call
    /// reappearing in `pam_logic.rs`. The pre-refactor tree resolved the service
    /// twice — once in the display-manager bypass and once for the conversation
    /// mode, the cache key and the request — so the bypass could decide from one
    /// string while the cache keyed on another.
    ///
    /// Same technique and the same positive-control discipline as
    /// `test_module_source_contains_no_pam_ignore_return`: the source is stripped
    /// of comments and literals first, and the detector is proved to fire on an
    /// in-memory snippet so an emptied or relocated scan cannot pass silently.
    #[test]
    fn only_one_get_service_name_call_site() {
        const NEEDLE: &str = "get_service_name";
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot list {dir}: {e}"))
            .map(|entry| entry.expect("readable dir entry").path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
            .collect();
        files.sort();
        assert!(
            files.iter().any(|p| p.ends_with("context.rs")),
            "the scan did not cover context.rs, home of the single read: {files:?}"
        );

        let mut definitions = 0usize;
        let mut call_sites: Vec<String> = Vec::new();
        for path in &files {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            let cleaned = stripped_source(&source);
            for (line, text) in identifier_hits(&cleaned, NEEDLE) {
                if text.contains("fn get_service_name") {
                    definitions += 1;
                } else {
                    call_sites.push(format!("{name}:{line}: {text}"));
                }
            }
        }

        assert_eq!(
            definitions, 1,
            "expected exactly one definition of {NEEDLE}, found {definitions}"
        );
        assert_eq!(
            call_sites.len(),
            1,
            "PAM_SERVICE must be read at exactly one call site, found:\n{}",
            call_sites.join("\n")
        );
        let only = call_sites.first().map(String::as_str).unwrap_or_default();
        assert!(
            only.starts_with("context.rs:"),
            "the single read must be `CallerContext::capture`, found {only}"
        );

        // Positive control: two planted call sites must both be reported, or a
        // scan that stopped matching would pass the assertion above.
        let planted = stripped_source(
            "let a = pam_sys::get_service_name(pamh);\n\
             let b = pam_sys::get_service_name(pamh);\n",
        );
        assert_eq!(
            identifier_hits(&planted, NEEDLE).len(),
            2,
            "the detector must report both planted call sites"
        );
    }

    /// The remote-user item is read nowhere in this crate's production code.
    ///
    /// The defect this catches: the retired `PAM_RUSER` fallback reappearing,
    /// either by identifier or by the item's numeric value — `pam_get_item(pamh,
    /// 8, ..)` is the same read without the name, which a name-only scan would
    /// miss. A resolved name for the wrong account is the whole reason the
    /// fallback is gone: it became the daemon request's username, the cache key
    /// and the locale lookup's NSS name.
    ///
    /// Only the production half of each file is scanned, because the test that
    /// pins the removal names the item in strings.
    #[test]
    fn no_ruser_read() {
        const ITEM: &str = "PAM_RUSER";
        // The item's numeric value, spelled arithmetically so this test's own
        // source carries no literal for its own scan to find.
        let item_number: u128 = 2 * 2 * 2;

        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot list {dir}: {e}"))
            .map(|entry| entry.expect("readable dir entry").path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
            .collect();
        files.sort();
        assert!(
            files.iter().any(|p| p.ends_with("pam_sys.rs")),
            "the scan did not cover pam_sys.rs, home of the user item: {files:?}"
        );

        let mut findings: Vec<String> = Vec::new();
        for path in &files {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            // The production half only: everything before the first
            // `#[cfg(test)]`, the same split the other source scans here use.
            let production = source
                .split_once("#[cfg(test)]")
                .map(|(before, _)| before)
                .unwrap_or(source.as_str());
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            let cleaned = stripped_source(production);
            for (line, text) in identifier_hits(&cleaned, ITEM) {
                findings.push(format!("{name}:{line}: {ITEM} read in: {text}"));
            }
            for (line, text) in numeric_literals_equal_to(&cleaned, item_number) {
                findings.push(format!(
                    "{name}:{line}: item value {item_number} used in: {text}"
                ));
            }
        }
        assert!(
            findings.is_empty(),
            "a null PAM_USER must fail closed, not fall back to another item:\n{}",
            findings.join("\n")
        );

        // Positive control: both detectors must fire on an in-memory snippet, or
        // an emptied or broken scan passes for the wrong reason.
        let planted = stripped_source(
            "let a = pam_get_item(pamh, 8, &mut item);\n\
             let b = ffi::PAM_RUSER;\n",
        );
        assert_eq!(
            identifier_hits(&planted, ITEM).len(),
            1,
            "the identifier detector must report the planted item"
        );
        assert_eq!(
            numeric_literals_equal_to(&planted, item_number),
            vec![(1, "8".to_owned())],
            "the numeric detector must report the planted item value"
        );
    }

    #[test]
    fn test_map_pam_outcome_matrix() {
        let conv = unsafe { pam_sys::PamConversation::dummy() };
        let msgs = pam_messages::load_for_user("testuser");
        // The daemon-answer path as the call sites run it: the verdict, its one
        // message and its code, from the response alone.
        let map = |resp: shared::ipc::pb::PamAuthenticateResponse| {
            emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).to_pam()
        };

        let resp_for = |outcome: shared::ipc::pb::PamOutcome,
                        detail: &str|
         -> shared::ipc::pb::PamAuthenticateResponse {
            shared::ipc::pb::PamAuthenticateResponse {
                outcome: outcome as i32,
                detail: detail.to_string(),
                challenge: vec![],
            }
        };

        // A grant is the only success.
        assert_eq!(
            map(resp_for(shared::ipc::pb::PamOutcome::Success, "Success")),
            pam_sys::PAM_SUCCESS
        );

        // An explicit phone denial must stay a denial: it fails in both the
        // `required` and the `[success=done default=bad]` stack shapes.
        assert_eq!(
            map(resp_for(shared::ipc::pb::PamOutcome::Denied, "Denied")),
            pam_sys::PAM_PERM_DENIED
        );

        // No usable answer from the service (timeout, skip, no paired device):
        // the auth service could not be consulted.
        for outcome in [
            shared::ipc::pb::PamOutcome::Timeout,
            shared::ipc::pb::PamOutcome::Ignore,
        ] {
            assert_eq!(
                map(resp_for(outcome, "detail")),
                pam_sys::PAM_AUTHINFO_UNAVAIL,
                "{outcome:?} must report the service as unavailable"
            );
        }

        // The daemon answered but could not process the attempt.
        assert_eq!(
            map(resp_for(shared::ipc::pb::PamOutcome::Error, "boom")),
            pam_sys::PAM_AUTH_ERR
        );
    }

    /// The `outcome` field is a raw `i32` on the wire, so a peer can put any
    /// value in it. Unknown values must fail closed (`Error` → `PAM_AUTH_ERR`)
    /// rather than decode to `PamOutcome::default()` = `SUCCESS`.
    #[test]
    fn test_unknown_outcome_raw_values_fail_closed() {
        use crate::outcome::DenyVia;
        use crate::outcome::ErrorReason;
        use crate::outcome::GrantVia;
        use crate::outcome::Outcome;
        use crate::outcome::UnavailableReason;

        let from_raw = |raw: i32| {
            Outcome::from_daemon(shared::ipc::pb::PamAuthenticateResponse {
                outcome: raw,
                detail: "detail".to_owned(),
                challenge: vec![],
            })
        };

        for raw in [-1, 5, 99, 255, i32::MAX, i32::MIN] {
            let outcome = from_raw(raw);
            assert_eq!(
                outcome,
                Outcome::Error(ErrorReason::Daemon("detail".into())),
                "raw outcome {raw} must fail closed instead of {outcome:?}"
            );
        }

        // Known values keep exactly today's mapping.
        for (raw, expected) in [
            (0, Outcome::Granted(GrantVia::PhoneTap)),
            (1, Outcome::Denied(DenyVia::PhoneDenial)),
            (2, Outcome::Unavailable(UnavailableReason::DaemonTimedOut)),
            (3, Outcome::Unavailable(UnavailableReason::DaemonIgnored)),
            (4, Outcome::Error(ErrorReason::Daemon("detail".into()))),
        ] {
            assert_eq!(
                from_raw(raw),
                expected,
                "raw outcome {raw} must keep its mapping"
            );
        }
    }

    /// Wire-level version of the test above: hand-encode a
    /// `PamAuthenticateResponse` whose `outcome` field is an unknown value,
    /// decode it with prost and drive the real PAM mapping.
    ///
    /// Layout (proto3): `outcome` is field 1, varint, so the tag byte is
    /// `(1 << 3) | 0 == 0x08`, followed by the value's base-128 varint. `detail`
    /// and `challenge` are empty and therefore absent from the encoding.
    #[test]
    fn test_undecodable_wire_outcome_never_grants() {
        use prost::Message;

        /// Base-128 varint encoding of `value`.
        fn varint(mut value: u32) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                if value == 0 {
                    out.push(byte);
                    return out;
                }
                out.push(byte | 0x80);
            }
        }

        let conv = unsafe { pam_sys::PamConversation::dummy() };
        let msgs = pam_messages::load_for_user("testuser");

        for raw in [99_i32, i32::MAX] {
            let mut bytes = vec![0x08_u8];
            bytes.extend(varint(raw as u32));

            let resp = shared::ipc::pb::PamAuthenticateResponse::decode(bytes.as_slice()).unwrap();
            // The hand-built bytes really did carry the unknown outcome.
            assert_eq!(resp.outcome, raw, "hand-encoded bytes decode as expected");

            let code = emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).to_pam();
            assert_ne!(
                code,
                pam_sys::PAM_SUCCESS,
                "unknown outcome {raw} must not grant access"
            );
            assert_eq!(
                code,
                pam_sys::PAM_AUTH_ERR,
                "unknown outcome {raw} must be a processing failure"
            );
        }
    }

    /// Regression test for the `PAM_IGNORE` authentication bypass.
    ///
    /// Linux-PAM records no failure for `PAM_IGNORE`, so in a stack shaped like
    /// `auth required pam_tapauth.so` + `auth optional pam_permit` +
    /// `auth required pam_env` the `optional` module's success vote turned the
    /// whole stack into `PAM_SUCCESS` — a grant without any phone approval.
    /// No daemon outcome may map to `PAM_IGNORE`.
    #[test]
    fn test_no_pam_outcome_maps_to_pam_ignore() {
        let conv = unsafe { pam_sys::PamConversation::dummy() };
        let msgs = pam_messages::load_for_user("testuser");

        // Every variant of the IPC enum. This list is not compiler-enforced:
        // the `match` in `Outcome::from_daemon` is exhaustive but this array is
        // not, so extend this list by hand when adding a variant.
        let all_outcomes = [
            shared::ipc::pb::PamOutcome::Success,
            shared::ipc::pb::PamOutcome::Denied,
            shared::ipc::pb::PamOutcome::Timeout,
            shared::ipc::pb::PamOutcome::Ignore,
            shared::ipc::pb::PamOutcome::Error,
        ];

        for outcome in all_outcomes {
            let resp = shared::ipc::pb::PamAuthenticateResponse {
                outcome: outcome as i32,
                detail: "detail".to_string(),
                challenge: vec![],
            };
            let code = emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).to_pam();
            // `PAM_IGNORE` is 25 and is deliberately absent from this list: it
            // is not a verdict, so a later `optional pam_permit` can still make
            // the whole stack succeed.
            let is_real_verdict = [
                pam_sys::PAM_SUCCESS,
                pam_sys::PAM_PERM_DENIED,
                pam_sys::PAM_AUTHINFO_UNAVAIL,
                pam_sys::PAM_AUTH_ERR,
            ]
            .contains(&code);
            assert!(
                is_real_verdict,
                "{outcome:?} mapped to {code}, which is not a real PAM verdict \
                 (PAM_IGNORE is 25)"
            );
        }
    }

    /// Blank every comment, string literal and char literal, keeping the
    /// newlines so that the reported line numbers still match the file on disk.
    ///
    /// The docs in this crate deliberately name the forbidden code in prose, and
    /// the test's own assertions quote both needles, so scanning raw source
    /// would flag those instead of the return site it is looking for.
    ///
    /// Runs over bytes: every delimiter involved is ASCII, and the crate's
    /// sources are ASCII apart from localisation strings, which are blanked
    /// here.  A non-ASCII *char* literal would be taken for a lifetime and
    /// copied verbatim, which can only hide a needle, never invent one.
    #[allow(clippy::indexing_slicing)]
    pub(crate) fn stripped_source(source: &str) -> String {
        let b = source.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(b.len());
        let mut i = 0usize;
        while i < b.len() {
            // Line comment.
            if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            // Block comment (Rust nests them).
            if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                let mut depth = 1usize;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        if b[i] == b'\n' {
                            out.push(b'\n');
                        }
                        i += 1;
                    }
                }
                continue;
            }
            // Raw strings: `r"…"`, `r#"…"#`, `br"…"`, `br#"…"#`.
            let raw_at = if b[i] == b'r' {
                Some(i + 1)
            } else if b[i] == b'b' && b.get(i + 1) == Some(&b'r') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(at) = raw_at {
                let mut hashes = 0usize;
                while b.get(at + hashes) == Some(&b'#') {
                    hashes += 1;
                }
                if b.get(at + hashes) == Some(&b'"') {
                    let mut j = at + hashes + 1;
                    let mut end = b.len();
                    while j < b.len() {
                        if b[j] == b'"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&b'#')) {
                            end = j + 1 + hashes;
                            break;
                        }
                        j += 1;
                    }
                    out.extend(blank(b, i, end));
                    i = end;
                    continue;
                }
            }
            // Normal and byte strings, honouring backslash escapes.
            let quote_at = if b[i] == b'"' {
                Some(i)
            } else if b[i] == b'b' && b.get(i + 1) == Some(&b'"') {
                Some(i + 1)
            } else {
                None
            };
            if let Some(q) = quote_at {
                let mut j = q + 1;
                while j < b.len() {
                    if b[j] == b'\\' {
                        j += 2;
                    } else if b[j] == b'"' {
                        j += 1;
                        break;
                    } else {
                        j += 1;
                    }
                }
                let end = j.min(b.len());
                out.extend(blank(b, i, end));
                i = end;
                continue;
            }
            // Char literals and byte chars.  A tick that does not open a
            // one-character or escaped literal is a lifetime (`'a`) and is
            // copied verbatim.
            let tick_at = if b[i] == b'\'' {
                Some(i)
            } else if b[i] == b'b' && b.get(i + 1) == Some(&b'\'') {
                Some(i + 1)
            } else {
                None
            };
            if let Some(t) = tick_at {
                let opens_literal = matches!(
                    (b.get(t + 1), b.get(t + 2)),
                    (Some(&b'\\'), _) | (Some(_), Some(&b'\''))
                );
                if !opens_literal {
                    out.push(b[i]);
                    i += 1;
                    continue;
                }
                let mut j = t + 1;
                if b.get(j) == Some(&b'\\') {
                    j += 2;
                    // `'\u{1F600}'`
                    if b.get(j - 1) == Some(&b'u') && b.get(j) == Some(&b'{') {
                        while j < b.len() && b[j] != b'}' {
                            j += 1;
                        }
                        j += 1;
                    }
                } else {
                    j += 1;
                }
                if b.get(j) == Some(&b'\'') {
                    j += 1;
                }
                let end = j.min(b.len());
                out.extend(blank(b, i, end));
                i = end;
                continue;
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// `bytes[start..end]` as spaces, keeping its newlines.
    #[allow(clippy::indexing_slicing)]
    fn blank(bytes: &[u8], start: usize, end: usize) -> Vec<u8> {
        bytes[start..end]
            .iter()
            .map(|&c| if c == b'\n' { b'\n' } else { b' ' })
            .collect()
    }

    /// The source line containing byte offset `at`, trimmed.
    fn line_at(source: &str, at: usize) -> String {
        let start = source[..at].rfind('\n').map_or(0, |n| n + 1);
        let end = source[at..].find('\n').map_or(source.len(), |n| at + n);
        source[start..end].trim().to_owned()
    }

    /// Every occurrence of `needle` used as a whole identifier, as
    /// `(line, source line)`.
    #[allow(clippy::indexing_slicing)]
    fn identifier_hits(cleaned: &str, needle: &str) -> Vec<(usize, String)> {
        let b = cleaned.as_bytes();
        let mut hits = Vec::new();
        let mut from = 0usize;
        while let Some(offset) = cleaned[from..].find(needle) {
            let start = from + offset;
            let end = start + needle.len();
            let is_ident_char = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_';
            let whole_word = !(start > 0 && is_ident_char(&b[start - 1]))
                && !(end < b.len() && is_ident_char(&b[end]));
            if whole_word {
                let line = cleaned[..start].matches('\n').count() + 1;
                hits.push((line, line_at(cleaned, start)));
            }
            from = end;
        }
        hits
    }

    /// Every occurrence of `PAM_IGNORE` used as an identifier, as
    /// `(line, source line)`.
    fn pam_ignore_identifiers(cleaned: &str) -> Vec<(usize, String)> {
        identifier_hits(cleaned, "PAM_IGNORE")
    }

    /// Every numeric literal in `cleaned` whose value equals `code`, as
    /// `(line, token)`.
    ///
    /// The literal is evaluated rather than substring-matched, so `0.25`
    /// (rounded float), `0x25` (hex 37) and `1_025` (1025) are not hits while
    /// `25u32` is.
    #[allow(clippy::indexing_slicing)]
    fn numeric_literals_equal_to(cleaned: &str, code: u128) -> Vec<(usize, String)> {
        let b = cleaned.as_bytes();
        let mut hits = Vec::new();
        let mut i = 0usize;
        while i < b.len() {
            // Skip a digit that continues an identifier (`foo25`).
            let begins_literal = b[i].is_ascii_digit()
                && !(i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'));
            if !begins_literal {
                i += 1;
                continue;
            }
            let (value, next) = read_numeric_literal(b, i);
            if value == Some(code) {
                let line = cleaned[..i].matches('\n').count() + 1;
                hits.push((line, cleaned[i..next].to_owned()));
            }
            i = next.max(i + 1);
        }
        hits
    }

    /// Read the numeric literal starting at `start` as `(value, end)`, with
    /// `None` for floats.
    #[allow(clippy::indexing_slicing)]
    fn read_numeric_literal(b: &[u8], start: usize) -> (Option<u128>, usize) {
        let mut i = start;
        let radix = if b[i] == b'0' {
            match b.get(i + 1).copied() {
                Some(b'x' | b'X') => Some(16u32),
                Some(b'o' | b'O') => Some(8u32),
                Some(b'b' | b'B') => Some(2u32),
                _ => None,
            }
        } else {
            None
        };
        if let Some(radix) = radix {
            i += 2;
            let mut digits = String::new();
            while let Some(&c) = b.get(i) {
                if c == b'_' {
                    i += 1;
                } else if (c as char).is_digit(radix) {
                    digits.push(c as char);
                    i += 1;
                } else {
                    break;
                }
            }
            while matches!(b.get(i), Some(c) if c.is_ascii_alphanumeric()) {
                i += 1;
            }
            return (u128::from_str_radix(&digits, radix).ok(), i);
        }

        let mut digits = String::new();
        let mut is_float = false;
        while let Some(&c) = b.get(i) {
            if c == b'_' {
                i += 1;
            } else if c.is_ascii_digit() {
                digits.push(c as char);
                i += 1;
            } else {
                break;
            }
        }
        if b.get(i) == Some(&b'.') && matches!(b.get(i + 1), Some(c) if c.is_ascii_digit()) {
            is_float = true;
            i += 1;
            while matches!(b.get(i), Some(c) if c.is_ascii_digit() || *c == b'_') {
                i += 1;
            }
        }
        if matches!(b.get(i).copied(), Some(b'e' | b'E'))
            && matches!(b.get(i + 1).copied(), Some(c) if c.is_ascii_digit() || c == b'+' || c == b'-')
        {
            is_float = true;
            i += 2;
            while matches!(b.get(i), Some(c) if c.is_ascii_digit() || *c == b'_') {
                i += 1;
            }
        }
        // Integer/float suffix (`25u32`, `1.5f64`).
        while matches!(b.get(i), Some(c) if c.is_ascii_alphanumeric()) {
            i += 1;
        }
        if is_float {
            return (None, i);
        }
        (digits.parse::<u128>().ok(), i)
    }

    // ------------------------------------------------------------------
    // The two scans step 4d turns on: no PAM code outside `outcome.rs`, and
    // no grant outside the two constructors.
    // ------------------------------------------------------------------

    /// Every `client-pam/src/**/*.rs`, sorted, so a new module cannot be added
    /// and stay outside the scans.
    ///
    /// Recursive: `src/mechanism/` is a directory with no `rs` extension, so a
    /// single-level `read_dir` would silently stop covering the mechanisms once
    /// step 6 creates them.
    pub(crate) fn source_files() -> Vec<std::path::PathBuf> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            let mut paths: Vec<std::path::PathBuf> = entries
                .map(|entry| entry.expect("readable dir entry").path())
                .collect();
            paths.sort();
            for path in paths {
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut files = Vec::new();
        walk(src, &mut files);
        files.sort();
        files
    }

    /// A source file's path relative to `src`, e.g. `outcome.rs` or
    /// `mechanism/threaded.rs`. Every exemption below is written against this,
    /// never against a bare file name.
    pub(crate) fn relative_to_src(path: &std::path::Path) -> String {
        let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        path.strip_prefix(src)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    /// The production half of a source file: everything before the first
    /// `#[cfg(test)]`.
    ///
    /// The tests below quote every forbidden token, so scanning the whole file
    /// would flag the assertions instead of the code.
    pub(crate) fn production_source(path: &std::path::Path) -> String {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let production = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(source.as_str());
        stripped_source(production)
    }

    /// `pam_sys` constants that are not return codes: they name an item type, so
    /// a line holding one is an argument (`pam_get_authtok(.., PAM_AUTHTOK, ..)`,
    /// which rustfmt may put on its own line), never a verdict.
    const NON_CODE_PAM_CONSTANTS: [&str; 1] = ["pam_sys::PAM_AUTHTOK"];

    /// The `pam_sys::PAM_*` values this crate returns, as `(byte offset, line)`.
    ///
    /// A site is a line of the *stripped* source that either returns one
    /// (`return pam_sys::PAM_X`) or is a bare code in tail position
    /// (`pam_sys::PAM_X` / `pam_sys::PAM_X,` — a match arm or a function tail).
    /// Comparisons and arguments (`res != pam_sys::PAM_SUCCESS`,
    /// `pam_get_authtok(.., pam_sys::PAM_AUTHTOK, ..)`) are not sites: they
    /// consume a code, they do not produce one.
    fn pam_code_sites(cleaned: &str) -> Vec<(usize, String)> {
        let mut hits = Vec::new();
        let mut offset = 0usize;
        for line in cleaned.lines() {
            let trimmed = line.trim();
            if trimmed.contains("pam_sys::PAM_") {
                let bare_token = trimmed.trim_end_matches([',', ';']).trim();
                let bare = !NON_CODE_PAM_CONSTANTS.contains(&bare_token)
                    && bare_token
                        .strip_prefix("pam_sys::PAM_")
                        .is_some_and(|rest| {
                            !rest.is_empty()
                                && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        });
                if trimmed.contains("return ") || bare {
                    hits.push((offset, trimmed.to_owned()));
                }
            }
            offset += line.len() + 1;
        }
        hits
    }

    /// The name of the function whose body contains `at`, as written.
    ///
    /// Used only for the `lib.rs` exemption, which names the six ABI functions
    /// (`guard`'s panic arm and the five constant stubs) — never a line number,
    /// so an edit above them cannot silently move the exemption.
    fn enclosing_fn(cleaned: &str, at: usize) -> Option<String> {
        let before = cleaned.get(..at)?;
        let start = before.rfind("fn ")? + "fn ".len();
        let name: String = before[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    /// The `lib.rs` functions allowed to answer with a constant: the five
    /// constant ABI stubs and `guard`'s panic arm.
    ///
    /// These are the whole ABI surface: they convert no verdict, never see an
    /// `Outcome`, and are not part of any authentication decision.
    const LIB_PAM_EXEMPTIONS: [&str; 6] = [
        "guard",
        "pam_sm_setcred",
        "pam_sm_acct_mgmt",
        "pam_sm_open_session",
        "pam_sm_close_session",
        "pam_sm_chauthtok",
    ];

    /// No `pam_sys::PAM_*` value is produced outside `outcome.rs`, except the
    /// six `lib.rs` ABI sites named above.
    ///
    /// The defect this catches: a return code minted at the site that observed
    /// the failure instead of through `Outcome::to_pam` — the 24 `pam_logic.rs`
    /// sites this step removes. Such a site can return `PAM_SUCCESS`, can return
    /// a code the verdict does not imply, and adds a path no outcome test
    /// covers. The exemption is by *function name* and the scan asserts it
    /// covered `outcome.rs` (by path) and `lib.rs`, so a moved or emptied scan
    /// cannot pass vacuously.
    #[test]
    fn only_outcome_rs_returns_pam_constants() {
        let files = source_files();
        let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
        for required in ["outcome.rs", "lib.rs", "pam_logic.rs", "transaction.rs"] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }

        let mut findings: Vec<String> = Vec::new();
        let mut exempted = 0usize;
        for path in &files {
            let rel = relative_to_src(path);
            // Exempt by path, not by file name: a future `mechanism/outcome.rs`
            // must not inherit this file's exemption.
            if rel == "outcome.rs" {
                continue;
            }
            let cleaned = production_source(path);
            for (offset, text) in pam_code_sites(&cleaned) {
                if rel == "lib.rs" {
                    let enclosing = enclosing_fn(&cleaned, offset).unwrap_or_default();
                    if LIB_PAM_EXEMPTIONS.contains(&enclosing.as_str()) {
                        exempted += 1;
                        continue;
                    }
                }
                findings.push(format!("{rel}: {text}"));
            }
        }

        assert!(
            findings.is_empty(),
            "every PAM code must come from `Outcome::to_pam`, found:\n{}",
            findings.join("\n")
        );
        assert_eq!(
            exempted, 6,
            "the six `lib.rs` ABI sites (guard's panic arm and the five constant \
             stubs) are the only exemption; found {exempted}"
        );
    }

    /// The grant constructors, and any hand-built `Outcome::Granted`, as
    /// findings for the file `rel`.
    ///
    /// `outcome.rs` is where both constructors are defined, and the
    /// orchestration (`pam_logic.rs` now, `transaction.rs` once the cache moves
    /// there) is the only code allowed to call them. A mechanism, a rule, a
    /// plan or a test helper calling either — or building `Outcome::Granted`
    /// by hand — is a second way to mint a grant.
    fn grant_findings(rel: &str, cleaned: &str) -> Vec<String> {
        let mut findings = Vec::new();
        for (line, text) in identifier_hits(cleaned, "granted_from_daemon")
            .into_iter()
            .chain(identifier_hits(cleaned, "replayed"))
            .chain(identifier_hits(cleaned, "Granted"))
        {
            let call = text.contains("granted_from_daemon")
                || text.contains("Outcome::replayed")
                || text.contains("fn replayed");
            let allowed = match rel {
                "outcome.rs" => true,
                "pam_logic.rs" | "transaction.rs" => call,
                _ => false,
            };
            if !allowed {
                findings.push(format!("{rel}:{line}: {text}"));
            }
        }
        findings
    }

    /// A `Granted` is minted only by `Outcome::granted_from_daemon` or
    /// `Outcome::replayed`, from the orchestration, and nowhere else.
    ///
    /// The defect this catches: a mechanism (or anything else outside the
    /// orchestration) building `Outcome::Granted(..)` directly, or calling one
    /// of the two constructors, which would be a second grant path beside the
    /// daemon's `Success` and the replay. The retired check — "the token
    /// `Outcome::Granted` appears only in `outcome.rs`" — is not used: it
    /// passes for the very code that defines the constructors, so it cannot
    /// catch a grant minted inside that module or reached from a mechanism.
    #[test]
    fn granted_only_from_daemon() {
        let files = source_files();
        let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
        for required in ["outcome.rs", "pam_logic.rs", "transaction.rs"] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }

        let mut findings: Vec<String> = Vec::new();
        let mut definitions = 0usize;
        for path in &files {
            let rel = relative_to_src(path);
            let cleaned = production_source(path);
            if rel == "outcome.rs" {
                definitions += cleaned.matches("fn granted_from_daemon").count();
                definitions += cleaned.matches("fn replayed").count();
                continue;
            }
            findings.extend(grant_findings(&rel, &cleaned));
        }

        assert!(
            findings.is_empty(),
            "only the orchestration may reach a grant constructor, and only \
             `outcome.rs` may build a `Granted`:\n{}",
            findings.join("\n")
        );
        assert_eq!(
            definitions, 2,
            "the two grant constructors — granted_from_daemon and replayed — are \
             defined once, in outcome.rs"
        );
    }

    /// The `PAM_*` return-site detector fires on a planted return and on a
    /// planted bare arm, and not on a comparison or on prose.
    ///
    /// Without this, a detector that stopped matching would make
    /// `only_outcome_rs_returns_pam_constants` pass for every tree.
    #[test]
    fn pam_return_scan_detects_a_planted_return() {
        let planted = stripped_source(
            "fn returns_one() -> c_int {\n    return pam_sys::PAM_AUTH_ERR;\n}\n\
             fn tail_position() -> c_int {\n    pam_sys::PAM_SUCCESS\n}\n\
             fn compares_one(res: c_int) -> c_int {\n    if res != pam_sys::PAM_SUCCESS {}\n    0\n}\n",
        );
        let sites = pam_code_sites(&planted);
        assert_eq!(
            sites.len(),
            2,
            "the detector must report the return and the tail expression, and \
             not the comparison: {sites:?}"
        );
        assert_eq!(
            enclosing_fn(&planted, sites[0].0).as_deref(),
            Some("returns_one"),
            "the exemption is by enclosing function name"
        );
        assert_eq!(
            enclosing_fn(&planted, sites[1].0).as_deref(),
            Some("tail_position")
        );

        // Prose is not a site, which is what makes the whole-crate assertion
        // meaningful: this file's docs name the forbidden codes.
        let prose = stripped_source(
            "// return pam_sys::PAM_AUTH_ERR;\nlet s = \"return pam_sys::PAM_SUCCESS;\";\n",
        );
        assert!(pam_code_sites(&prose).is_empty());

        // An item type is not a verdict, even alone on its line: the whole-crate
        // scan would otherwise report `pam_get_authtok`'s argument.
        let item = stripped_source(
            "pam_get_authtok(\n    pamh,\n    pam_sys::PAM_AUTHTOK,\n    &mut tok,\n);\n",
        );
        assert!(
            pam_code_sites(&item).is_empty(),
            "an item-type constant is not a return code"
        );
    }

    /// The grant detector reports a hand-built `Granted` and a constructor call
    /// from a mechanism, and accepts `outcome.rs` and the orchestration.
    ///
    /// Without this, `granted_only_from_daemon` would pass for a tree in which
    /// the detector had stopped matching.
    #[test]
    fn granted_scan_detects_a_planted_construction() {
        let planted = stripped_source(
            "fn drive() -> Outcome {\n    Outcome::Granted(GrantVia::PhoneTap)\n}\n\
             fn other() -> Outcome {\n    Outcome::granted_from_daemon()\n}\n",
        );

        let mechanism = grant_findings("mechanism/threaded.rs", &planted);
        assert_eq!(
            mechanism.len(),
            2,
            "a mechanism must not build a grant or call a grant constructor: {mechanism:?}"
        );

        let orchestration = grant_findings("pam_logic.rs", &planted);
        assert_eq!(
            orchestration.len(),
            1,
            "the orchestration may call the constructor but may not build a \
             `Granted` by hand: {orchestration:?}"
        );
        assert!(orchestration[0].contains("Outcome::Granted"));

        assert!(
            grant_findings("outcome.rs", &planted).is_empty(),
            "outcome.rs defines both constructors, so it is exempt by path"
        );
    }

    /// The mapping above only covers daemon responses.  Guard *every* file of
    /// this crate — not just `pam_logic.rs` and `lib.rs` — against
    /// reintroducing `PAM_IGNORE`, by identifier and by its numeric value.
    ///
    /// The numeric half is the one that matters for regressions: the vectors
    /// that remain are a `pam_sys::PAM_IGNORE` re-export reaching a `return`, or
    /// a bare literal equal to PAM_IGNORE's value, in any `client-pam/src/*.rs`
    /// — either is a single edit away from the bypass this guards, and a
    /// name-only scan would miss the numeric form.
    #[test]
    fn test_module_source_contains_no_pam_ignore_return() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot list {dir}: {e}"))
            .map(|entry| entry.expect("readable dir entry").path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
            .collect();
        files.sort();
        // An empty or relocated scan must not pass silently: `pam_logic.rs`
        // carries the return codes today.
        assert!(
            files.iter().any(|p| p.ends_with("pam_logic.rs")),
            "the scan did not cover pam_logic.rs: {files:?}"
        );

        // Spelled arithmetically so this test's own source carries no literal
        // for its own scan to find.
        let ignore_code: u128 = 5 * 5;
        let mut findings: Vec<String> = Vec::new();
        for path in &files {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            let cleaned = stripped_source(&source);
            for (line, text) in pam_ignore_identifiers(&cleaned) {
                findings.push(format!("{name}:{line}: PAM_IGNORE identifier in: {text}"));
            }
            for (line, text) in numeric_literals_equal_to(&cleaned, ignore_code) {
                findings.push(format!(
                    "{name}:{line}: PAM_IGNORE value {ignore_code} used in: {text}"
                ));
            }
        }
        assert!(
            findings.is_empty(),
            "the module must never return PAM_IGNORE:\n{}",
            findings.join("\n")
        );
    }

    /// The whole-crate scan above returns empty for two independent reasons —
    /// every `PAM_IGNORE` in this crate is prose inside a comment, and no bare
    /// literal holds its value — so it would stay green even if the stripper or
    /// either detector were broken.  Prove both detectors fire on a synthetic
    /// snippet, and that a comment or a string naming the code does not count.
    #[test]
    fn test_pam_ignore_scan_detects_a_real_return() {
        // Spelled arithmetically so this test's own source carries no literal
        // for its own scan to find (as in the whole-crate scan above).
        let ignore_code: u128 = 5 * 5;

        let source = format!(
            "// PAM_IGNORE in a comment is prose, not a return.\n\
             /* PAM_IGNORE and {ignore_code} in a block comment, too. */\n\
             let prose = \"return pam_sys::PAM_IGNORE; return {ignore_code};\";\n\
             let code = {{ let x = pam_sys::PAM_IGNORE; x }};\n\
             return {ignore_code}u32;\n"
        );
        let cleaned = stripped_source(&source);

        assert_eq!(
            pam_ignore_identifiers(&cleaned),
            vec![(
                4,
                "let code = { let x = pam_sys::PAM_IGNORE; x };".to_owned()
            )],
            "the identifier scan must report the real return and neither the \
             comment nor the string"
        );

        assert_eq!(
            numeric_literals_equal_to(&cleaned, ignore_code),
            vec![(5, format!("{ignore_code}u32"))],
            "the numeric scan must report the bare value and neither the \
             comment nor the string"
        );

        // The negative half: prose alone must never be reported, which is what
        // makes the whole-crate assertion meaningful today.
        assert_eq!(
            pam_ignore_identifiers(&stripped_source("// PAM_IGNORE\n")),
            Vec::new(),
            "a comment naming PAM_IGNORE is not a return"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_arguments,
    clippy::indexing_slicing
)]
mod gui_loop_tests {
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

        assert_eq!(reason, ExitReason::Timeout);
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

        assert_eq!(reason, ExitReason::PasswordEntered);
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

        assert_eq!(reason, ExitReason::PasswordFailed);
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

        assert_eq!(reason, ExitReason::IpcResponseReceived);
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

        assert_eq!(reason, ExitReason::IpcError);
        assert!(auth_response.is_none());
        assert_eq!(pending, Some(UnavailableReason::IpcConnectionLost));

        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
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

    /// **Smoke test only.**  It compares *source byte offsets* and would still
    /// pass if the announcement sat behind a branch that never executes.
    ///
    /// The authoritative coverage is `scripts/ci/test-pam-host-cases.sh` case 1
    /// (`ttyless_wait_announced_before_blocking`), which counts and times the
    /// real `PAM_TEXT_INFO` on a live PAM stack.
    #[test]
    fn test_sequential_wait_is_announced_before_it_blocks() {
        let source = include_str!("pam_logic.rs");
        // Only the production half of the file: the test modules below contain
        // the same identifiers inside string literals, which would otherwise
        // satisfy the searches no matter what the production code does.
        let production = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(source);

        let announce = production
            .find("waiting_for_tap_password()")
            .unwrap_or_else(|| {
                panic!("invariant broken: the sequential wait never announces a password route")
            });

        // `rfind` picks the call after the function definition; every test-only
        // call site passes `mock_ipc` and does not match.
        let blocking_wait = production
            .rfind("run_sequential_event_loop(ipc")
            .unwrap_or_else(|| {
                panic!("invariant broken: production call to the sequential wait not found")
            });

        assert!(
            announce < blocking_wait,
            "invariant broken: the password-route announcement (byte {}) must be emitted \
             before the call that blocks on the sequential wait (byte {}), otherwise the \
             host never reveals its password entry during the wait",
            announce,
            blocking_wait
        );
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod conversation_mode_tests {
    use super::*;
    use std::os::raw::c_void;

    #[test]
    fn conversation_mode_is_an_allowlist_with_a_sequential_default() {
        // (service, process, reauth, expected)
        let cases: &[(&str, Option<&str>, bool, ConversationMode)] = &[
            // polkit: conversation is a fd answered by the separate agent
            // process.  Reauth is irrelevant to it.
            (
                "polkit-1",
                Some("polkit-agent-helper-1"),
                false,
                ConversationMode::Threaded,
            ),
            (
                "polkit-1",
                Some("polkit-agent-he"),
                false,
                ConversationMode::Threaded,
            ),
            // kscreenlocker >= 6.8 answers on Qt's D-Bus daemon thread; the
            // greet helper does not, so it stays sequential.
            (
                "kde",
                Some("kscreenlocker_worker"),
                false,
                ConversationMode::Threaded,
            ),
            (
                "kde",
                Some("kscreenlocker_w"),
                false,
                ConversationMode::Threaded,
            ),
            (
                "kde",
                Some("kscreenlocker_greet"),
                false,
                ConversationMode::Sequential,
            ),
            (
                "kde",
                Some("kscreenlocker_g"),
                false,
                ConversationMode::Sequential,
            ),
            ("sudo", Some("sudo"), false, ConversationMode::Sequential),
            ("su", Some("su"), false, ConversationMode::Sequential),
            // hyprlock answers concurrently (documented residual risk).
            (
                "hyprlock",
                Some("hyprlock"),
                false,
                ConversationMode::Threaded,
            ),
            // xsecurelock's helper answers on its own thread pool.
            (
                "xsecurelock",
                Some("authproto_pam"),
                false,
                ConversationMode::Threaded,
            ),
            // xfce4-screensaver / mate-screensaver dialog children, full and
            // `/proc/self/comm`-truncated spellings.  Their conversation parks
            // in `g_cond_wait`, which is not a cancellation point, so they stay
            // sequential.
            (
                "xfce4-screensaver",
                Some("xfce4-screensaver-dialog"),
                false,
                ConversationMode::Sequential,
            ),
            (
                "xfce4-screensaver",
                Some("xfce4-screensav"),
                false,
                ConversationMode::Sequential,
            ),
            (
                "mate-screensaver",
                Some("mate-screensaver-dialog"),
                false,
                ConversationMode::Sequential,
            ),
            (
                "mate-screensaver",
                Some("mate-screensave"),
                false,
                ConversationMode::Sequential,
            ),
            // Hosts that read the password before pam_authenticate: their
            // conversation only replays it, so the phone is not consulted.
            (
                "swaylock",
                Some("swaylock"),
                false,
                ConversationMode::PreCollected,
            ),
            (
                "gtklock",
                Some("gtklock"),
                false,
                ConversationMode::PreCollected,
            ),
            (
                "i3lock",
                Some("i3lock"),
                false,
                ConversationMode::PreCollected,
            ),
            // GDM: only a reauthentication prompt may be driven from a worker
            // thread, and only behind the `gdm-password` service.
            (
                "gdm-password",
                Some("gdm-session-worker"),
                true,
                ConversationMode::Threaded,
            ),
            (
                "gdm-password",
                Some("gdm-session-wor"),
                true,
                ConversationMode::Threaded,
            ),
            // The env var is absent (reauth=false): same worker, sequential.
            (
                "gdm-password",
                Some("gdm-session-worker"),
                false,
                ConversationMode::Sequential,
            ),
            // The reauth flag alone must not promote a non-DM service.
            (
                "sudo",
                Some("gdm-session-worker"),
                true,
                ConversationMode::Sequential,
            ),
            // Case-insensitive service match.
            (
                "GDM-Password",
                Some("gdm-session-worker"),
                true,
                ConversationMode::Threaded,
            ),
            (
                "whatever",
                Some("whatever"),
                false,
                ConversationMode::Sequential,
            ),
            ("polkit-1", None, false, ConversationMode::Threaded),
            ("sudo", None, false, ConversationMode::Sequential),
            ("", None, false, ConversationMode::Sequential),
        ];

        for &(service, process, reauth, expected) in cases {
            assert_eq!(
                conversation_mode(service, process, reauth),
                expected,
                "service {service:?} with process {process:?} and reauth {reauth}"
            );
        }
    }

    /// The DM bypass and the GDM reauth exemption both hang off this prefix
    /// test: it must stay exact-or-`-`-suffixed so an unrelated service whose
    /// name merely starts with a DM name is not skipped.
    #[test]
    fn display_manager_prefix_matching() {
        for service in [
            "gdm",
            "gdm3",
            "gdm-password",
            "GDM-Password",
            "gdm-tapauth-host",
            "sddm",
            "sddm-helper",
            "lightdm",
            "greetd",
            "plasmalogin",
        ] {
            assert!(
                policy::is_dm_service(service),
                "{service:?} must be treated as a display manager service"
            );
        }
        for service in [
            "gdmfoo",
            "sddmfoo",
            "sudo",
            "su",
            "polkit-1",
            "tapauth-conv-sufficient",
            "",
        ] {
            assert!(
                !policy::is_dm_service(service),
                "{service:?} must not be treated as a display manager service"
            );
        }
    }

    static JOIN_TEST_STARTED: AtomicBool = AtomicBool::new(false);

    struct JoinTestCtx {
        pipe_read: libc::c_int,
    }

    /// Blocks in `read(2)` — a cancellation point, just like
    /// `pam_get_authtok` — so `cancel_and_join` can only return promptly by
    /// actually cancelling the thread.  `C-unwind` lets glibc's
    /// `abi::__forced_unwind` pass through this frame.
    unsafe extern "C-unwind" fn join_test_worker(arg: *mut c_void) -> *mut c_void {
        let ctx = unsafe { &*(arg as *const JoinTestCtx) };
        JOIN_TEST_STARTED.store(true, Ordering::Release);
        let mut buf = [0u8; 1];
        unsafe {
            libc::read(ctx.pipe_read, buf.as_mut_ptr() as *mut c_void, 1);
        }
        std::ptr::null_mut()
    }

    // `libc::pthread_create` wants an `extern "C"` fn; this binding keeps the
    // worker's `C-unwind` ABI without transmuting function signatures.
    extern "C" {
        #[link_name = "pthread_create"]
        fn pthread_create_unwind(
            thread: *mut libc::pthread_t,
            attr: *const libc::pthread_attr_t,
            start_routine: unsafe extern "C-unwind" fn(*mut c_void) -> *mut c_void,
            arg: *mut c_void,
        ) -> libc::c_int;
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

/// The verdict-reuse record: the 500 ms window, its `(username, service)` key,
/// and the two gates that decide what may be recorded.
///
/// Every case drives the real `transaction::record` / `transaction::replay_for`
/// pair, so the assertions are about the record `authenticate` writes and reads
/// and not about a parallel copy of its logic; each case holds
/// `transaction::CACHE_SLOT_LOCK` for its whole body, because the record is one
/// slot for the process.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod verdict_reuse_tests {
    use super::tests::{no_daemon, NullIpc};
    use super::*;
    use crate::outcome::{DenyVia, UnavailableReason};
    use crate::transaction::{record, replay_for, Concluded, Via};

    const SERVICE: &str = "tapauth-test";

    /// The three verdicts these tests replay: a grant, an unavailable service
    /// and an explicit denial. They are the three the daemon can reach, and the
    /// record stores the verdict itself now, so a replay cannot re-enter the
    /// code path.
    fn granted() -> Outcome {
        Outcome::granted_from_daemon()
    }

    fn unavailable() -> Outcome {
        Outcome::Unavailable(UnavailableReason::TimedOut)
    }

    fn denied() -> Outcome {
        Outcome::Denied(DenyVia::PhoneDenial)
    }

    /// The single process-wide slot, held for the whole case.
    fn slot() -> std::sync::MutexGuard<'static, ()> {
        crate::transaction::CACHE_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record `outcome` for `(user, service)` as if it had concluded `ms_ago`,
    /// through the same `Armed` — conclude — record path `authenticate` uses,
    /// and hand back the instant the lookup should use.
    fn record_ago(ms_ago: u64, user: &str, service: Option<&str>, outcome: Outcome) -> Instant {
        let now = Instant::now();
        let concluded = crate::transaction::armed_for_test(NullIpc, "reuse-test-request").conclude(
            outcome,
            user,
            service.map(ServiceName::new),
        );
        let _ = record(concluded, now - Duration::from_millis(ms_ago));
        now
    }

    /// The verdict a lookup returns for `(user, service)` at `now`.
    ///
    /// A hit is `Outcome::replayed(..)` of what was recorded: the marker is the
    /// provenance this step adds, and `record` is what refuses it.
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
            let code = outcome.clone().to_pam();
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
            let code = outcome.clone().to_pam();
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

        let recorded = crate::transaction::armed_for_test(NullIpc, "replace-success-request")
            .conclude(granted(), "alice", Some(ServiceName::new(SERVICE)));
        record(recorded, now);
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&granted()))
        );

        let recorded = crate::transaction::armed_for_test(NullIpc, "replace-failure-request")
            .conclude(unavailable(), "alice", Some(ServiceName::new(SERVICE)));
        record(recorded, now);
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&unavailable())),
            "the record holds the *last* conclusion, so a later failure must \
             overwrite the earlier success"
        );
    }

    /// A connect failure says nothing about the phone, so it must leave the
    /// process-wide record unarmed — and a retry must therefore be able to start
    /// a real transaction instead of replaying a verdict that never existed.
    ///
    /// The key is unique to this test: the record is process-wide and other
    /// tests in this module write to it in parallel.
    ///
    /// Not covered here: a *caller* that records before opening a request —
    /// `record` takes a `Concluded` by value and `Armed::conclude` is its only
    /// fresh producer, so that shape is a move error rather than something a
    /// test has to look for. `armed_requires_both_connect_and_send` covers the
    /// arming itself.
    #[test]
    fn a_failed_connect_records_nothing_and_the_retry_dials_again() {
        let _slot = slot();

        const USER: &str = "failed-connect-user";
        const UNIQUE_SERVICE: &str = "failed-connect-service";
        let now = Instant::now();

        let first = Armed::<NullIpc>::open(
            || Err(no_daemon()),
            |_: &mut NullIpc| Ok(()),
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

        // The retry: with nothing recorded it must dial again and arm a real
        // transaction, whose conclusion *is* recorded.
        let Ok(armed) = Armed::<NullIpc>::open(
            || Ok(NullIpc),
            |_: &mut NullIpc| Ok(()),
            "retry-request".into(),
        ) else {
            panic!("the retry must be able to connect after the failed attempt");
        };
        let concluded = armed.conclude(unavailable(), USER, Some(ServiceName::new(UNIQUE_SERVICE)));
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

    /// A verdict replayed from the record must not be recorded again: that would
    /// refresh the timestamp and turn the fixed 500 ms window into a sliding one.
    #[test]
    fn a_from_cache_verdict_is_not_recorded() {
        let _slot = slot();

        const USER: &str = "from-cache-user";
        const UNIQUE_SERVICE: &str = "from-cache-service";
        let now = Instant::now();

        let recorded = crate::transaction::armed_for_test(NullIpc, "original-request").conclude(
            denied(),
            USER,
            Some(ServiceName::new(UNIQUE_SERVICE)),
        );
        record(recorded, now);

        // A replay carrying a *different* verdict, recorded again on purpose: if
        // `record` accepted it, the slot would hold the grant instead of the
        // denial and the assertion below would see it.
        let replay = Concluded::replay(granted(), USER.into(), ServiceName::new(UNIQUE_SERVICE));
        assert_eq!(record(replay, now), Outcome::replayed(&granted()));
        assert_eq!(
            replayable(USER, UNIQUE_SERVICE, now),
            Some(Outcome::replayed(&denied())),
            "a cache hit must not be re-recorded: it would overwrite the original \
             code and refresh the timestamp, making the window sliding"
        );
    }

    /// An unresolved service is never cached: the empty string would collapse
    /// every such call into one key.
    #[test]
    fn an_unresolved_service_is_not_recorded() {
        let _slot = slot();

        const USER: &str = "unresolved-service-user";
        let now = Instant::now();

        let recorded = crate::transaction::armed_for_test(NullIpc, "unresolved-service-request")
            .conclude(unavailable(), USER, None);
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
            .conclude(unavailable(), "alice", Some(ServiceName::new(SERVICE)));
        record(recorded, now + Duration::from_millis(50));
        // `saturating_duration_since` reads a clock anomaly as "no time has
        // passed", so the conclusion still counts as fresh.  The point of the
        // test is that it must not panic.
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&unavailable())),
            "a record stamped in the future must read as fresh, not panic"
        );
    }

    /// **Smoke test only.**  It compares source byte offsets, so it would still
    /// pass if the lookup sat behind a branch that never executes.
    ///
    /// The authoritative coverage is the `duplicate`, `duplicate-unavailable`,
    /// `duplicate-cross-user` and `duplicate-cross-service` shapes in
    /// `scripts/ci/test-pam-conv-thread.sh`, which count the connections the
    /// fake daemon accepted: this ordering is what makes those counts
    /// meaningful.
    #[test]
    fn cache_lookup_precedes_daemon_contact() {
        let source = include_str!("pam_logic.rs");
        // Only the production half of the file: the test modules contain the
        // same identifiers inside string literals, which would otherwise
        // satisfy the searches no matter what the production code does.
        let production = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(source);

        // The call, not the `if let` that contains it: rustfmt is free to break
        // the pattern across lines.
        let lookup = production
            .find("replay_for(&username, service_name.original(), Instant::now())")
            .unwrap_or_else(|| panic!("invariant broken: the reuse lookup is gone from `run`"));

        let daemon_contact = production
            .find("let request = SendParams {")
            .unwrap_or_else(|| {
                panic!("invariant broken: production call to the IPC connect not found")
            });

        assert!(
            lookup < daemon_contact,
            "invariant broken: the verdict-reuse lookup (byte {}) must run before the \
             module contacts the daemon (byte {}), otherwise a duplicate transaction \
             still sends a request and rings the phone",
            lookup,
            daemon_contact
        );
    }

    /// The reuse suite is the fifteen named cases, and exactly one test in the
    /// crate is ignored: the fork experiment.
    ///
    /// The defect this catches: a rewritten suite that silently drops a case —
    /// presence is asserted by name, so a deleted test fails here rather than
    /// passing as "all green with fewer tests". The ignore rule is the other
    /// half: if `#[ignore]` could be used to silence a broken case, the fork
    /// test's own ignore would hide it, so the crate must contain exactly one
    /// and it must be that one.
    #[test]
    fn reuse_suite_is_intact() {
        let files = super::tests::source_files();
        let names: Vec<String> = files
            .iter()
            .map(|path| super::tests::relative_to_src(path))
            .collect();
        for required in ["pam_logic.rs", "transaction.rs"] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }
        // Comment- and string-stripped, so a doc comment that quotes a name or
        // an attribute is not a finding, and this test's own literals cannot
        // satisfy its searches.
        let sources: String = files
            .iter()
            .map(|path| {
                let source = std::fs::read_to_string(path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                super::tests::stripped_source(&source)
            })
            .collect();

        // The fifteen: the fourteen cases that survived the retargeting, plus
        // `armed_requires_both_connect_and_send`, which replaces
        // `the_verdict_record_is_armed_only_inside_the_helper` — that one is
        // deleted below because the by-value `Concluded` makes its source scan
        // redundant, and a replacement asserting "the type is constructed here"
        // would be strictly weaker than the type.
        const REUSE_CASES: [&str; 15] = [
            "a_success_inside_the_window_is_reused",
            "a_success_after_the_window_is_not_reused",
            "an_unavailability_inside_the_window_is_reused",
            "a_denial_inside_the_window_is_reused",
            "an_unavailability_after_the_window_is_not_reused",
            "another_users_conclusion_is_never_reused",
            "another_services_conclusion_is_never_reused",
            "recording_a_failure_replaces_the_cached_success",
            "a_failed_connect_records_nothing_and_the_retry_dials_again",
            "a_from_cache_verdict_is_not_recorded",
            "an_unresolved_service_is_not_recorded",
            "a_poisoned_lock_reads_as_a_cache_miss",
            "a_future_timestamp_does_not_panic",
            "cache_lookup_precedes_daemon_contact",
            "armed_requires_both_connect_and_send",
        ];
        for name in REUSE_CASES {
            assert!(
                sources.contains(&format!("fn {name}(")),
                "the reuse case `{name}` is missing: the suite may not be \
                 rewritten by dropping a case"
            );
        }
        assert!(
            !sources.contains(concat!(
                "fn the_verdict_record_is_armed_only_inside_the",
                "_helper("
            )),
            "the arming source scan is deleted, not renamed: the by-value \
             `Concluded` replaces it, and a weaker copy must not return"
        );

        // The new cases this step adds, so a dropped one fails like any other.
        for name in [
            "reuse_key_is_case_sensitive",
            "replay_notice_is_silent",
            "cache_owner_is_local",
            "conclusion_cache_survives_fork",
        ] {
            assert!(
                sources.contains(&format!("fn {name}(")),
                "the new reuse case `{name}` is missing"
            );
        }

        // Exactly one ignored test in the crate, and it is the fork experiment.
        let ignored: Vec<&str> = sources
            .match_indices("#[ignore")
            .map(|(at, _)| at)
            .map(|at| &sources[at..])
            .collect();
        assert_eq!(
            ignored.len(),
            1,
            "exactly one test may be ignored (the fork experiment); found {}",
            ignored.len()
        );
        let Some(after) = ignored.first().copied() else {
            panic!("invariant broken: no `#[ignore]` found");
        };
        assert!(
            after.contains("fn conclusion_cache_survives_fork("),
            "the one ignored test must be `conclusion_cache_survives_fork`: the \
             attribute may not be reused to silence a dropped case"
        );
    }

    /// No other module may name the reuse record's lock or its static.
    ///
    /// The defect this catches: a second file reaching `LAST_CONCLUSION` (or
    /// any `.lock()` on it), or this module handing the guard out through a
    /// non-test `pub(crate)` getter — either defeats the ownership that keeps a
    /// fork fix (an `atfork` reinit, an atomic cell, or dropping the cache)
    /// inside one file. The scan is over the comment- and string-stripped
    /// production half of every `src/**/*.rs`, so `#[cfg(test)]` code is exempt
    /// by construction and a doc comment that quotes the token is not a
    /// finding. The positive control runs the detector over an in-memory
    /// string, never a planted file under `src/`, which would race the parallel
    /// recursive walk.
    #[test]
    fn cache_owner_is_local() {
        let files = super::tests::source_files();
        let names: Vec<String> = files
            .iter()
            .map(|path| super::tests::relative_to_src(path))
            .collect();
        assert!(
            names.iter().any(|name| name == "transaction.rs"),
            "the scan did not cover the cache's own module: {names:?}"
        );

        let mut findings: Vec<String> = Vec::new();
        for path in &files {
            let rel = super::tests::relative_to_src(path);
            let production = super::tests::production_source(path);
            if rel == "transaction.rs" {
                // The owner may lock the static; it may not hand the lock, the
                // guard or the record out.
                for (line, text) in production.lines().enumerate() {
                    let leaks_guard = text.contains("MutexGuard");
                    let exposes_record =
                        text.contains("pub(crate) fn") && text.contains("LastConclusion");
                    if leaks_guard || exposes_record {
                        findings.push(format!("{rel}:{}: {}", line + 1, text.trim()));
                    }
                }
                continue;
            }
            for hit in lock_references(&production) {
                findings.push(format!("{rel}: {hit}"));
            }
        }
        assert!(
            findings.is_empty(),
            "only `transaction.rs` may name the reuse record's lock:\n{}",
            findings.join("\n")
        );

        // Positive control: the detector fires on a planted reach.
        let planted = super::tests::stripped_source(
            "fn steal() -> Option<Outcome> {\n    let guard = LAST_CONCLUSION.lock().ok()?;\n    None\n}\n",
        );
        assert!(
            !lock_references(&planted).is_empty(),
            "the detector must report a planted `LAST_CONCLUSION.lock()`"
        );
        let getter = lock_references(&super::tests::stripped_source(
            "pub(crate) fn guard() -> MutexGuard<'static, ()> { CACHE_SLOT_LOCK.lock().unwrap() }\n",
        ));
        assert!(
            !getter.is_empty(),
            "the detector must report a getter that hands the guard out"
        );
        // Negative control: prose and strings are not reaches.
        let prose = super::tests::stripped_source(
            "// LAST_CONCLUSION.lock() is what this module forbids elsewhere\n\
             let doc = \"LAST_CONCLUSION\";\n",
        );
        assert!(
            lock_references(&prose).is_empty(),
            "comments and string literals are not lock references"
        );
    }

    /// Every line of `source` that reaches the cache's lock or its static.
    fn lock_references(source: &str) -> Vec<String> {
        const TOKENS: [&str; 5] = [
            ".lock()",
            ".try_lock()",
            ".try_lock_for",
            "LAST_CONCLUSION",
            "MutexGuard",
        ];
        source
            .lines()
            .enumerate()
            .filter(|(_, line)| TOKENS.iter().any(|token| line.contains(token)))
            .map(|(line, text)| format!("line {}: {}", line + 1, text.trim()))
            .collect()
    }
}

/// Test-only compatibility wrapper: the pre-refactor entry point expressed in
/// terms of the policy table.
///
/// The policy itself — which host is threaded, which keeps the conversation on
/// the caller's thread, and which collected its password first — is
/// `policy::RULES`, in order, with each row's justification and evidence. The
/// process rules are order-insensitive among themselves; R2 is deliberately
/// excluded here because `conversation_mode` never ran for a display-manager
/// service (the bypass preceded it).
///
/// It exists so the 24-row decision table test keeps exercising the same
/// inputs, and it is deleted with that test once the table is the only
/// representation. It lives at the end of this file on purpose: the three
/// source-scan tests here read "the production half", i.e. everything before the
/// first `#[cfg(test)]`, so a test-only item among the production code would
/// silently truncate what they scan.
#[cfg(test)]
fn conversation_mode(service: &str, process: Option<&str>, reauth: bool) -> ConversationMode {
    let process = match process {
        Some(name) => crate::context::ProcessIdentity::Exe(name.into()),
        None => crate::context::ProcessIdentity::Unknown,
    };
    let gdm_reauth = if reauth {
        crate::context::GdmReauth::Present
    } else {
        crate::context::GdmReauth::Absent
    };
    let ctx = CallerContext::from_parts(Some(service), process, gdm_reauth);
    match policy::conversation_mode_of(&ctx) {
        policy::Conversation::Threaded => ConversationMode::Threaded,
        policy::Conversation::Sequential => ConversationMode::Sequential,
        policy::Conversation::PreCollected => ConversationMode::PreCollected,
    }
}
