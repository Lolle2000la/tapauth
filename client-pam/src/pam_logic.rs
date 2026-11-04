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
//! three conversation modes by `conversation_mode`; only allowlisted hosts get
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

use crate::ipc_client::IpcClient;
use crate::logging;
use crate::pam_messages;
use crate::pam_sys;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Minimal abstraction over the IPC transport so `run_gui_event_loop` can be
/// tested with a mock backed by real OS file descriptors.
pub trait IpcResponseReader {
    fn fd(&self) -> RawFd;
    fn try_read_response_nonblocking(
        &mut self,
    ) -> Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error>;
    /// Best-effort cancellation of an in-flight authentication request.
    fn send_cancel(&mut self, reason: &str, request_id: &str) -> Result<(), std::io::Error>;
}

impl IpcResponseReader for IpcClient {
    fn fd(&self) -> RawFd {
        IpcClient::fd(self)
    }

    fn try_read_response_nonblocking(
        &mut self,
    ) -> Result<Option<shared::ipc::pb::PamAuthenticateResponse>, std::io::Error> {
        self.try_read_response_nonblocking()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn send_cancel(&mut self, reason: &str, request_id: &str) -> Result<(), std::io::Error> {
        self.send_cancel(reason, request_id)
            .map(|_| ())
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

// The terminal flow below uses a single-threaded poll loop over the IPC
// socket and /dev/tty.  The GUI flow (no TTY) comes in three variants,
// selected by `conversation_mode` — an allowlist of calling processes with a
// sequential default:
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

/// Best-effort identity of the process that called into this module.
///
/// `/proc/self/exe` is authoritative and untruncated, but it is unreadable in
/// some sandboxes; `/proc/self/comm` is the fallback and holds at most
/// `TASK_COMM_LEN - 1` (15) bytes, which is why `conversation_mode` accepts
/// both the full and the truncated spelling of each process name.
fn process_identity() -> Option<String> {
    if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
        if let Some(name) = exe.file_name() {
            let name = name.to_string_lossy();
            // The kernel suffixes " (deleted)" once the binary is unlinked.
            let name = name.strip_suffix(" (deleted)").unwrap_or(name.as_ref());
            if !name.is_empty() {
                return Some(name.to_owned());
            }
        }
    }
    std::fs::read_to_string("/proc/self/comm")
        .ok()
        .map(|comm| comm.trim().to_owned())
        .filter(|comm| !comm.is_empty())
}

/// Classify the calling host's PAM conversation.
///
/// This is an **allowlist with a sequential default**: only hosts whose
/// conversation is known to stay answerable while this thread is blocked are
/// listed.  An unknown host therefore keeps the behaviour that cannot
/// deadlock, at the cost of the existing (shorter) GUI timeout before password
/// fallback — the failure direction is "slower", never "wedged".  Only hosts
/// whose conversation blocks in a cancellation point may be threaded; a host
/// that parks in a bare futex must stay sequential.
///
/// What makes a host eligible:
/// * `polkit-agent-helper-1` — the conversation is a blocking fd answered by
///   the separate agent process.
/// * `kscreenlocker_worker` (≥ 6.8) — the conversation is a peer D-Bus call
///   answered by Qt's `QDBusConnectionManager` daemon thread.  On kscreenlocker
///   ≤ 6.7 the answer is instead posted back to the thread that called
///   `pam_authenticate`, which would deadlock; nothing in `/proc` reveals the
///   version, so the allowlist stays as narrow as it can and
///   `kscreenlocker_greet` is deliberately absent.
/// * `hyprlock` — a worker `std::thread` with mutex/condvar, i.e. a genuine
///   concurrent race.  Known residual risk, accepted by the operator:
///   `resetConversation` and `checkWaiting` are not synchronised, so more than
///   one waiter would be unsafe.
/// * `authproto_pam` (xsecurelock) — the conversation is answered by the host's
///   own thread pool, not by the thread that called `pam_authenticate`.  Quirk:
///   `CallPAMWithRetries` (`helpers/authproto_pam.c:109-132`) re-runs
///   `pam_authenticate` for every status except `ABORT`, `MAXTRIES`,
///   `NEW_AUTHTOK_REQD` and `SUCCESS`, so an explicit denial can ring the phone
///   up to three times too.  Documented, not fixed here.
/// * `gdm-session-worker` on a `gdm-password` **reauthentication** — the
///   unlock/re-auth prompt of a running GDM session, whose conversation is
///   answered by the worker's GLib main loop on another thread.  Only a
///   reauthentication qualifies: a GDM *login* is bypassed by
///   `guard_display_manager_bypass` for keyring reasons, and the worker is
///   otherwise the host whose event loop must own the conversation.
///
/// The screen-saver dialogs are deliberately absent: `xfce4-screensaver-dialog`
/// and `mate-screensaver-dialog` park their PAM conversation in GLib's
/// `g_cond_wait`, a bare `futex(FUTEX_WAIT_PRIVATE)` with no cancellation
/// handshake, so a phone grant cannot abandon the conversation.  Sequential
/// keeps the phone race and only gives up in-call password fallback.
///
/// Pre-collected hosts (`swaylock`, `gtklock`, `i3lock`) are classified
/// `PreCollected` instead: their conversation replays a password that was read
/// before `pam_authenticate`, so the phone must not be consulted at all.
///
/// Extending the list is one match entry plus one row in the table test below;
/// every host that is not named stays on the sequential path.
fn conversation_mode(service: &str, process: Option<&str>, reauth: bool) -> ConversationMode {
    match process {
        Some("polkit-agent-helper-1" | "polkit-agent-he")
        | Some("kscreenlocker_worker" | "kscreenlocker_w")
        | Some("hyprlock")
        | Some("authproto_pam") => ConversationMode::Threaded,
        // A GDM reauthentication prompt only.  `reauth` is false when
        // `GDM_SESSION_FOR_REAUTH` is absent (a missed or renamed variable
        // therefore degrades to the sequential default, never to a deadlock),
        // and a non-`gdm-password` service behind `gdm-session-worker` stays
        // sequential.
        Some("gdm-session-worker" | "gdm-session-wor")
            if reauth && service.eq_ignore_ascii_case("gdm-password") =>
        {
            ConversationMode::Threaded
        }
        // All three names are shorter than `TASK_COMM_LEN` (15), so the
        // `/proc/self/comm` spelling equals the full name and there is no
        // truncated variant to accept.  These hosts read the password before
        // `pam_authenticate` (swaylock `pam.c:51` `strdup(state->password)`,
        // gtklock `auth.c:61` `strdup(data->pw)`, i3lock `i3lock.c:836`
        // `strdup(password)`) and their conversation is a synchronous replay of
        // it, so collecting the token on the calling thread is not a race.
        Some("swaylock" | "gtklock" | "i3lock") => ConversationMode::PreCollected,
        // /proc unreadable: preserve the historic polkit behaviour rather than
        // silently changing how polkit drives its conversation.
        None if service == "polkit-1" => ConversationMode::Threaded,
        _ => ConversationMode::Sequential,
    }
}

/// Whether this invocation is a GDM reauthentication (unlock, or the admin
/// prompt of a running GNOME session) rather than a fresh login.
///
/// GDM exports `GDM_SESSION_FOR_REAUTH` for the `gdm-session-worker` it spawns
/// to reauthenticate an existing session.  The variable is the only signal
/// available inside the module: the service name (`gdm-password`) is identical
/// for login and reauthentication.
fn is_gdm_reauth(service: &str) -> bool {
    service.eq_ignore_ascii_case("gdm-password")
        && std::env::var_os("GDM_SESSION_FOR_REAUTH").is_some()
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
/// `ExitReason` plus whichever side-channel data was collected (auth response
/// or error message).  Extracted from the main authentication body so the
/// multiplexing logic can be unit-tested independently.
#[allow(clippy::too_many_arguments)]
fn run_gui_event_loop<'a, T: IpcResponseReader>(
    ipc: &mut T,
    pipe_read: libc::c_int,
    deadline: Instant,
    ctx: &ThreadContext,
    request_id: &str,
    msgs: &'a pam_messages::PamMessages,
    auth_response: &mut Option<shared::ipc::pb::PamAuthenticateResponse>,
    pending_error: &mut Option<&'a str>,
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
                                    *pending_error = Some(msgs.connection_lost());
                                    return ExitReason::IpcError;
                                }
                                continue;
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {e}");
                                *pending_error = Some(msgs.communication_error());
                                return ExitReason::IpcError;
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        tracing::error!("Daemon closed connection or error detected");
                        *pending_error = Some(msgs.connection_lost());
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
                    *pending_error = Some(msgs.communication_error());
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

/// Main PAM authentication entry point.
///
/// ## Returns
///
/// - `PAM_SUCCESS`: Authentication succeeded via TapAuth
/// - `PAM_PERM_DENIED`: The user explicitly denied the request on the phone
/// - `PAM_AUTHINFO_UNAVAIL`: The authentication service could not be consulted —
///   no paired devices, the user skipped, the daemon is unreachable, or the
///   attempt timed out. On a `sufficient` line (which expands to
///   `[success=done new_authtok_reqd=done default=ignore]`) this still falls
///   through to the next module, so password fallback is preserved
/// - `PAM_AUTH_ERR`: This attempt failed while being processed — a local
///   processing failure, or the daemon reported an internal error
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

    if let Some(pam_status) = guard_display_manager_bypass(pamh) {
        return pam_status;
    }

    // Load configuration for timeouts
    let config = crate::config::PamConfig::load();
    tracing::debug!(
        "PAM operation timeout: {}s",
        config.pam_operation_timeout_secs
    );

    let username = unsafe {
        match pam_sys::get_user(pamh) {
            Ok(user) => {
                tracing::info!("Got username from PAM: {}", user);
                user
            }
            Err(code) => {
                tracing::error!("Failed to get username, PAM error code: {}", code);
                return pam_sys::PAM_USER_UNKNOWN;
            }
        }
    };

    tracing::info!("TapAuth: Authenticating user: {}", username);

    let pam_conv = unsafe {
        match pam_sys::PamConversation::new(pamh) {
            Ok(conv) => conv,
            Err(e) => {
                tracing::error!("Failed to get PAM conversation function: {}", e);
                return pam_sys::PAM_AUTH_ERR;
            }
        }
    };

    // No explicit root check here; shared config enforces file ownership/permissions.

    let msgs = pam_messages::load_for_user(&username);

    // Block terminal polling if the calling host drives its own conversation.
    // This prevents the PAM module from stealing stdin strings from checking
    // hooks via /dev/tty inheritance, which causes polkit-agent-helper-1
    // to deadlock during graphical challenge-response dialogs.
    let service = unsafe { pam_sys::get_service_name(pamh) }.unwrap_or_default();
    let process = process_identity();
    // GDM reauthentication (unlock / admin prompt of a running session) must
    // not take the display-manager bypass below, and it is the only GDM case
    // whose conversation we may drive from a worker thread.
    let reauth = is_gdm_reauth(&service);
    let mode = conversation_mode(&service, process.as_deref(), reauth);
    tracing::debug!(
        "TapAuth conversation mode: {mode:?} (process: {:?}, service: {:?}, reauth: {reauth})",
        process,
        service
    );
    // A host whose conversation we drive from a worker thread must not take the
    // terminal branch: it would start polling /dev/tty on this thread and steal
    // the stdin the host expects for its own dialog.
    let tty_file = if mode == ConversationMode::Sequential {
        std::fs::File::open("/dev/tty").ok()
    } else {
        None
    };
    let has_terminal = tty_file.is_some();

    // Pre-collected hosts (swaylock, gtklock, i3lock) read the password before
    // they call `pam_authenticate`; their conversation is a synchronous replay
    // of it, so `pam_get_authtok` returns immediately and never waits for the
    // user.  Collect the token on the calling thread — a worker thread would
    // only reintroduce the cross-thread libpam pattern the threaded path has to
    // join around — and let it be cached in `PAM_AUTHTOK`, which is what the
    // next module (`pam_unix` with `try_first_pass`/`use_first_pass`) verifies.
    //
    // This is deliberately a skip, not a wait: the user has already typed the
    // password, so ringing the phone would be misleading and could only ever
    // end in a timeout.  The skip returns `PAM_AUTHINFO_UNAVAIL` (never
    // `PAM_IGNORE`): a `sufficient` line treats that as `ignore`, exactly as
    // `PAM_IGNORE` would, so the next module still runs; a `required` line
    // fails closed.  If the token cannot be read (the host's
    // conversation refused it, or nothing was collected) the next module simply
    // prompts as it would without this module.
    if mode == ConversationMode::PreCollected {
        let mut authtok: *const std::os::raw::c_char = std::ptr::null();
        // SAFETY: `pamh` is the live handle libpam passed to this call and the
        // conversation belongs to this thread, which is what the host expects.
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
        return pam_sys::PAM_AUTHINFO_UNAVAIL;
    }

    // Announce the wait.  Each call is a single non-blocking `PAM_TEXT_INFO`
    // (one conversation round trip that carries no input and never waits for
    // the user).  The terminal and polkit paths get theirs here, before the
    // wait starts; event-loop hosts get it further down, right before the
    // module begins blocking (see `run_sequential_event_loop`), because such
    // hosts only reveal their password entry once a PAM message arrives.
    if has_terminal {
        pam_conv.try_info(msgs.waiting_for_tap_skip());
    } else if mode == ConversationMode::Threaded {
        pam_conv.try_info(msgs.waiting_for_tap());
    }

    // Generate a per-request id to correlate cancellation (shared by auth and skip branches)
    let mut rid_bytes = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut rid_bytes) {
        tracing::warn!("Failed to generate random request ID: {}, skipping...", e);
        return pam_sys::PAM_AUTH_ERR;
    }
    let request_id = hex::encode(rid_bytes);
    // Use the configured PAM operation timeout for both the local poll deadline
    // and the daemon's authentication timeout, so they stay in sync.  GUI
    // contexts without a usable conversation get the shorter GUI deadline so
    // password fallback remains close at hand.
    let effective_timeout_secs = if !has_terminal && mode == ConversationMode::Sequential {
        config
            .pam_gui_timeout_secs
            .min(config.pam_operation_timeout_secs)
    } else {
        config.pam_operation_timeout_secs
    };
    let timeout_secs = {
        let secs = effective_timeout_secs;
        if secs > u64::from(u32::MAX) {
            u32::MAX
        } else {
            secs as u32
        }
    };
    let context = if has_terminal {
        "terminal"
    } else if mode == ConversationMode::Threaded {
        "gui-threaded"
    } else {
        "gui-sequential"
    };
    tracing::debug!(
        "Authentication deadline: {}s (context: {})",
        timeout_secs,
        context
    );

    // Establish nonblocking IPC connection and send authenticate request
    let mut ipc = match IpcClient::connect_nonblocking() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to connect to tapauthd: {}", e);
            pam_conv.try_error(msgs.cannot_connect());
            return pam_sys::PAM_AUTHINFO_UNAVAIL;
        }
    };
    if let Err(e) = ipc.send_authenticate_start(&username, has_terminal, timeout_secs, &request_id)
    {
        tracing::error!("Failed to send authenticate request: {}", e);
        pam_conv.try_error(msgs.communication_error());
        return pam_sys::PAM_AUTHINFO_UNAVAIL;
    }

    // GUI contexts whose conversation must be left to the host (the sequential
    // mode, e.g. the KDE lock screen before kscreenlocker 6.8): wait for the
    // daemon on this thread and never *drive* the conversation.  Password
    // fallback happens after this returns, when the next PAM module runs its
    // own conversation.
    if !has_terminal && mode == ConversationMode::Sequential {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);
        // Announce the wait now that the request is on the wire and the module
        // is about to block.  Event-loop hosts (GDM's auth prompt, KDE's
        // kscreenlocker_worker) only reveal their password entry once a PAM
        // module sends a query or a `PAM_TEXT_INFO`, so this is what gives the
        // user a visible password route while we wait.  A single non-blocking
        // `PAM_TEXT_INFO` — it never prompts, never reads input and never runs
        // on another thread; a host whose conversation returns `PAM_CONV_ERR`
        // is unaffected because `try_info` swallows the error.
        pam_conv.try_info(msgs.waiting_for_tap_password());
        let (exit_reason, auth_response) = run_sequential_event_loop(&mut ipc, deadline);

        return match exit_reason {
            ExitReason::IpcResponseReceived => match auth_response {
                Some(resp) => map_pam_outcome(&resp, &username, &pam_conv, &msgs),
                None => pam_sys::PAM_AUTHINFO_UNAVAIL,
            },
            ExitReason::Timeout => {
                // The daemon runs on the same deadline and multicasts its own
                // AuthenticationCancel, so no client-side cancel is needed.
                pam_conv.try_info(msgs.timed_out());
                pam_sys::PAM_AUTHINFO_UNAVAIL
            }
            _ => {
                // IPC error: the request may still be in flight daemon-side.
                // Best-effort cancel uses a new blocking connection with a
                // short timeout so the phone doesn't keep buzzing.
                if let Ok(mut c) = IpcClient::connect(Duration::from_millis(100)) {
                    let _ = c.send_cancel("gui-ipc-error", &request_id);
                }
                pam_conv.try_error(msgs.communication_error());
                pam_sys::PAM_AUTHINFO_UNAVAIL
            }
        };
    }

    // GUI context with a threaded-conversation-capable host (see
    // `conversation_mode`): offload blocking credential collection to a native
    // background thread so the host can process window events, then multiplex
    // loop events using a secure close-on-exec self-pipe.
    if !has_terminal && mode == ConversationMode::Threaded {
        // O_CLOEXEC prevents the pipe fds from leaking to child processes
        // started by the long-running privileged host (sudo, gdm, polkitd).
        let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
        if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            let err = std::io::Error::last_os_error();
            tracing::error!("Failed to create secure self-pipe: {err}");
            // Best-effort cancel so the phone doesn't keep buzzing.
            if let Ok(mut c) = IpcClient::connect(Duration::from_millis(100)) {
                let _ = c.send_cancel("gui-pipe2-fail", &request_id);
            }
            return pam_sys::PAM_AUTH_ERR;
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
                )
                    -> *mut std::os::raw::c_void,
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
                let _ = c.send_cancel("gui-thread-spawn-fail", &request_id);
            }
            unsafe {
                libc::close(pipe_read);
                libc::close(pipe_write);
            }
            return pam_sys::PAM_AUTH_ERR;
        }

        let pthread_id = unsafe { pthread_id.assume_init() };
        let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);

        // The verdict when no daemon response arrived.  Every remaining exit
        // reason means the service could not be consulted — the user chose the
        // password (`PasswordEntered`, which leaves the token cached by
        // `pam_get_authtok` for the next module), dismissed the dialog
        // (`PasswordFailed`), the daemon went quiet (`Timeout`) or the IPC layer
        // failed (`IpcError`, announced through `pending_error` above).  It is
        // not `PAM_IGNORE`: on a `sufficient` line `PAM_AUTHINFO_UNAVAIL` is
        // equally `ignore`, while on a `required` line `PAM_IGNORE` would let a
        // later `optional pam_permit` grant the whole stack.
        let mut final_outcome = pam_sys::PAM_AUTHINFO_UNAVAIL;
        let mut auth_response = None;
        let mut pending_error: Option<&str> = None;

        let exit_reason = run_gui_event_loop(
            &mut ipc,
            pipe_read,
            deadline,
            &ctx,
            &request_id,
            &msgs,
            &mut auth_response,
            &mut pending_error,
        );

        // Cancel the worker if it hasn't already exited on its own, then always
        // reap it (see `cancel_and_join` for why the join is load-bearing).
        //
        // Password entry and dialog dismissal both mean the worker has left
        // `pam_get_authtok` on its own, so those paths skip the cancel.
        unsafe {
            cancel_and_join(
                pthread_id,
                exit_reason != ExitReason::PasswordEntered
                    && exit_reason != ExitReason::PasswordFailed,
            );
            libc::close(pipe_read);
            libc::close(pipe_write);
        }

        // The worker is fully reaped.  It is now safe to touch the PAM
        // conversation function without racing the background thread.
        //
        // &username is a stack-allocated Rust String reference passed to
        // map_pam_outcome.  This is sound because map_pam_outcome only uses
        // it for tracing log messages and immediately returns a PAM status
        // code; it never stores the reference or passes it to C via
        // pam_set_item.  No CString allocation is needed here.
        if let Some(err_msg) = pending_error {
            pam_conv.try_info(err_msg);
        }

        if let Some(resp) = auth_response {
            final_outcome = map_pam_outcome(&resp, &username, &pam_conv, &msgs);
        }

        if exit_reason == ExitReason::Timeout {
            pam_conv.try_info(msgs.timed_out());
        }

        return final_outcome;
    }

    // Terminal: poll socket and /dev/tty; skip only on Enter
    //
    // Safety: at this point has_terminal is true, so tty_file is
    // guaranteed Some. We still use let-else as a non-panicking
    // defuse instead of expect()/unwrap().
    let Some(mut tty) = tty_file else {
        return pam_sys::PAM_AUTHINFO_UNAVAIL;
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
    let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);
    let mut kb = [0u8; 4];
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
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
                            Ok(Some(resp)) => {
                                return map_pam_outcome(&resp, &username, &pam_conv, &msgs)
                            }
                            Ok(None) => {
                                // No complete frame yet, check for errors
                                if rev.contains(PollFlags::POLLHUP)
                                    || rev.contains(PollFlags::POLLERR)
                                {
                                    tracing::error!(
                                        "Daemon closed connection before sending response"
                                    );
                                    pam_conv.try_info(msgs.connection_lost());
                                    return pam_sys::PAM_AUTHINFO_UNAVAIL;
                                }
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {}", e);
                                pam_conv.try_info(msgs.communication_error());
                                return pam_sys::PAM_AUTHINFO_UNAVAIL;
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        // Hangup/error without any data available
                        tracing::error!("Daemon closed connection or error detected");
                        pam_conv.try_info(msgs.connection_lost());
                        return pam_sys::PAM_AUTHINFO_UNAVAIL;
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
                                            let _ = c.send_cancel("tty-skip", &request_id);
                                        }
                                        pam_conv.try_info(msgs.skipped());
                                        return pam_sys::PAM_AUTHINFO_UNAVAIL;
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

    pam_conv.try_info(msgs.timed_out());
    pam_sys::PAM_AUTHINFO_UNAVAIL
}

/// Whether the PAM service name belongs to a primary display manager.
///
/// Matched by exact name or by a `-`-suffixed prefix, so `gdm`, `gdm3` and
/// `gdm-password` all qualify but an unrelated service such as `gdmfoo` does
/// not.
fn is_dm_service(service: &str) -> bool {
    const DM_PREFIXES: [&str; 13] = [
        "sddm",
        "gdm",
        "gdm3",
        "lightdm",
        "lxdm",
        "slim",
        "xdm",
        "kdm",
        "greetd",
        "ly",
        "nodm",
        "entrance",
        "plasmalogin",
    ];
    let service_lower = service.to_ascii_lowercase();
    DM_PREFIXES.iter().any(|p| {
        service_lower == *p
            || (service_lower.starts_with(p)
                && service_lower.as_bytes().get(p.len()) == Some(&b'-'))
    })
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
/// Returns `Some(PAM_AUTHINFO_UNAVAIL)` for display manager services, `None`
/// otherwise.
fn guard_display_manager_bypass(pamh: *mut pam_sys::PamHandle) -> Option<c_int> {
    let service = unsafe { pam_sys::get_service_name(pamh) }?;
    tracing::debug!("Calling PAM service name: {}", service);

    if is_dm_service(&service) && !is_gdm_reauth(&service) {
        tracing::info!(
            "TapAuth: Service '{}' is a primary display manager. \
             Skipping to avoid breaking keyring auto-unlock.",
            service
        );
        return Some(pam_sys::PAM_AUTHINFO_UNAVAIL);
    }

    None
}

/// Spawn a thread to monitor `/dev/tty` for skip signals.
///
/// Reads from the controlling terminal and signals via `skip_tx` when any key
/// is pressed. Uses `/dev/tty` instead of stdin to work correctly in PAM contexts
/// where stdin may not be connected to the terminal.
fn map_pam_outcome(
    resp: &shared::ipc::pb::PamAuthenticateResponse,
    username: &str,
    pam_conv: &pam_sys::PamConversation,
    msgs: &pam_messages::PamMessages,
) -> c_int {
    match response_outcome(resp) {
        shared::ipc::pb::PamOutcome::Success => {
            tracing::info!("Authentication successful for user: {}", username);
            pam_conv.try_info(msgs.auth_successful());
            pam_sys::PAM_SUCCESS
        }
        shared::ipc::pb::PamOutcome::Denied => {
            tracing::info!("Authentication explicitly denied for user: {}", username);
            pam_conv.try_info(msgs.auth_denied());
            pam_sys::PAM_PERM_DENIED
        }
        shared::ipc::pb::PamOutcome::Timeout => {
            tracing::info!("Authentication timed out for user: {}", username);
            pam_sys::PAM_AUTHINFO_UNAVAIL
        }
        shared::ipc::pb::PamOutcome::Ignore => {
            tracing::info!("Daemon indicated IGNORE for user: {}", username);
            pam_sys::PAM_AUTHINFO_UNAVAIL
        }
        shared::ipc::pb::PamOutcome::Error => {
            tracing::error!(
                "Daemon reported error for user {}: {}",
                username,
                resp.detail
            );
            pam_conv.try_error(&msgs.error(&resp.detail));
            pam_sys::PAM_AUTH_ERR
        }
    }
}

/// Map the raw protobuf `outcome` field to a [`shared::ipc::pb::PamOutcome`].
///
/// This must not be replaced by prost's generated accessor
/// `PamAuthenticateResponse::outcome()`: that accessor is
/// `PamOutcome::try_from(self.outcome).unwrap_or_default()`, and
/// `PamOutcome::default()` is the first declared variant, `SUCCESS` (0). A
/// response carrying a value prost does not recognise — `99`, or a variant
/// added by a newer daemon — therefore decoded as a *grant*.
///
/// Unknown values fail closed as `PamOutcome::Error`, which `map_pam_outcome`
/// turns into `PAM_AUTH_ERR`.
fn outcome_from_raw(raw: i32) -> shared::ipc::pb::PamOutcome {
    use shared::ipc::pb::PamOutcome;

    // `PamOutcome::try_from` is the authority for "known variant"; a proto variant
    // makes this match (and `map_pam_outcome`) go non-exhaustive, forcing a
    // decision here. Arms are spelled out, not `unwrap_or(...)`, to stay auditable.
    match PamOutcome::try_from(raw) {
        Ok(PamOutcome::Success) => PamOutcome::Success,
        Ok(PamOutcome::Denied) => PamOutcome::Denied,
        Ok(PamOutcome::Timeout) => PamOutcome::Timeout,
        Ok(PamOutcome::Ignore) => PamOutcome::Ignore,
        Ok(PamOutcome::Error) => PamOutcome::Error,
        Err(_) => PamOutcome::Error,
    }
}

/// Outcome of a daemon response, failing closed on unknown values.
fn response_outcome(
    resp: &shared::ipc::pb::PamAuthenticateResponse,
) -> shared::ipc::pb::PamOutcome {
    // Reads the raw `i32` field, not the generated `outcome()` accessor.
    outcome_from_raw(resp.outcome)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::logging;

    #[test]
    fn test_logging_init() {
        logging::init_logging();
        logging::init_logging();
    }

    #[test]
    fn test_map_pam_outcome_matrix() {
        let conv = unsafe { pam_sys::PamConversation::dummy() };
        let msgs = pam_messages::load_for_user("testuser");

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
            map_pam_outcome(
                &resp_for(shared::ipc::pb::PamOutcome::Success, "Success"),
                "testuser",
                &conv,
                &msgs
            ),
            pam_sys::PAM_SUCCESS
        );

        // An explicit phone denial must stay a denial: it fails in both the
        // `required` and the `[success=done default=bad]` stack shapes.
        assert_eq!(
            map_pam_outcome(
                &resp_for(shared::ipc::pb::PamOutcome::Denied, "Denied"),
                "testuser",
                &conv,
                &msgs
            ),
            pam_sys::PAM_PERM_DENIED
        );

        // No usable answer from the service (timeout, skip, no paired device):
        // the auth service could not be consulted.
        for outcome in [
            shared::ipc::pb::PamOutcome::Timeout,
            shared::ipc::pb::PamOutcome::Ignore,
        ] {
            assert_eq!(
                map_pam_outcome(&resp_for(outcome, "detail"), "testuser", &conv, &msgs),
                pam_sys::PAM_AUTHINFO_UNAVAIL,
                "{outcome:?} must report the service as unavailable"
            );
        }

        // The daemon answered but could not process the attempt.
        assert_eq!(
            map_pam_outcome(
                &resp_for(shared::ipc::pb::PamOutcome::Error, "boom"),
                "testuser",
                &conv,
                &msgs
            ),
            pam_sys::PAM_AUTH_ERR
        );
    }

    /// The `outcome` field is a raw `i32` on the wire, so a peer can put any
    /// value in it. Unknown values must fail closed (`Error` → `PAM_AUTH_ERR`)
    /// rather than decode to `PamOutcome::default()` = `SUCCESS`.
    #[test]
    fn test_unknown_outcome_raw_values_fail_closed() {
        use shared::ipc::pb::PamOutcome;

        for raw in [-1, 5, 99, 255, i32::MAX, i32::MIN] {
            assert_eq!(
                outcome_from_raw(raw),
                PamOutcome::Error,
                "raw outcome {raw} must fail closed instead of {:?}",
                outcome_from_raw(raw)
            );
        }

        // Known values keep exactly today's mapping.
        for (raw, expected) in [
            (0, PamOutcome::Success),
            (1, PamOutcome::Denied),
            (2, PamOutcome::Timeout),
            (3, PamOutcome::Ignore),
            (4, PamOutcome::Error),
        ] {
            assert_eq!(
                outcome_from_raw(raw),
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

            let code = map_pam_outcome(&resp, "testuser", &conv, &msgs);
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
        // the `match` in `map_pam_outcome` is exhaustive but this array is not,
        // so extend this list by hand when adding a variant.
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
            let code = map_pam_outcome(&resp, "testuser", &conv, &msgs);
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
    fn stripped_source(source: &str) -> String {
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

    /// Every occurrence of `PAM_IGNORE` used as an identifier, as
    /// `(line, source line)`.
    #[allow(clippy::indexing_slicing)]
    fn pam_ignore_identifiers(cleaned: &str) -> Vec<(usize, String)> {
        const NEEDLE: &str = "PAM_IGNORE";
        let b = cleaned.as_bytes();
        let mut hits = Vec::new();
        let mut from = 0usize;
        while let Some(offset) = cleaned[from..].find(NEEDLE) {
            let start = from + offset;
            let end = start + NEEDLE.len();
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
    use std::os::fd::AsRawFd;
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
        let msgs = pam_messages::load_for_user("testuser");

        let deadline = Instant::now() - Duration::from_secs(1);
        let mut auth_response = None;
        let mut pending_error = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &msgs,
            &mut auth_response,
            &mut pending_error,
        );

        assert_eq!(reason, ExitReason::Timeout);
        assert!(auth_response.is_none());
        assert!(pending_error.is_none());

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
        let msgs = pam_messages::load_for_user("testuser");

        ctx.password_entered.store(true, Ordering::Release);
        let dummy = [1u8];
        unsafe {
            libc::write(pipe_write, dummy.as_ptr() as *const _, 1);
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending_error = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &msgs,
            &mut auth_response,
            &mut pending_error,
        );

        assert_eq!(reason, ExitReason::PasswordEntered);
        assert!(auth_response.is_none());
        assert!(pending_error.is_none());

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
        let msgs = pam_messages::load_for_user("testuser");

        ctx.password_entered.store(false, Ordering::Release);
        let dummy = [1u8];
        unsafe {
            libc::write(pipe_write, dummy.as_ptr() as *const _, 1);
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending_error = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &msgs,
            &mut auth_response,
            &mut pending_error,
        );

        assert_eq!(reason, ExitReason::PasswordFailed);
        assert!(auth_response.is_none());
        assert!(pending_error.is_none());

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
        let msgs = pam_messages::load_for_user("testuser");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending_error = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &msgs,
            &mut auth_response,
            &mut pending_error,
        );

        assert_eq!(reason, ExitReason::IpcResponseReceived);
        assert_eq!(
            auth_response.unwrap().outcome(),
            shared::ipc::pb::PamOutcome::Success
        );
        assert!(pending_error.is_none());

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
        let msgs = pam_messages::load_for_user("testuser");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut auth_response = None;
        let mut pending_error = None;

        let reason = run_gui_event_loop(
            &mut mock_ipc,
            pipe_read,
            deadline,
            &ctx,
            "req-123",
            &msgs,
            &mut auth_response,
            &mut pending_error,
        );

        assert_eq!(reason, ExitReason::IpcError);
        assert!(auth_response.is_none());
        assert_eq!(pending_error, Some(msgs.connection_lost()));

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
            .rfind("run_sequential_event_loop(&mut ipc")
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
                is_dm_service(service),
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
                !is_dm_service(service),
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
