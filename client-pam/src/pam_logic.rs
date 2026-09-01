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
//! 5. Return `PAM_SUCCESS` on authentication, `PAM_IGNORE` to allow fallback to password
//!
//! ## Threading
//!
//! Uses a shared async runtime to avoid the ~100ms overhead of creating a new
//! runtime per authentication attempt. A separate thread monitors `/dev/tty`
//! for skip signals in terminal contexts.

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
// socket and /dev/tty.  The GUI flow (no TTY) comes in two variants:
//
// * `polkit-1` (polkit-agent-helper-1): the conversation is a plain blocking
//   socket fd fed by the *separate* agent process, so it can safely be driven
//   from a background thread.  A native POSIX thread collects the password
//   while the main thread waits for the phone, and the main loop multiplexes
//   the IPC socket and a self-pipe (`run_gui_event_loop`).
//
// * All other TTY-less hosts (notably KDE's `kscreenlocker_worker`): the
//   conversation is a synchronous round-trip that must be dispatched by the
//   host's own event loop on the thread that called `pam_authenticate`.
//   Blocking that thread (or driving the conversation from a second thread)
//   deadlocks the host, so the main thread simply waits for the daemon on its
//   own and never touches the conversation (`run_sequential_event_loop`).
//
// The native password thread used by the polkit variant uses no Drop-bearing
// Rust types so that pthread_cancel is safe.

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

// `write` is declared `extern "C-unwind"` so that glibc's forced unwind
// exceptions (`abi::__forced_unwind`) triggered by `pthread_cancel` can
// safely propagate through this call frame.  `extern "C"` alone would
// imply `nounwind` and abort the process.
// `pam_get_authtok` is generated with the correct ABI by bindgen's
// `.override_abi(bindgen::Abi::CUnwind, ...)` in build.rs.
extern "C-unwind" {
    #[link_name = "write"]
    fn write_unwind(
        fd: std::os::raw::c_int,
        buf: *const std::os::raw::c_void,
        count: usize,
    ) -> isize;
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
    let dummy: [u8; 1] = [1];
    loop {
        let written = unsafe {
            write_unwind(
                ctx.pipe_write_fd,
                dummy.as_ptr() as *const std::os::raw::c_void,
                1,
            )
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
/// Some graphical PAM hosts — most importantly KDE's lock screen, which runs
/// the PAM stack inside `kscreenlocker_worker` — implement the conversation as
/// a synchronous D-Bus round-trip that can only be answered by the event loop
/// running on the very thread that called `pam_authenticate`.  For those
/// hosts:
///
/// 1. collecting the password from a background thread deadlocks: the
///    conversation reply is queued for the blocked host event loop and can
///    never be dispatched, so password entry stops working entirely, and
/// 2. `pthread_cancel`-ing that background thread (as the polkit flow does)
///    would force-unwind through the host's non-Rust frames, which can
///    `abort()` the host process and take the lock screen down with it.
///
/// The safe pattern is to leave the conversation completely alone: block on
/// the daemon IPC socket on the calling thread, return the result, and let
/// the PAM stack fall through to the password module afterwards (whose own
/// conversation then runs on the host's terms).  The cost is that password
/// entry is only possible *after* the (shorter) GUI timeout, which is why
/// `pam_gui_timeout_secs` exists.
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
/// - `PAM_IGNORE`: No paired devices, skipped, or timed out (allows password fallback)
/// - `PAM_PERM_DENIED`: Not running as root
/// - `PAM_USER_UNKNOWN`: Failed to retrieve username from PAM
pub fn authenticate(pamh: *mut pam_sys::PamHandle) -> c_int {
    logging::init_logging();

    tracing::info!("TapAuth PAM module called (custom bindings)");

    let service = unsafe { pam_sys::get_service_name(pamh) }.unwrap_or_default();
    let is_polkit = service == "polkit-1";
    let tty_file = if !is_polkit {
        std::fs::File::open("/dev/tty").ok()
    } else {
        None
    };
    let has_terminal = tty_file.is_some();
    let pam_context = classify_pam_context(&service, has_terminal);

    if pam_context == PamContext::DisplayManagerBypass {
        tracing::info!(
            "TapAuth: Service '{}' is a primary display manager. \
             Skipping to avoid breaking keyring auto-unlock.",
            service
        );
        return pam_sys::PAM_IGNORE;
    }

    // Load configuration for timeouts
    let config = crate::config::PamConfig::load();
    tracing::debug!(
        "PAM operation timeout: {}s (context: {:?})",
        config.pam_operation_timeout_secs,
        pam_context
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
                return unavail_or_ignore(pam_context);
            }
        }
    };

    // No explicit root check here; shared config enforces file ownership/permissions.

    let msgs = pam_messages::load_for_user(&username);

    // Only hosts whose conversation is a plain blocking fd fed by a separate
    // process (polkit-agent-helper-1) can safely run the conversation from a
    // background thread while this thread waits for the daemon.  Event-loop
    // based hosts (e.g. kscreenlocker_worker) deadlock instead — see
    // `run_sequential_event_loop`.
    let supports_threaded_conversation = pam_context == PamContext::PolkitThreaded;

    if has_terminal {
        pam_conv.try_info(msgs.waiting_for_tap_skip());
    } else {
        pam_conv.try_info(msgs.waiting_for_tap());
    }

    // Generate a per-request id to correlate cancellation (shared by auth and skip branches)
    let mut rid_bytes = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut rid_bytes) {
        tracing::warn!("Failed to generate random request ID: {}, skipping...", e);
        return unavail_or_ignore(pam_context);
    }
    let request_id = hex::encode(rid_bytes);

    // Use the configured PAM operation timeout for both the local poll deadline
    // and the daemon's authentication timeout, so they stay in sync.
    // In DualStackSecondary mode, we use full operation timeout since the primary
    // worker's password box is completely free and interactive.
    // GUI contexts without a usable conversation (GuiSequential) get the shorter
    // GUI deadline so password fallback remains close at hand.
    let effective_timeout_secs = match pam_context {
        PamContext::DualStackSecondary | PamContext::PolkitThreaded | PamContext::Terminal => {
            config.pam_operation_timeout_secs
        }
        PamContext::GuiSequential => config
            .pam_gui_timeout_secs
            .min(config.pam_operation_timeout_secs),
        PamContext::DisplayManagerBypass => 0,
    };
    let timeout_secs = {
        let secs = effective_timeout_secs;
        if secs > u64::from(u32::MAX) {
            u32::MAX
        } else {
            secs as u32
        }
    };
    tracing::debug!(
        "Authentication deadline: {}s (context: {:?})",
        timeout_secs,
        pam_context
    );

    // Establish nonblocking IPC connection and send authenticate request
    let mut ipc = match IpcClient::connect_nonblocking() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to connect to tapauthd: {}", e);
            pam_conv.try_error(msgs.cannot_connect());
            return unavail_or_ignore(pam_context);
        }
    };
    if let Err(e) =
        ipc.send_authenticate_start(&username, has_terminal, timeout_secs, &request_id, &service)
    {
        tracing::error!("Failed to send authenticate request: {}", e);
        pam_conv.try_error(msgs.communication_error());
        return unavail_or_ignore(pam_context);
    }

    // GUI contexts without a usable conversation (e.g. DualStackSecondary or GuiSequential):
    // wait for the daemon on this thread and never touch the conversation.
    // Password fallback happens after this returns, when the next PAM module runs its own conversation.
    if !has_terminal && !supports_threaded_conversation {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);
        let (exit_reason, auth_response) = run_sequential_event_loop(&mut ipc, deadline);

        return match exit_reason {
            ExitReason::IpcResponseReceived => match auth_response {
                Some(resp) => map_pam_outcome(&resp, &username, &pam_conv, &msgs, pam_context),
                None => unavail_or_ignore(pam_context),
            },
            ExitReason::Timeout => {
                // The daemon runs on the same deadline and broadcasts its own
                // AuthenticationCancel, so no client-side cancel is needed.
                pam_conv.try_info(msgs.timed_out());
                if pam_context == PamContext::DualStackSecondary {
                    pam_sys::PAM_AUTHINFO_UNAVAIL
                } else {
                    pam_sys::PAM_IGNORE
                }
            }
            _ => {
                // IPC error: the request may still be in flight daemon-side.
                // Best-effort cancel uses a new blocking connection with a
                // short timeout so the phone doesn't keep buzzing.
                if let Ok(mut c) = IpcClient::connect(Duration::from_millis(100)) {
                    let _ = c.send_cancel("gui-ipc-error", &request_id);
                }
                pam_conv.try_error(msgs.communication_error());
                unavail_or_ignore(pam_context)
            }
        };
    }

    // GUI context with a threaded-conversation-capable host (polkit-1 only):
    // offload blocking credential collection to a native background thread so
    // the Polkit graphical helper can process window events, then multiplex
    // loop events using a secure close-on-exec self-pipe.
    if !has_terminal && supports_threaded_conversation {
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
            return pam_sys::PAM_IGNORE;
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
            return pam_sys::PAM_IGNORE;
        }

        let pthread_id = unsafe { pthread_id.assume_init() };
        let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);

        let mut final_outcome = pam_sys::PAM_IGNORE;
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

        // Cancel the worker if it hasn't already exited on its own.
        //
        // NOTE: pthread_cancel carries a theoretical risk of deadlocking the
        // parent process if the cancellation signal arrives while the worker
        // holds an internal libc lock (e.g. inside a malloc arena entered by
        // pam_get_authtok).  This is an accepted architectural trade-off;
        // fully isolating the conversation pipe would require a separate
        // helper process, as Howdy does with its Python subprocess.
        if exit_reason != ExitReason::PasswordEntered && exit_reason != ExitReason::PasswordFailed {
            unsafe {
                let cancel_res = libc::pthread_cancel(pthread_id);
                // ESRCH is benign: the thread already exited naturally during
                // a race between password entry and the phone tap response.
                if cancel_res != 0 && cancel_res != libc::ESRCH {
                    let err = std::io::Error::from_raw_os_error(cancel_res);
                    tracing::error!("pthread_cancel failed: {err}; worker may not have terminated");
                }
            }
        }

        // SAFETY: if pthread_join fails the worker thread may still be
        // running with a dangling &ctx reference into our stack frame.
        // Aborting is the only safe response.
        unsafe {
            let join_res = libc::pthread_join(pthread_id, std::ptr::null_mut());
            if join_res != 0 {
                let err = std::io::Error::from_raw_os_error(join_res);
                tracing::error!("pthread_join failed: {err}. Aborting to defend stack safety.");
                std::process::abort();
            }
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
            final_outcome = map_pam_outcome(&resp, &username, &pam_conv, &msgs, pam_context);
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
        return pam_sys::PAM_IGNORE;
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
                                return map_pam_outcome(
                                    &resp,
                                    &username,
                                    &pam_conv,
                                    &msgs,
                                    pam_context,
                                )
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
                                    return pam_sys::PAM_IGNORE;
                                }
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {}", e);
                                pam_conv.try_info(msgs.communication_error());
                                return pam_sys::PAM_IGNORE;
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        // Hangup/error without any data available
                        tracing::error!("Daemon closed connection or error detected");
                        pam_conv.try_info(msgs.connection_lost());
                        return pam_sys::PAM_IGNORE;
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
                                        return pam_sys::PAM_IGNORE;
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
    pam_sys::PAM_IGNORE
}

/// Execution mode determined from the calling PAM service name and environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamContext {
    /// Polkit authentication agent helper (`polkit-1`).
    /// Uses a threaded self-pipe to collect passwords in parallel with TapAuth.
    PolkitThreaded,
    /// Terminal / TTY: interactive conversation is safe and direct.
    Terminal,
    /// Dual-stack secondary biometric service (e.g. `kde-fingerprint`, `gdm-fingerprint`, `sddm-fingerprint`).
    /// Runs concurrently alongside password worker. Uses full `pam_operation_timeout_secs`
    /// without touching the conversation.
    DualStackSecondary,
    /// Primary display manager login (e.g. `sddm`, `gdm`, `gdm-password`, `lightdm`, `plasmalogin`).
    /// Bypasses TapAuth to preserve keyring/kwallet auto-unlock via password.
    DisplayManagerBypass,
    /// Standalone / single-stack GUI context (e.g. legacy `kscreenlocker`).
    /// Uses shorter `pam_gui_timeout_secs` sequential wait before falling through to password.
    GuiSequential,
}

/// Classify the PAM service context.
///
/// Priority order:
/// 1. Polkit agent (`polkit-1`).
/// 2. Secondary biometric stacks (`kde-fingerprint`, `gdm-fingerprint`, `sddm-fingerprint`, etc.).
/// 3. Primary display manager logins (e.g. `sddm`, `gdm`, `gdm-password`, `plasmalogin`).
/// 4. Interactive terminal (`/dev/tty` available).
/// 5. Standalone GUI sequential fallback.
pub fn classify_pam_context(service: &str, has_terminal: bool) -> PamContext {
    let service_lower = service.to_ascii_lowercase();

    // 1. Polkit Agent
    if service_lower == "polkit-1" {
        return PamContext::PolkitThreaded;
    }

    // 2. Dual-Stack Secondary Biometric Services (Lockscreen workers)
    const DUAL_STACK_SECONDARY: &[&str] = &[
        "kde-fingerprint",
        "kde-smartcard",
        "kde-face",
        "kde-u2f",
        "gdm-fingerprint",
        "gdm-smartcard",
        "sddm-fingerprint",
    ];
    if DUAL_STACK_SECONDARY.iter().any(|s| service_lower == *s) {
        return PamContext::DualStackSecondary;
    }

    // 3. Primary Display Manager Logins (Exact matches & primary prefixes)
    // Note: gdm-password is intentionally included here so the password worker is 100% responsive
    const DM_SERVICES: &[&str] = &[
        "sddm",
        "gdm",
        "gdm-password",
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
    let is_dm = DM_SERVICES.iter().any(|p| {
        service_lower == *p
            || (service_lower.starts_with(p)
                && service_lower.as_bytes().get(p.len()) == Some(&b'-'))
    });
    if is_dm {
        return PamContext::DisplayManagerBypass;
    }

    // 4. Interactive Terminal
    if has_terminal {
        return PamContext::Terminal;
    }

    // 5. Standalone / Single-Stack GUI
    PamContext::GuiSequential
}

/// Helper returning `PAM_AUTHINFO_UNAVAIL` in dual-stack secondary mode, or `PAM_IGNORE` otherwise.
fn unavail_or_ignore(context: PamContext) -> c_int {
    if context == PamContext::DualStackSecondary {
        pam_sys::PAM_AUTHINFO_UNAVAIL
    } else {
        pam_sys::PAM_IGNORE
    }
}

/// Map daemon IPC response outcome to the appropriate PAM return code based on context.
fn map_pam_outcome(
    resp: &shared::ipc::pb::PamAuthenticateResponse,
    username: &str,
    pam_conv: &pam_sys::PamConversation,
    msgs: &pam_messages::PamMessages,
    context: PamContext,
) -> c_int {
    match resp.outcome() {
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
            if context == PamContext::DualStackSecondary {
                pam_conv.try_info(msgs.timed_out());
                pam_sys::PAM_AUTHINFO_UNAVAIL
            } else {
                pam_sys::PAM_IGNORE
            }
        }
        shared::ipc::pb::PamOutcome::Ignore => {
            tracing::info!(
                "Daemon indicated IGNORE for user: {} (context: {:?})",
                username,
                context
            );
            if context == PamContext::DualStackSecondary {
                pam_sys::PAM_AUTHINFO_UNAVAIL
            } else {
                pam_sys::PAM_IGNORE
            }
        }
        shared::ipc::pb::PamOutcome::Error => {
            tracing::error!(
                "Daemon reported error for user {}: {}",
                username,
                resp.detail
            );
            pam_conv.try_error(&msgs.error(&resp.detail));
            if context == PamContext::DualStackSecondary {
                pam_sys::PAM_AUTHINFO_UNAVAIL
            } else {
                pam_sys::PAM_IGNORE
            }
        }
    }
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
    fn test_classify_pam_context() {
        // Dual-stack secondary
        assert_eq!(
            classify_pam_context("kde-fingerprint", false),
            PamContext::DualStackSecondary
        );
        assert_eq!(
            classify_pam_context("gdm-fingerprint", false),
            PamContext::DualStackSecondary
        );
        assert_eq!(
            classify_pam_context("sddm-fingerprint", false),
            PamContext::DualStackSecondary
        );
        assert_eq!(
            classify_pam_context("KDE-FINGERPRINT", false),
            PamContext::DualStackSecondary
        );
        assert_eq!(
            classify_pam_context("kde-fingerprint", true),
            PamContext::DualStackSecondary
        );

        // Display managers
        assert_eq!(
            classify_pam_context("sddm", false),
            PamContext::DisplayManagerBypass
        );
        assert_eq!(
            classify_pam_context("sddm-autologin", false),
            PamContext::DisplayManagerBypass
        );
        assert_eq!(
            classify_pam_context("gdm", false),
            PamContext::DisplayManagerBypass
        );
        assert_eq!(
            classify_pam_context("gdm-password", false),
            PamContext::DisplayManagerBypass
        );
        assert_eq!(
            classify_pam_context("gdm3", false),
            PamContext::DisplayManagerBypass
        );
        assert_eq!(
            classify_pam_context("lightdm", false),
            PamContext::DisplayManagerBypass
        );
        assert_eq!(
            classify_pam_context("plasmalogin", false),
            PamContext::DisplayManagerBypass
        );

        // Polkit
        assert_eq!(
            classify_pam_context("polkit-1", false),
            PamContext::PolkitThreaded
        );
        assert_eq!(
            classify_pam_context("polkit-1", true),
            PamContext::PolkitThreaded
        );

        // Terminal
        assert_eq!(classify_pam_context("sudo", true), PamContext::Terminal);
        assert_eq!(classify_pam_context("login", true), PamContext::Terminal);
        assert_eq!(classify_pam_context("su", true), PamContext::Terminal);

        // Sequential GUI (single-stack lockscreens)
        assert_eq!(
            classify_pam_context("kde", false),
            PamContext::GuiSequential
        );
        assert_eq!(
            classify_pam_context("swaylock", false),
            PamContext::GuiSequential
        );
        assert_eq!(
            classify_pam_context("hyprlock", false),
            PamContext::GuiSequential
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

    #[test]
    fn test_dual_stack_secondary_outcomes_are_decisive() {
        let conv = pam_sys::PamConversation::dummy();
        let msgs = pam_messages::PamMessages::new("en");
        let context = PamContext::DualStackSecondary;

        let success_resp = shared::ipc::pb::PamAuthenticateResponse {
            outcome: shared::ipc::pb::PamOutcome::Success as i32,
            detail: "Success".to_string(),
            challenge: vec![],
        };
        assert_eq!(
            map_pam_outcome(&success_resp, "testuser", &conv, &msgs, context),
            pam_sys::PAM_SUCCESS
        );

        let denied_resp = shared::ipc::pb::PamAuthenticateResponse {
            outcome: shared::ipc::pb::PamOutcome::Denied as i32,
            detail: "Denied".to_string(),
            challenge: vec![],
        };
        assert_eq!(
            map_pam_outcome(&denied_resp, "testuser", &conv, &msgs, context),
            pam_sys::PAM_PERM_DENIED
        );

        let timeout_resp = shared::ipc::pb::PamAuthenticateResponse {
            outcome: shared::ipc::pb::PamOutcome::Timeout as i32,
            detail: "Timeout".to_string(),
            challenge: vec![],
        };
        assert_eq!(
            map_pam_outcome(&timeout_resp, "testuser", &conv, &msgs, context),
            pam_sys::PAM_AUTHINFO_UNAVAIL
        );

        let ignore_resp = shared::ipc::pb::PamAuthenticateResponse {
            outcome: shared::ipc::pb::PamOutcome::Ignore as i32,
            detail: "Ignore".to_string(),
            challenge: vec![],
        };
        assert_eq!(
            map_pam_outcome(&ignore_resp, "testuser", &conv, &msgs, context),
            pam_sys::PAM_AUTHINFO_UNAVAIL
        );

        let error_resp = shared::ipc::pb::PamAuthenticateResponse {
            outcome: shared::ipc::pb::PamOutcome::Error as i32,
            detail: "Error".to_string(),
            challenge: vec![],
        };
        assert_eq!(
            map_pam_outcome(&error_resp, "testuser", &conv, &msgs, context),
            pam_sys::PAM_AUTHINFO_UNAVAIL
        );
    }
}
