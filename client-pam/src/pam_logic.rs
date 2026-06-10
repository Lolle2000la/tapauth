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
use crate::pam_sys::{self, PAM_IGNORE};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// No async runtime: PAM modules should avoid multithreading. We use a single-threaded
// polling loop (poll/select) over the IPC socket and optional /dev/tty to detect skip.

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
    /// Write end of the self-pipe.  The worker writes a single byte here when
    /// a password is collected, so the main loop's poll set wakes instantly.
    pipe_write_fd: std::os::raw::c_int,
}

// Deeper FFI bindings declared with `extern "C-unwind"` so that glibc's
// forced unwind exceptions (`abi::__forced_unwind`) triggered by
// `pthread_cancel` can safely propagate through these call frames.
// `extern "C"` alone would imply `nounwind` and abort the process.
extern "C-unwind" {
    #[link_name = "pam_get_authtok"]
    fn pam_get_authtok_unwind(
        pamh: *mut pam_sys::PamHandle,
        item_type: std::os::raw::c_int,
        authtok: *mut *const std::os::raw::c_char,
        prompt: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;

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
        pam_get_authtok_unwind(
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
                return pam_sys::PAM_IGNORE;
            }
        }
    };

    // No explicit root check here; shared config enforces file ownership/permissions.

    let msgs = pam_messages::load_for_user(&username);

    // Block terminal polling if running under the Polkit Graphical Helper.
    // This prevents the PAM module from stealing stdin strings from checking
    // hooks via /dev/tty inheritance, which causes polkit-agent-helper-1
    // to deadlock during graphical challenge-response dialogs.
    let service = unsafe { pam_sys::get_service_name(pamh) }.unwrap_or_default();
    let is_polkit = service == "polkit-1";
    let tty_file = if !is_polkit {
        std::fs::File::open("/dev/tty").ok()
    } else {
        None
    };
    let has_terminal = tty_file.is_some();

    if has_terminal {
        pam_conv.try_info(msgs.waiting_for_tap_skip());
    } else {
        pam_conv.try_info(msgs.waiting_for_tap());
    }

    // Generate a per-request id to correlate cancellation (shared by auth and skip branches)
    let mut rid_bytes = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut rid_bytes) {
        tracing::warn!("Failed to generate random request ID: {}, skipping...", e);
        return PAM_IGNORE;
    }
    let request_id = hex::encode(rid_bytes);
    // Use the configured PAM operation timeout for both the local poll deadline
    // and the daemon's authentication timeout, so they stay in sync.
    let timeout_secs = {
        let secs = config.pam_operation_timeout_secs;
        if secs > u64::from(u32::MAX) {
            u32::MAX
        } else {
            secs as u32
        }
    };

    // Establish nonblocking IPC connection and send authenticate request
    let mut ipc = match IpcClient::connect_nonblocking() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to connect to tapauthd: {}", e);
            pam_conv.try_error(msgs.cannot_connect());
            return pam_sys::PAM_IGNORE;
        }
    };
    if let Err(e) = ipc.send_authenticate_start(&username, has_terminal, timeout_secs, &request_id)
    {
        tracing::error!("Failed to send authenticate request: {}", e);
        pam_conv.try_error(msgs.communication_error());
        return pam_sys::PAM_IGNORE;
    }

    // GUI context (no TTY): offload blocking credential collection to a
    // native background thread so the Polkit graphical helper can process
    // window events, then multiplex loop events using a secure
    // close-on-exec self-pipe.
    if !has_terminal {
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
        let mut exit_reason = ExitReason::Timeout;

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }

            // nix 0.31 PollTimeout is capped at u16::MAX ms (~65.5s).
            // For timeouts beyond that we would need libc::poll directly.
            let remain_ms = (deadline - now).as_millis().min(u16::MAX as u128) as u16;
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

            match poll(&mut fds, remain_ms) {
                Ok(0) => continue,
                Ok(_) => {
                    // Check IPC first: if the daemon response arrives in the
                    // same poll wakeup as a self-pipe notification, we must
                    // not drop it by breaking on the pipe first.
                    if let Some(rev) = fds[0].revents() {
                        if rev.contains(PollFlags::POLLIN) {
                            match ipc.try_read_response_nonblocking() {
                                Ok(Some(resp)) => {
                                    auth_response = Some(resp);
                                    exit_reason = ExitReason::IpcResponseReceived;
                                    break;
                                }
                                Ok(None) => {
                                    if rev.contains(PollFlags::POLLHUP)
                                        || rev.contains(PollFlags::POLLERR)
                                    {
                                        tracing::error!(
                                            "Daemon closed connection before sending response"
                                        );
                                        pending_error = Some(msgs.connection_lost());
                                        exit_reason = ExitReason::IpcError;
                                        break;
                                    }
                                    continue;
                                }
                                Err(e) => {
                                    tracing::error!("IPC read failed: {e}");
                                    pending_error = Some(msgs.communication_error());
                                    exit_reason = ExitReason::IpcError;
                                    break;
                                }
                            }
                        } else if rev.contains(PollFlags::POLLHUP)
                            || rev.contains(PollFlags::POLLERR)
                        {
                            tracing::error!("Daemon closed connection or error detected");
                            pending_error = Some(msgs.connection_lost());
                            exit_reason = ExitReason::IpcError;
                            break;
                        }
                    }

                    // Self-pipe: worker finished (password collected or dialog dismissed)
                    if let Some(rev) = fds[1].revents() {
                        if rev.contains(PollFlags::POLLIN) {
                            if ctx.password_entered.load(Ordering::Acquire) {
                                tracing::info!("Password pipe signalled, exiting poll loop.");
                                if let Ok(mut c) = IpcClient::connect(Duration::from_millis(100)) {
                                    let _ = c.send_cancel("gui-password-skip", &request_id);
                                }
                                exit_reason = ExitReason::PasswordEntered;
                            } else {
                                tracing::info!(
                                    "Password dialog closed or failed, yielding to downstream PAM modules."
                                );
                                exit_reason = ExitReason::PasswordFailed;
                            }
                            break;
                        }
                    }
                }
                Err(e) => {
                    if e != nix::errno::Errno::EINTR {
                        tracing::warn!("poll error: {e}");
                    }
                }
            }
        }

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
        let remain_ms = (deadline - now).as_millis().min(u16::MAX as u128) as u16;
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

        match poll(fds_slice, remain_ms) {
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

/// Yield `PAM_IGNORE` if the calling service is a primary display manager.
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
/// Returns `Some(PAM_IGNORE)` for display manager services, `None` otherwise.
fn guard_display_manager_bypass(pamh: *mut pam_sys::PamHandle) -> Option<c_int> {
    let service = unsafe { pam_sys::get_service_name(pamh) }?;
    tracing::debug!("Calling PAM service name: {}", service);

    let service_lower = service.to_ascii_lowercase();
    let dm_prefixes = [
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
    if dm_prefixes.iter().any(|p| {
        service_lower == *p
            || (service_lower.starts_with(p)
                && service_lower.as_bytes().get(p.len()) == Some(&b'-'))
    }) {
        tracing::info!(
            "TapAuth: Service '{}' is a primary display manager. \
             Skipping to avoid breaking keyring auto-unlock.",
            service
        );
        return Some(pam_sys::PAM_IGNORE);
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
            pam_sys::PAM_IGNORE
        }
        shared::ipc::pb::PamOutcome::Ignore => {
            tracing::info!("Daemon indicated IGNORE for user: {}", username);
            pam_sys::PAM_IGNORE
        }
        shared::ipc::pb::PamOutcome::Error => {
            tracing::error!(
                "Daemon reported error for user {}: {}",
                username,
                resp.detail
            );
            pam_conv.try_error(&msgs.error(&resp.detail));
            pam_sys::PAM_IGNORE
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::logging;

    #[test]
    fn test_logging_init() {
        logging::init_logging();
        logging::init_logging();
    }
}
