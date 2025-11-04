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
use crate::pam_sys::{self, PAM_IGNORE};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

// No async runtime: PAM modules should avoid multithreading. We use a single-threaded
// polling loop (poll/select) over the IPC socket and optional /dev/tty to detect skip.

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

    let has_terminal = std::fs::File::open("/dev/tty").is_ok();

    if has_terminal {
        pam_conv.try_info("TapAuth: Waiting for phone tap (press Enter to skip)...");
    } else {
        pam_conv.try_info("TapAuth: Waiting for phone tap...");
    }

    // Generate a per-request id to correlate cancellation (shared by auth and skip branches)
    let mut rid_bytes = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut rid_bytes) {
        tracing::warn!("Failed to generate random request ID: {}, skipping...", e);
        return PAM_IGNORE;
    }
    let request_id = hex::encode(rid_bytes);
    // Session timeout used for both daemon and local bound
    let timeout_secs = {
        let dur = shared::network::get_session_timeout();
        let secs = dur.as_secs();
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
            return pam_sys::PAM_IGNORE;
        }
    };
    if let Err(e) = ipc.send_authenticate_start(&username, has_terminal, timeout_secs, &request_id)
    {
        tracing::error!("Failed to send authenticate request: {}", e);
        return pam_sys::PAM_IGNORE;
    }

    // GUI (no TTY): poll only the socket until response or timeout
    if !has_terminal {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remain_ms_u16 = ((deadline - now).as_millis() as u128).min(u16::MAX as u128) as u16;
            let mut fds = [PollFd::new(
                unsafe { BorrowedFd::borrow_raw(ipc.fd()) },
                PollFlags::POLLIN,
            )];
            match poll(&mut fds, remain_ms_u16) {
                Ok(0) => continue,
                Ok(_) => {
                    if let Some(rev) = fds[0].revents() {
                        // Read data first if available (POLLIN can be set with POLLHUP)
                        if rev.contains(PollFlags::POLLIN) {
                            match ipc.try_read_response_nonblocking() {
                                Ok(Some(resp)) => {
                                    return map_pam_outcome(&resp, &username, &pam_conv)
                                }
                                Ok(None) => {
                                    // No complete frame yet, check for errors
                                    if rev.contains(PollFlags::POLLHUP)
                                        || rev.contains(PollFlags::POLLERR)
                                    {
                                        tracing::error!(
                                            "Daemon closed connection before sending response"
                                        );
                                        pam_conv.try_info(
                                            "TapAuth: Connection lost, trying password...",
                                        );
                                        return pam_sys::PAM_IGNORE;
                                    }
                                    continue;
                                }
                                Err(e) => {
                                    tracing::error!("IPC read failed: {}", e);
                                    pam_conv.try_info(
                                        "TapAuth: Communication error, trying password...",
                                    );
                                    return pam_sys::PAM_IGNORE;
                                }
                            }
                        } else if rev.contains(PollFlags::POLLHUP)
                            || rev.contains(PollFlags::POLLERR)
                        {
                            // Hangup/error without any data available
                            tracing::error!("Daemon closed connection or error detected");
                            pam_conv.try_info("TapAuth: Connection lost, trying password...");
                            return pam_sys::PAM_IGNORE;
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
        pam_conv.try_info("TapAuth: Timed out, trying password...");
        return pam_sys::PAM_IGNORE;
    }

    // Terminal: poll socket and /dev/tty; skip only on Enter
    let mut tty = match std::fs::File::open("/dev/tty") {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(
                "Could not open /dev/tty: {}, falling back to socket-only",
                e
            );
            let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let mut fds = [PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(ipc.fd()) },
                    PollFlags::POLLIN,
                )];
                let remain_ms_u16 =
                    ((deadline - now).as_millis() as u128).min(u16::MAX as u128) as u16;
                match poll(&mut fds, remain_ms_u16) {
                    Ok(0) => continue,
                    Ok(_) => {
                        if let Some(rev) = fds[0].revents() {
                            // Read data first if available (POLLIN can be set with POLLHUP)
                            if rev.contains(PollFlags::POLLIN) {
                                match ipc.try_read_response_nonblocking() {
                                    Ok(Some(resp)) => {
                                        return map_pam_outcome(&resp, &username, &pam_conv)
                                    }
                                    Ok(None) => {
                                        // No complete frame yet, check for errors
                                        if rev.contains(PollFlags::POLLHUP)
                                            || rev.contains(PollFlags::POLLERR)
                                        {
                                            tracing::error!(
                                                "Daemon closed connection before sending response"
                                            );
                                            pam_conv.try_info(
                                                "TapAuth: Connection lost, trying password...",
                                            );
                                            return pam_sys::PAM_IGNORE;
                                        }
                                        continue;
                                    }
                                    Err(e) => {
                                        tracing::error!("IPC read failed: {}", e);
                                        pam_conv.try_info(
                                            "TapAuth: Communication error, trying password...",
                                        );
                                        return pam_sys::PAM_IGNORE;
                                    }
                                }
                            } else if rev.contains(PollFlags::POLLHUP)
                                || rev.contains(PollFlags::POLLERR)
                            {
                                // Hangup/error without any data available
                                tracing::error!("Daemon closed connection or error detected");
                                pam_conv.try_info("TapAuth: Connection lost, trying password...");
                                return pam_sys::PAM_IGNORE;
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
            pam_conv.try_info("TapAuth: Timed out, trying password...");
            return pam_sys::PAM_IGNORE;
        }
    };

    // Set tty nonblocking to avoid read(1) blocking unexpectedly
    {
        let fd = tty.as_raw_fd();
        if let Ok(cur) = fcntl(fd, FcntlArg::F_GETFL) {
            let mut flags = OFlag::from_bits_truncate(cur);
            flags.insert(OFlag::O_NONBLOCK);
            let _ = fcntl(fd, FcntlArg::F_SETFL(flags));
        }
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);
    let mut kb = [0u8; 4];
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remain_ms_u16 = ((deadline - now).as_millis() as u128).min(u16::MAX as u128) as u16;
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
        match poll(&mut fds, remain_ms_u16) {
            Ok(0) => {}
            Ok(_) => {
                // IPC
                if let Some(rev) = fds[0].revents() {
                    // Read data first if available (POLLIN can be set with POLLHUP)
                    if rev.contains(PollFlags::POLLIN) {
                        match ipc.try_read_response_nonblocking() {
                            Ok(Some(resp)) => return map_pam_outcome(&resp, &username, &pam_conv),
                            Ok(None) => {
                                // No complete frame yet, check for errors
                                if rev.contains(PollFlags::POLLHUP)
                                    || rev.contains(PollFlags::POLLERR)
                                {
                                    tracing::error!(
                                        "Daemon closed connection before sending response"
                                    );
                                    pam_conv
                                        .try_info("TapAuth: Connection lost, trying password...");
                                    return pam_sys::PAM_IGNORE;
                                }
                            }
                            Err(e) => {
                                tracing::error!("IPC read failed: {}", e);
                                pam_conv
                                    .try_info("TapAuth: Communication error, trying password...");
                                return pam_sys::PAM_IGNORE;
                            }
                        }
                    } else if rev.contains(PollFlags::POLLHUP) || rev.contains(PollFlags::POLLERR) {
                        // Hangup/error without any data available
                        tracing::error!("Daemon closed connection or error detected");
                        pam_conv.try_info("TapAuth: Connection lost, trying password...");
                        return pam_sys::PAM_IGNORE;
                    }
                }
                // TTY - peek for Enter; don't consume other keys
                if let Some(rev) = fds[1].revents() {
                    if rev.contains(PollFlags::POLLIN) {
                        // Peek at the byte without consuming unless it's Enter
                        if let Ok(1) = tty.read(&mut kb[..1]) {
                            let b = kb[0];
                            if b == b'\n' || b == b'\r' {
                                tracing::info!("User pressed Enter to skip");
                                // Best-effort cancel uses a fresh blocking connection with configured timeout
                                if let Ok(mut c) = IpcClient::connect(config.operation_timeout()) {
                                    let _ = c.send_cancel("tty-skip", &request_id);
                                }
                                pam_conv.try_info("TapAuth: Skipped, trying password...");
                                return pam_sys::PAM_IGNORE;
                            }
                            // Non-Enter key: consume and ignore (could be user typing password early)
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

    pam_conv.try_info("TapAuth: Timed out, trying password...");
    pam_sys::PAM_IGNORE
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
) -> c_int {
    match resp.outcome() {
        shared::ipc::pb::PamOutcome::Success => {
            tracing::info!("Authentication successful for user: {}", username);
            pam_conv.try_info("TapAuth: Authentication successful!");
            pam_sys::PAM_SUCCESS
        }
        shared::ipc::pb::PamOutcome::Denied => {
            tracing::info!("Authentication explicitly denied for user: {}", username);
            pam_conv.try_info("TapAuth: Authentication denied by server");
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
