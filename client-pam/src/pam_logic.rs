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

use crate::auth_client::AuthenticationClient;
use crate::ipc_client::IpcClient;
use crate::pam_sys;
use once_cell::sync::Lazy;
use std::os::raw::c_int;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

/// Shared Tokio runtime for all PAM authentication attempts.
///
/// Creating a runtime is expensive (~100ms), so we reuse a single instance.
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime for PAM module")
});

/// Initialize logging for the PAM module.
fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
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
    init_logging();

    tracing::info!("TapAuth PAM module called (custom bindings)");

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

    let client = match AuthenticationClient::new(username.to_string()) {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to create authentication client: {}", e);
            let error_msg = match e {
                crate::auth_client::AuthError::NoPairedDevices => {
                    "No paired devices found. Use tapauth-config to pair a device."
                }
                _ => "Failed to initialize TapAuth",
            };

            pam_conv.try_error(error_msg);
            return pam_sys::PAM_IGNORE;
        }
    };

    let has_terminal = std::fs::File::open("/dev/tty").is_ok();

    if has_terminal {
        pam_conv.try_info("TapAuth: Waiting for phone tap (press Enter to skip)...");
    } else {
        pam_conv.try_info("TapAuth: Waiting for phone tap...");
    }

    let (skip_tx, skip_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();

    let skip_thread_handle = if has_terminal {
        Some(spawn_skip_reader(skip_tx, stop_rx))
    } else {
        tracing::info!("Running in GUI context (no /dev/tty), skip feature disabled");
        None
    };

    // Build an auth future that talks to tapauthd via IPC (thin client)
    let ipc_username = username.to_string();
    let ipc_auth_future = async move {
        let timeout_secs = {
            let dur = shared::network::get_session_timeout();
            let secs = dur.as_secs();
            if secs > u64::from(u32::MAX) { u32::MAX } else { secs as u32 }
        };
        let tty_flag = has_terminal;
        // Generate a per-request id to correlate cancellation
        let mut rid_bytes = [0u8; 16];
        getrandom::fill(&mut rid_bytes).ok();
        let request_id = hex::encode(rid_bytes);
        let rid_clone = request_id.clone();
        // Use spawn_blocking to avoid blocking the async runtime with UnixStream I/O
        match tokio::task::spawn_blocking(move || {
            let mut ipc = IpcClient::connect()?;
            ipc.send_authenticate(&ipc_username, tty_flag, timeout_secs, &request_id)
        }).await {
            Ok(Ok(resp)) => Ok((resp, rid_clone)),
            Ok(Err(e)) => Err(e),
            Err(join_err) => Err(crate::ipc_client::IpcError::Io(std::io::Error::other(format!(
                "IPC auth task failed: {}", join_err
            )))),
        }
    };

    let result = if has_terminal {
        let skip_future = async {
            skip_rx.await.ok();
        };

        RUNTIME.block_on(async {
            tokio::select! {
                auth_resp = ipc_auth_future => {
                    match auth_resp {
                        Ok((resp, _rid)) => {
                            // Map daemon outcome to PAM code
                            match resp.outcome() {
                                shared::ipc::pb::PamOutcome::Success => {
                                    tracing::info!("Authentication successful for user: {}", username);
                                    Some(pam_sys::PAM_SUCCESS)
                                }
                                other => {
                                    tracing::warn!("Daemon returned outcome {:?}: {}", other, resp.detail);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("IPC authentication failed: {}", e);
                            None
                        }
                    }
                }
                _ = skip_future => {
                    tracing::info!("User skipped TapAuth via Enter key");
                    
                    // Best-effort IPC cancel to daemon (so connected devices can dismiss notifications)
                    if let Ok(mut ipc) = IpcClient::connect() {
                        tracing::debug!("Sending IPC cancel to tapauthd");
                        // Reuse the same request_id if still available; otherwise send empty-id cancel
                        // Note: in this simplified flow, if the auth task already returned, cancel is a no-op
                        let rid = ""; // best effort: daemon will ignore empty/unknown IDs
                        let _ = ipc.send_cancel("tty-skip", rid);
                    } else {
                        tracing::debug!("Could not connect to tapauthd for IPC cancel (daemon may not be running)");
                    }
                    
                    // Also send network cancel for backward compatibility
                    let _ = client.send_cancellation().await;
                    None
                }
            }
        })
    } else {
        RUNTIME.block_on(async {
            match ipc_auth_future.await {
                Ok((resp, _rid)) => {
                    match resp.outcome() {
                        shared::ipc::pb::PamOutcome::Success => {
                            tracing::info!("Authentication successful for user: {}", username);
                            Some(pam_sys::PAM_SUCCESS)
                        }
                        other => {
                            tracing::warn!("Daemon returned outcome {:?}: {}", other, resp.detail);
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("IPC authentication failed: {}", e);
                    None
                }
            }
        })
    };

    let _ = stop_tx.send(());

    if result.is_none() {
        if let Some(handle) = skip_thread_handle {
            let _ = handle.join();
        }
    } else if skip_thread_handle.is_some() {
        tracing::debug!("Authentication succeeded, not waiting for skip thread");
    }

    if let Some(code) = result {
        pam_conv.try_info("TapAuth: Authentication successful!");
        return code;
    }

    pam_conv.try_info("TapAuth: Skipped or timed out, trying password...");
    pam_sys::PAM_IGNORE
}

/// Spawn a thread to monitor `/dev/tty` for skip signals.
///
/// Reads from the controlling terminal and signals via `skip_tx` when any key
/// is pressed. Uses `/dev/tty` instead of stdin to work correctly in PAM contexts
/// where stdin may not be connected to the terminal.
fn spawn_skip_reader(
    skip_tx: oneshot::Sender<()>,
    stop_rx: std::sync::mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::fs::File;
        use std::io::Read;

        let mut tty = match File::open("/dev/tty") {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("Could not open /dev/tty: {}, skip unavailable", e);
                return;
            }
        };

        let mut buffer = [0u8; 1024];
        loop {
            match stop_rx.try_recv() {
                Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    tracing::debug!("Skip reader thread received stop signal");
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }

            match tty.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    if stop_rx.try_recv().is_ok() {
                        tracing::debug!("Skip reader thread received stop signal (after read)");
                        break;
                    }
                    tracing::debug!("User pressed key to skip TapAuth");
                    let _ = skip_tx.send(());
                    break;
                }
                Ok(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    tracing::debug!("Error reading from /dev/tty: {}", e);
                    break;
                }
            }
        }
        tracing::debug!("Skip reader thread exiting");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_init() {
        init_logging();
        init_logging();
    }
}
