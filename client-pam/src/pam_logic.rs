use crate::auth_client::AuthenticationClient;
use crate::pam_sys;
use once_cell::sync::Lazy;
use std::os::raw::c_int;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

/// Shared Tokio runtime for all PAM authentication attempts
/// Creating a runtime is expensive (~100ms), so we reuse a single instance
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime for PAM module")
});

/// Initialize logging for PAM module
fn init_logging() {
    // Try to initialize logging, but don't fail if it's already initialized
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // Default to debug level for now to see BLE issues
                tracing_subscriber::EnvFilter::new("info")
            }),
        )
        .try_init();
}

/// Main authentication logic for PAM
pub fn authenticate(pamh: *mut pam_sys::PamHandle) -> c_int {
    init_logging();

    tracing::info!("TapAuth PAM module called (custom bindings)");

    // Get the username using our custom bindings
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

    // Create safe PAM conversation wrapper
    let pam_conv = unsafe {
        match pam_sys::PamConversation::new(pamh) {
            Ok(conv) => conv,
            Err(e) => {
                tracing::error!("Failed to get PAM conversation function: {}", e);
                // Continue without conversation - we can still authenticate
                // but won't be able to send messages to the user
                return pam_sys::PAM_IGNORE;
            }
        }
    };

    // Check if we're running as root
    if !shared::config::is_root() {
        tracing::error!("PAM module must be run as root");
        pam_conv.try_error("TapAuth: Permission denied (must run as root)");
        return pam_sys::PAM_PERM_DENIED;
    }

    // Create authentication client
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

            // Inform user via PAM conversation
            pam_conv.try_error(error_msg);

            // Return IGNORE to allow other auth methods to proceed
            return pam_sys::PAM_IGNORE;
        }
    };

    // Notify user that TapAuth is waiting for phone tap
    // Detect if we're in a terminal context or GUI context
    // We need to actually try to OPEN /dev/tty, not just check if it exists
    let has_terminal = std::fs::File::open("/dev/tty").is_ok();

    if has_terminal {
        pam_conv.try_info("TapAuth: Waiting for phone tap (press Enter to skip)...");
    } else {
        // GUI context (e.g., Polkit dialog) - no terminal available
        pam_conv.try_info("TapAuth: Waiting for phone tap...");
    }

    // Create a channel for skip signal from /dev/tty
    let (skip_tx, skip_rx) = oneshot::channel();

    // Create a channel to signal the stdin thread to stop
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();

    // Only spawn the skip detection thread if we have a terminal
    let skip_thread_handle = if has_terminal {
        // Spawn a thread to read from /dev/tty for skip signal
        // Using /dev/tty instead of stdin is important for PAM modules
        Some(std::thread::spawn(move || {
            use std::fs::File;
            use std::io::Read;

            // Try to open /dev/tty (the controlling terminal)
            let mut tty = match File::open("/dev/tty") {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!("Could not open /dev/tty: {}, skip unavailable", e);
                    return;
                }
            };

            // Read one byte at a time
            // We'll check the stop_rx channel periodically using try_recv
            let mut buffer = [0u8; 1024];
            loop {
                // Check if we should stop before attempting to read
                match stop_rx.try_recv() {
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        tracing::debug!("Skip reader thread received stop signal");
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        // Continue to read
                    }
                }

                // Read with a small buffer to detect any input
                // Note: This will block until input arrives, so we check stop signal first
                // The key is that File::read on /dev/tty will return quickly when data arrives
                match tty.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        // Got input - check if stop signal was sent while we were blocked
                        if stop_rx.try_recv().is_ok() {
                            tracing::debug!("Skip reader thread received stop signal (after read)");
                            break;
                        }
                        // User pressed a key
                        tracing::debug!("User pressed key to skip TapAuth");
                        let _ = skip_tx.send(());
                        break;
                    }
                    Ok(_) => {
                        // EOF or no data - shouldn't happen with /dev/tty
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(e) => {
                        tracing::debug!("Error reading from /dev/tty: {}", e);
                        break;
                    }
                }
            }
            tracing::debug!("Skip reader thread exiting");
        }))
    } else {
        tracing::info!("Running in GUI context (no /dev/tty), skip feature disabled");
        None
    };

    // Run the authentication flow with skip detection
    let auth_future = client.authenticate();

    let result = if has_terminal {
        // Terminal context - support skip detection
        let skip_future = async {
            skip_rx.await.ok();
        };

        RUNTIME.block_on(async {
            tokio::select! {
                auth_result = auth_future => {
                    match auth_result {
                        Ok(()) => {
                            tracing::info!("Authentication successful for user: {}", username);
                            Some(pam_sys::PAM_SUCCESS)
                        }
                        Err(e) => {
                            tracing::error!("Authentication failed: {}", e);
                            None
                        }
                    }
                }
                _ = skip_future => {
                    tracing::info!("User skipped TapAuth via Enter key");
                    // Send cancellation to dismiss server notifications
                    let _ = client.send_cancellation().await;
                    None
                }
            }
        })
    } else {
        // GUI context - no skip detection, just run authentication
        RUNTIME.block_on(async {
            match auth_future.await {
                Ok(()) => {
                    tracing::info!("Authentication successful for user: {}", username);
                    Some(pam_sys::PAM_SUCCESS)
                }
                Err(e) => {
                    tracing::error!("Authentication failed: {}", e);
                    None
                }
            }
        })
    };

    // Signal the skip reader thread to stop
    let _ = stop_tx.send(());

    // Only wait for the thread if authentication didn't succeed
    // If it succeeded, the thread is probably still blocked on read() and we don't want to wait
    if result.is_none() {
        // Authentication failed or was skipped - wait for thread to clean up
        if let Some(handle) = skip_thread_handle {
            // Give it a short time to exit gracefully
            let _ = handle.join();
        }
    } else {
        // Authentication succeeded - don't wait for the thread
        // It will exit when the user presses a key or the process ends
        if skip_thread_handle.is_some() {
            tracing::debug!("Authentication succeeded, not waiting for skip thread");
        }
    }

    // If authentication succeeded, return success
    if let Some(code) = result {
        pam_conv.try_info("TapAuth: Authentication successful!");
        return code;
    }

    // Authentication failed or was skipped - inform user and return IGNORE
    pam_conv.try_info("TapAuth: Skipped or timed out, trying password...");

    // Return IGNORE to let other authentication methods (like password) proceed
    pam_sys::PAM_IGNORE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_init() {
        // Should not panic
        init_logging();
        init_logging(); // Second call should be fine too
    }
}
