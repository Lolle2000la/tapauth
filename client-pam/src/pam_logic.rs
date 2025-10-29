use crate::auth_client::AuthenticationClient;
use crate::pam_sys;
use once_cell::sync::Lazy;
use std::io::{self, BufRead};
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
    pam_conv.try_info("TapAuth: Waiting for phone tap (press Enter to skip)...");

    // Create a channel for skip signal from stdin
    let (skip_tx, skip_rx) = oneshot::channel();

    // Spawn a thread to read from stdin for skip signal
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut buffer = String::new();

        // Wait for any input (Enter key)
        if handle.read_line(&mut buffer).is_ok() {
            tracing::info!("User pressed Enter to skip TapAuth");
            let _ = skip_tx.send(());
        }
    });

    // Run the authentication flow with skip detection
    let auth_future = client.authenticate();
    let skip_future = async {
        skip_rx.await.ok();
    };

    let result = RUNTIME.block_on(async {
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
    });

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
