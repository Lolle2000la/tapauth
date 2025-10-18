use crate::auth_client::AuthenticationClient;
use pam::{constants::{PamFlag, PamResultCode}, module::PamHandle};
use std::ffi::CStr;
use tracing_subscriber;

/// Initialize logging for PAM module
fn init_logging() {
    // Try to initialize logging, but don't fail if it's already initialized
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Main authentication logic for PAM
pub fn authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    init_logging();

    // Get the username
    let username = match pamh.get_user(None) {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to get username: {:?}", e);
            return PamResultCode::PAM_USER_UNKNOWN;
        }
    };

    tracing::info!("TapAuth: Authenticating user: {}", username);

    // Check if we're running as root
    if !shared::config::is_root() {
        tracing::error!("PAM module must be run as root");
        return PamResultCode::PAM_PERM_DENIED;
    }

    // Create authentication client
    let client = match AuthenticationClient::new(username.to_string()) {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to create authentication client: {}", e);
            return match e {
                crate::auth_client::AuthError::NoPairedDevices => {
                    tracing::warn!("No paired devices found. Use tapauth-config to pair a device.");
                    PamResultCode::PAM_AUTH_ERR
                }
                _ => PamResultCode::PAM_AUTH_ERR,
            };
        }
    };

    // Run the authentication flow
    // We need to use tokio runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("Failed to create tokio runtime: {}", e);
            return PamResultCode::PAM_AUTH_ERR;
        }
    };

    match runtime.block_on(client.authenticate()) {
        Ok(()) => {
            tracing::info!("Authentication successful for user: {}", username);
            PamResultCode::PAM_SUCCESS
        }
        Err(e) => {
            tracing::error!("Authentication failed for user {}: {}", username, e);
            match e {
                crate::auth_client::AuthError::Timeout => PamResultCode::PAM_AUTH_ERR,
                crate::auth_client::AuthError::Denied => PamResultCode::PAM_AUTH_ERR,
                _ => PamResultCode::PAM_AUTH_ERR,
            }
        }
    }
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
