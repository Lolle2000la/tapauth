use crate::auth_client::AuthenticationClient;
use crate::pam_sys;
use once_cell::sync::Lazy;
use std::os::raw::c_int;
use tokio::runtime::Runtime;

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

    // Check if we're running as root
    if !shared::config::is_root() {
        tracing::error!("PAM module must be run as root");
        return pam_sys::PAM_PERM_DENIED;
    }

    // Create authentication client
    let client = match AuthenticationClient::new(username.to_string()) {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to create authentication client: {}", e);
            return match e {
                crate::auth_client::AuthError::NoPairedDevices => {
                    tracing::warn!("No paired devices found. Use tapauth-config to pair a device.");
                    pam_sys::PAM_AUTH_ERR
                }
                _ => pam_sys::PAM_AUTH_ERR,
            };
        }
    };

    // Run the authentication flow using the shared runtime
    match RUNTIME.block_on(client.authenticate()) {
        Ok(()) => {
            tracing::info!("Authentication successful for user: {}", username);
            pam_sys::PAM_SUCCESS
        }
        Err(e) => {
            tracing::error!("Authentication failed for user {}: {}", username, e);
            match e {
                crate::auth_client::AuthError::Timeout => pam_sys::PAM_AUTH_ERR,
                crate::auth_client::AuthError::Denied => pam_sys::PAM_AUTH_ERR,
                _ => pam_sys::PAM_AUTH_ERR,
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
