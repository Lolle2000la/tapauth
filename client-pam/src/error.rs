//! PAM-specific error types and mapping to PAM return codes.

use std::os::raw::c_int;
use thiserror::Error;

/// Errors that can occur during PAM authentication.
#[derive(Error, Debug)]
pub enum PamError {
    /// User does not exist on this system
    #[error("user unknown")]
    UserUnknown,

    /// PAM conversation (user interaction) failed
    #[error("PAM conversation error: {0}")]
    Conversation(String),

    /// IPC connection to daemon timed out
    #[error("IPC connect timeout (daemon not available)")]
    IpcConnectTimeout,

    /// IPC I/O error
    #[error("IPC I/O error: {0}")]
    IpcIo(#[from] std::io::Error),

    /// Protobuf decode error from daemon
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),

    /// Daemon returned an error outcome
    #[error("daemon error: {0}")]
    DaemonError(String),

    /// User explicitly denied authentication on phone
    #[error("explicit denial by user")]
    ExplicitDenied,

    /// Operation timed out (PAM budget exhausted)
    #[error("timeout (PAM deadline exceeded)")]
    Timeout,

    /// Generic "ignore this PAM module" result
    #[error("ignore")]
    Ignore,

    /// Configuration error (file missing, invalid perms, parse error)
    #[error("config error: {0}")]
    ConfigError(String),
}

impl PamError {
    /// Convert PAM error to a PAM return code.
    ///
    /// Mapping:
    /// - `ExplicitDenied` → `PAM_PERM_DENIED`
    /// - `UserUnknown` → `PAM_USER_UNKNOWN`
    /// - `Timeout`, `Ipc*`, `DaemonError`, `ProtoDecode`, `Ignore` → `PAM_IGNORE`
    /// - `ConfigError` → `PAM_SYSTEM_ERR`
    pub fn to_pam_code(&self) -> c_int {
        use crate::pam_sys;
        match self {
            PamError::ExplicitDenied => pam_sys::PAM_PERM_DENIED,
            PamError::UserUnknown => pam_sys::PAM_USER_UNKNOWN,
            PamError::ConfigError(_) => pam_sys::PAM_SYSTEM_ERR,
            PamError::Conversation(_) => pam_sys::PAM_CONV_ERR,
            // All transient/daemon errors map to IGNORE to allow password fallback
            PamError::IpcConnectTimeout
            | PamError::IpcIo(_)
            | PamError::ProtoDecode(_)
            | PamError::DaemonError(_)
            | PamError::Timeout
            | PamError::Ignore => pam_sys::PAM_IGNORE,
        }
    }
}
