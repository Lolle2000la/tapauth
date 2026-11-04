//! PAM-specific error types.

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
