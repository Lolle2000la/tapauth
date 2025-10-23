#[cfg(feature = "dbus")]
use serde::{Deserialize, Serialize};
/// D-Bus interface for TapAuth BLE Daemon
///
/// This module defines the D-Bus API contract between the PAM module and the BLE daemon.
/// The daemon runs as a system service and handles BLE advertising and authentication,
/// while the PAM module communicates with it via synchronous D-Bus calls.

#[cfg(feature = "dbus")]
use zbus::zvariant::Type;

/// D-Bus service name for the BLE daemon
pub const DBUS_SERVICE_NAME: &str = "dev.rourunisen.tapauth.BLE";

/// D-Bus object path for the BLE service
pub const DBUS_OBJECT_PATH: &str = "/dev/rourunisen/tapauth/BLE";

/// Authentication result codes returned by the daemon
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication granted - credentials verified successfully
    Granted = 0,
    /// Authentication denied - credentials invalid or verification failed
    Denied = 1,
    /// Authentication timeout - no response received within timeout period
    Timeout = 2,
    /// Authentication error - internal error occurred during authentication
    Error = 3,
}

impl AuthResult {
    /// Convert from u32 to AuthResult
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => AuthResult::Granted,
            1 => AuthResult::Denied,
            2 => AuthResult::Timeout,
            _ => AuthResult::Error,
        }
    }

    /// Convert to u32
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

/// Authentication request sent from PAM module to daemon
#[cfg(feature = "dbus")]
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct AuthRequest {
    /// Encrypted authentication packet from the client
    pub encrypted_packet: Vec<u8>,
    /// Temporal ID for this authentication session
    pub temporal_id: Vec<u8>,
    /// Timeout in seconds for this authentication attempt
    pub timeout_secs: u64,
}

#[cfg(feature = "dbus")]
impl AuthRequest {
    pub fn new(encrypted_packet: Vec<u8>, temporal_id: Vec<u8>, timeout_secs: u64) -> Self {
        Self {
            encrypted_packet,
            temporal_id,
            timeout_secs,
        }
    }
}
