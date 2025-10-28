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

/// D-Bus interface for the BLE daemon
///
/// This trait defines both the client proxy (via #[zbus::proxy]) and can be
/// implemented by the server (via #[zbus::interface]). This ensures the client
/// and server always have matching method signatures.
///
/// # Client Usage
/// ```rust,ignore
/// use shared::BleServiceProxy;
///
/// let connection = zbus::Connection::system().await?;
/// let proxy = BleServiceProxy::new(&connection).await?;
/// let result = proxy.authenticate(packet, temporal_id, timeout).await?;
/// ```
///
/// # Server Implementation
/// The daemon implements this trait and uses `#[zbus::interface]` to expose it:
/// ```rust,ignore
/// #[zbus::interface(name = "dev.rourunisen.tapauth.BLE")]
/// impl BleService for MyService {
///     async fn authenticate(...) -> u32 { ... }
/// }
/// ```
#[cfg(feature = "dbus")]
#[zbus::proxy(
    interface = "dev.rourunisen.tapauth.BLE",
    default_service = "dev.rourunisen.tapauth.BLE",
    default_path = "/dev/rourunisen/tapauth/BLE"
)]
pub trait BleService {
    /// Start BLE authentication session
    ///
    /// # Arguments
    /// * `encrypted_packet` - Serialized EncryptedPacket containing auth request
    /// * `temporal_id` - 10-byte temporal identifier for advertising
    /// * `timeout_secs` - Maximum time to wait for authentication
    ///
    /// # Returns
    /// * `0` - Authentication granted
    /// * `1` - Authentication denied
    /// * `2` - Timeout
    /// * Other - Error code
    async fn authenticate(
        &self,
        encrypted_packet: Vec<u8>,
        temporal_id: Vec<u8>,
        timeout_secs: u64,
    ) -> zbus::Result<u32>;

    /// Get daemon status
    async fn get_status(&self) -> zbus::Result<String>;

    /// Get daemon version
    async fn get_version(&self) -> zbus::Result<String>;

    /// Cancel ongoing authentication
    /// This stops BLE advertising and returns immediately
    async fn cancel(&self) -> zbus::Result<()>;
}
