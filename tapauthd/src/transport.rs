// Suppress async_fn_in_trait warning since this trait is only used internally
// and we don't need to specify Send bounds explicitly
#![allow(async_fn_in_trait)]

//! Transport abstraction for authentication protocol
//!
//! This module has been reorganized into submodules for better maintainability.

mod types;
mod udp;

#[cfg(feature = "ble")]
mod ble;

// Re-export the Transport trait and implementations at module level
pub use types::ReceiveResult;
pub use udp::UdpTransport;

#[cfg(feature = "ble")]
pub use ble::{BleTransport, PairingBleSession, ServerVerifier};

use crate::auth_handler::AuthHandlerError as AuthError;
use shared::config::CskMetadata;
use shared::protocol::pb::EncryptedPacket;
use std::future::Future;
use std::time::Duration;

/// Pause between publishing a characteristic value and tearing the link down,
/// so BlueZ can put the notification on the air before the connection drops.
///
/// It lives here rather than in the BLE module because both users of it need to
/// agree on the value: the BLE transport's own send-then-teardown paths, and the
/// authentication handler's confirmation task, which releases a transport it
/// just notified. A transport whose send is already a completed syscall (UDP)
/// only pays a harmless 50 ms before its no-op teardown.
pub(crate) const NOTIFY_SETTLE: Duration = Duration::from_millis(50);

/// Trait for authentication transport mechanisms
///
/// Implementors provide methods to send authentication requests, receive responses,
/// send confirmations, and cancel ongoing operations.
pub trait Transport: Send + Sync {
    /// Send an authentication request packet
    ///
    /// # Arguments
    /// * `packet` - The encrypted authentication request packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    fn send_request(
        &self,
        packet: &EncryptedPacket,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;

    /// Try to receive a response packet with timeout
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a response
    /// * `csk_meta` - The CSK's algorithm metadata; a transport that decrypts
    ///   (BLE) must pin the packet's algorithm to
    ///   [`CskMetadata::symmetric_algorithm`](shared::config::CskMetadata::symmetric_algorithm)
    ///
    /// # Returns
    /// * `ReceiveResult::Response` with packet and address if response received
    /// * `ReceiveResult::Timeout` if no response within timeout
    /// * `Err` on error
    fn receive_response(
        &self,
        timeout: Duration,
        csk_meta: &CskMetadata,
    ) -> impl Future<Output = Result<ReceiveResult, AuthError>> + Send;

    /// Send a confirmation packet (GrantConfirmation)
    ///
    /// The confirmation goes only to the peer whose response won the race, not
    /// to every device on the link.
    ///
    /// # Arguments
    /// * `packet` - The encrypted confirmation packet
    /// * `csk_meta` - The CSK's algorithm metadata
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    fn send_confirmation(
        &self,
        packet: &EncryptedPacket,
        csk_meta: &CskMetadata,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;

    /// Send a cancel packet (AuthenticationCancel)
    ///
    /// Reaches every paired device (multicast / GATT notify) plus a copy to the
    /// peer whose response won the race, if one has answered.
    ///
    /// # Arguments
    /// * `packet` - The encrypted cancel packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    fn send_cancel(
        &self,
        packet: &EncryptedPacket,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;

    /// Finalize and tear down any transport-specific state
    ///
    /// Default is a no-op. Transports with long-lived connections (e.g., BLE)
    /// should override this to explicitly disconnect and release resources.
    fn finalize(&self) -> impl Future<Output = Result<(), AuthError>> + Send {
        async { Ok(()) }
    }
}
