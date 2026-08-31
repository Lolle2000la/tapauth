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
pub use ble::BleTransport;

use crate::auth_handler::AuthHandlerError as AuthError;
use shared::protocol::pb::EncryptedPacket;
use std::future::Future;
use std::time::Duration;

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
    ///
    /// # Returns
    /// * `ReceiveResult::Response` with packet and address if response received
    /// * `ReceiveResult::Timeout` if no response within timeout
    /// * `Err` on error
    fn receive_response(
        &self,
        timeout: Duration,
    ) -> impl Future<Output = Result<ReceiveResult, AuthError>> + Send;

    /// Send a confirmation packet (GrantConfirmation)
    ///
    /// # Arguments
    /// * `packet` - The encrypted confirmation packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    fn send_confirmation(
        &self,
        packet: &EncryptedPacket,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;

    /// Send a cancel packet (AuthenticationCancel)
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
