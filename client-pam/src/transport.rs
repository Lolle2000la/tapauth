// Suppress async_fn_in_trait warning since this trait is only used internally
// and we don't need to specify Send bounds explicitly
#![allow(async_fn_in_trait)]

/// Transport abstraction for authentication protocol
///
/// This module provides a trait-based abstraction for different transport mechanisms
/// (UDP broadcast/multicast, BLE via daemon, etc.) to enable code reuse, testability,
/// and easy extension with new transport types.
use enum_dispatch::enum_dispatch;
use shared::protocol::pb::EncryptedPacket;
use std::net::SocketAddr;
use std::time::Duration;

use crate::AuthError;

/// Result of attempting to receive an authentication response
#[derive(Debug)]
pub enum ReceiveResult {
    /// Successfully received a response packet from the given address
    Response(EncryptedPacket, SocketAddr),
    /// No response received within the timeout
    Timeout,
}

/// Trait for authentication transport mechanisms
///
/// Implementors provide methods to send authentication requests, receive responses,
/// send confirmations, and cancel ongoing operations.
#[enum_dispatch]
pub trait Transport {
    /// Send an authentication request packet
    ///
    /// # Arguments
    /// * `packet` - The encrypted authentication request packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_request(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Try to receive a response packet with timeout
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a response
    ///
    /// # Returns
    /// * `ReceiveResult::Response` with packet and address if response received
    /// * `ReceiveResult::Timeout` if no response within timeout
    /// * `Err` on error
    async fn receive_response(&mut self, timeout: Duration) -> Result<ReceiveResult, AuthError>;

    /// Send a confirmation packet (GrantConfirmation)
    ///
    /// # Arguments
    /// * `packet` - The encrypted confirmation packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_confirmation(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Send a cancel packet (AuthenticationCancel)
    ///
    /// # Arguments
    /// * `packet` - The encrypted cancel packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_cancel(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Get a human-readable name for this transport (for logging)
    fn name(&self) -> &'static str;
}

/// Transport enum using enum_dispatch for zero-cost abstraction
#[enum_dispatch(Transport)]
pub enum AuthTransport {
    Udp(UdpTransport),
    #[cfg(feature = "ble")]
    Ble(BleTransport),
}

/// UDP transport using broadcast (IPv4) and multicast (IPv6)
pub struct UdpTransport {
    socket: tokio::net::UdpSocket,
    port: u16,
}

impl UdpTransport {
    /// Create a new UDP transport
    ///
    /// # Arguments
    /// * `port` - The UDP port to bind and send to
    pub async fn new(port: u16) -> Result<Self, AuthError> {
        let socket = shared::network::create_broadcast_socket(port).await?;
        Ok(Self { socket, port })
    }
}

impl Transport for UdpTransport {
    async fn send_request(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use shared::network::{
            is_ipv6_available, send_udp_broadcast, send_udp_multicast_all_interfaces,
            IPV6_MULTICAST_ADDR,
        };

        // Send broadcast on IPv4
        if let Err(e) = send_udp_broadcast(&self.socket, self.port, packet).await {
            tracing::warn!("Failed to send IPv4 broadcast: {}", e);
        }

        // Send multicast on IPv6 (on all available interfaces)
        if is_ipv6_available() {
            match send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await {
                Ok(count) if count > 0 => {
                    tracing::trace!("Sent IPv6 multicast on {} interface(s)", count);
                }
                Ok(_) => {
                    tracing::debug!("No suitable IPv6 interfaces found for multicast");
                }
                Err(e) => {
                    tracing::warn!("Failed to send IPv6 multicast: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn receive_response(&mut self, timeout: Duration) -> Result<ReceiveResult, AuthError> {
        use shared::network::try_receive_udp_packet;

        match try_receive_udp_packet(&self.socket, timeout).await? {
            Some((packet, addr)) => {
                // Filter out local addresses (already done in receive_udp_packet)
                Ok(ReceiveResult::Response(packet, addr))
            }
            None => Ok(ReceiveResult::Timeout),
        }
    }

    async fn send_confirmation(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use shared::network::{
            is_ipv6_available, send_udp_broadcast, send_udp_multicast_all_interfaces,
            IPV6_MULTICAST_ADDR,
        };

        // Send on both IPv4 and IPv6
        send_udp_broadcast(&self.socket, self.port, packet).await?;
        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await;
        }

        Ok(())
    }

    async fn send_cancel(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use shared::network::{
            is_ipv6_available, send_udp_broadcast, send_udp_multicast_all_interfaces,
            IPV6_MULTICAST_ADDR,
        };

        // Send on both IPv4 and IPv6
        send_udp_broadcast(&self.socket, self.port, packet).await?;
        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "UDP"
    }
}

/// BLE transport using the BLE daemon via D-Bus
#[cfg(feature = "ble")]
pub struct BleTransport {
    client: crate::ble_client::BleClient,
    temporal_id: [u8; 10],
    timeout_secs: u64,
}

#[cfg(feature = "ble")]
impl BleTransport {
    /// Create a new BLE transport
    ///
    /// # Arguments
    /// * `temporal_id` - The 10-byte temporal identifier for BLE advertising
    /// * `timeout_secs` - Timeout for authentication in seconds
    pub async fn new(temporal_id: [u8; 10], timeout_secs: u64) -> Result<Self, AuthError> {
        let client = crate::ble_client::BleClient::new()
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to create BLE client: {}", e)))?;

        // Check if daemon is available
        if !client.is_daemon_available().await {
            return Err(AuthError::BleError(
                "BLE daemon is not available".to_string(),
            ));
        }

        Ok(Self {
            client,
            temporal_id,
            timeout_secs,
        })
    }
}

#[cfg(feature = "ble")]
impl Transport for BleTransport {
    async fn send_request(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use prost::Message;

        // Encode the packet
        let mut packet_bytes = Vec::new();
        packet
            .encode(&mut packet_bytes)
            .map_err(|e| AuthError::BleError(format!("Failed to encode packet: {}", e)))?;

        // Call the daemon to start advertising
        let result = self
            .client
            .authenticate(packet_bytes, self.temporal_id.to_vec(), self.timeout_secs)
            .await
            .map_err(|e| AuthError::BleError(format!("D-Bus call failed: {}", e)))?;

        // Convert daemon result to our result
        match result {
            shared::AuthResult::Granted => Ok(()),
            shared::AuthResult::Denied => Err(AuthError::Denied),
            shared::AuthResult::Timeout => Err(AuthError::Timeout),
            shared::AuthResult::Error => {
                Err(AuthError::BleError("Daemon returned error".to_string()))
            }
        }
    }

    async fn receive_response(&mut self, _timeout: Duration) -> Result<ReceiveResult, AuthError> {
        // BLE daemon handles the entire flow internally (send + receive)
        // This method should not be called for BLE transport
        Err(AuthError::BleError(
            "BLE daemon handles responses internally".to_string(),
        ))
    }

    async fn send_confirmation(&mut self, _packet: &EncryptedPacket) -> Result<(), AuthError> {
        // BLE daemon handles confirmations internally
        Ok(())
    }

    async fn send_cancel(&mut self, _packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Cancel the BLE authentication
        self.client
            .cancel()
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to cancel BLE authentication: {}", e)))
    }

    fn name(&self) -> &'static str {
        "BLE"
    }
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        tracing::debug!("UDP transport explicitly closed");
    }
}

#[cfg(feature = "ble")]
impl Drop for BleTransport {
    fn drop(&mut self) {
        tracing::debug!("BLE transport explicitly closed");
    }
}
