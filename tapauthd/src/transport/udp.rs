//! UDP transport using broadcast (IPv4) and multicast (IPv6)

use super::{ReceiveResult, Transport};
use crate::auth_handler::AuthHandlerError as AuthError;
use shared::protocol::pb::EncryptedPacket;
use std::time::Duration;

use std::sync::Arc;

/// UDP transport using broadcast (IPv4) and multicast (IPv6)
pub struct UdpTransport {
    socket: Arc<tokio::net::UdpSocket>,
    port: u16,
    owned: bool,
}

impl UdpTransport {
    /// Create a new UDP transport with its own socket
    ///
    /// # Arguments
    /// * `port` - The UDP port to bind and send to
    #[allow(dead_code)] // Used in tests
    pub async fn new(port: u16) -> Result<Self, AuthError> {
        let socket = shared::network::create_broadcast_socket(port).await?;
        Ok(Self {
            socket: Arc::new(socket),
            port,
            owned: true,
        })
    }

    /// Create a UDP transport from an existing shared socket
    ///
    /// # Arguments
    /// * `socket` - Shared reference to an existing UDP socket
    /// * `port` - The UDP port the socket is bound to
    pub fn from_socket(socket: Arc<tokio::net::UdpSocket>, port: u16) -> Self {
        Self {
            socket,
            port,
            owned: false,
        }
    }
}

impl Transport for UdpTransport {
    async fn send_request(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
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

    async fn receive_response(&self, timeout: Duration) -> Result<ReceiveResult, AuthError> {
        use shared::network::try_receive_udp_packet;

        match try_receive_udp_packet(&self.socket, timeout).await? {
            Some((packet, addr)) => {
                // Filter out local addresses (already done in receive_udp_packet)
                Ok(ReceiveResult::Response(packet, addr))
            }
            None => Ok(ReceiveResult::Timeout),
        }
    }

    async fn send_confirmation(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
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

    async fn send_cancel(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
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
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        if self.owned {
            tracing::debug!("UDP transport (owned) explicitly closed");
        }
        // Shared sockets are not closed here - they're managed by DaemonState
    }
}
