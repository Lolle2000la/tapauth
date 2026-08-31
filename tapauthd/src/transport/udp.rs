//! UDP transport using broadcast (IPv4) and multicast (IPv6)

use super::{ReceiveResult, Transport};
use crate::auth_handler::AuthHandlerError as AuthError;
use shared::network::{
    is_ipv6_available, send_udp_broadcast, send_udp_multicast_all_interfaces,
    try_receive_udp_packet, IPV6_MULTICAST_ADDR,
};
use shared::protocol::pb::EncryptedPacket;
use std::sync::Arc;
use std::time::Duration;

/// UDP transport using broadcast (IPv4) and multicast (IPv6)
///
/// Always wraps a socket owned by `DaemonState`; it never closes the socket
/// itself.
pub struct UdpTransport {
    socket: Arc<tokio::net::UdpSocket>,
    port: u16,
}

impl UdpTransport {
    /// Create a UDP transport from an existing shared socket
    ///
    /// # Arguments
    /// * `socket` - Shared reference to an existing UDP socket
    /// * `port` - The UDP port the socket is bound to
    pub fn from_socket(socket: Arc<tokio::net::UdpSocket>, port: u16) -> Self {
        Self { socket, port }
    }
}

#[cfg(any(feature = "dev-udp-loopback", test))]
fn dev_udp_target() -> Option<&'static str> {
    static TARGET: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    TARGET
        .get_or_init(|| {
            if std::env::var("TAPAUTH_DEV_MODE").is_ok() {
                Some(
                    // Default must stay in sync with DEV_HOST_PORT in
                    // scripts/test-e2e.sh (exported to the bridge helpers as
                    // TAPAUTH_E2E_DEV_HOST_PORT); the suite always sets this
                    // env var explicitly, so this only matters for bare dev runs.
                    std::env::var("TAPAUTH_DEV_UDP_TARGET")
                        .unwrap_or_else(|_| "127.0.0.1:36695".to_string()),
                )
            } else {
                None
            }
        })
        .as_deref()
}

#[cfg(any(feature = "dev-udp-loopback", test))]
fn send_to_emulator_if_dev_mode(packet: &EncryptedPacket) {
    if let Some(target) = dev_udp_target() {
        // One ephemeral socket for the lifetime of the process instead of a fresh
        // bind per packet (this fires on every request/confirmation/denial/cancel).
        static DEV_SOCK: std::sync::OnceLock<Option<std::net::UdpSocket>> =
            std::sync::OnceLock::new();
        if let Some(sock) = DEV_SOCK.get_or_init(|| std::net::UdpSocket::bind("0.0.0.0:0").ok()) {
            use prost::Message;
            let data = packet.encode_to_vec();
            let _ = sock.send_to(&data, target);
            tracing::debug!(
                "Directly forwarded {} bytes to dev target on {}",
                data.len(),
                target
            );
        }
    }
}

impl Transport for UdpTransport {
    async fn send_request(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Send broadcast on IPv4
        if let Err(e) = send_udp_broadcast(&self.socket, self.port, packet).await {
            tracing::warn!("Failed to send IPv4 broadcast: {}", e);
        }

        #[cfg(any(feature = "dev-udp-loopback", test))]
        send_to_emulator_if_dev_mode(packet);

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
        match try_receive_udp_packet(&self.socket, timeout).await? {
            Some((packet, addr)) => {
                // Filter out local addresses (already done in receive_udp_packet)
                Ok(ReceiveResult::Response(packet, addr))
            }
            None => Ok(ReceiveResult::Timeout),
        }
    }

    async fn send_confirmation(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Send on both IPv4 and IPv6
        send_udp_broadcast(&self.socket, self.port, packet).await?;

        #[cfg(any(feature = "dev-udp-loopback", test))]
        send_to_emulator_if_dev_mode(packet);

        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await;
        }

        Ok(())
    }

    async fn send_cancel(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Send on both IPv4 and IPv6
        send_udp_broadcast(&self.socket, self.port, packet).await?;

        #[cfg(any(feature = "dev-udp-loopback", test))]
        send_to_emulator_if_dev_mode(packet);

        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await;
        }

        Ok(())
    }
}
