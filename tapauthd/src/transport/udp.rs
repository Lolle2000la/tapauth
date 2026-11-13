//! UDP transport using IPv4 + IPv6 multicast

use super::{ReceiveResult, Transport};
use crate::auth_handler::AuthHandlerError as AuthError;
use prost::Message;
use shared::config::CskMetadata;
use shared::network::{
    is_ipv6_available, send_udp_multicast_all_interfaces, send_udp_multicast_v4_all_interfaces,
    try_receive_udp_packet, IPV4_MULTICAST_ADDR, IPV6_MULTICAST_ADDR,
};
use shared::protocol::pb::EncryptedPacket;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// UDP transport using multicast on both address families.
///
/// Always wraps a socket owned by `DaemonState`; it never closes the socket
/// itself.
pub struct UdpTransport {
    socket: Arc<tokio::net::UdpSocket>,
    port: u16,
    /// Source address of the most recent response accepted by
    /// [`Transport::receive_response`].
    ///
    /// v2 sends the confirmation unicast to the peer that answered instead of
    /// multicasting it to every device on the link, and copies a cancel there
    /// too. `None` until a peer has replied.
    last_peer_addr: Mutex<Option<SocketAddr>>,
}

impl UdpTransport {
    /// Create a UDP transport from an existing shared socket
    ///
    /// # Arguments
    /// * `socket` - Shared reference to an existing UDP socket
    /// * `port` - The UDP port the socket is bound to
    pub fn from_socket(socket: Arc<tokio::net::UdpSocket>, port: u16) -> Self {
        Self {
            socket,
            port,
            last_peer_addr: Mutex::new(None),
        }
    }

    /// The peer recorded by [`Transport::receive_response`], if any.
    ///
    /// A poisoned lock is recovered: the guarded value is a plain
    /// `Option<SocketAddr>`, so poison cannot leave it torn.
    fn peer_addr(&self) -> Option<SocketAddr> {
        *self
            .last_peer_addr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record `addr` as the peer that produced the winning response.
    fn record_peer_addr(&self, addr: SocketAddr) {
        *self
            .last_peer_addr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(addr);
    }

    /// Send `bytes` to a single address, logging rather than failing: the
    /// devices may still be reachable over BLE.
    async fn unicast(&self, bytes: &[u8], addr: SocketAddr, what: &str) {
        if let Err(e) = self.socket.send_to(bytes, addr).await {
            tracing::warn!("Failed to send {} to {}: {}", what, addr, e);
        }
    }

    /// Send `packet` to the IPv4 and IPv6 discovery groups on every suitable
    /// interface. Failures on either family are logged, never fatal: the
    /// devices may be reachable over the other transport (BLE) or the still
    /// configured IPv4/IPv6 pair.
    async fn send_to_multicast_groups(&self, packet: &EncryptedPacket) {
        // The send helpers log the per-family success count themselves; only the
        // cases the caller cannot otherwise observe are surfaced here.
        match send_udp_multicast_v4_all_interfaces(IPV4_MULTICAST_ADDR, self.port, packet).await {
            Ok(0) => tracing::debug!("No suitable IPv4 interfaces found for multicast"),
            Ok(_) => {}
            Err(e) => tracing::warn!("Failed to send IPv4 multicast: {}", e),
        }

        if is_ipv6_available() {
            match send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await {
                Ok(0) => tracing::debug!("No suitable IPv6 interfaces found for multicast"),
                Ok(_) => {}
                Err(e) => tracing::warn!("Failed to send IPv6 multicast: {}", e),
            }
        }
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
        #[cfg(any(feature = "dev-udp-loopback", test))]
        send_to_emulator_if_dev_mode(packet);

        self.send_to_multicast_groups(packet).await;

        Ok(())
    }

    async fn receive_response(
        &self,
        timeout: Duration,
        _csk_meta: &CskMetadata,
    ) -> Result<ReceiveResult, AuthError> {
        match try_receive_udp_packet(&self.socket, timeout).await? {
            Some((packet, addr)) => {
                // Filter out local addresses (already done in receive_udp_packet)
                // The first accepted response is the winner: the handler verifies
                // it and returns without waiting again, so this is the peer the
                // confirmation is unicast back to.
                self.record_peer_addr(addr);
                Ok(ReceiveResult::Response(packet, addr))
            }
            None => Ok(ReceiveResult::Timeout),
        }
    }

    async fn send_confirmation(
        &self,
        packet: &EncryptedPacket,
        _csk_meta: &CskMetadata,
    ) -> Result<(), AuthError> {
        #[cfg(any(feature = "dev-udp-loopback", test))]
        send_to_emulator_if_dev_mode(packet);

        let Some(peer_addr) = self.peer_addr() else {
            // No response has been accepted yet, so there is no peer to confirm
            // to; multicasting here would confirm to every device on the link.
            tracing::warn!("No peer address recorded; confirmation not sent");
            return Ok(());
        };

        let bytes = packet.encode_to_vec();
        self.unicast(&bytes, peer_addr, "confirmation").await;

        // A loopback peer keeps the port it answered from: the QEMU SLIRP NAT
        // hands out an ephemeral port for the reply and forwards it to the
        // emulated phone, so rewriting the port would send the confirmation
        // somewhere nobody listens.
        if !peer_addr.ip().is_loopback() && peer_addr.port() != self.port {
            let service_addr = SocketAddr::new(peer_addr.ip(), self.port);
            self.unicast(&bytes, service_addr, "confirmation").await;
        }
        Ok(())
    }

    async fn send_cancel(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        #[cfg(any(feature = "dev-udp-loopback", test))]
        send_to_emulator_if_dev_mode(packet);

        self.send_to_multicast_groups(packet).await;

        // A device that already answered the request has left the multicast
        // group, so the cancel also goes directly to the recorded peer.
        if let Some(peer_addr) = self.peer_addr() {
            let bytes = packet.encode_to_vec();
            self.unicast(&bytes, peer_addr, "cancel").await;
        }
        Ok(())
    }
}
