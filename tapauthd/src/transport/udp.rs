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
    /// Source address of the response the session accepted as authenticated by a
    /// Server authorized for the request, recorded through
    /// [`Transport::record_authenticated_peer`].
    ///
    /// v2 sends the confirmation unicast to the peer that answered instead of
    /// multicasting it to every device on the link, and copies a cancel there
    /// too. `None` until a response has passed the session's checks, so an
    /// unauthenticated datagram from any host on the link cannot become the
    /// target of either.
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

    /// The peer recorded by [`Transport::record_authenticated_peer`], if any.
    ///
    /// A poisoned lock is recovered: the guarded value is a plain
    /// `Option<SocketAddr>`, so poison cannot leave it torn.
    fn peer_addr(&self) -> Option<SocketAddr> {
        *self
            .last_peer_addr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Hand a received datagram to the session.
    ///
    /// The source travels with the datagram and is deliberately *not* recorded
    /// here: [`Transport::receive_response`] sees every datagram on the link, and
    /// only the session can tell an authorized answer from an injected one
    /// (replay cache, AEAD, signature). Recording it at this point would let any
    /// host redirect the unicast `GrantConfirmation` and `AuthenticationCancel`;
    /// the authenticated source is recorded through
    /// [`Transport::record_authenticated_peer`] once the session accepts it.
    fn deliver_datagram(&self, packet: EncryptedPacket, addr: SocketAddr) -> ReceiveResult {
        ReceiveResult::Response(packet, addr)
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
            Some((packet, addr)) => Ok(self.deliver_datagram(packet, addr)),
            None => Ok(ReceiveResult::Timeout),
        }
    }

    fn record_authenticated_peer(&self, addr: SocketAddr) {
        *self
            .last_peer_addr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(addr);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use shared::protocol::pb::SymmetricAlgorithm;
    use std::net::Ipv4Addr;

    /// The address a spoofed datagram claims to come from: any loopback address
    /// that is not the transport's own.
    const SPOOFER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

    fn sample_packet() -> EncryptedPacket {
        EncryptedPacket {
            temporal_identifier: vec![7u8; 16],
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0xAAu8; 32],
        }
    }

    /// A transport bound to loopback, plus the socket a spoofed datagram comes
    /// from.
    async fn transport_and_peer() -> (UdpTransport, tokio::net::UdpSocket, SocketAddr, SocketAddr) {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let local = socket.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind((SPOOFER, 0)).await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        (
            UdpTransport::from_socket(socket, local.port()),
            peer,
            local,
            peer_addr,
        )
    }

    /// A datagram nobody authenticated must not become the unicast target of the
    /// confirmation or the cancel.
    ///
    /// The defect this catches: recording the source on delivery, i.e. in
    /// `receive_response`/`deliver_datagram`, which hands every datagram on the
    /// link — including one injected by any host that can reach the port — to
    /// `last_peer_addr`, letting that host receive the session's
    /// `GrantConfirmation` and `AuthenticationCancel`.
    #[tokio::test]
    async fn an_unauthenticated_datagram_does_not_become_the_unicast_target() {
        let (transport, peer, local, peer_addr) = transport_and_peer().await;

        let delivered = transport.deliver_datagram(sample_packet(), peer_addr);
        match delivered {
            ReceiveResult::Response(_, source) => {
                assert_eq!(source, peer_addr, "the datagram's source travels with it")
            }
            ReceiveResult::Timeout => panic!("a delivered datagram must reach the session"),
        }
        assert!(
            transport.peer_addr().is_none(),
            "the source of an unauthenticated datagram must not be recorded"
        );

        // ...and the confirmation does not go back to it.
        transport
            .send_confirmation(&sample_packet(), &CskMetadata::default())
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buf))
                .await
                .is_err(),
            "the host that injected the datagram received the confirmation"
        );
        assert_eq!(local.port(), transport.port);
    }

    /// The authenticated path: once the session accepts a response, its source is
    /// the peer the confirmation is unicast to.
    ///
    /// The defect this catches: dropping the recording altogether along with the
    /// premature one — no peer recorded at all, so `send_confirmation` logs "No
    /// peer address recorded" and the phone that granted never gets its
    /// acknowledgement.
    #[tokio::test]
    async fn an_authenticated_response_records_the_unicast_target() {
        let (transport, peer, local, peer_addr) = transport_and_peer().await;
        assert!(transport.peer_addr().is_none(), "nothing is accepted yet");

        transport.record_authenticated_peer(peer_addr);
        assert_eq!(transport.peer_addr(), Some(peer_addr));

        let confirmation = sample_packet();
        transport
            .send_confirmation(&confirmation, &CskMetadata::default())
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (len, source) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("the confirmation never reached the accepted peer")
            .unwrap();
        assert_eq!(source.port(), local.port());
        assert_eq!(
            buf.get(..len),
            Some(confirmation.encode_to_vec().as_slice())
        );
    }

    /// The same property on the real receive path: a datagram the session has not
    /// accepted leaves `last_peer_addr` untouched.
    ///
    /// `shared`'s receive filter drops every locally-sourced datagram as a
    /// self-echo unless `TAPAUTH_DEV_MODE` is set, and the bypass only exists in a
    /// `dev-udp-loopback` build (`cfg(test)` there does not cover a dependency),
    /// so this half of the pair is compiled only for that feature — which is how
    /// the E2E sandbox daemon is built.
    #[cfg(feature = "dev-udp-loopback")]
    #[tokio::test]
    async fn a_spoofed_source_on_the_wire_is_not_recorded() {
        std::env::set_var("TAPAUTH_DEV_MODE", "1");
        let (transport, peer, local, peer_addr) = transport_and_peer().await;
        peer.send_to(&sample_packet().encode_to_vec(), local)
            .await
            .unwrap();

        match transport
            .receive_response(Duration::from_millis(500), &CskMetadata::default())
            .await
            .unwrap()
        {
            ReceiveResult::Response(_, source) => assert_eq!(source, peer_addr),
            ReceiveResult::Timeout => panic!("the datagram was never delivered to the session"),
        }
        assert!(
            transport.peer_addr().is_none(),
            "an unauthenticated on-the-wire datagram became the unicast target"
        );
    }
}
