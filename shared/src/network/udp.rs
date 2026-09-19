//! UDP networking for TapAuth discovery and communication.
//!
//! Provides dual-stack (IPv4/IPv6) UDP socket creation with multicast support
//! for device discovery. Handles interface enumeration, multicast group joining,
//! and encrypted packet transmission.
//!
//! ## IPv6 Multicast
//!
//! IPv6 multicast requires explicit interface scope specification. This module
//! automatically discovers suitable network interfaces and caches interface
//! addresses to avoid repeated system calls.

use prost::Message;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[cfg(unix)]
use std::ffi::CString;

use super::NetworkError;
use crate::protocol::pb::EncryptedPacket;

const MAX_UDP_MESSAGE_SIZE: usize = 16 * 1024; // 16KB, matches TCP pairing path

// Track whether IPv6 is available (cached after first check)
static IPV6_AVAILABLE: AtomicBool = AtomicBool::new(true);
static IPV6_CHECKED: AtomicBool = AtomicBool::new(false);

const INTERFACE_CACHE_TTL: Duration = Duration::from_secs(1);
static INTERFACE_ADDR_CACHE: OnceLock<RwLock<InterfaceCache>> = OnceLock::new();

struct InterfaceCache {
    addresses: Vec<IpAddr>,
    last_refresh: Instant,
}

/// Represents a network interface suitable for IP multicast.
///
/// An interface is included when it is not loopback and has at least one IPv4 or
/// IPv6 address; oper-status and point-to-point are not filtered (see
/// [`get_multicast_interfaces`]). The selected addresses are recorded so an IPv4
/// multicast send can pin `IP_MULTICAST_IF` on that interface and an IPv6 send
/// can use the interface index as its scope.
#[derive(Debug, Clone)]
pub struct MulticastInterface {
    pub name: String,
    pub index: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

/// Addresses collected for one interface before a single one per family is
/// selected. Interfaces may carry several addresses of the same family (e.g. a
/// routable address plus APIPA).
#[derive(Debug, Default)]
struct InterfaceAddrs {
    v4: Vec<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
}

/// Choose the IPv4 address used as the multicast source for an interface.
///
/// A routable address is preferred over APIPA (`169.254.0.0/16`): the address
/// chosen here becomes the source of the discovery datagram and therefore the
/// unicast reply target the phone uses, and an unroutable source would send the
/// reply nowhere. The smallest address wins, so the result does not depend on
/// `getifaddrs` ordering.
fn select_ipv4(addrs: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    addrs
        .iter()
        .copied()
        .find(|addr| !addr.is_link_local())
        .or_else(|| addrs.first().copied())
}

/// Get all network interfaces suitable for IP multicast.
///
/// Returns every non-loopback interface that has at least one IPv4 or IPv6
/// address. That is the only filter: point-to-point links and interfaces whose
/// oper-status is not "up" are deliberately left in, because address presence is
/// the signal that matters. Callers skip interfaces lacking the address family
/// they need, and per-interface send failures are logged rather than fatal.
pub fn get_multicast_interfaces() -> Vec<MulticastInterface> {
    let mut by_name: std::collections::HashMap<String, InterfaceAddrs> =
        std::collections::HashMap::new();

    match if_addrs::get_if_addrs() {
        Ok(addrs) => {
            tracing::trace!("Enumerating network interfaces for IP multicast");

            for iface in &addrs {
                // Skip loopback interfaces
                if iface.is_loopback() {
                    tracing::trace!("  Skipping {} - loopback", iface.name);
                    continue;
                }

                match &iface.addr {
                    if_addrs::IfAddr::V4(v4) => {
                        tracing::trace!("  Interface {} has IPv4 {}", iface.name, v4.ip);
                        by_name
                            .entry(iface.name.clone())
                            .or_default()
                            .v4
                            .push(v4.ip);
                    }
                    if_addrs::IfAddr::V6(v6) => {
                        tracing::trace!("  Interface {} has IPv6 {}", iface.name, v6.ip);
                        by_name
                            .entry(iface.name.clone())
                            .or_default()
                            .v6
                            .push(v6.ip);
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to enumerate network interfaces: {}", e);
        }
    }

    let mut interfaces = Vec::new();
    for (name, mut addrs) in by_name {
        addrs.v4.sort_unstable();
        addrs.v4.dedup();
        addrs.v6.sort_unstable();
        addrs.v6.dedup();

        match get_interface_index(&name) {
            Ok(index) => {
                let ipv4 = select_ipv4(&addrs.v4);
                let ipv6 = addrs.v6.first().copied();
                tracing::trace!(
                    "  Added interface {} with index {} (ipv4={:?}, ipv6={:?})",
                    name,
                    index,
                    ipv4,
                    ipv6
                );
                interfaces.push(MulticastInterface {
                    name,
                    index,
                    ipv4,
                    ipv6,
                });
            }
            Err(e) => {
                tracing::trace!("  Failed to get index for {}: {}", name, e);
            }
        }
    }

    // Stable ordering so logs/tests are deterministic regardless of HashMap
    // iteration order.
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));

    tracing::trace!(
        "Found {} suitable multicast interface(s): {:?}",
        interfaces.len(),
        interfaces.iter().map(|i| &i.name).collect::<Vec<_>>()
    );

    interfaces
}

/// Return true if the provided IP address belongs to a local interface on this host.
pub fn is_local_ip(addr: &IpAddr) -> bool {
    if addr.is_loopback() {
        return true;
    }

    let cache = INTERFACE_ADDR_CACHE.get_or_init(|| {
        let initial = InterfaceCache {
            addresses: Vec::new(),
            last_refresh: Instant::now() - INTERFACE_CACHE_TTL,
        };
        RwLock::new(initial)
    });

    if let Ok(guard) = cache.read() {
        if guard.last_refresh.elapsed() < INTERFACE_CACHE_TTL && !guard.addresses.is_empty() {
            return guard.addresses.iter().any(|ip| ip == addr);
        }
    }

    let mut guard = match cache.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if guard.last_refresh.elapsed() >= INTERFACE_CACHE_TTL || guard.addresses.is_empty() {
        match if_addrs::get_if_addrs() {
            Ok(addrs) => {
                let mut addresses = Vec::new();
                for iface in addrs {
                    let ip = match iface.addr {
                        if_addrs::IfAddr::V4(v4) => IpAddr::V4(v4.ip),
                        if_addrs::IfAddr::V6(v6) => IpAddr::V6(v6.ip),
                    };
                    if !addresses.contains(&ip) {
                        addresses.push(ip);
                    }
                }
                guard.addresses = addresses;
                guard.last_refresh = Instant::now();
            }
            Err(_) => {
                guard.last_refresh = Instant::now();
            }
        }
    }

    guard.addresses.iter().any(|ip| ip == addr)
}

/// Get the interface index for a given interface name.
///
/// This is required for IPv6 multicast scope specification.
///
/// ## Safety
///
/// Calls `libc::if_nametoindex()` which:
/// - Accepts a null-terminated C string pointer
/// - Returns 0 on error (invalid name or interface not found)
/// - Is thread-safe per POSIX specification
/// - Does not modify the input string
///
/// The `CString` ensures proper null termination and lifetime for the FFI call.
#[cfg(unix)]
fn get_interface_index(name: &str) -> Result<u32, std::io::Error> {
    let c_name = CString::new(name).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid interface name")
    })?;

    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

    if index == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

#[cfg(not(unix))]
fn get_interface_index(_name: &str) -> Result<u32, std::io::Error> {
    // On non-Unix platforms, we can't easily get interface indices
    // This is a limitation - Windows would need different API calls
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Interface index lookup not supported on this platform",
    ))
}

/// Check if IPv6 is available on this system
pub fn is_ipv6_available() -> bool {
    // Return cached result if already checked
    if IPV6_CHECKED.load(Ordering::Relaxed) {
        return IPV6_AVAILABLE.load(Ordering::Relaxed);
    }

    // Try to create an IPv6 socket to test availability
    let available = std::net::UdpSocket::bind("[::]:0").is_ok();

    IPV6_AVAILABLE.store(available, Ordering::Relaxed);
    IPV6_CHECKED.store(true, Ordering::Relaxed);

    available
}

/// Create the daemon's dual-stack UDP socket for multicast discovery (async).
///
/// Binds to the configured UDP port so unicast responses from paired servers
/// are received on that port. The daemon only *sends* to multicast groups;
/// replies are always unicast, so no group membership is required here.
pub async fn create_multicast_socket(port: u16) -> Result<UdpSocket, NetworkError> {
    let std_socket = bind_dual_stack_socket(port)?;
    let socket = UdpSocket::from_std(std_socket)?;

    let local_addr = socket.local_addr()?;
    tracing::info!(
        "Created multicast socket on {} (listening for responses on configured port)",
        local_addr
    );

    Ok(socket)
}

/// Create a UDP socket for listening on a specific port (async)
pub async fn create_listen_socket(port: u16) -> Result<UdpSocket, NetworkError> {
    let std_socket = bind_dual_stack_socket(port)?;
    let socket = UdpSocket::from_std(std_socket)?;
    Ok(socket)
}

/// Send an encrypted packet to the IPv4 multicast group on all available
/// interfaces.
///
/// `IP_MULTICAST_IF` is pinned per interface so a multi-homed host reaches
/// every segment (mirroring the IPv6 path below).
pub async fn send_udp_multicast_v4_all_interfaces(
    multicast_addr: &str,
    port: u16,
    packet: &EncryptedPacket,
) -> Result<usize, NetworkError> {
    let data = packet.encode_to_vec();

    let multicast_ip: Ipv4Addr = multicast_addr.parse().map_err(|_| {
        NetworkError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid IPv4 multicast address",
        ))
    })?;

    let interfaces = get_multicast_interfaces();
    let mut success_count = 0;

    for iface in interfaces {
        // Only interfaces with an IPv4 address can carry an IPv4 group.
        let Some(iface_ip) = iface.ipv4 else {
            continue;
        };

        let socket = match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("Failed to create IPv4 socket for {}: {}", iface.name, e);
                continue;
            }
        };

        let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        if let Err(e) = socket.bind(&bind_addr.into()) {
            tracing::debug!("Failed to bind IPv4 socket for {}: {}", iface.name, e);
            continue;
        }

        // Do not loop multicast back to ourselves: the daemon does not join
        // these groups, so a self-delivery would only be redundant traffic.
        if let Err(e) = socket.set_multicast_loop_v4(false) {
            tracing::trace!(
                "Failed to disable IPv4 multicast loop for {}: {}",
                iface.name,
                e
            );
        }

        if let Err(e) = socket.set_multicast_if_v4(&iface_ip) {
            tracing::debug!(
                "Failed to set multicast interface for {}: {}",
                iface.name,
                e
            );
            continue;
        }

        let dest_addr = SocketAddr::from((multicast_ip, port));
        match socket.send_to(&data, &dest_addr.into()) {
            Ok(_) => {
                tracing::trace!(
                    "Sent IPv4 multicast on interface {} ({})",
                    iface.name,
                    iface_ip
                );
                success_count += 1;
            }
            Err(e) => {
                tracing::debug!("Failed to send IPv4 multicast on {}: {}", iface.name, e);
            }
        }
    }

    if success_count > 0 {
        tracing::trace!("Sent IPv4 multicast on {} interface(s)", success_count);
    }

    Ok(success_count)
}

fn bind_dual_stack_socket(port: u16) -> Result<std::net::UdpSocket, std::io::Error> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    // Allow the socket to accept both IPv4 and IPv6 traffic
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    socket.bind(&SockAddr::from(addr))?;
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

/// Send an encrypted packet via UDP multicast on all available IPv6 interfaces
/// This function creates separate sockets for each interface and uses socket2 to
/// properly set the IPV6_MULTICAST_IF option for each send.
pub async fn send_udp_multicast_all_interfaces(
    multicast_addr: &str,
    port: u16,
    packet: &EncryptedPacket,
) -> Result<usize, NetworkError> {
    let data = packet.encode_to_vec();

    // Parse the multicast address
    let multicast_ip: Ipv6Addr = multicast_addr.parse().map_err(|_| {
        NetworkError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid multicast address",
        ))
    })?;

    // Get all suitable interfaces
    let interfaces = get_multicast_interfaces();

    if interfaces.is_empty() {
        tracing::debug!("No suitable IPv6 interfaces found for multicast");
        return Ok(0);
    }

    let mut success_count = 0;

    // Send on each interface by setting the multicast interface option
    for iface in interfaces {
        // Link-local IPv6 groups can only be sent on interfaces that have an
        // IPv6 address.
        if iface.ipv6.is_none() {
            continue;
        }

        // Create a UDP socket for IPv6
        let socket_addr = match "[::]:0".parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                tracing::error!("Failed to parse IPv6 any address - this should never happen");
                continue;
            }
        };
        let socket = match socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("Failed to create IPv6 socket for {}: {}", iface.name, e);
                continue;
            }
        };

        // Bind to any address
        if let Err(e) = socket.bind(&socket_addr.into()) {
            tracing::debug!("Failed to bind IPv6 socket for {}: {}", iface.name, e);
            continue;
        }

        // Disable loopback of multicast packets so we don't receive our own sends
        if let Err(e) = socket.set_multicast_loop_v6(false) {
            tracing::trace!(
                "Failed to disable IPv6 multicast loop for {}: {}",
                iface.name,
                e
            );
            // Not fatal; continue
        }

        // Set the multicast interface to this specific interface
        if let Err(e) = socket.set_multicast_if_v6(iface.index) {
            tracing::debug!(
                "Failed to set multicast interface for {}: {}",
                iface.name,
                e
            );
            continue;
        }

        // Send using the std socket (synchronous, but fast)
        let dest_addr = SocketAddr::new(std::net::IpAddr::V6(multicast_ip), port);

        match socket.send_to(&data, &dest_addr.into()) {
            Ok(_) => {
                tracing::trace!(
                    "Sent IPv6 multicast on interface {} (index {})",
                    iface.name,
                    iface.index
                );
                success_count += 1;
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to send IPv6 multicast on interface {}: {}",
                    iface.name,
                    e
                );
            }
        }
    }

    if success_count > 0 {
        tracing::trace!("Sent IPv6 multicast on {} interface(s)", success_count);
    }

    Ok(success_count)
}

/// Send an encrypted packet via UDP unicast - async
pub async fn send_udp_unicast(
    socket: &UdpSocket,
    addr: SocketAddr,
    packet: &EncryptedPacket,
) -> Result<(), NetworkError> {
    let data = packet.encode_to_vec();
    socket.send_to(&data, addr).await?;
    Ok(())
}

/// Receive an encrypted packet from UDP - async
pub async fn receive_udp_packet(
    socket: &UdpSocket,
) -> Result<(EncryptedPacket, SocketAddr), NetworkError> {
    let mut buf = [0u8; 65536];

    // Our own bound source port, used to detect exact self-echoes (below).
    let local_port = socket.local_addr().ok().map(|a| a.port());

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;

        // Normalize IP for comparison
        let src_ip = match addr.ip() {
            std::net::IpAddr::V6(v6) => {
                // Map IPv4-mapped IPv6 addresses to IPv4 for local comparison
                if let Some(mapped) = v6.to_ipv4() {
                    IpAddr::V4(mapped)
                } else {
                    IpAddr::V6(v6)
                }
            }
            v4 => IpAddr::V4(match v4 {
                std::net::IpAddr::V4(a) => a,
                _ => unreachable!(),
            }),
        };

        // A locally-sourced datagram whose source port equals the port this
        // socket is bound to is a loopback/echo artefact, never a legitimate
        // remote peer; processing it would make the retransmission loop spin
        // (each echo looks like a fast "no valid response yet" outcome). The
        // daemon's own multicast sends use ephemeral source ports and do not
        // join these groups, so this is purely defensive. It is independent of
        // the dev-mode local-address filter below, which must stay permissive
        // so loopback test harnesses (Android emulator over SLIRP) keep working.
        if local_port == Some(addr.port()) && is_local_ip(&src_ip) {
            tracing::debug!("Ignored self-echoed UDP packet from {}", addr);
            // drop and continue waiting for next packet
            continue;
        }

        #[cfg(any(feature = "dev-udp-loopback", test))]
        let skip_local_filter = {
            static DEV_MODE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            *DEV_MODE.get_or_init(|| std::env::var("TAPAUTH_DEV_MODE").is_ok())
        };
        #[cfg(not(any(feature = "dev-udp-loopback", test)))]
        let skip_local_filter = false;

        if !skip_local_filter && is_local_ip(&src_ip) {
            tracing::debug!("Ignored self-sent UDP packet from {}", addr);
            // drop and continue waiting for next packet
            continue;
        }

        tracing::trace!(
            "Received UDP packet from {} ({} bytes, protocol: {})",
            addr,
            len,
            if addr.is_ipv4() { "IPv4" } else { "IPv6" }
        );

        let packet_bytes = buf.get(..len).ok_or_else(|| {
            NetworkError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "buffer length mismatch",
            ))
        })?;
        if packet_bytes.len() > MAX_UDP_MESSAGE_SIZE {
            tracing::warn!(
                "UDP packet too large ({} bytes), dropping",
                packet_bytes.len()
            );
            continue;
        }
        let packet = EncryptedPacket::decode(packet_bytes)?;
        return Ok((packet, addr));
    }
}

/// Try to receive an encrypted packet with timeout - async
pub async fn try_receive_udp_packet(
    socket: &UdpSocket,
    timeout: Duration,
) -> Result<Option<(EncryptedPacket, SocketAddr)>, NetworkError> {
    match tokio::time::timeout(timeout, receive_udp_packet(socket)).await {
        Ok(Ok(result)) => Ok(Some(result)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None), // Timeout elapsed
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_sockets() {
        // Test creating the daemon's multicast socket on an ephemeral port
        // (0 = OS assigns)
        let multicast_socket = create_multicast_socket(0).await;
        assert!(multicast_socket.is_ok());

        // Test creating listen socket on a random port
        let listen_socket = create_listen_socket(0).await;
        assert!(listen_socket.is_ok());
    }

    #[tokio::test]
    async fn test_send_udp_multicast_v4_all_interfaces() {
        use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};

        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0u8; 64],
        };

        let result = send_udp_multicast_v4_all_interfaces(
            crate::network::IPV4_MULTICAST_ADDR,
            36692,
            &packet,
        )
        .await;

        // Should succeed or return 0 if no suitable interfaces
        assert!(result.is_ok());
    }

    #[test]
    fn test_multicast_group_constants() {
        use crate::network::{IPV4_MULTICAST_ADDR, IPV6_MULTICAST_ADDR};

        // IPv4 group must be a multicast address inside the IPv4 Local Scope
        // (239.255.0.0/16, RFC 2365), not the limited broadcast address.
        let v4: Ipv4Addr = IPV4_MULTICAST_ADDR.parse().unwrap();
        assert!(v4.is_multicast());
        assert_eq!(v4.octets()[0], 239);
        assert_eq!(v4.octets()[1], 255);

        // IPv6 group must be multicast, transient (flag = 1) and link-local
        // (scope = 2) => ff12::/16.
        let v6: Ipv6Addr = IPV6_MULTICAST_ADDR.parse().unwrap();
        assert!(v6.is_multicast());
        let second_byte = v6.octets()[1];
        assert_eq!(second_byte >> 4, 0x1, "IPv6 group must be transient");
        assert_eq!(second_byte & 0x0f, 0x2, "IPv6 group must be link-local");

        // The low 32 bits are the IPv6 group ID and must be inside the IANA
        // "Reserved for Private Use" dynamic range 0xFD000000-0xFDFFFFFF.
        let o = v6.octets();
        let low32 = u32::from_be_bytes([o[12], o[13], o[14], o[15]]);
        assert!(
            (0xFD00_0000..=0xFDFF_FFFF).contains(&low32),
            "IPv6 group ID 0x{low32:08X} is outside the private-use range"
        );
    }

    #[tokio::test]
    async fn test_multicast_interface_detection() {
        let interfaces = get_multicast_interfaces();

        // Should return a list (may be empty on some systems)
        // Each interface should have a valid index
        for iface in interfaces {
            assert!(iface.index > 0);
            assert!(!iface.name.is_empty());
            // Loopback is always excluded.
            assert_ne!(iface.name, "lo");
            // Every returned interface carries at least one usable address.
            assert!(iface.ipv4.is_some() || iface.ipv6.is_some());
        }
    }

    #[test]
    fn test_select_ipv4_prefers_routable_over_apipa() {
        let apipa = Ipv4Addr::new(169, 254, 1, 2);
        let routable = Ipv4Addr::new(192, 168, 1, 10);

        // A routable address wins so the phone's unicast reply has a routable
        // destination.
        assert_eq!(select_ipv4(&[apipa, routable]), Some(routable));
        assert_eq!(select_ipv4(&[routable, apipa]), Some(routable));
        // APIPA is still usable when it is all the interface has.
        assert_eq!(select_ipv4(&[apipa]), Some(apipa));
        assert_eq!(select_ipv4(&[]), None);
    }

    #[tokio::test]
    async fn test_send_udp_multicast_rejects_invalid_addresses() {
        use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};

        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0u8; 64],
        };

        // A malformed group must fail fast rather than silently send nothing.
        assert!(
            send_udp_multicast_v4_all_interfaces("not-an-ip", 36692, &packet)
                .await
                .is_err()
        );
        assert!(
            send_udp_multicast_all_interfaces("not-an-ip", 36692, &packet)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_send_udp_multicast_all_interfaces() {
        use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};

        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0u8; 64],
        };

        let result =
            send_udp_multicast_all_interfaces(crate::network::IPV6_MULTICAST_ADDR, 36692, &packet)
                .await;

        // Should succeed or return 0 if no suitable interfaces
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_listen_socket_binding() {
        // Create a listen socket on a random port
        let socket = create_listen_socket(0).await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Port should be assigned
        assert!(addr.port() > 0);

        // Should be bound to 0.0.0.0 or [::]
        assert!(addr.ip().is_unspecified() || addr.ip().to_string() == "0.0.0.0");
    }

    #[test]
    fn test_get_interface_index() {
        // Test with loopback interface (should exist on most Unix systems)
        let result = get_interface_index("lo");

        // On Unix systems with loopback, should succeed
        // On other systems or non-existent interfaces, should error
        match result {
            Ok(idx) => assert!(idx > 0),
            Err(_) => {
                // Acceptable - may not be Unix or interface doesn't exist
            }
        }
    }
}
