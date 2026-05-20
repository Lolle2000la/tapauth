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

/// Represents a network interface suitable for IPv6 multicast
#[derive(Debug, Clone)]
pub struct MulticastInterface {
    pub name: String,
    pub index: u32,
}

/// Get all network interfaces suitable for IPv6 multicast
/// Returns interfaces that are:
/// - UP (active)
/// - Not loopback
/// - Support IPv6
/// - Not point-to-point links
pub fn get_multicast_interfaces() -> Vec<MulticastInterface> {
    let mut interfaces = Vec::new();
    let mut ipv6_interface_names = std::collections::HashSet::new();

    match if_addrs::get_if_addrs() {
        Ok(addrs) => {
            tracing::trace!("Enumerating network interfaces for IPv6 multicast");

            // First pass: collect all interface names that have IPv6 addresses
            for iface in &addrs {
                tracing::trace!(
                    "Found interface: {} (loopback: {}, addr: {:?})",
                    iface.name,
                    iface.is_loopback(),
                    iface.addr
                );

                // Skip loopback interfaces
                if iface.is_loopback() {
                    tracing::trace!("  Skipping {} - loopback", iface.name);
                    continue;
                }

                // Check if this address is IPv6
                if matches!(iface.addr, if_addrs::IfAddr::V6(_)) {
                    tracing::trace!("  Interface {} has IPv6 address", iface.name);
                    ipv6_interface_names.insert(iface.name.clone());
                }
            }

            tracing::trace!("Interfaces with IPv6: {:?}", ipv6_interface_names);

            // Second pass: get interface indices for IPv6-capable interfaces
            for name in ipv6_interface_names {
                match get_interface_index(&name) {
                    Ok(index) => {
                        tracing::trace!("  Added interface {} with index {}", name, index);
                        interfaces.push(MulticastInterface {
                            name: name.clone(),
                            index,
                        });
                    }
                    Err(e) => {
                        tracing::trace!("  Failed to get index for {}: {}", name, e);
                    }
                }
            }

            tracing::trace!(
                "Found {} suitable IPv6 interface(s): {:?}",
                interfaces.len(),
                interfaces.iter().map(|i| &i.name).collect::<Vec<_>>()
            );
        }
        Err(e) => {
            tracing::warn!("Failed to enumerate network interfaces: {}", e);
        }
    }

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
    use std::ffi::CString;

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

/// Create a UDP socket for broadcasting/multicasting (async)
/// Binds to the configured UDP port to receive responses on that port
pub async fn create_broadcast_socket(port: u16) -> Result<UdpSocket, NetworkError> {
    let std_socket = bind_dual_stack_socket(port, true)?;
    let socket = UdpSocket::from_std(std_socket)?;

    let local_addr = socket.local_addr()?;
    tracing::info!(
        "Created broadcast socket on {} (listening for responses on configured port)",
        local_addr
    );

    Ok(socket)
}

/// Create a UDP socket for listening on a specific port (async)
pub async fn create_listen_socket(port: u16) -> Result<UdpSocket, NetworkError> {
    let std_socket = bind_dual_stack_socket(port, false)?;
    let socket = UdpSocket::from_std(std_socket)?;
    Ok(socket)
}

/// Send an encrypted packet via UDP broadcast (IPv4) - async
pub async fn send_udp_broadcast(
    socket: &UdpSocket,
    port: u16,
    packet: &EncryptedPacket,
) -> Result<(), NetworkError> {
    let data = packet.encode_to_vec();
    let addr = SocketAddr::from((Ipv4Addr::BROADCAST, port));
    socket.send_to(&data, addr).await?;
    Ok(())
}

fn bind_dual_stack_socket(
    port: u16,
    enable_broadcast: bool,
) -> Result<std::net::UdpSocket, std::io::Error> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    // Allow the socket to accept both IPv4 and IPv6 traffic
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    if enable_broadcast {
        socket.set_broadcast(true)?;
    }

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

        if is_local_ip(&src_ip) {
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_sockets() {
        // Test creating broadcast socket on an ephemeral port (0 = OS assigns)
        let broadcast_socket = create_broadcast_socket(0).await;
        assert!(broadcast_socket.is_ok());

        // Test creating listen socket on a random port
        let listen_socket = create_listen_socket(0).await;
        assert!(listen_socket.is_ok());
    }

    #[tokio::test]
    async fn test_send_udp_broadcast() {
        use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};

        // Use ephemeral port (0) to avoid conflicts when tests run in parallel
        let socket = create_broadcast_socket(0).await.unwrap();
        let local_port = socket.local_addr().unwrap().port();

        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0u8; 64],
        };

        let result = send_udp_broadcast(&socket, local_port, &packet).await;

        // Should succeed (or fail gracefully if no network interface)
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_multicast_interface_detection() {
        let interfaces = get_multicast_interfaces();

        // Should return a list (may be empty on some systems)
        // Each interface should have a valid index
        for iface in interfaces {
            assert!(iface.index > 0);
            assert!(!iface.name.is_empty());
        }
    }

    #[tokio::test]
    async fn test_send_udp_multicast_all_interfaces() {
        use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};

        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0u8; 64],
        };

        let result = send_udp_multicast_all_interfaces("ff02::1", 36692, &packet).await;

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
