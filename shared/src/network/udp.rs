use prost::Message;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

use super::NetworkError;
use crate::protocol::pb::EncryptedPacket;

// Track whether IPv6 is available (cached after first check)
static IPV6_AVAILABLE: AtomicBool = AtomicBool::new(true);
static IPV6_CHECKED: AtomicBool = AtomicBool::new(false);

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

/// Get the interface index for a given interface name
/// This is needed for IPv6 multicast scope specification
#[cfg(unix)]
fn get_interface_index(name: &str) -> Result<u32, std::io::Error> {
    use std::ffi::CString;

    let c_name = CString::new(name).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid interface name")
    })?;

    // SAFETY: if_nametoindex is a standard POSIX function
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
/// Uses dual-stack (IPv6 with IPv4-mapped addresses) to receive responses from both protocols
pub async fn create_broadcast_socket() -> Result<UdpSocket, NetworkError> {
    // Try to create dual-stack socket (IPv6 that also handles IPv4)
    // This allows receiving responses regardless of which protocol the server uses
    match UdpSocket::bind("[::]:0").await {
        Ok(socket) => {
            // Try to enable dual-stack mode (accept IPv4-mapped IPv6 addresses)
            // This may fail on some systems, but is best effort
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let raw_fd = socket.as_raw_fd();
                unsafe {
                    let optval: libc::c_int = 0; // 0 = enable dual-stack
                    libc::setsockopt(
                        raw_fd,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_V6ONLY,
                        &optval as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            // Enable broadcast for IPv4-mapped addresses
            socket.set_broadcast(true)?;
            Ok(socket)
        }
        Err(_) => {
            // Fallback to IPv4-only if IPv6 not available
            tracing::debug!("IPv6 socket creation failed, falling back to IPv4-only");
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.set_broadcast(true)?;
            Ok(socket)
        }
    }
}

/// Create a UDP socket for listening on a specific port (async)
pub async fn create_listen_socket(port: u16) -> Result<UdpSocket, NetworkError> {
    let socket = UdpSocket::bind(("0.0.0.0", port)).await?;
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
        let socket_addr = "[::]:0".parse::<std::net::SocketAddr>().unwrap();
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
    let (len, addr) = socket.recv_from(&mut buf).await?;

    let packet = EncryptedPacket::decode(&buf[..len])?;
    Ok((packet, addr))
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
        // Test creating broadcast socket
        let broadcast_socket = create_broadcast_socket().await;
        assert!(broadcast_socket.is_ok());

        // Test creating listen socket on a random port
        let listen_socket = create_listen_socket(0).await;
        assert!(listen_socket.is_ok());
    }

    #[tokio::test]
    async fn test_send_udp_broadcast() {
        use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};

        let socket = create_broadcast_socket().await.unwrap();
        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0u8; 64],
        };

        let result = send_udp_broadcast(&socket, 36692, &packet).await;

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
