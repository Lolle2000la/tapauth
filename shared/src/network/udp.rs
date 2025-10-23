use prost::Message;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

use super::NetworkError;
use crate::protocol::pb::EncryptedPacket;

// Track whether IPv6 is available (cached after first check)
static IPV6_AVAILABLE: AtomicBool = AtomicBool::new(true);
static IPV6_CHECKED: AtomicBool = AtomicBool::new(false);

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
pub async fn create_broadcast_socket() -> Result<UdpSocket, NetworkError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    Ok(socket)
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

/// Send an encrypted packet via UDP multicast (IPv6) - async
/// Returns Ok(()) if sent successfully, or Err if IPv6 is unavailable or send fails
pub async fn send_udp_multicast(
    socket: &UdpSocket,
    multicast_addr: &str,
    port: u16,
    packet: &EncryptedPacket,
) -> Result<(), NetworkError> {
    let data = packet.encode_to_vec();
    let addr: SocketAddr = format!("[{}]:{}", multicast_addr, port)
        .parse()
        .map_err(|_| {
            NetworkError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid multicast address",
            ))
        })?;

    // Try to send, but provide a more specific error for IPv6 unavailability
    match socket.send_to(&data, addr).await {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == Some(97) => {
            // EAFNOSUPPORT (97) - Address family not supported by protocol
            Err(NetworkError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "IPv6 not available on this system",
            )))
        }
        Err(e) => Err(NetworkError::Io(e)),
    }
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

    #[test]
    fn test_create_sockets() {
        // Test creating broadcast socket
        let broadcast_socket = create_broadcast_socket();
        assert!(broadcast_socket.is_ok());

        // Test creating listen socket on a random port
        let listen_socket = create_listen_socket(0);
        assert!(listen_socket.is_ok());
    }
}
