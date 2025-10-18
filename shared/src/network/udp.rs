use prost::Message;
use std::net::{SocketAddr, UdpSocket, Ipv4Addr};
use std::time::Duration;

use crate::protocol::pb::EncryptedPacket;
use super::NetworkError;

/// Create a UDP socket for broadcasting/multicasting
pub fn create_broadcast_socket() -> Result<UdpSocket, NetworkError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    Ok(socket)
}

/// Create a UDP socket for listening on a specific port
pub fn create_listen_socket(port: u16) -> Result<UdpSocket, NetworkError> {
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    Ok(socket)
}

/// Send an encrypted packet via UDP broadcast (IPv4)
pub fn send_udp_broadcast(
    socket: &UdpSocket,
    port: u16,
    packet: &EncryptedPacket,
) -> Result<(), NetworkError> {
    let data = packet.encode_to_vec();
    let addr = SocketAddr::from((Ipv4Addr::BROADCAST, port));
    socket.send_to(&data, addr)?;
    Ok(())
}

/// Send an encrypted packet via UDP multicast (IPv6)
pub fn send_udp_multicast(
    socket: &UdpSocket,
    multicast_addr: &str,
    port: u16,
    packet: &EncryptedPacket,
) -> Result<(), NetworkError> {
    let data = packet.encode_to_vec();
    let addr: SocketAddr = format!("[{}]:{}", multicast_addr, port).parse()
        .map_err(|_| NetworkError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid multicast address"
        )))?;
    socket.send_to(&data, addr)?;
    Ok(())
}

/// Send an encrypted packet via UDP unicast
pub fn send_udp_unicast(
    socket: &UdpSocket,
    addr: SocketAddr,
    packet: &EncryptedPacket,
) -> Result<(), NetworkError> {
    let data = packet.encode_to_vec();
    socket.send_to(&data, addr)?;
    Ok(())
}

/// Receive an encrypted packet from UDP
pub fn receive_udp_packet(
    socket: &UdpSocket,
) -> Result<(EncryptedPacket, SocketAddr), NetworkError> {
    let mut buf = [0u8; 65536];
    let (len, addr) = socket.recv_from(&mut buf)?;
    
    let packet = EncryptedPacket::decode(&buf[..len])?;
    Ok((packet, addr))
}

/// Try to receive an encrypted packet with timeout
pub fn try_receive_udp_packet(
    socket: &UdpSocket,
    timeout: Duration,
) -> Result<Option<(EncryptedPacket, SocketAddr)>, NetworkError> {
    socket.set_read_timeout(Some(timeout))?;
    
    match receive_udp_packet(socket) {
        Ok(result) => Ok(Some(result)),
        Err(NetworkError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(NetworkError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
        Err(e) => Err(e),
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
