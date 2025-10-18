use prost::Message;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use super::NetworkError;
use crate::protocol::pb::WrapperMessage;

/// Create a TCP listener for pairing
pub fn create_tcp_listener(port: u16) -> Result<TcpListener, NetworkError> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    listener.set_nonblocking(false)?;
    Ok(listener)
}

/// Accept a TCP connection with timeout
pub fn accept_connection(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), NetworkError> {
    listener.set_nonblocking(true)?;

    let start = std::time::Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                return Ok((stream, addr));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() >= timeout {
                    return Err(NetworkError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Connect to a TCP server
pub fn connect_tcp(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, NetworkError> {
    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    Ok(stream)
}

/// Send a WrapperMessage over TCP
pub fn send_tcp_message(
    stream: &mut TcpStream,
    message: &WrapperMessage,
) -> Result<(), NetworkError> {
    let data = message.encode_to_vec();

    // Send length prefix (4 bytes, big-endian)
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;

    // Send message data
    stream.write_all(&data)?;
    stream.flush()?;

    Ok(())
}

/// Receive a WrapperMessage from TCP
pub fn receive_tcp_message(stream: &mut TcpStream) -> Result<WrapperMessage, NetworkError> {
    // Read length prefix (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check: limit message size to 1MB
    if len > 1_000_000 {
        return Err(NetworkError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Message too large",
        )));
    }

    // Read message data
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;

    // Decode message
    let message = WrapperMessage::decode(&data[..])?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::pb::*;

    #[test]
    fn test_tcp_listener() {
        let listener = create_tcp_listener(0);
        assert!(listener.is_ok());
    }

    #[test]
    fn test_message_serialization() {
        let message = WrapperMessage {
            version: 1,
            payload: None,
        };

        let encoded = message.encode_to_vec();
        let decoded = WrapperMessage::decode(&encoded[..]).unwrap();

        assert_eq!(message.version, decoded.version);
    }
}
