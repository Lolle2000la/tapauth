use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use super::NetworkError;

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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_listener() {
        let listener = create_tcp_listener(0);
        assert!(listener.is_ok());
    }
}
