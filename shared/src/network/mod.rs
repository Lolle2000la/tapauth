pub mod discovery;
pub mod tcp;
pub mod udp;

pub use discovery::*;
pub use tcp::*;
pub use udp::*;

/// Default UDP port for authentication
pub const DEFAULT_UDP_PORT: u16 = 36692;

/// IPv6 multicast address for discovery
pub const IPV6_MULTICAST_ADDR: &str = "ff02::bfb4:3e78:bc99:80f5:f6e5:9e8e:45b8";

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("Decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("No response received")]
    NoResponse,
    #[error("Timeout")]
    Timeout,
}
