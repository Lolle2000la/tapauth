pub mod discovery;
pub mod tcp;
pub mod udp;

pub use discovery::*;
pub use tcp::*;
pub use udp::*;

pub use udp::{get_multicast_interfaces, MulticastInterface};

/// Default UDP port for authentication
pub const DEFAULT_UDP_PORT: u16 = 36692;

/// IPv6 multicast address for discovery (all nodes on local network segment)
/// Note: This is a link-local multicast address that requires an interface scope
pub const IPV6_MULTICAST_ADDR: &str = "ff02::1";

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
