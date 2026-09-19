pub mod discovery;
pub mod tcp;
pub mod udp;

pub use discovery::*;
pub use tcp::*;
pub use udp::*;

pub use udp::{get_multicast_interfaces, MulticastInterface};

/// Default UDP port for authentication
pub const DEFAULT_UDP_PORT: u16 = 36692;

/// IPv4 multicast group for local-network discovery.
///
/// Deliberately *not* the broadcast address: an administratively scoped group
/// limits processing to hosts that actually joined it. The address sits inside
/// the IPv4 Local Scope (`239.255.0.0/16`, RFC 2365) and is not assigned by
/// IANA (the only entries in that scope are the small set of relative offsets
/// at the top of the block, e.g. SSDP's `239.255.255.250`).
///
/// Derived from `SHA-256("org.tapauth.multicast.group.v1")` bytes 3-4 so it is
/// stable but unlikely to collide with another application's group.
///
/// Must stay in sync with `IPV4_MULTICAST_GROUP` in
/// `server-android/.../service/AuthenticationService.kt`.
pub const IPV4_MULTICAST_ADDR: &str = "239.255.26.44";

/// IPv6 multicast group for local-network discovery.
///
/// Link-local scope (`ff*2::/16`), so it is never routed off the segment. The
/// transient flag is set (`ff12::`), i.e. this is a dynamically assigned group
/// rather than an IANA permanent one. The low 32 bits are the IPv6 group ID
/// and fall inside the IANA "Reserved for Private Use" dynamic range
/// (`0xFD000000`-`0xFDFFFFFF`, RFC 10028), so no IANA allocation can collide.
///
/// Derived from `SHA-256("org.tapauth.multicast.group.v1")` bytes 0-2. This is
/// a link-local address, so sends must specify an interface scope (handled by
/// `send_udp_multicast_all_interfaces`).
///
/// Must stay in sync with `IPV6_MULTICAST_GROUP` in
/// `server-android/.../service/AuthenticationService.kt`.
pub const IPV6_MULTICAST_ADDR: &str = "ff12::fdec:fc27";

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
