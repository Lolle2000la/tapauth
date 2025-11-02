//! Shared types for transport implementations

use shared::protocol::pb::EncryptedPacket;
use std::net::SocketAddr;

/// Result of attempting to receive an authentication response
#[derive(Debug)]
pub enum ReceiveResult {
    /// Successfully received a response packet from the given address
    Response(EncryptedPacket, SocketAddr),
    /// No response received within the timeout
    Timeout,
}
