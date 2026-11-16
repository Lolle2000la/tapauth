use super::PAIRING_SESSION_ID_LEN;
use crate::protocol::messages::{ProtocolError, PROTOCOL_VERSION_V2};
use crate::protocol::pb::PairingPacket;
use prost::Message as ProstMessage;

/// Envelope rules shared by the encoder, the decoder and the session-id accessor:
/// the v2 framing and a full-length session id, both checked before anything reads
/// the body.
fn validate_envelope(packet: &PairingPacket) -> Result<(), ProtocolError> {
    if packet.version != PROTOCOL_VERSION_V2 {
        return Err(ProtocolError::InvalidMessageFormat);
    }
    if packet.session_id.len() != PAIRING_SESSION_ID_LEN {
        return Err(ProtocolError::InvalidMessageFormat);
    }
    Ok(())
}

/// Encode a [`PairingPacket`] for a UDP datagram payload or a BLE GATT value.
///
/// Rejects a version other than
/// [`PROTOCOL_VERSION_V2`](crate::protocol::messages::PROTOCOL_VERSION_V2) and a `session_id` that
/// is not exactly [`PAIRING_SESSION_ID_LEN`] bytes.
pub fn encode_pairing_packet(packet: &PairingPacket) -> Result<Vec<u8>, ProtocolError> {
    validate_envelope(packet)?;
    Ok(packet.encode_to_vec())
}

/// Decode a [`PairingPacket`] received from UDP or BLE.
///
/// The same envelope rules as [`encode_pairing_packet`] apply, so a caller never
/// has to defend against a foreign protocol version or a truncated session id.
pub fn decode_pairing_packet(bytes: &[u8]) -> Result<PairingPacket, ProtocolError> {
    let packet = PairingPacket::decode(bytes)?;
    validate_envelope(&packet)?;
    Ok(packet)
}

/// Extract the validated `session_id` of a frame for session filtering.
pub fn pairing_session_id(
    packet: &PairingPacket,
) -> Result<[u8; PAIRING_SESSION_ID_LEN], ProtocolError> {
    validate_envelope(packet)?;
    packet
        .session_id
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::InvalidMessageFormat)
}

/// The address information a pairing session publishes in its QR code.
///
/// These values never enter the transcript; they only build the
/// `tapauth://pair?v=2&...` URL. Every field is optional, and `Default` is the
/// BLE-only endpoint that publishes none of them.
#[derive(Debug, Clone, Copy, Default)]
pub struct PairingEndpoint {
    /// The UDP pairing port, or `None` when this session has no UDP endpoint
    /// (the network transport is disabled and the phone pairs over BLE only).
    /// `None` omits `&p=` from the QR code entirely; `&p=0` would advertise a
    /// port nothing can send to.
    pub udp_port: Option<u16>,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// What the desktop needs to show/emit after [`ClientPairingState::start`](crate::protocol::pairing::ClientPairingState::start).
pub struct StartedPairing {
    /// Random 16-byte session id (`sid`), also carried by every `PairingPacket`.
    pub session_id: [u8; PAIRING_SESSION_ID_LEN],
    /// Ephemeral X25519 public key `X_C` — the `pk` committed in the QR code.
    pub client_x25519_public_key: [u8; 32],
    /// 10-byte identifier to advertise in `ServiceData(SERVICE_UUID)` while pairing.
    pub pairing_adv_id: [u8; 10],
    /// `tapauth://pair?v=2&sid=...&pk=...&p=...` QR code URL.
    pub qr_url: String,
}
