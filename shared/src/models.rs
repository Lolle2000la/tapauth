/// BLE Service and Characteristic UUIDs
pub mod ble {
    /// TapAuth BLE GATT Service UUID
    /// Also used as the key for service data in BLE advertisements
    pub const SERVICE_UUID: &str = "b4ad84c0-2adb-4876-8315-b39d983b2bde";

    /// Client Command Characteristic UUID (Server reads auth request from this)
    pub const CLIENT_COMMAND_CHAR_UUID: &str = "caf54438-9d78-4697-8886-0a4cfa87ba8d";

    /// Server Response Characteristic UUID (Server writes auth response to this)
    pub const SERVER_RESPONSE_CHAR_UUID: &str = "ca6238be-c194-49b7-855b-58f41d3da626";

    /// Client Confirmation Characteristic UUID (Server reads confirmation from this)
    pub const CLIENT_CONFIRMATION_CHAR_UUID: &str = "ace3e9ad-5f0d-48bf-825a-5b7f4dc49cdf";

    /// Pairing Channel Characteristic UUID — unified bidirectional channel for
    /// v2 `PairingPacket` frames (ble-gatt-specification.md §2.4).
    pub const PAIRING_CHAR_UUID: &str = "d9e8f1a2-3b4c-4d5e-8f60-7a8b9c0d1e2f";

    /// Largest GATT payload a single ATT notification/PDU carries under an MTU
    /// of 517 (`EncryptedPacket` ≤ 470 B, `PairingPacket` ≤ 300 B fit under it).
    pub const MAX_GATT_PAYLOAD_BYTES: usize = 512;
}

/// Pairing QR code URL format
pub mod pairing {
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Length of the v2 pairing session id (`sid`): 16 raw bytes, 32 hex chars.
    const SESSION_ID_LEN: usize = 16;

    #[derive(thiserror::Error, Debug)]
    pub enum PairingInfoError {
        #[error("invalid URL scheme")]
        InvalidScheme,
        #[error("invalid query parameter")]
        InvalidQuery,
        #[error("invalid version number")]
        InvalidVersion,
        #[error("invalid port number")]
        InvalidPort,
        #[error("invalid IPv4 address")]
        InvalidIpv4,
        #[error("invalid IPv6 address")]
        InvalidIpv6,
        #[error("invalid session id")]
        InvalidSessionId,
        #[error("missing field: {0}")]
        MissingField(&'static str),
    }

    /// Generate a v1 pairing URL for QR code
    pub fn generate_pairing_url(
        public_key_hex: &str,
        port: u16,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> String {
        let mut url = format!("tapauth://pair?v=1&pk={}&p={}", public_key_hex, port);

        if let Some(ip) = ipv4 {
            url.push_str(&format!("&ip4={}", ip));
        }

        if let Some(ip) = ipv6 {
            url.push_str(&format!("&ip6={}", ip));
        }

        url
    }

    /// Generate a v2 pairing URL for QR code:
    ///
    /// ```text
    /// tapauth://pair?v=2&sid=<32 hex>&pk=<x25519 hex>[&p=<port>][&ip4=<ipv4>][&ip6=<ipv6>]
    /// ```
    ///
    /// `p`/`ip4`/`ip6` are omitted for a BLE-only pairing session
    /// (initial-key-exchange.md Step 1).
    pub fn generate_pairing_url_v2(
        session_id: &[u8; 16],
        client_x25519_public_key_hex: &str,
        port: Option<u16>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> String {
        let mut url = format!(
            "tapauth://pair?v=2&sid={}&pk={}",
            hex::encode(session_id),
            client_x25519_public_key_hex
        );

        if let Some(port) = port {
            url.push_str(&format!("&p={}", port));
        }

        if let Some(ip) = ipv4 {
            url.push_str(&format!("&ip4={}", ip));
        }

        if let Some(ip) = ipv6 {
            url.push_str(&format!("&ip6={}", ip));
        }

        url
    }

    /// Parse a pairing URL
    #[derive(Debug, Clone)]
    pub struct PairingInfo {
        pub version: u32,
        /// v2 session id (`sid`); `None` for a v1 URL.
        pub session_id: Option<[u8; 16]>,
        pub public_key_hex: String,
        /// v1 requires the UDP port; v2 may omit it for BLE-only pairing.
        pub port: Option<u16>,
        pub ipv4: Option<Ipv4Addr>,
        pub ipv6: Option<Ipv6Addr>,
    }

    impl PairingInfo {
        pub fn parse(url: &str) -> Result<Self, PairingInfoError> {
            if !url.starts_with("tapauth://pair?") {
                return Err(PairingInfoError::InvalidScheme);
            }

            let query = &url[15..];
            let mut version = None;
            let mut session_id = None;
            let mut public_key_hex = None;
            let mut port = None;
            let mut ipv4 = None;
            let mut ipv6 = None;

            for pair in query.split('&') {
                let mut parts = pair.split('=');
                let key = parts.next().ok_or(PairingInfoError::InvalidQuery)?;
                let value = parts.next().ok_or(PairingInfoError::InvalidQuery)?;

                match key {
                    "v" => {
                        version = Some(
                            value
                                .parse()
                                .map_err(|_| PairingInfoError::InvalidVersion)?,
                        )
                    }
                    "sid" => session_id = Some(parse_session_id(value)?),
                    "pk" => public_key_hex = Some(value.to_string()),
                    "p" => port = Some(value.parse().map_err(|_| PairingInfoError::InvalidPort)?),
                    "ip4" => ipv4 = Some(value.parse().map_err(|_| PairingInfoError::InvalidIpv4)?),
                    "ip6" => ipv6 = Some(value.parse().map_err(|_| PairingInfoError::InvalidIpv6)?),
                    _ => {}
                }
            }

            let version = version.ok_or(PairingInfoError::MissingField("version"))?;
            let public_key_hex =
                public_key_hex.ok_or(PairingInfoError::MissingField("public key"))?;

            match version {
                // v1 carries no session id and always carries the UDP port.
                1 => Ok(Self {
                    version,
                    session_id: None,
                    public_key_hex,
                    port: Some(port.ok_or(PairingInfoError::MissingField("port"))?),
                    ipv4,
                    ipv6,
                }),
                // v2 always carries the session id; the transport fields are
                // optional because a BLE-only session has neither.
                2 => Ok(Self {
                    version,
                    session_id: Some(
                        session_id.ok_or(PairingInfoError::MissingField("session id"))?,
                    ),
                    public_key_hex,
                    port,
                    ipv4,
                    ipv6,
                }),
                _ => Err(PairingInfoError::InvalidVersion),
            }
        }
    }

    /// Decode a 32-hex-character v2 session id into its 16 raw bytes.
    fn parse_session_id(value: &str) -> Result<[u8; SESSION_ID_LEN], PairingInfoError> {
        let bytes = hex::decode(value).map_err(|_| PairingInfoError::InvalidSessionId)?;
        let array: [u8; SESSION_ID_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| PairingInfoError::InvalidSessionId)?;
        Ok(array)
    }
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
    fn test_pairing_url_generation() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let url = pairing::generate_pairing_url(
            "aabbccdd",
            12345,
            Some(Ipv4Addr::new(192, 168, 1, 100)),
            Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        );

        assert!(url.starts_with("tapauth://pair?"));
        assert!(url.contains("pk=aabbccdd"));
        assert!(url.contains("p=12345"));
        assert!(url.contains("ip4=192.168.1.100"));
    }

    #[test]
    fn test_pairing_url_parsing() {
        let url = "tapauth://pair?v=1&pk=aabbccdd&p=12345&ip4=192.168.1.100";
        let info = pairing::PairingInfo::parse(url).unwrap();

        assert_eq!(info.version, 1);
        assert_eq!(info.public_key_hex, "aabbccdd");
        assert_eq!(info.port, Some(12345));
        assert!(info.ipv4.is_some());
    }

    #[test]
    fn test_pairing_url_missing_required_fields() {
        // Missing public key
        let url1 = "tapauth://pair?v=1&p=12345";
        assert!(pairing::PairingInfo::parse(url1).is_err());

        // Missing port
        let url2 = "tapauth://pair?v=1&pk=aabbccdd";
        assert!(pairing::PairingInfo::parse(url2).is_err());

        // Missing version
        let url3 = "tapauth://pair?pk=aabbccdd&p=12345";
        assert!(pairing::PairingInfo::parse(url3).is_err());
    }

    #[test]
    fn test_pairing_url_with_ipv6() {
        use std::net::Ipv6Addr;

        let url = pairing::generate_pairing_url(
            "test123",
            8080,
            None,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        assert!(url.contains("pk=test123"));
        assert!(url.contains("p=8080"));
        assert!(url.contains("ip6="));
    }

    #[test]
    fn test_pairing_url_round_trip() {
        use std::net::Ipv4Addr;

        let original_key = "fedcba9876543210";
        let original_port = 9999;
        let original_ip = Ipv4Addr::new(10, 0, 0, 1);

        let url =
            pairing::generate_pairing_url(original_key, original_port, Some(original_ip), None);
        let parsed = pairing::PairingInfo::parse(&url).unwrap();

        assert_eq!(parsed.public_key_hex, original_key);
        assert_eq!(parsed.port, Some(original_port));
        assert_eq!(parsed.ipv4, Some(original_ip));
        assert_eq!(parsed.session_id, None);
    }

    #[test]
    fn test_pairing_url_invalid_scheme() {
        let url = "http://pair?v=1&pk=aabbccdd&p=12345";
        assert!(pairing::PairingInfo::parse(url).is_err());
    }

    #[test]
    fn test_pairing_url_duplicate_parameters() {
        // Last value should win for duplicate parameters
        let url = "tapauth://pair?v=1&pk=first_key&p=12345&pk=second_key";
        let info = pairing::PairingInfo::parse(url).unwrap();
        assert_eq!(info.public_key_hex, "second_key");
    }

    #[test]
    fn test_pairing_url_unknown_parameters_ignored() {
        // Unknown parameters should be silently ignored
        let url = "tapauth://pair?v=1&pk=abc&p=12345&extra=ignored&random=stuff";
        let info = pairing::PairingInfo::parse(url).unwrap();
        assert_eq!(info.public_key_hex, "abc");
        assert_eq!(info.port, Some(12345));
    }

    #[test]
    fn test_pairing_url_malformed_ipv4() {
        let url = "tapauth://pair?v=1&pk=abc&p=12345&ip4=not_an_ip";
        assert!(pairing::PairingInfo::parse(url).is_err());
    }

    #[test]
    fn test_pairing_url_malformed_ipv6() {
        let url = "tapauth://pair?v=1&pk=abc&p=12345&ip6=not_an_ip";
        assert!(pairing::PairingInfo::parse(url).is_err());
    }

    /// A v1 QR code still parses, with no session id, after the v2 change.
    /// The defect this catches: v1 URLs rejected (`MissingField("session id")`)
    /// during a rollout, which would make every already-printed QR code fail.
    #[test]
    fn test_pairing_url_v1_has_no_session_id() {
        let url = "tapauth://pair?v=1&pk=aabbccdd&p=12345";
        let info = pairing::PairingInfo::parse(url).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.session_id, None);
        assert_eq!(info.port, Some(12345));
        assert_eq!(info.ipv4, None);
        assert_eq!(info.ipv6, None);
    }

    /// v2 round-trip with a UDP pairing port and both addresses.
    /// The defect this catches: the `sid` hex encoding/decoding disagreeing
    /// (e.g. wrong byte order or length), or the optional fields dropped.
    #[test]
    fn test_pairing_url_v2_round_trip() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let session_id: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0xFF,
        ];
        let public_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let ipv4 = Ipv4Addr::new(192, 168, 1, 100);
        let ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        let url = pairing::generate_pairing_url_v2(
            &session_id,
            public_key,
            Some(40000),
            Some(ipv4),
            Some(ipv6),
        );

        assert!(
            url.starts_with("tapauth://pair?v=2&sid=000102030405060708090a0b0c0d0eff&pk="),
            "unexpected URL prefix: {}",
            url
        );

        let parsed = pairing::PairingInfo::parse(&url).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.session_id, Some(session_id));
        assert_eq!(parsed.public_key_hex, public_key);
        assert_eq!(parsed.port, Some(40000));
        assert_eq!(parsed.ipv4, Some(ipv4));
        assert_eq!(parsed.ipv6, Some(ipv6));
    }

    /// A BLE-only v2 QR code has no `p`/`ip4`/`ip6`.
    /// The defect this catches: the port being required again, which would make
    /// BLE-only pairing impossible.
    #[test]
    fn test_pairing_url_v2_ble_only() {
        let session_id = [0xABu8; 16];
        let url = pairing::generate_pairing_url_v2(&session_id, "cafebabe", None, None, None);

        assert_eq!(
            url,
            "tapauth://pair?v=2&sid=abababababababababababababababab&pk=cafebabe"
        );

        let parsed = pairing::PairingInfo::parse(&url).unwrap();
        assert_eq!(parsed.session_id, Some(session_id));
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.ipv4, None);
        assert_eq!(parsed.ipv6, None);
    }

    /// A present-but-invalid `sid`, or a v2 URL without one, is rejected with a
    /// distinct error — never silently treated as a v1 session.
    #[test]
    fn test_pairing_url_v2_invalid_session_id() {
        // Too short, not hex, and too long.
        let too_long = "aa".repeat(17);
        for sid in [
            "abcd",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            too_long.as_str(),
        ] {
            let url = format!("tapauth://pair?v=2&sid={}&pk=abc&p=1234", sid);
            match pairing::PairingInfo::parse(&url) {
                Err(pairing::PairingInfoError::InvalidSessionId) => {}
                other => panic!(
                    "expected InvalidSessionId for sid {:?}, got {:?}",
                    sid, other
                ),
            }
        }

        // Missing sid entirely.
        let url = "tapauth://pair?v=2&pk=abc&p=1234";
        match pairing::PairingInfo::parse(url) {
            Err(pairing::PairingInfoError::MissingField("session id")) => {}
            other => panic!("expected MissingField(\"session id\"), got {:?}", other),
        }
    }

    /// v2 with a duplicate `sid` keeps the last value (same rule as every other
    /// query parameter).
    #[test]
    fn test_pairing_url_v2_duplicate_session_id_last_wins() {
        let url = "tapauth://pair?v=2&sid=00000000000000000000000000000000&pk=abc\
                   &sid=11111111111111111111111111111111";
        let parsed = pairing::PairingInfo::parse(url).unwrap();
        assert_eq!(parsed.session_id, Some([0x11u8; 16]));
    }

    /// The pairing channel UUID must be the one both transports open
    /// (ble-gatt-specification.md §2.4), and the GATT payload ceiling is 512 B.
    /// The defect this catches: a transcription slip in the UUID, so Linux
    /// registers one characteristic and Android subscribes to another.
    #[test]
    fn test_ble_pairing_constants() {
        assert_eq!(
            ble::PAIRING_CHAR_UUID,
            "d9e8f1a2-3b4c-4d5e-8f60-7a8b9c0d1e2f"
        );
        assert_eq!(ble::MAX_GATT_PAYLOAD_BYTES, 512);
        // Distinct from the three authentication characteristics.
        for other in [
            ble::CLIENT_COMMAND_CHAR_UUID,
            ble::SERVER_RESPONSE_CHAR_UUID,
            ble::CLIENT_CONFIRMATION_CHAR_UUID,
        ] {
            assert_ne!(ble::PAIRING_CHAR_UUID, other);
        }
    }
}
