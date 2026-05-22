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
}

/// Pairing QR code URL format
pub mod pairing {
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Generate a pairing URL for QR code
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

    /// Parse a pairing URL
    #[derive(Debug, Clone)]
    pub struct PairingInfo {
        pub version: u32,
        pub public_key_hex: String,
        pub port: u16,
        pub ipv4: Option<Ipv4Addr>,
        pub ipv6: Option<Ipv6Addr>,
    }

    impl PairingInfo {
        pub fn parse(url: &str) -> Result<Self, String> {
            if !url.starts_with("tapauth://pair?") {
                return Err("Invalid URL scheme".to_string());
            }

            let query = &url[15..];
            let mut version = None;
            let mut public_key_hex = None;
            let mut port = None;
            let mut ipv4 = None;
            let mut ipv6 = None;

            for pair in query.split('&') {
                let mut parts = pair.split('=');
                let key = parts.next().ok_or("Invalid query")?;
                let value = parts.next().ok_or("Invalid query")?;

                match key {
                    "v" => version = Some(value.parse().map_err(|_| "Invalid version")?),
                    "pk" => public_key_hex = Some(value.to_string()),
                    "p" => port = Some(value.parse().map_err(|_| "Invalid port")?),
                    "ip4" => ipv4 = Some(value.parse().map_err(|_| "Invalid IPv4")?),
                    "ip6" => ipv6 = Some(value.parse().map_err(|_| "Invalid IPv6")?),
                    _ => {}
                }
            }

            Ok(Self {
                version: version.ok_or("Missing version")?,
                public_key_hex: public_key_hex.ok_or("Missing public key")?,
                port: port.ok_or("Missing port")?,
                ipv4,
                ipv6,
            })
        }
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
        assert_eq!(info.port, 12345);
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
        assert_eq!(parsed.port, original_port);
        assert_eq!(parsed.ipv4, Some(original_ip));
    }

    #[test]
    fn test_pairing_url_invalid_scheme() {
        let url = "http://pair?v=1&pk=aabbccdd&p=12345";
        assert!(pairing::PairingInfo::parse(url).is_err());
    }
}
