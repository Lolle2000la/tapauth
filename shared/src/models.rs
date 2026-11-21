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

    /// Hex-character length of a v2 pairing session id (`sid`).
    const SESSION_ID_HEX_LEN: usize = SESSION_ID_LEN * 2;

    /// Hex-character length of the client ephemeral X25519 public key (`pk`):
    /// 32 raw bytes, 64 hex chars.
    const PUBLIC_KEY_HEX_LEN: usize = 64;

    /// Lowest `p` that names a usable UDP endpoint; `p=0` is not one.
    const MIN_PORT: u16 = 1;

    /// Longest `tapauth://pair?...` URL [`PairingInfo::parse`] accepts, in bytes.
    ///
    /// The longest legitimate v2 URL — every optional component present, each written
    /// in its longest form — measures 195 bytes: 15 for the scheme and `?`, 4 for
    /// `v=2&`, 36 for `sid=<32 hex>`, 68 for `&pk=<64 hex>`, 8 for `&p=65535`, 20 for
    /// `&ip4=255.255.255.255` and 44 for `&ip6=` plus a full 39-character IPv6 literal.
    /// 512 therefore leaves room for a full-length IPv6 literal twice over and for
    /// another optional parameter, while keeping the QR payload at a module density a
    /// phone camera still reads reliably at pairing distance.
    ///
    /// It is also the first thing [`PairingInfo::parse`] checks, so no later step ever
    /// works on an unbounded input.
    pub const MAX_PAIRING_URL_LEN: usize = 512;

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
        #[error("invalid public key")]
        InvalidPublicKey,
        #[error("pairing URL is too long")]
        UrlTooLong,
        #[error("missing field: {0}")]
        MissingField(&'static str),
    }

    /// Generate a v2 pairing URL for QR code:
    ///
    /// ```text
    /// tapauth://pair?v=2&sid=<32 hex>&pk=<x25519 64 hex>[&p=<port>][&ip4=<ipv4>][&ip6=<ipv6>]
    /// ```
    ///
    /// `p`/`ip4`/`ip6` are omitted for a BLE-only pairing session
    /// (initial-key-exchange.md Step 1).
    ///
    /// # Errors
    ///
    /// [`PairingInfoError::InvalidPublicKey`] when `client_x25519_public_key_hex` is not
    /// exactly 64 hex characters or is the all-zero key, and
    /// [`PairingInfoError::InvalidPort`] for `port == 0`. Every URL this function does
    /// emit is one [`PairingInfo::parse`] accepts: the generator refuses rather than
    /// producing a QR the other side of the wire has to reject.
    pub fn generate_pairing_url_v2(
        session_id: &[u8; 16],
        client_x25519_public_key_hex: &str,
        port: Option<u16>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<String, PairingInfoError> {
        validate_public_key(client_x25519_public_key_hex)?;
        if port == Some(0) {
            return Err(PairingInfoError::InvalidPort);
        }

        Ok(build_pairing_url(
            session_id,
            client_x25519_public_key_hex,
            port,
            ipv4,
            ipv6,
        ))
    }

    /// Generate a v2 pairing URL from the ephemeral public key's raw bytes.
    ///
    /// The infallible companion of [`generate_pairing_url_v2`], for the caller that
    /// holds the key as bytes rather than as hex: `hex::encode` of 32 bytes is always
    /// 64 hex characters, so the string form's only refusal (a malformed `pk`) cannot
    /// arise and there is no error to carry. `Some(0)` is not a UDP endpoint, so it is
    /// written as no `p` at all — the same shape a BLE-only session has.
    pub fn generate_pairing_url_v2_for_key(
        session_id: &[u8; 16],
        client_x25519_public_key: &[u8; 32],
        port: Option<u16>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> String {
        build_pairing_url(
            session_id,
            &hex::encode(client_x25519_public_key),
            port.filter(|port| *port >= MIN_PORT),
            ipv4,
            ipv6,
        )
    }

    /// The one place a pairing URL is assembled, from an already-validated `pk` and an
    /// already-validated port.
    fn build_pairing_url(
        session_id: &[u8; 16],
        public_key_hex: &str,
        port: Option<u16>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> String {
        let mut url = format!(
            "tapauth://pair?v=2&sid={}&pk={}",
            hex::encode(session_id),
            percent_encode(public_key_hex)
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

    /// A parsed v2 pairing URL.
    #[derive(Debug, Clone)]
    pub struct PairingInfo {
        /// Protocol pairing version; always 2 (every other version is rejected).
        pub version: u32,
        /// v2 session id (`sid`), 16 raw bytes.
        pub session_id: [u8; 16],
        pub public_key_hex: String,
        /// UDP pairing port; `None` for a BLE-only pairing session.
        pub port: Option<u16>,
        pub ipv4: Option<Ipv4Addr>,
        pub ipv6: Option<Ipv6Addr>,
    }

    impl PairingInfo {
        /// Parse a `tapauth://pair?v=2&sid=…&pk=…` URL.
        ///
        /// Only `v=2` is accepted: anything else is
        /// [`PairingInfoError::InvalidVersion`]. The `sid` is required and must be
        /// exactly 32 hex characters, the `pk` exactly 64 hex characters and not the
        /// all-zero key; `p`/`ip4`/`ip6` stay optional for a BLE-only session, and `p`
        /// must be a real port (`1..=65535`). Every query key may appear at most once:
        /// a repeated key is [`PairingInfoError::InvalidQuery`] rather than "first
        /// wins" or "last wins". Unknown keys are ignored. Values are
        /// percent-decoded (the exact accepted escapes are documented on the private
        /// `percent_decode` below).
        ///
        /// Panic-freedom here is a property, not a hope: the length cap
        /// ([`MAX_PAIRING_URL_LEN`]) is checked before any other work, so every later
        /// step is bounded by 512 bytes, and nothing allocates from a length the caller
        /// chose — `sid` is validated as 32 hex characters before
        /// `hex::decode_to_slice` writes into a fixed 16-byte buffer, and `pk`'s length
        /// and hex-ness are checked before its string is copied.
        pub fn parse(url: &str) -> Result<Self, PairingInfoError> {
            if url.len() > MAX_PAIRING_URL_LEN {
                return Err(PairingInfoError::UrlTooLong);
            }

            let Some(query) = url.strip_prefix("tapauth://pair?") else {
                return Err(PairingInfoError::InvalidScheme);
            };

            let mut seen: Vec<String> = Vec::new();
            let mut version: Option<String> = None;
            let mut session_id: Option<String> = None;
            let mut public_key_hex: Option<String> = None;
            let mut port: Option<String> = None;
            let mut ipv4: Option<String> = None;
            let mut ipv6: Option<String> = None;

            for pair in query.split('&') {
                // Every pair is `key=value`; an empty pair (a trailing `&`) has no `=`
                // and is refused, as is a value that carries a second `=` of its own —
                // `=` inside a value has to be percent-encoded.
                let (raw_key, raw_value) =
                    pair.split_once('=').ok_or(PairingInfoError::InvalidQuery)?;
                if raw_value.contains('=') {
                    return Err(PairingInfoError::InvalidQuery);
                }

                let key = percent_decode(raw_key)?;
                let value = percent_decode(raw_value)?;

                // At most one of each key, known or not: the two parsers used to
                // disagree about which duplicate they kept (Kotlin first, Rust last),
                // so a QR could pin one `pk` on the desktop and another on the phone.
                if seen.contains(&key) {
                    return Err(PairingInfoError::InvalidQuery);
                }

                let slot = match key.as_str() {
                    "v" => Some(&mut version),
                    "sid" => Some(&mut session_id),
                    "pk" => Some(&mut public_key_hex),
                    "p" => Some(&mut port),
                    "ip4" => Some(&mut ipv4),
                    "ip6" => Some(&mut ipv6),
                    // Unknown parameters stay ignored, so a future extension is
                    // forward-compatible; they still take part in the duplicate rule.
                    _ => None,
                };

                seen.push(key);
                if let Some(slot) = slot {
                    *slot = Some(value);
                }
            }

            let raw_version = version.ok_or(PairingInfoError::MissingField("version"))?;
            let version = parse_ascii_u32(&raw_version).ok_or(PairingInfoError::InvalidVersion)?;
            if version != 2 {
                return Err(PairingInfoError::InvalidVersion);
            }

            let raw_session_id = session_id.ok_or(PairingInfoError::MissingField("session id"))?;
            let session_id = parse_session_id(&raw_session_id)?;

            let public_key_hex =
                public_key_hex.ok_or(PairingInfoError::MissingField("public key"))?;
            validate_public_key(&public_key_hex)?;

            let port = match port.as_deref() {
                Some(value) => Some(parse_port(value)?),
                None => None,
            };

            let ipv4 = match ipv4.as_deref() {
                Some(value) => Some(value.parse().map_err(|_| PairingInfoError::InvalidIpv4)?),
                None => None,
            };

            let ipv6 = match ipv6.as_deref() {
                Some(value) => Some(value.parse().map_err(|_| PairingInfoError::InvalidIpv6)?),
                None => None,
            };

            Ok(Self {
                version,
                session_id,
                public_key_hex,
                port,
                ipv4,
                ipv6,
            })
        }
    }

    /// Validate a `pk` value: exactly 64 hex characters, and not the all-zero key.
    ///
    /// The all-zero key is refused on both sides of the wire. A real Client publishes a
    /// random 32-byte X25519 key, so it never appears in an honest QR, while the phone
    /// reads an all-zero `pk` as the "skip the QR comparison" sentinel — accepting one
    /// from a scanned sticker would let that sticker turn the check off. Rust is the
    /// source of truth here: it rejects, and `PairingUrl.parse` in `Models.kt` rejects
    /// the same value, pinned by `shared/testdata/pairing_url_vectors.json`.
    fn validate_public_key(value: &str) -> Result<(), PairingInfoError> {
        if value.len() != PUBLIC_KEY_HEX_LEN || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PairingInfoError::InvalidPublicKey);
        }
        if value.bytes().all(|byte| byte == b'0') {
            return Err(PairingInfoError::InvalidPublicKey);
        }
        Ok(())
    }

    /// Decode a 32-hex-character v2 session id into its 16 raw bytes.
    ///
    /// The length and hex checks run before the decode, which writes into a fixed-size
    /// buffer and allocates nothing.
    fn parse_session_id(value: &str) -> Result<[u8; SESSION_ID_LEN], PairingInfoError> {
        if value.len() != SESSION_ID_HEX_LEN || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PairingInfoError::InvalidSessionId);
        }
        let mut session_id = [0u8; SESSION_ID_LEN];
        hex::decode_to_slice(value, &mut session_id)
            .map_err(|_| PairingInfoError::InvalidSessionId)?;
        Ok(session_id)
    }

    /// Parse `p`: ASCII digits only, inside `1..=65535`.
    ///
    /// ASCII digits only because both language runtimes are looser than the grammar:
    /// Rust's `u16::from_str` also takes a leading `+`, and Kotlin's `toIntOrNull`
    /// takes non-ASCII digits (`٤٢` is 42 to it). One PC would then accept a port the
    /// other refuses.
    fn parse_port(value: &str) -> Result<u16, PairingInfoError> {
        let port = parse_ascii_u32(value).ok_or(PairingInfoError::InvalidPort)?;
        let port = u16::try_from(port).map_err(|_| PairingInfoError::InvalidPort)?;
        if port < MIN_PORT {
            return Err(PairingInfoError::InvalidPort);
        }
        Ok(port)
    }

    /// Parse a decimal number written only in ASCII digits.
    fn parse_ascii_u32(value: &str) -> Option<u32> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        value.parse().ok()
    }

    /// Decode `%XX` escapes, rejecting anything malformed or non-ASCII.
    ///
    /// The rules are mirrored byte for byte by `percentDecode` in
    /// `server-android/.../data/Models.kt`, because the desktop generates the URL and
    /// the phone is its only consumer: a `%` not followed by two ASCII hex digits, and
    /// an escape whose byte is not ASCII, make the URL invalid rather than becoming a
    /// literal character. Every field of this grammar is ASCII, so such a byte cannot
    /// belong to a valid value, and passing it through (or decoding it to a Latin-1
    /// char, as the phone used to) is how the two parsers came to disagree.
    fn percent_decode(value: &str) -> Result<String, PairingInfoError> {
        let bytes = value.as_bytes();
        if !bytes.contains(&b'%') {
            return Ok(value.to_owned());
        }

        let mut out = Vec::with_capacity(bytes.len());
        let mut rest = bytes;
        loop {
            let Some(position) = rest.iter().position(|byte| *byte == b'%') else {
                out.extend_from_slice(rest);
                break;
            };

            let (plain, escape) = rest.split_at(position);
            out.extend_from_slice(plain);

            let (_, tail) = escape.split_first().ok_or(PairingInfoError::InvalidQuery)?;
            let (high_byte, tail) = tail.split_first().ok_or(PairingInfoError::InvalidQuery)?;
            let (low_byte, tail) = tail.split_first().ok_or(PairingInfoError::InvalidQuery)?;
            let high = hex_digit(*high_byte).ok_or(PairingInfoError::InvalidQuery)?;
            let low = hex_digit(*low_byte).ok_or(PairingInfoError::InvalidQuery)?;
            let decoded = (high << 4) | low;
            if !decoded.is_ascii() {
                return Err(PairingInfoError::InvalidQuery);
            }

            out.push(decoded);
            rest = tail;
        }

        // Only the input's own UTF-8 bytes and decoded ASCII bytes were pushed, so this
        // cannot fail; it is handled rather than unwrapped because the type says it can.
        String::from_utf8(out).map_err(|_| PairingInfoError::InvalidQuery)
    }

    /// Percent-encode a query value: the inverse of [`percent_decode`].
    ///
    /// Only unreserved characters (RFC 3986 §2.3) are left literal. A validated `pk` is
    /// hex, so this leaves every URL the desktop generates today unchanged; it is here
    /// so `generate_pairing_url_v2` cannot emit a value that carries a `&` or an `=`
    /// into the query, which is what used to make `parse(&generate(…))` fail.
    fn percent_encode(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(byte));
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
        out
    }

    /// The value of one ASCII hex digit.
    fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
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

    /// The v2 URL is the only shape this type carries; a v1 URL (`v=1`, no `sid`)
    /// must be refused, never silently parsed as a session without a session id.
    /// The defect this catches: a v1 URL being accepted (as `MissingField("port")`
    /// compatibility, or with `session_id: None`), which would hand the phone an
    /// unbound pairing session.
    #[test]
    fn test_pairing_url_rejects_any_version_but_two() {
        for url in [
            "tapauth://pair?v=1&pk=aabbccdd&p=12345",
            "tapauth://pair?v=1&sid=00000000000000000000000000000000&pk=aabbccdd",
            "tapauth://pair?v=3&sid=00000000000000000000000000000000&pk=aabbccdd",
            "tapauth://pair?v=0&sid=00000000000000000000000000000000&pk=aabbccdd",
        ] {
            match pairing::PairingInfo::parse(url) {
                Err(pairing::PairingInfoError::InvalidVersion) => {}
                other => panic!("expected InvalidVersion for {:?}, got {:?}", url, other),
            }
        }
    }

    /// A v2 URL still requires the version, the session id and the public key.
    /// The defect this catches: any one of those defaulting to an empty value
    /// instead of failing the scan.
    #[test]
    fn test_pairing_url_v2_missing_required_fields() {
        match pairing::PairingInfo::parse("tapauth://pair?sidaabbccdd&pk=abc") {
            Err(pairing::PairingInfoError::InvalidQuery) => {}
            other => panic!("expected InvalidQuery, got {:?}", other),
        }

        match pairing::PairingInfo::parse("tapauth://pair?v=2&sid=00000000000000000000000000000000")
        {
            Err(pairing::PairingInfoError::MissingField("public key")) => {}
            other => panic!("expected MissingField(\"public key\"), got {:?}", other),
        }

        match pairing::PairingInfo::parse("tapauth://pair?pk=aabbccdd") {
            Err(pairing::PairingInfoError::MissingField("version")) => {}
            other => panic!("expected MissingField(\"version\"), got {:?}", other),
        }

        match pairing::PairingInfo::parse("tapauth://pair?v=2&pk=aabbccdd") {
            Err(pairing::PairingInfoError::MissingField("session id")) => {}
            other => panic!("expected MissingField(\"session id\"), got {:?}", other),
        }
    }

    #[test]
    fn test_pairing_url_invalid_scheme() {
        let url = "http://pair?v=2&sid=00000000000000000000000000000000&pk=aabbccdd";
        assert!(pairing::PairingInfo::parse(url).is_err());
    }

    /// A repeated key is refused outright. The test name records the rule this
    /// replaced ("last value should win"): first-wins and last-wins disagree about which
    /// `pk` a scanned QR carries, so the two parsers could pin different keys for the
    /// same sticker. The defect this catches: any duplicate key being resolved by
    /// position instead of being rejected.
    #[test]
    fn test_pairing_url_duplicate_parameters() {
        let url = "tapauth://pair?v=2&sid=00000000000000000000000000000000&pk=first_key&p=12345\
                   &pk=second_key";
        match pairing::PairingInfo::parse(url) {
            Err(pairing::PairingInfoError::InvalidQuery) => {}
            other => panic!("expected InvalidQuery for a duplicate pk, got {:?}", other),
        }
    }

    #[test]
    fn test_pairing_url_unknown_parameters_ignored() {
        // Unknown parameters should be silently ignored
        let url = "tapauth://pair?v=2&sid=00000000000000000000000000000000\
                   &pk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                   &p=12345&extra=ignored&random=stuff";
        let info = pairing::PairingInfo::parse(url).unwrap();
        assert_eq!(
            info.public_key_hex,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(info.port, Some(12345));
    }

    #[test]
    fn test_pairing_url_malformed_ipv4() {
        let url = "tapauth://pair?v=2&sid=00000000000000000000000000000000\
                   &pk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                   &p=12345&ip4=not_an_ip";
        match pairing::PairingInfo::parse(url) {
            Err(pairing::PairingInfoError::InvalidIpv4) => {}
            other => panic!("expected InvalidIpv4, got {:?}", other),
        }
    }

    #[test]
    fn test_pairing_url_malformed_ipv6() {
        let url = "tapauth://pair?v=2&sid=00000000000000000000000000000000\
                   &pk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                   &p=12345&ip6=not_an_ip";
        match pairing::PairingInfo::parse(url) {
            Err(pairing::PairingInfoError::InvalidIpv6) => {}
            other => panic!("expected InvalidIpv6, got {:?}", other),
        }
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
        let public_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let ipv4 = Ipv4Addr::new(192, 168, 1, 100);
        let ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        let url = pairing::generate_pairing_url_v2(
            &session_id,
            public_key,
            Some(40000),
            Some(ipv4),
            Some(ipv6),
        )
        .expect("a 64-hex key and a real port generate a URL");

        assert!(
            url.starts_with("tapauth://pair?v=2&sid=000102030405060708090a0b0c0d0eff&pk="),
            "unexpected URL prefix: {}",
            url
        );

        let parsed = pairing::PairingInfo::parse(&url).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.session_id, session_id);
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
        let url = pairing::generate_pairing_url_v2(
            &session_id,
            "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
            None,
            None,
            None,
        )
        .expect("a 64-hex key with no endpoint generates a URL");

        assert_eq!(
            url,
            "tapauth://pair?v=2&sid=abababababababababababababababab\
             &pk=cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
        );

        let parsed = pairing::PairingInfo::parse(&url).unwrap();
        assert_eq!(parsed.session_id, session_id);
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

    /// v2 with a duplicate `sid` is refused, so the session id is unambiguous.
    ///
    /// The test name records the rule this replaced (the last value won). A repeated
    /// key is now `InvalidQuery` in both languages: the defect this catches is a QR
    /// whose two `sid`s are resolved differently by the desktop and the phone, which
    /// would make the pairing session ids disagree.
    #[test]
    fn test_pairing_url_v2_duplicate_session_id_last_wins() {
        let url = "tapauth://pair?v=2&sid=00000000000000000000000000000000\
                   &pk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                   &sid=11111111111111111111111111111111";
        match pairing::PairingInfo::parse(url) {
            Err(pairing::PairingInfoError::InvalidQuery) => {}
            other => panic!("expected InvalidQuery for a duplicate sid, got {:?}", other),
        }
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

    /// The whole GATT table this side registers, against the specification both transports
    /// are written from (`ble-gatt-specification.md` §2). `tapauthd`'s `transport/ble.rs`
    /// derives its attribute table from these constants and Android's `BleGattService`
    /// copies the same five literals, so a drifted one is served under one UUID and looked
    /// up under another — a link that silently never matches, with no error anywhere.
    ///
    /// The defect this catches: a transcription slip in the service or any of the four
    /// characteristics. Android's copy is pinned separately by `SharedProtocolLiteralsTest`.
    #[test]
    fn test_ble_gatt_uuids_match_the_specification() {
        assert_eq!(ble::SERVICE_UUID, "b4ad84c0-2adb-4876-8315-b39d983b2bde");
        assert_eq!(
            ble::CLIENT_COMMAND_CHAR_UUID,
            "caf54438-9d78-4697-8886-0a4cfa87ba8d"
        );
        assert_eq!(
            ble::SERVER_RESPONSE_CHAR_UUID,
            "ca6238be-c194-49b7-855b-58f41d3da626"
        );
        assert_eq!(
            ble::CLIENT_CONFIRMATION_CHAR_UUID,
            "ace3e9ad-5f0d-48bf-825a-5b7f4dc49cdf"
        );
        assert_eq!(
            ble::PAIRING_CHAR_UUID,
            "d9e8f1a2-3b4c-4d5e-8f60-7a8b9c0d1e2f"
        );
    }

    /// The GATT payload ceiling and the MTU Android negotiates are one budget: a single
    /// ATT PDU carries `MTU - 5` bytes of payload, so the 512-byte ceiling needs an MTU of
    /// 517 (`BleGattService.GATT_REQUESTED_MTU`, `BlePairingClient.TARGET_MTU`).
    ///
    /// The defect this catches: either number moving alone — a ceiling above what the MTU
    /// can carry makes Rust accept frames the stack must fragment or truncate, and a
    /// lowered one silently refuses frames the desktop believes are deliverable. Android's
    /// half of the same assertion is in `SharedProtocolLiteralsTest`.
    #[test]
    fn test_gatt_payload_fits_the_negotiated_mtu() {
        assert_eq!(ble::MAX_GATT_PAYLOAD_BYTES, 512);
        assert_eq!(ble::MAX_GATT_PAYLOAD_BYTES + 5, 517);
    }

    /// A canonical `sid` and `pk`, 32 and 64 lower-case hex characters.
    const SID: &str = "00112233445566778899aabbccddeeff";
    const PK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[derive(serde::Deserialize)]
    struct PairingUrlVectors {
        cases: Vec<PairingUrlVector>,
    }

    #[derive(serde::Deserialize)]
    struct PairingUrlVector {
        name: String,
        url: String,
        accept: bool,
        sid: Option<String>,
        pk: Option<String>,
        port: Option<u16>,
        ip4: Option<String>,
        ip6: Option<String>,
    }

    /// Every pairing-URL vector in `shared/testdata/pairing_url_vectors.json`.
    ///
    /// The same file drives `PairingUrlTest.kt` on the Android side, so the two
    /// parsers cannot drift: the defect this catches is the phone and the desktop
    /// disagreeing about which URLs are pairing URLs and which values they carry —
    /// duplicates resolved first-wins on one side and last-wins on the other, `p=0`
    /// accepted by one and refused by the other, an all-zero `pk` refused by one and
    /// accepted by the other, a short `pk` refused by one and accepted by the other.
    ///
    /// The file lives in `shared/` and the Kotlin test reaches it through a relative
    /// path from its Gradle working directory; this side reads it with `include_str!`,
    /// so only the Kotlin path depends on the undeclared cwd. The case count is
    /// asserted exactly, not as a lower bound: a bound would let the file lose whole
    /// groups (every duplicate case, say) while staying green. Adding a vector means
    /// bumping this number and `PairingUrlTest`'s together.
    #[test]
    fn test_pairing_url_vectors_are_honoured() {
        const EXPECTED_CASES: usize = 49;

        let vectors: PairingUrlVectors =
            serde_json::from_str(include_str!("../testdata/pairing_url_vectors.json"))
                .expect("pairing URL vector file must parse");
        assert_eq!(
            vectors.cases.len(),
            EXPECTED_CASES,
            "the shared vector file must hold exactly {EXPECTED_CASES} cases, found {}",
            vectors.cases.len()
        );

        for case in &vectors.cases {
            let parsed = pairing::PairingInfo::parse(&case.url);
            if !case.accept {
                assert!(
                    parsed.is_err(),
                    "vector '{}' must be refused: {}",
                    case.name,
                    case.url
                );
                continue;
            }

            let info = match parsed {
                Ok(info) => info,
                Err(error) => panic!(
                    "vector '{}' must parse, got {error}: {}",
                    case.name, case.url
                ),
            };
            assert_eq!(
                Some(hex::encode(info.session_id)),
                case.sid,
                "vector '{}' sid",
                case.name
            );
            assert_eq!(
                Some(info.public_key_hex),
                case.pk,
                "vector '{}' pk",
                case.name
            );
            assert_eq!(info.port, case.port, "vector '{}' port", case.name);
            assert_eq!(
                info.ipv4.map(|ip| ip.to_string()),
                case.ip4,
                "vector '{}' ip4",
                case.name
            );
            assert_eq!(
                info.ipv6.map(|ip| ip.to_string()),
                case.ip6,
                "vector '{}' ip6",
                case.name
            );
        }
    }

    proptest::proptest! {
        /// `parse(&generate(x)) == x` for every input the generator accepts, with the
        /// keys drawn as arbitrary bytes and hex-encoded rather than as arbitrary
        /// strings.
        ///
        /// The defect this catches: a URL the generator writes and the parser cannot
        /// read back as the same values — a `pk` carrying a `&` or an `=` split the
        /// query, so `parse` saw a different key than `generate` wrote, and
        /// `p`/`ip4`/`ip6` were silently dropped.
        #[test]
        fn test_pairing_url_round_trip_is_lossless(
            session_id in proptest::arbitrary::any::<[u8; 16]>(),
            pk_bytes in proptest::arbitrary::any::<[u8; 32]>(),
            port in proptest::arbitrary::any::<Option<u16>>(),
            ipv4 in proptest::arbitrary::any::<Option<[u8; 4]>>(),
            ipv6 in proptest::arbitrary::any::<Option<[u8; 16]>>(),
        ) {
            // The all-zero `pk` and port 0 are the two values `generate_pairing_url_v2`
            // refuses on purpose, and no real Client produces either.
            proptest::prop_assume!(pk_bytes.iter().any(|byte| *byte != 0));
            proptest::prop_assume!(port != Some(0));

            let ipv4 = ipv4.map(std::net::Ipv4Addr::from);
            let ipv6 = ipv6.map(std::net::Ipv6Addr::from);
            let public_key_hex = hex::encode(pk_bytes);

            let url =
                pairing::generate_pairing_url_v2(&session_id, &public_key_hex, port, ipv4, ipv6)
                    .expect("a 64-hex key, a real port and both addresses generate a URL");
            proptest::prop_assert!(url.len() <= pairing::MAX_PAIRING_URL_LEN);

            // The byte-taking form is what the QR path uses, so it must produce the same
            // URL for the same key.
            proptest::prop_assert_eq!(
                url.clone(),
                pairing::generate_pairing_url_v2_for_key(&session_id, &pk_bytes, port, ipv4, ipv6)
            );

            let parsed = match pairing::PairingInfo::parse(&url) {
                Ok(parsed) => parsed,
                Err(error) => {
                    return Err(proptest::test_runner::TestCaseError::fail(format!(
                        "{url} must parse: {error}"
                    )));
                }
            };

            proptest::prop_assert_eq!(parsed.version, 2);
            proptest::prop_assert_eq!(parsed.session_id, session_id);
            proptest::prop_assert_eq!(parsed.public_key_hex, public_key_hex);
            proptest::prop_assert_eq!(parsed.port, port);
            proptest::prop_assert_eq!(parsed.ipv4, ipv4);
            proptest::prop_assert_eq!(parsed.ipv6, ipv6);
        }
    }

    /// The length cap, on both sides of the boundary.
    ///
    /// The defect this catches: a cap that is off by one (a URL of exactly 512 bytes
    /// refused, or 513 accepted), which the QR side would then disagree with.
    #[test]
    fn test_pairing_url_enforces_max_length() {
        let base = format!("tapauth://pair?v=2&sid={SID}&pk={PK}&note=");
        assert_eq!(pairing::MAX_PAIRING_URL_LEN, 512);

        let at_cap = format!(
            "{base}{}",
            "x".repeat(pairing::MAX_PAIRING_URL_LEN - base.len())
        );
        assert_eq!(at_cap.len(), pairing::MAX_PAIRING_URL_LEN);
        let info = pairing::PairingInfo::parse(&at_cap)
            .expect("a URL of exactly the cap is still a pairing URL");
        assert_eq!(hex::encode(info.session_id), SID);
        assert_eq!(info.public_key_hex, PK);

        let over_cap = format!("{at_cap}y");
        assert_eq!(over_cap.len(), pairing::MAX_PAIRING_URL_LEN + 1);
        match pairing::PairingInfo::parse(&over_cap) {
            Err(pairing::PairingInfoError::UrlTooLong) => {}
            other => panic!("expected UrlTooLong for 513 bytes, got {:?}", other),
        }
    }

    /// `p` outside `1..=65535` is refused, and only ASCII digits are a number.
    ///
    /// The defect this catches: `p=0` accepted by the desktop and refused by the phone
    /// (the Rust parser took any `u16`), plus the looser forms both runtimes would
    /// otherwise take — a leading `+` or a non-ASCII digit.
    #[test]
    fn test_pairing_url_rejects_port_out_of_range() {
        for value in [
            "0",
            "65536",
            "4294967296",
            "-1",
            "abc",
            "",
            " 80",
            "+80",
            "٤٢",
        ] {
            let url = format!("tapauth://pair?v=2&sid={SID}&pk={PK}&p={value}");
            match pairing::PairingInfo::parse(&url) {
                Err(pairing::PairingInfoError::InvalidPort) => {}
                other => panic!("expected InvalidPort for p={value:?}, got {:?}", other),
            }
        }

        for (value, expected) in [("1", 1u16), ("65535", 65535)] {
            let url = format!("tapauth://pair?v=2&sid={SID}&pk={PK}&p={value}");
            assert_eq!(
                pairing::PairingInfo::parse(&url).unwrap().port,
                Some(expected)
            );
        }
    }

    /// Query values are percent-decoded, keys included, and only ASCII escapes count.
    ///
    /// The defect this catches: a decoder applied to some values and not others (the
    /// Rust parser never decoded, so `fe80%3A%3A1` stayed literal while the phone read
    /// `fe80::1`), or escapes accepted in a value but not in a key.
    #[test]
    fn test_pairing_url_percent_decodes_query_values() {
        let encoded_pk = format!("%30{}", &PK[1..]);
        let url = format!(
            "tapauth://pair?%76=2&sid=%30%30112233445566778899aabbccddeeff\
             &pk={encoded_pk}&no%74e=ignored&ip6=fe80%3A%3A1"
        );
        let info = pairing::PairingInfo::parse(&url).unwrap();
        assert_eq!(hex::encode(info.session_id), SID);
        assert_eq!(info.public_key_hex, PK);
        assert_eq!(info.ipv6, Some("fe80::1".parse().unwrap()));
        assert_eq!(info.port, None);
    }

    /// A malformed or non-ASCII escape makes the URL invalid; it never becomes a
    /// literal `%` or a Latin-1 character.
    ///
    /// The defect this catches: passthrough of a broken escape (the phone used to
    /// accept `%zz` verbatim and decode `%FF` to `ÿ`), which the other parser rejects,
    /// so the same QR was valid on one side of the wire and not the other.
    #[test]
    fn test_pairing_url_rejects_malformed_percent_escape() {
        for bad in ["%", "%2", "%zz", "%2G", "%FF", "%ff", "%C3%A9"] {
            let url = format!("tapauth://pair?v=2&sid={SID}&pk={PK}&ip6=fe80{bad}");
            match pairing::PairingInfo::parse(&url) {
                Err(pairing::PairingInfoError::InvalidQuery) => {}
                other => panic!("expected InvalidQuery for escape {bad:?}, got {:?}", other),
            }
        }

        // A malformed escape in a key the parser does not know is still malformed.
        let url = format!("tapauth://pair?v=2&sid={SID}&pk={PK}&x=%zz");
        match pairing::PairingInfo::parse(&url) {
            Err(pairing::PairingInfoError::InvalidQuery) => {}
            other => panic!(
                "expected InvalidQuery for an unknown key's escape, got {:?}",
                other
            ),
        }
    }

    /// `generate_pairing_url_v2` refuses the keys and ports its own parser refuses.
    ///
    /// The defect this catches: a generator that emits a URL (`pk=abc`, `pk=` with 64
    /// zeros, `p=0`) the parser then rejects, which is exactly the "generate(x) is not
    /// parseable" class of bug this grammar exists to prevent.
    #[test]
    fn test_generate_pairing_url_refuses_invalid_public_key() {
        let session_id = [0x5Au8; 16];
        let short = "ab".repeat(31);
        let long = "ab".repeat(33);
        let non_hex = format!("{}zz", "ab".repeat(31));
        let all_zero = "0".repeat(64);

        for bad in [
            "",
            "cafebabe",
            short.as_str(),
            long.as_str(),
            non_hex.as_str(),
            all_zero.as_str(),
        ] {
            match pairing::generate_pairing_url_v2(&session_id, bad, None, None, None) {
                Err(pairing::PairingInfoError::InvalidPublicKey) => {}
                other => panic!("expected InvalidPublicKey for pk {bad:?}, got {:?}", other),
            }
        }

        match pairing::generate_pairing_url_v2(&session_id, PK, Some(0), None, None) {
            Err(pairing::PairingInfoError::InvalidPort) => {}
            other => panic!("expected InvalidPort for p=0, got {:?}", other),
        }
    }

    /// Hex is accepted in either case, as `hex::decode` (and the phone's `toInt(16)`)
    /// read it. Kept out of the shared corpus because that file compares the literal
    /// `sid` text, and `PairingInfo` re-encodes the id in lower case.
    ///
    /// The defect this catches: a case check that refuses a QR another tool wrote in
    /// upper case.
    #[test]
    fn test_pairing_url_accepts_uppercase_hex() {
        let upper_pk = PK.to_uppercase();
        let url = format!(
            "tapauth://pair?v=2&sid={}&pk={upper_pk}",
            SID.to_uppercase()
        );
        let info = pairing::PairingInfo::parse(&url).unwrap();
        assert_eq!(hex::encode(info.session_id), SID);
        assert_eq!(info.public_key_hex, upper_pk);
    }
}
