//! Fuzz target: the pairing QR URL, both directions.
//!
//! Entry points (called, not copied): `shared::models::pairing::PairingInfo::parse`
//! and its generator `generate_pairing_url_v2_for_key`.
//!
//! Half one is the parser on arbitrary text — the shape a scanned sticker can have.
//! Half two is the generator on arbitrary fields, then the parser on what it wrote,
//! which is the QR the phone actually has to read.
//!
//! Invariants asserted, beyond "does not panic":
//!
//! * A URL `parse` accepts is at most `MAX_PAIRING_URL_LEN` bytes, `version == 2`, and
//!   carries a `pk` that decodes to 32 bytes and is not the all-zero key (the phone
//!   reads an all-zero `pk` as its "skip the QR comparison" sentinel); `p` is never 0.
//! * A URL longer than the cap is refused by the length cap itself (`UrlTooLong`), not
//!   by some later check — the cap is documented as the first thing `parse` does.
//! * What `parse` accepted survives a regenerate/reparse: the same `sid`, key bytes,
//!   port and addresses come back. This is the property a scanned QR relies on.
//! * What `generate` emits always parses back to the same fields, is at most
//!   `MAX_PAIRING_URL_LEN` bytes, and renders `Some(0)` as no `p` at all (a BLE-only
//!   shape), which is the generator's documented treatment of a non-endpoint port.
#![no_main]

use libfuzzer_sys::fuzz_target;
use shared::models::pairing::{
    generate_pairing_url_v2_for_key, PairingInfo, PairingInfoError, MAX_PAIRING_URL_LEN,
};

/// `N` bytes read from `data` at `offset`, wrapping around it.
///
/// Every field of the generator call comes from the same input bytes, so a mutation
/// moves all of them together instead of only the first few; an empty input yields
/// zeros, which is still a legal call.
fn take<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    if data.is_empty() {
        return out;
    }
    for (index, slot) in out.iter_mut().enumerate() {
        if let Some(byte) = data.get((offset + index) % data.len()) {
            *slot = *byte;
        }
    }
    out
}

fn check_parse(url: &str) {
    match PairingInfo::parse(url) {
        Ok(info) => {
            assert!(
                url.len() <= MAX_PAIRING_URL_LEN,
                "accepted a {} byte URL, above the {MAX_PAIRING_URL_LEN} byte cap: {url:?}",
                url.len()
            );
            assert_eq!(
                info.version, 2,
                "accepted {url:?} as version {}",
                info.version
            );

            let key = hex::decode(&info.public_key_hex).unwrap_or_else(|err| {
                panic!(
                    "accepted pk {:?} from {url:?} is not hex: {err}",
                    info.public_key_hex
                )
            });
            assert_eq!(
                key.len(),
                32,
                "accepted a {}-byte pk from {url:?}, expected the 32 bytes of 64 hex chars",
                key.len()
            );
            assert!(
                key.iter().any(|byte| *byte != 0),
                "accepted the all-zero pk from {url:?}, the phone's skip-the-QR-comparison sentinel"
            );
            assert_ne!(
                info.port,
                Some(0),
                "accepted p=0 from {url:?}, which is not a UDP endpoint"
            );

            // Regenerate from what was accepted and parse it back: a scan of the QR the
            // desktop would print for these fields has to yield these fields.
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&info.session_id);
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key);

            let regenerated = generate_pairing_url_v2_for_key(
                &session_id,
                &key_bytes,
                info.port,
                info.ipv4,
                info.ipv6,
            );
            let reparsed = PairingInfo::parse(&regenerated).unwrap_or_else(|err| {
                panic!("regenerated {regenerated:?} from {url:?} does not parse: {err}")
            });

            assert_eq!(
                reparsed.session_id, info.session_id,
                "{url:?} lost its sid through {regenerated:?}"
            );
            assert_eq!(
                hex::decode(&reparsed.public_key_hex).ok(),
                Some(key),
                "{url:?} lost its pk through {regenerated:?}"
            );
            assert_eq!(
                reparsed.port, info.port,
                "{url:?} lost its port through {regenerated:?}"
            );
            assert_eq!(
                reparsed.ipv4, info.ipv4,
                "{url:?} lost its ip4 through {regenerated:?}"
            );
            assert_eq!(
                reparsed.ipv6, info.ipv6,
                "{url:?} lost its ip6 through {regenerated:?}"
            );
        }
        Err(err) => {
            if url.len() > MAX_PAIRING_URL_LEN {
                assert!(
                    matches!(err, PairingInfoError::UrlTooLong),
                    "a {} byte URL must be refused by the length cap, got {err}",
                    url.len()
                );
            }
        }
    }
}

fn check_generated(data: &[u8]) {
    let session_id = take::<16>(data, 0);
    let mut key = take::<32>(data, 17);
    // The all-zero key is refused on purpose by both the generator and the parser (it is
    // the phone's sentinel), so it is not part of the round trip's domain — the same
    // assumption `test_pairing_url_round_trip_is_lossless` makes.
    if key.iter().all(|byte| *byte == 0) {
        key[0] = 1;
    }

    let port = match data.get(49) {
        // `Some(0)` is a legal argument: it is written as no `p` at all.
        Some(selector) if selector % 3 == 0 => None,
        _ => Some(u16::from_le_bytes(take::<2>(data, 50))),
    };
    let ipv4 = match data.get(52) {
        Some(selector) if selector % 2 == 0 => Some(std::net::Ipv4Addr::from(take::<4>(data, 53))),
        _ => None,
    };
    let ipv6 = match data.get(57) {
        Some(selector) if selector % 2 == 0 => Some(std::net::Ipv6Addr::from(take::<16>(data, 58))),
        _ => None,
    };

    let url = generate_pairing_url_v2_for_key(&session_id, &key, port, ipv4, ipv6);
    assert!(
        url.len() <= MAX_PAIRING_URL_LEN,
        "the generator wrote a {} byte URL, above the {MAX_PAIRING_URL_LEN} byte cap: {url:?}",
        url.len()
    );

    let parsed = PairingInfo::parse(&url).unwrap_or_else(|err| {
        panic!("a URL the generator wrote must parse: {url:?} (sid={session_id:02x?}, p={port:?}, ip4={ipv4:?}, ip6={ipv6:?}) failed: {err}")
    });

    assert_eq!(parsed.version, 2, "{url:?}");
    assert_eq!(parsed.session_id, session_id, "{url:?} lost its sid");
    assert_eq!(
        hex::decode(&parsed.public_key_hex).ok(),
        Some(key.to_vec()),
        "{url:?} lost its pk"
    );
    assert_eq!(
        parsed.port,
        port.filter(|port| *port != 0),
        "{url:?} lost its p (a zero port is written as no p at all)"
    );
    assert_eq!(parsed.ipv4, ipv4, "{url:?} lost its ip4");
    assert_eq!(parsed.ipv6, ipv6, "{url:?} lost its ip6");
}

fuzz_target!(|data: &[u8]| {
    // `parse` takes `&str`; bytes that are not UTF-8 cannot reach it at all (the URL is
    // a `String` on every caller), so they are mapped lossily rather than skipped, which
    // would throw away most mutations before they exercise anything.
    let url = String::from_utf8_lossy(data);
    check_parse(&url);
    check_generated(data);
});
