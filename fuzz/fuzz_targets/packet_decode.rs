//! Fuzz target: the daemon's datagram decode path.
//!
//! Entry points (called, not copied): `datagram_within_size_cap_for_fuzz` — the
//! `fuzz-api` delegate of the predicate `receive_udp_packet` gates on
//! (`shared/src/network/udp.rs`, `pub(crate) datagram_within_size_cap`, the
//! `MAX_UDP_MESSAGE_SIZE` = 16 KiB check) — and `EncryptedPacket::decode`, the exact
//! call the receive loop makes after that gate, from the same `prost` version.
//!
//! The target's domain is therefore the daemon's: an arbitrary UDP datagram of any
//! length, decoded only if the receive path would decode it.
//!
//! Invariants asserted, beyond "does not panic":
//!
//! * Bounded payload: the bytes a decode yields — `temporal_identifier` and
//!   `ciphertext`, the fields an unauthenticated sender sizes — never exceed the
//!   datagram that produced them. That is the bound on what a sender can make this
//!   process hold. It is asserted as `payload <= data.len()`; the entry gate bounds
//!   `data.len()`, so the 16 KiB cap needs no assertion of its own.
//! * Round-trip stability: `decode(encode(decode(b))) == decode(b)`, so "what we would
//!   re-emit" decodes back to "what we accepted". This is the property a re-send (the
//!   phone's cached `PairingConfirmServer` bytes, `tapauthd`'s retransmitted
//!   `PairingConfirmClient`) depends on.
//!
//! Not asserted: that two decodes of the same bytes agree. `decode` is a pure function
//! of its input over an owned value with no interior mutability, so that assertion
//! cannot fail and is not carried.
//!
//! Not asserted, because it is **false**: a re-encoded packet is not always the size of
//! the datagram it came from. A non-minimal varint for `encryption_algorithm` (the one
//! `int32` field) truncates to a negative `i32`, which protobuf re-encodes as a 10-byte
//! sign-extended varint: `10ff85fc85fc9c9c62` (9 bytes) decodes to `-1061223681` and
//! re-encodes to 11. Growth is bounded and tiny — 9 bytes for this message's single
//! numeric field, since `bytes` fields are copied verbatim — so the payload bound above
//! holds; see the strategy record (`docs/design-documents/assurance-strategy.md` §5)
//! and the corpus seed of that exact input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message as _;
use shared::network::udp::datagram_within_size_cap_for_fuzz;
use shared::protocol::pb::EncryptedPacket;

fuzz_target!(|data: &[u8]| {
    // A datagram this receive path would drop on size never reaches a decoder, so it is
    // not part of the target's domain; feeding it would only measure `prost` on inputs
    // the daemon refuses.
    if !datagram_within_size_cap_for_fuzz(data.len()) {
        return;
    }

    let Ok(packet) = EncryptedPacket::decode(data) else {
        return;
    };

    let encoded = packet.encode_to_vec();
    // The fields a sender chooses the size of are copied out of the datagram, never
    // inflated by decoding: each is a length-delimited slice of the input plus its own
    // tag and length prefix. So the payload a decode hands upward is at most the
    // datagram.
    let payload = packet.temporal_identifier.len() + packet.ciphertext.len();
    assert!(
        payload <= data.len(),
        "a {} byte datagram decoded to {} bytes of payload (16 byte temporal identifier \
         plus {} byte ciphertext), so a decode may grow what an unauthenticated sender \
         chose the size of",
        data.len(),
        payload,
        packet.ciphertext.len()
    );

    let round_tripped =
        EncryptedPacket::decode(encoded.as_slice()).expect("re-encoding a decoded packet decodes");
    assert_eq!(
        round_tripped,
        packet,
        "a decode is not stable under re-serialization: {} bytes re-encoded from a {} byte \
         datagram decode to a different packet",
        encoded.len(),
        data.len()
    );
});
