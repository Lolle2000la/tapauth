//! The 4-byte big-endian length prefix shared by every TapAuth IPC endpoint.
//!
//! Every message on the daemon's Unix socket is framed as a 4-byte big-endian
//! body length followed by the protobuf body. The daemon, the PAM module, the
//! admin GUI and `tapauth-ipc-cli` all speak that one wire format, so the
//! prefix is written and read here once instead of four times.
//!
//! # Why one cap, and why 10 MiB
//!
//! [`MAX_FRAME_LEN`] bounds **what a peer may make us allocate**, not what the
//! protocol may carry. That framing matters for the choice of value:
//!
//! - The daemon is the trusted writer and the only reader whose socket a
//!   privileged peer can reach (`/run/tapauthd/tapauthd.sock`, root-owned,
//!   `0660 root:tapauthd-clients`), and every reader checks the announced
//!   length *before* it allocates the body (see [`decode_len`]). A hostile
//!   client can therefore ask the daemon to reserve at most this many bytes
//!   per connection, and a hostile daemon can ask a client for at most the
//!   same.
//! - The previous split — 10 MiB in the daemon, GUI and CLI, but 1 MiB in the
//!   shipped PAM module — was two arbitrary guards against the same risk. The
//!   only thing the tighter one bought was a class of daemon reply the
//!   daemon's own PAM client refuses after the daemon has already done the
//!   work and written the bytes. A single value has to be the permissive one,
//!   and 10 MiB is the value three of the four endpoints already used.
//! - No message in `proto/ipc.proto` is close to either bound. The largest
//!   realistic admin reply is [`GetServersResponse`]-shaped: a `repeated
//!   PairedServerInfo` where each entry is a device name, a 64-hex-character
//!   public key, its allowed-user list and a timestamp — hundreds of bytes per
//!   paired phone. `GetConfigResponse` is four small fields, and
//!   `PamAuthenticateResponse` carries a fixed-size challenge. Nothing here
//!   can grow to 1 MiB, let alone 10 MiB, so the cap is not a protocol limit.
//!
//! Enforcing it on the **send** side too (via [`encode_len`]) is what stops a
//! producer from emitting a frame a consumer would refuse: the writer fails
//! with a typed error instead of putting bytes on the socket that the reader
//! will reject as corruption.
//!
//! # Verification
//!
//! The `kani_proofs` module at the bottom of this file is compiled only under
//! `cfg(kani)` and is **ungated by the default test suite**: `cargo test` does
//! not build it and `cargo kani -p shared --lib` is the only thing that
//! verifies it.
//!
//! [`GetServersResponse`]: crate::ipc::pb::GetServersResponse

use crate::error::TapAuthError;

/// Largest frame body any TapAuth IPC endpoint will encode or accept, in bytes.
///
/// See the module documentation for why this is one shared cap and why it is
/// this value. It guards the allocation a peer can request; it is not a limit
/// on what the protocol may legitimately carry.
pub const MAX_FRAME_LEN: usize = 10 * 1024 * 1024;

/// Message carried by [`TapAuthError::InvalidInput`] when a length is out of
/// range.
///
/// It is a fixed string rather than a `format!` of the offending length on
/// purpose: the Kani harnesses below reach this path, and CBMC cannot bound
/// the recursion of the formatting machinery, so an interpolated message turns
/// a proof that finishes in seconds into one that never terminates. The number
/// in it is pinned to [`MAX_FRAME_LEN`] by
/// `the_refusal_names_the_current_cap`.
const LENGTH_OUT_OF_RANGE: &str = "frame length above the 10485760-byte (10 MiB) maximum";

/// Encode a body length as the 4-byte big-endian prefix.
///
/// Rejects a length above [`MAX_FRAME_LEN`] on the send side, so no producer
/// can put a frame on the wire that [`decode_len`] (and therefore every
/// reader) would refuse.
pub fn encode_len(len: usize) -> Result<[u8; 4], TapAuthError> {
    if len > MAX_FRAME_LEN {
        return Err(TapAuthError::InvalidInput(String::from(
            LENGTH_OUT_OF_RANGE,
        )));
    }
    // `MAX_FRAME_LEN` is 10 MiB, far below `u32::MAX`, so this conversion
    // cannot truncate for any length that passed the check above.
    Ok((len as u32).to_be_bytes())
}

/// Decode the 4-byte big-endian prefix into a body length.
///
/// Rejects a length above [`MAX_FRAME_LEN`] before the caller allocates the
/// body, so the value returned is always a length a reader may reserve.
pub fn decode_len(prefix: [u8; 4]) -> Result<usize, TapAuthError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_LEN {
        return Err(TapAuthError::InvalidInput(String::from(
            LENGTH_OUT_OF_RANGE,
        )));
    }
    Ok(len)
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The cap is inclusive: a body of exactly `MAX_FRAME_LEN` bytes is a
    /// legitimate frame, and `0` is the health-check frame the daemon accepts.
    #[test]
    fn zero_and_the_cap_round_trip() {
        for len in [0, 1, MAX_FRAME_LEN - 1, MAX_FRAME_LEN] {
            let prefix = encode_len(len).expect("length within the cap must encode");
            assert_eq!(
                u32::from_be_bytes(prefix) as usize,
                len,
                "encoded prefix must be the big-endian length"
            );
            assert_eq!(decode_len(prefix).expect("must decode"), len);
        }
    }

    /// One byte past the cap is refused in both directions. `decode_len`
    /// refusing is what stops a reader from reserving a body it should not.
    #[test]
    fn length_above_the_cap_is_rejected_by_encode_and_decode() {
        let over = MAX_FRAME_LEN + 1;

        let encoded = encode_len(over);
        assert!(
            matches!(encoded, Err(TapAuthError::InvalidInput(_))),
            "encode_len must refuse {over}, got {encoded:?}"
        );

        let decoded = decode_len((over as u32).to_be_bytes());
        assert!(
            matches!(decoded, Err(TapAuthError::InvalidInput(_))),
            "decode_len must refuse {over}, got {decoded:?}"
        );

        // And the largest representable length, so the rejection is not only
        // about the first value past the cap.
        let decoded = decode_len(u32::MAX.to_be_bytes());
        assert!(
            matches!(decoded, Err(TapAuthError::InvalidInput(_))),
            "decode_len must refuse u32::MAX, got {decoded:?}"
        );
    }

    /// `LENGTH_OUT_OF_RANGE` is a fixed string so the Kani proofs stay
    /// tractable, which means the number in it does not follow the constant on
    /// its own: an operator reading a log after a cap change would be told the
    /// wrong maximum.
    #[test]
    fn the_refusal_names_the_current_cap() {
        assert_eq!(MAX_FRAME_LEN, 10 * 1024 * 1024);
        assert!(
            LENGTH_OUT_OF_RANGE.contains("10485760"),
            "the refusal message must name the current cap, got {LENGTH_OUT_OF_RANGE:?}"
        );
    }
}

/// Machine-checked proofs of the three properties every framing site relies on:
/// `decode_len` inverts `encode_len` inside the cap, a decoded length never
/// exceeds the cap, and the cap is the inclusive boundary of what encodes.
///
/// Only `cargo kani -p shared --lib` builds this module; the default test
/// suite and release builds do not, so a broken harness cannot fail `cargo
/// test` — it fails Kani.
#[cfg(kani)]
mod kani_proofs {
    use super::{decode_len, encode_len, MAX_FRAME_LEN};

    /// A length inside the cap survives the round trip unchanged.
    #[kani::proof]
    fn encode_then_decode_is_the_identity() {
        let len: usize = kani::any();
        // An unbounded symbolic `usize` is not verifiable here: the cap check
        // would have to be reasoned about over the whole 64-bit range.
        kani::assume(len <= MAX_FRAME_LEN);

        let prefix = match encode_len(len) {
            Ok(prefix) => prefix,
            Err(_) => {
                kani::assert(false, "a length inside the cap must encode");
                return;
            }
        };
        match decode_len(prefix) {
            Ok(decoded) => kani::assert(decoded == len, "decode_len must invert encode_len"),
            Err(_) => kani::assert(false, "a prefix we just encoded must decode"),
        }
    }

    /// Whatever a peer sends, a reader never reserves more than the cap.
    #[kani::proof]
    fn decode_len_never_exceeds_the_cap() {
        let prefix: [u8; 4] = kani::any();
        if let Ok(len) = decode_len(prefix) {
            kani::assert(len <= MAX_FRAME_LEN, "decoded length must respect the cap");
        }
    }

    /// The send side refuses anything above the cap, and accepts the cap
    /// itself — the boundary is inclusive.
    #[kani::proof]
    fn encode_len_refuses_above_the_cap() {
        let len: usize = kani::any();
        kani::assume(len > MAX_FRAME_LEN);
        kani::assert(
            encode_len(len).is_err(),
            "a length above the cap must not encode",
        );

        // The boundary itself, concretely: one byte past the cap is refused
        // and the cap is accepted, so neither side of the comparison is off by
        // one regardless of what the symbolic value above turned out to be.
        kani::assert(
            encode_len(MAX_FRAME_LEN + 1).is_err(),
            "one byte past the cap must not encode",
        );
        kani::assert(encode_len(MAX_FRAME_LEN).is_ok(), "the cap must encode");
    }
}
