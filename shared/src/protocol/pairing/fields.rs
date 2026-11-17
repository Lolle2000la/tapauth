//! The per-field helpers both roles apply to a value before it enters the
//! transcript: a device name cut down to the transcript's byte budget, and a
//! 32-byte protobuf `bytes` field parsed as a key.
//!
//! Neither is transcript material — each normalizes one field — so they live here
//! rather than in [`super::transcript`].
//!
//! The Kani harness at the bottom of this file is `#[cfg(kani)]`, so it is ungated by
//! the default test suite: `cargo test` never compiles it and the shipped build is
//! unaffected — only `cargo kani -p shared --lib` runs it. The proptest properties
//! beside it are ordinary `#[cfg(test)]` tests and do run under `cargo test`.

use crate::protocol::messages::ProtocolError;

/// Truncate a device name to `max_bytes` on a UTF-8 char boundary.
pub(super) fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    match value.get(..end) {
        Some(truncated) => truncated.to_string(),
        None => String::new(),
    }
}

/// Parse a 32-byte protobuf `bytes` field, distinguishing "absent" from "wrong length".
pub(super) fn key_32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::MissingField(field));
    }
    bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidMessageFormat)
}

/// Kani bounded-model-checking harness for [`truncate_utf8`] (compiled only under
/// `cfg(kani)`).
///
/// In this file so the `pub(super)` function is reachable without a visibility
/// change.
///
/// **Ungated by the default test suite.** `cargo test` never compiles this module —
/// the whole module is behind `#[cfg(kani)]`, a cfg only Kani sets — so it cannot
/// fail a normal test run and nothing here gates a merge. Only `cargo kani -p shared
/// --lib` runs it; the `Kani Proofs (shared)` workflow is deliberately not one of the
/// eight required contexts in `scripts/ci/check-required-checks.sh`, so a regression
/// here produces no signal unless someone reads that job.
///
/// These harnesses pin **today's** semantics of `truncate_utf8`. Changing the
/// function means re-running them, not assuming they still hold.
#[cfg(kani)]
mod kani_proofs {
    use super::truncate_utf8;

    /// Longest symbolic input, in bytes.
    const INPUT_BYTES: usize = 8;

    /// The result is a prefix of the input, fits the budget, and never splits a
    /// UTF-8 sequence — and it is the *longest* such prefix, so a name is not cut
    /// shorter than the budget allows.
    ///
    /// **Harness restriction:** the input is a symbolic `[u8; INPUT_BYTES]`
    /// constrained to valid UTF-8 by `kani::assume`, then cut to a symbolic
    /// char-boundary prefix, so every `&str` of length `0..=INPUT_BYTES` is reachable
    /// (including multi-byte text) but longer ones are not, and the assume spends
    /// solver effort on UTF-8 validity that a `char`-built input would not.
    #[kani::proof]
    #[kani::unwind(10)]
    fn the_truncated_name_is_the_longest_prefix_within_budget() {
        let raw: [u8; INPUT_BYTES] = kani::any();
        kani::assume(core::str::from_utf8(&raw).is_ok());
        let Ok(full) = core::str::from_utf8(&raw) else {
            return;
        };
        // The prefix is what makes `truncate_utf8`'s early return reachable at all:
        // with a fixed-length input, `value.len() <= max_bytes` would only ever hold
        // at the single point `max_bytes == INPUT_BYTES`, leaving the
        // "short enough, return unchanged" branch unproved.
        let len: usize = kani::any();
        kani::assume(len <= INPUT_BYTES);
        kani::assume(full.is_char_boundary(len));
        let Some(input) = full.get(..len) else {
            return;
        };
        let max_bytes: usize = kani::any();
        kani::assume(max_bytes <= INPUT_BYTES);

        let truncated = truncate_utf8(input, max_bytes);

        assert!(
            truncated.len() <= max_bytes,
            "the truncated name exceeds its byte budget"
        );
        assert!(
            input.is_char_boundary(truncated.len()),
            "the cut landed inside a UTF-8 sequence"
        );
        assert!(
            input.starts_with(truncated.as_str()),
            "the truncated name is not a prefix of the input"
        );
        // Maximality: either nothing was cut, or the next character could not fit.
        // The defect this catches is a cut that is correct but shorter than the
        // budget allows (an over-eager decrement of `end`).
        if truncated.len() < input.len() {
            let rest = input.get(truncated.len()..).unwrap_or("");
            let next = rest.chars().next();
            assert!(
                next.is_some_and(|ch| truncated.len() + ch.len_utf8() > max_bytes),
                "the name was cut shorter than the byte budget allows"
            );
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
mod property_tests {
    use super::truncate_utf8;
    use proptest::prelude::*;

    /// Device names are user-supplied text: mixed ASCII and multi-byte code points,
    /// short enough that the byte-by-byte scan stays cheap.
    fn device_name() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                6 => prop::char::range('a', 'z'),
                2 => prop::sample::select(vec!['€', '漢', '😀', 'é', 'ß']),
                1 => Just(' '),
            ],
            0..12,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        /// No byte-prefix of the input that is within the budget, ends on a code-point
        /// boundary and is a prefix of the input is longer than the result — i.e. the
        /// cut never discards a code point that would have fit.
        ///
        /// The defect this catches is an over-eager boundary walk (decrementing `end`
        /// past the last boundary that fits), which the existing example tests would
        /// only notice for the input they happen to use.
        #[test]
        fn truncated_name_is_the_longest_prefix_within_budget(
            value in device_name(),
            max_bytes in 0usize..=32,
        ) {
            let truncated = truncate_utf8(&value, max_bytes);

            prop_assert!(
                value.is_char_boundary(truncated.len()),
                "cut at {} landed inside a UTF-8 sequence of {:?}",
                truncated.len(),
                value
            );
            prop_assert!(
                value.starts_with(truncated.as_str()),
                "result {:?} is not a prefix of {:?}",
                truncated,
                value
            );
            for end in 0..=value.len() {
                if end <= max_bytes && value.is_char_boundary(end) {
                    prop_assert!(
                        end <= truncated.len(),
                        "prefix of {} bytes fits the budget of {} but the result was only {}",
                        end,
                        max_bytes,
                        truncated.len()
                    );
                }
            }
        }

        /// The result fits the budget and is valid UTF-8. Validity is type-enforced by
        /// the `String` return type, so the assertion can only fail if that type ever
        /// changes; it is here to make that signature change a test failure rather than
        /// a silent contract loss.
        #[test]
        fn truncated_name_fits_the_byte_budget_and_is_valid_utf8(
            value in device_name(),
            max_bytes in 0usize..=32,
        ) {
            let truncated = truncate_utf8(&value, max_bytes);

            prop_assert!(
                truncated.len() <= max_bytes,
                "result of {} bytes exceeds the budget of {}",
                truncated.len(),
                max_bytes
            );
            prop_assert!(
                core::str::from_utf8(truncated.as_bytes()) == Ok(truncated.as_str()),
                "result is not valid UTF-8"
            );
        }
    }
}
