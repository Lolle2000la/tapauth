//! Fuzz target: `shared::protocol::sanitize_context_string` with an arbitrary byte
//! string and an arbitrary truncation budget.
//!
//! The budget is the axis a checked-in vector corpus cannot vary: the shipped field
//! budgets are five fixed numbers (32/64/32/32/128), while the property has to hold for
//! every `usize`. It is taken as a full `u64` and never clamped, so `0`, the 3-byte
//! ellipsis threshold, both sides of every field budget and `usize::MAX` are all in the
//! domain.
//!
//! Invariants asserted, beyond "does not panic":
//!
//! * The output fits the requested byte budget, whatever the budget — including the
//!   budgets below the 3-byte ellipsis, where the cut happens without one.
//! * The output is valid UTF-8 (same assertions as the shipped `proptest` property).
//! * No forbidden code point survives, asserted with the module's own
//!   `is_forbidden_context_char` via `is_forbidden_context_char_for_fuzz` — not a
//!   re-transcription, so a code point added to the set is covered here for free.
//! * Idempotence, **only at budgets >= 4**. That is the domain the documented hole in
//!   `assurance-strategy.md` §3 leaves: at 2 or 3 bytes a cut can land on the very space
//!   the second pass trims, so asserting it there would be asserting something the
//!   function does not promise.
#![no_main]

use libfuzzer_sys::fuzz_target;
use shared::protocol::{is_forbidden_context_char_for_fuzz, sanitize_context_string};

fuzz_target!(|data: &[u8]| {
    let Some(head) = data.get(..8) else {
        return;
    };
    let mut budget_bytes = [0u8; 8];
    budget_bytes.copy_from_slice(head);
    let budget = u64::from_le_bytes(budget_bytes) as usize;

    // `sanitize_context_string` takes `&str`: bytes that are not UTF-8 cannot reach it,
    // so they are mapped lossily instead of skipped, which would drop most mutations
    // before they exercise the sanitizer.
    let input = String::from_utf8_lossy(&data[8..]);

    let out = sanitize_context_string(&input, budget);

    assert!(
        out.len() <= budget,
        "sanitizing {:?} to {budget} bytes produced {} bytes: {:?}",
        input,
        out.len(),
        out
    );

    assert_eq!(
        core::str::from_utf8(out.as_bytes()).ok(),
        Some(out.as_str()),
        "sanitizing {:?} to {budget} bytes produced invalid UTF-8",
        input
    );

    if let Some(found) = out
        .chars()
        .find(|ch| is_forbidden_context_char_for_fuzz(*ch))
    {
        panic!(
            "sanitizing {:?} to {budget} bytes kept forbidden U+{:04X} in {:?}",
            input, found as u32, out
        );
    }

    if budget >= 4 {
        let twice = sanitize_context_string(&out, budget);
        assert_eq!(
            twice, out,
            "sanitizing {:?} to {budget} bytes is not idempotent: a second pass produced {:?}",
            input, twice
        );
    }
});
