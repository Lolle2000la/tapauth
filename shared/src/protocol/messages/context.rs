//! The context strings an `AuthenticationRequest` carries, and why they are cut.
//!
//! The seam against `messages` is "the text that is cut, and why" versus "the
//! messages it is cut for". This module owns the per-field byte budgets, the table
//! saying which over-budget value is rejected and which is shortened, and the
//! sanitizer that makes display-only text safe to show on the Server prompt. The
//! request constructors that apply those rows stay in `messages`, which re-exports
//! this module's items so their public paths do not move.

use super::ProtocolError;
#[cfg(test)]
use crate::protocol::pb::AuthenticationRequest;

/// Maximum byte length of `AuthenticationRequest.username`.
///
/// The budget of `ContextField::Username`'s row; that row's
/// `FieldPolicy::on_overflow` is what says an over-budget username is
/// **rejected** rather than truncated.
pub const USERNAME_MAX_BYTES: usize = 32;
/// Maximum byte length of `AuthenticationRequest.hostname`.
///
/// The budget of `ContextField::Hostname`'s row; that row says an over-budget
/// hostname is sanitized and truncated instead of rejected.
pub const HOSTNAME_MAX_BYTES: usize = 64;
/// Maximum byte length of `AuthenticationRequest.pam_service`.
///
/// The budget of `ContextField::PamService`'s row.
pub const PAM_SERVICE_MAX_BYTES: usize = 32;
/// Maximum byte length of `AuthenticationRequest.process_name`.
///
/// The budget of `ContextField::ProcessName`'s row.
pub const PROCESS_NAME_MAX_BYTES: usize = 32;
/// Maximum byte length of `AuthenticationRequest.command_preview`.
///
/// The budget of `ContextField::CommandPreview`'s row.
pub const COMMAND_PREVIEW_MAX_BYTES: usize = 128;

/// What an over-budget context value does.
///
/// The variant is the whole security-relevant half of a field's policy, so it is a
/// value in the table rather than an `if` at a call site: which fields the phone may
/// see shortened is then one column to read, not a branch to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Overflow {
    /// Refuse to build the request, with [`ProtocolError::InvalidMessageFormat`].
    ///
    /// The value is neither sanitized nor shortened: the field is one the Server acts
    /// on (or names the account it acts for), so a shortened value would name
    /// something the caller never asked for. The budget is measured on the value the
    /// caller passed in.
    Reject,
    /// Sanitize with [`sanitize_context_string`] and cut to the budget, `…` inside it.
    ///
    /// For a display-only field, where a long value is still worth showing. The budget
    /// is measured on the sanitized value.
    Truncate,
}

/// One row of the per-field table: the byte budget and what an over-budget value
/// does. A row carries no behaviour of its own — [`bound_context_value`] applies it
/// and [`sanitize_context_string`] owns the *how* of a cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FieldPolicy {
    pub(super) max_bytes: usize,
    pub(super) on_overflow: Overflow,
}

/// A field of `AuthenticationRequest` that
/// [`create_auth_request_with_context`](super::create_auth_request_with_context)
/// bounds: one variant per row of [`ContextField::policy`].
///
/// A variant exists only to pick a row, and `policy`'s `match` is exhaustive, so a
/// field cannot be added here without its budget and its overflow policy; a field
/// added to the *message* is forced through the same table by
/// `every_context_field_has_exactly_one_policy_row`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ContextField {
    Username,
    Hostname,
    PamService,
    ProcessName,
    CommandPreview,
}

impl ContextField {
    /// The field's row — this is the table: one arm per field, referencing the
    /// budget constants rather than repeating their values. The `match` is
    /// exhaustive, so an arm is not optional.
    pub(super) const fn policy(self) -> FieldPolicy {
        match self {
            ContextField::Username => FieldPolicy {
                max_bytes: USERNAME_MAX_BYTES,
                on_overflow: Overflow::Reject,
            },
            ContextField::Hostname => FieldPolicy {
                max_bytes: HOSTNAME_MAX_BYTES,
                on_overflow: Overflow::Truncate,
            },
            ContextField::PamService => FieldPolicy {
                max_bytes: PAM_SERVICE_MAX_BYTES,
                on_overflow: Overflow::Truncate,
            },
            ContextField::ProcessName => FieldPolicy {
                max_bytes: PROCESS_NAME_MAX_BYTES,
                on_overflow: Overflow::Truncate,
            },
            ContextField::CommandPreview => FieldPolicy {
                max_bytes: COMMAND_PREVIEW_MAX_BYTES,
                on_overflow: Overflow::Truncate,
            },
        }
    }

    /// Every variant, in table order. `policy` is an exhaustive `match`, so a new
    /// variant cannot compile without a row; this list is what lets
    /// `every_context_field_has_exactly_one_policy_row` compare the table's size to
    /// the message's bounded fields and catch the same field listed twice or a row
    /// whose budget no longer matches its constant.
    #[cfg(test)]
    pub(super) const ALL: &[Self] = &[
        Self::Username,
        Self::Hostname,
        Self::PamService,
        Self::ProcessName,
        Self::CommandPreview,
    ];

    /// The field's spelling, for test failure messages. Exhaustive, so a variant
    /// without a name does not compile.
    #[cfg(test)]
    pub(super) fn as_str(self) -> &'static str {
        match self {
            ContextField::Username => "username",
            ContextField::Hostname => "hostname",
            ContextField::PamService => "pam_service",
            ContextField::ProcessName => "process_name",
            ContextField::CommandPreview => "command_preview",
        }
    }

    /// Read this field's value out of a built request. Exhaustive, so a variant
    /// without a reader does not compile.
    #[cfg(test)]
    pub(super) fn read(self, request: &AuthenticationRequest) -> &str {
        match self {
            ContextField::Username => &request.username,
            ContextField::Hostname => &request.hostname,
            ContextField::PamService => &request.pam_service,
            ContextField::ProcessName => &request.process_name,
            ContextField::CommandPreview => &request.command_preview,
        }
    }
}

/// Apply `field`'s row to `value`.
///
/// The `which` (budget, and what an over-budget value does) comes from the table;
/// the `how` of a cut is [`sanitize_context_string`]'s. A [`Overflow::Reject`] field
/// is passed through verbatim and an [`Overflow::Truncate`] field is sanitized, which
/// is the asymmetry the table records: a rejected value never reaches the phone, so
/// there is nothing to make display-safe.
pub(super) fn bound_context_value(
    field: ContextField,
    value: &str,
) -> Result<String, ProtocolError> {
    let policy = field.policy();
    match policy.on_overflow {
        Overflow::Reject if value.len() > policy.max_bytes => {
            Err(ProtocolError::InvalidMessageFormat)
        }
        Overflow::Reject => Ok(value.to_string()),
        Overflow::Truncate => Ok(sanitize_context_string(value, policy.max_bytes)),
    }
}

/// Truncation marker appended inside the byte budget when a context string is cut.
pub(super) const ELLIPSIS: char = '\u{2026}';

/// `ESC`, which opens every ANSI escape sequence stripped from a context string.
const ESC_BYTE: u8 = 0x1B;

/// `BEL`, the short terminator of an OSC sequence.
const BEL_BYTE: u8 = 0x07;

/// Sanitize untrusted contextual metadata for display on the Server prompt.
///
/// The Kotlin mirror (`ContextSanitizer` in `server-android`) must implement exactly
/// this, so both sides are driven by the same vectors in
/// `shared/testdata/context_sanitizer_vectors.json`:
///
/// 1. ANSI escape sequences are removed as a unit, first. A CSI (`ESC '['`, parameter
///    bytes `0x30..=0x3F`, intermediate bytes `0x20..=0x2F`, one final byte
///    `0x40..=0x7E`) and an OSC (`ESC ']'` up to `BEL` or `ESC '\'`, terminator
///    included) are deleted whole — deleting only the `ESC` would leave `[31m` in the
///    prompt. An unterminated sequence is deleted to end of input. A lone `ESC` is a
///    forbidden character and is dropped, and the byte after it is filtered normally.
/// 2. Then, per code point: a whitespace code point (see
///    [`is_context_whitespace`]) becomes one space, runs collapse to one space and
///    both ends are trimmed; otherwise a forbidden code point (see
///    [`is_forbidden_context_char`]) is dropped; everything else is kept. The
///    whitespace test comes *first*, so `\t`, `\n` and U+0085 separate words instead
///    of vanishing (`sudo\tapt` must not become `sudoapt`).
/// 3. The result is truncated to at most `max_bytes` bytes on a UTF-8 char boundary;
///    when truncation happens a single `…` is appended *inside* that budget, so a
///    budget of 3 bytes or less truncates without an ellipsis.
pub fn sanitize_context_string(input: &str, max_bytes: usize) -> String {
    let collapsed = normalize_context_string(input);

    if max_bytes == 0 {
        return String::new();
    }

    let sanitized = collapsed.as_str();
    if sanitized.len() <= max_bytes {
        return sanitized.to_string();
    }

    let ellipsis_len = ELLIPSIS.len_utf8();
    // The ellipsis itself costs 3 bytes and must leave room for at least one content
    // byte, so budgets below 4 truncate without one.
    let with_ellipsis = max_bytes > ellipsis_len;
    let budget = if with_ellipsis {
        max_bytes - ellipsis_len
    } else {
        max_bytes
    };

    let mut truncated = String::with_capacity(max_bytes);
    for ch in sanitized.chars() {
        if truncated.len() + ch.len_utf8() > budget {
            break;
        }
        truncated.push(ch);
    }
    if with_ellipsis {
        truncated.push(ELLIPSIS);
    }
    truncated
}

/// Delete ANSI escape sequences and every forbidden code point, and collapse
/// whitespace runs to one ASCII space (see [`sanitize_context_string`]).
///
/// Byte- and char-addressed at once: the escape scanner walks the byte slice (every
/// byte of an escape sequence is ASCII), and everything else is consumed one whole
/// `char` at a time, so the string is never split inside a multi-byte code point.
fn normalize_context_string(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut pending_space = false;
    let mut index = 0;

    while index < bytes.len() {
        if bytes.get(index).copied() == Some(ESC_BYTE) {
            match ansi_sequence_len(bytes, index) {
                Some(len) => index = index.saturating_add(len),
                // A lone `ESC` (end of input, or followed by anything but `[`/`]`) is
                // just a forbidden character: drop it and filter the next byte normally.
                None => index = index.saturating_add(1),
            }
            continue;
        }

        // `index` is on a char boundary: every advance above covers ASCII bytes only.
        let next_char = input.get(index..).and_then(|rest| rest.chars().next());
        let Some(ch) = next_char else {
            break;
        };
        index = index.saturating_add(ch.len_utf8());

        // Whitespace before the forbidden set: `U+0009..=U+000D` and `U+0085` are both.
        if is_context_whitespace(ch) {
            pending_space = !out.is_empty();
            continue;
        }
        if is_forbidden_context_char(ch) {
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }

    out
}

/// Length in bytes of the ANSI escape sequence starting at `start`, terminator included.
///
/// `None` when `bytes[start]` is an `ESC` that does not begin a CSI or OSC, which the
/// caller treats as a forbidden character. An unterminated CSI/OSC reports the rest of
/// the input, so a truncated escape cannot leak its parameter bytes into the prompt.
fn ansi_sequence_len(bytes: &[u8], start: usize) -> Option<usize> {
    match bytes.get(start.checked_add(1)?).copied() {
        // CSI: ESC '[' params intermediates final
        Some(b'[') => {
            let mut cursor = start.saturating_add(2);
            while bytes.get(cursor).copied().is_some_and(is_csi_parameter) {
                cursor = cursor.saturating_add(1);
            }
            while bytes.get(cursor).copied().is_some_and(is_csi_intermediate) {
                cursor = cursor.saturating_add(1);
            }
            if bytes.get(cursor).copied().is_some_and(is_csi_final) {
                Some(cursor.saturating_add(1).saturating_sub(start))
            } else {
                Some(bytes.len().saturating_sub(start))
            }
        }
        // OSC: ESC ']' ... (BEL | ESC '\')
        Some(b']') => {
            let mut cursor = start.saturating_add(2);
            while cursor < bytes.len() {
                if bytes.get(cursor).copied() == Some(BEL_BYTE) {
                    return Some(cursor.saturating_add(1).saturating_sub(start));
                }
                let is_string_terminator = bytes.get(cursor).copied() == Some(ESC_BYTE)
                    && bytes.get(cursor.saturating_add(1)).copied() == Some(b'\\');
                if is_string_terminator {
                    return Some(cursor.saturating_add(2).saturating_sub(start));
                }
                cursor = cursor.saturating_add(1);
            }
            Some(bytes.len().saturating_sub(start))
        }
        _ => None,
    }
}

/// One byte of a CSI parameter string: `0x30..=0x3F` (ECMA-48 §5.4).
fn is_csi_parameter(byte: u8) -> bool {
    (0x30..=0x3F).contains(&byte)
}

/// One byte of a CSI intermediate string: `0x20..=0x2F` (ECMA-48 §5.4).
fn is_csi_intermediate(byte: u8) -> bool {
    (0x20..=0x2F).contains(&byte)
}

/// The single final byte of a CSI sequence: `0x40..=0x7E` (ECMA-48 §5.4).
fn is_csi_final(byte: u8) -> bool {
    (0x40..=0x7E).contains(&byte)
}

/// The code points that become one ASCII space, collapsed and trimmed.
///
/// Spelled out instead of `char::is_whitespace` because the set is part of the display
/// contract the Kotlin mirror implements; `char::is_whitespace` is a Unicode property
/// that changes with the Unicode version and does not include `U+200B`.
fn is_context_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// Code points that must never reach the Server prompt: controls and bidi formatters.
fn is_forbidden_context_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{0000}'..='\u{001F}'
            | '\u{007F}'..='\u{009F}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// `fuzz-api` only: [`is_forbidden_context_char`], so the `fuzz/` sanitizer target
/// asserts "no forbidden code point survived" with this module's own predicate instead
/// of a re-transcription of the set. One delegate, no logic; uncompiled in every other
/// configuration. Re-exported by `messages`/`protocol`, so the target reaches it as
/// `shared::protocol::is_forbidden_context_char_for_fuzz`.
#[cfg(feature = "fuzz-api")]
#[doc(hidden)]
pub fn is_forbidden_context_char_for_fuzz(ch: char) -> bool {
    is_forbidden_context_char(ch)
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
    fn test_sanitize_context_string_strips_control_and_bidi_characters() {
        assert_eq!(
            sanitize_context_string("a\u{0}b\u{1}c\u{7f}d", 32),
            "abcd",
            "C0 controls, NUL and DEL must be removed"
        );
        assert_eq!(
            sanitize_context_string("\u{202e}evil\u{2066}", 32),
            "evil",
            "bidi overrides/isolates removed"
        );
        assert_eq!(
            sanitize_context_string("a\u{80}b\u{9f}c", 32),
            "abc",
            "C1 controls removed"
        );
        assert_eq!(
            sanitize_context_string("a\u{61c}b\u{200b}c\u{feff}d", 32),
            "abcd",
            "Arabic letter mark, zero-width space and BOM removed"
        );
    }

    /// Whitespace is checked *before* the forbidden set, so a tab or newline separates
    /// words instead of being deleted: the defect this catches is `sudo\tapt` collapsing
    /// to `sudoapt`, which renders as one word the user never typed.
    #[test]
    fn test_sanitize_context_string_separates_words_on_whitespace() {
        assert_eq!(
            sanitize_context_string("sudo\tapt\nupdate", 128),
            "sudo apt update"
        );
        assert_eq!(sanitize_context_string("  a \t\n  b  ", 128), "a b");
        // U+0085 (NEL) is both Unicode whitespace and a C1 control: it must collapse.
        assert_eq!(sanitize_context_string("a\u{85}b", 128), "a b");
        // U+00A0 (NBSP) and U+3000 (ideographic space) are not ASCII spaces either.
        assert_eq!(
            sanitize_context_string("sudo\u{a0}apt\u{3000}update", 128),
            "sudo apt update"
        );
    }

    /// An escape sequence is deleted as a unit. The defect this catches is stripping only
    /// the `ESC`: the parameter bytes (`[31m`, `]0;…`) would survive into the prompt and
    /// render as text that was never meant to be shown.
    #[test]
    fn test_sanitize_context_string_removes_ansi_sequences() {
        assert_eq!(
            sanitize_context_string("\u{1b}[31mroot\u{1b}[0m", 128),
            "root"
        );
        // Unterminated CSI: removed to end of input, not leaked as "[31".
        assert_eq!(sanitize_context_string("x\u{1b}[31", 128), "x");
        // Parameter byte `1`, intermediate byte `0x20` and the final byte `q`: one
        // sequence, so the "b" survives and nothing of `ESC [1 q` does.
        assert_eq!(sanitize_context_string("x\u{1b}[1 qb", 128), "xb");
        // OSC terminated by BEL, and by ESC '\'.
        assert_eq!(sanitize_context_string("a\u{1b}]0;evil\u{7}b", 128), "ab");
        assert_eq!(
            sanitize_context_string("a\u{1b}]8;;http://evil.example\u{1b}\\b", 128),
            "ab"
        );
        // Unterminated OSC: removed to end of input, so the title text cannot render.
        assert_eq!(sanitize_context_string("a\u{1b}]0;evil", 128), "a");
        // A lone ESC is a forbidden character; the byte after it is filtered normally.
        assert_eq!(sanitize_context_string("a\u{1b}b", 128), "ab");
        assert_eq!(sanitize_context_string("ab\u{1b}", 128), "ab");
    }

    #[derive(serde::Deserialize)]
    struct SanitizerVectors {
        cases: Vec<SanitizerVector>,
    }

    #[derive(serde::Deserialize)]
    struct SanitizerVector {
        name: String,
        input: String,
        max_bytes: usize,
        expected: String,
    }

    /// Every sanitizer vector, including one case per code point of the whitespace and
    /// forbidden sets and the truncation boundaries.
    ///
    /// The same file drives `ContextSanitizerTest.kt` on the Android side, so the two
    /// implementations cannot drift: the defect this catches is the Kotlin mirror
    /// silently disagreeing with this one (deleting a tab instead of collapsing it, or
    /// appending an ellipsis at a 3-byte budget).
    ///
    /// The case count is asserted exactly, not as a lower bound: a bound would let the
    /// file lose whole groups (every truncation boundary, say) while staying green.
    /// Adding a vector means bumping this number and `ContextSanitizerTest`'s together.
    #[test]
    fn test_context_sanitizer_vectors_are_honoured() {
        const EXPECTED_CASES: usize = 130;

        let vectors: SanitizerVectors = serde_json::from_str(include_str!(
            "../../../testdata/context_sanitizer_vectors.json"
        ))
        .expect("context sanitizer vector file must parse");
        assert_eq!(
            vectors.cases.len(),
            EXPECTED_CASES,
            "the shared vector file must hold exactly {EXPECTED_CASES} cases, found {}",
            vectors.cases.len()
        );

        for case in &vectors.cases {
            assert_eq!(
                sanitize_context_string(&case.input, case.max_bytes),
                case.expected,
                "vector '{}' (max_bytes={})",
                case.name,
                case.max_bytes
            );
        }
    }

    #[test]
    fn test_sanitize_context_string_collapses_and_trims_whitespace() {
        assert_eq!(sanitize_context_string("a \t\n  b", 32), "a b");
        assert_eq!(sanitize_context_string("  spaced  out  ", 32), "spaced out");
        assert_eq!(sanitize_context_string("   ", 32), "");
        assert_eq!(sanitize_context_string("a b", 32), "a b");
    }

    #[test]
    fn test_sanitize_context_string_truncates_within_budget() {
        let input = "x".repeat(64);
        let out = sanitize_context_string(&input, 10);

        assert_eq!(
            out.len(),
            10,
            "must use the whole byte budget, ellipsis included"
        );
        assert!(out.ends_with('\u{2026}'));
        assert_eq!(out.chars().filter(|c| *c == 'x').count(), 7);

        // Short input is not truncated and gains no ellipsis.
        assert_eq!(sanitize_context_string("short", 10), "short");

        // max_bytes == 0 yields an empty string.
        assert_eq!(sanitize_context_string("anything", 0), "");
    }

    #[test]
    fn test_sanitize_context_string_never_splits_multibyte_characters() {
        let input = "\u{20ac}".repeat(20); // 3 bytes per character

        for max_bytes in 1..=12usize {
            let out = sanitize_context_string(&input, max_bytes);
            assert!(
                out.len() <= max_bytes,
                "len {} exceeds budget {}",
                out.len(),
                max_bytes
            );
            // Valid UTF-8 by construction: every char survived intact.
            assert_eq!(out.replace('\u{2026}', "").len() % 3, 0);
            assert!(out.chars().all(|c| c == '\u{20ac}' || c == '\u{2026}'));
        }

        // 10-byte budget: 7 content bytes -> two 3-byte chars, then the ellipsis.
        assert_eq!(
            sanitize_context_string(&input, 10),
            "\u{20ac}\u{20ac}\u{2026}"
        );
        // Below 4 bytes no ellipsis is added.
        assert_eq!(sanitize_context_string(&input, 2), "");
        assert_eq!(sanitize_context_string(&input, 3), "\u{20ac}");
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
    use super::{is_forbidden_context_char, sanitize_context_string};
    use proptest::prelude::*;

    /// The characters that make the sanitizer's three passes interesting, in the
    /// proportions that reach them: plain text, the bytes an ANSI sequence is made of,
    /// the whitespace set, the forbidden set and multi-byte code points.
    fn context_char() -> impl Strategy<Value = char> {
        prop_oneof![
            4 => prop::char::range('a', 'z'),
            1 => prop::char::range('0', '9'),
            2 => prop::sample::select(vec!['[', ']', ';', 'm', '\\']),
            2 => prop::sample::select(vec![
                '\t', '\n', '\r', ' ', '\u{a0}', '\u{3000}', '\u{85}',
            ]),
            2 => prop::sample::select(vec![
                '\u{0}', '\u{1b}', '\u{7}', '\u{7f}', '\u{9f}', '\u{61c}', '\u{200b}',
                '\u{200f}', '\u{202e}', '\u{2066}', '\u{feff}',
            ]),
            2 => prop::sample::select(vec!['€', '漢', '😀', 'é']),
        ]
    }

    fn context_input() -> impl Strategy<Value = String> {
        prop::collection::vec(context_char(), 0..24).prop_map(|chars| chars.into_iter().collect())
    }

    /// Budgets straddle every boundary the sanitizer has: `0`, the 3-byte ellipsis
    /// threshold (`3`/`4`), and both sides of the largest field budget (128).
    fn context_budget() -> impl Strategy<Value = usize> {
        0usize..=140
    }

    proptest! {
        /// The sanitized value never exceeds its byte budget, whatever the input and
        /// whatever the budget — including the budgets below the 3-byte ellipsis, where
        /// the result is cut without one.
        ///
        /// The defect this catches is an off-by-one in the ellipsis reservation, which
        /// would put a 129-byte value into a 128-byte field.
        #[test]
        fn sanitized_context_string_fits_the_byte_budget(
            input in context_input(),
            max_bytes in context_budget(),
        ) {
            let out = sanitize_context_string(&input, max_bytes);

            prop_assert!(
                out.len() <= max_bytes,
                "sanitizing {:?} to {} bytes produced {} bytes",
                input,
                max_bytes,
                out.len()
            );
        }

        /// Nothing in the forbidden set reaches the output: no control character, no
        /// bidi formatter, no zero-width character, and therefore no `ESC` that could
        /// open an escape sequence on the phone's prompt.
        ///
        /// The predicate is the module's own [`is_forbidden_context_char`], not a
        /// re-transcription, so a code point added to the set is covered here without
        /// editing the property.
        #[test]
        fn sanitized_context_string_has_no_forbidden_code_point(
            input in context_input(),
            max_bytes in context_budget(),
        ) {
            let out = sanitize_context_string(&input, max_bytes);

            if let Some(found) = out.chars().find(|ch| is_forbidden_context_char(*ch)) {
                prop_assert!(
                    false,
                    "sanitizing {:?} to {} bytes kept forbidden U+{:04X} in {:?}",
                    input,
                    max_bytes,
                    found as u32,
                    out
                );
            }
        }

        /// The output is valid UTF-8. Rust's `String` cannot hold anything else, so this
        /// can only fail if `sanitize_context_string` stops returning one — it makes
        /// that signature change a test failure rather than a silent loss of the
        /// guarantee the Kotlin mirror depends on.
        #[test]
        fn sanitized_context_string_is_valid_utf8(
            input in context_input(),
            max_bytes in context_budget(),
        ) {
            let out = sanitize_context_string(&input, max_bytes);

            prop_assert!(
                core::str::from_utf8(out.as_bytes()) == Ok(out.as_str()),
                "sanitizing {:?} to {} bytes produced invalid UTF-8",
                input,
                max_bytes
            );
        }

        /// Sanitizing an already-sanitized value changes nothing. That is only true
        /// above the ellipsis threshold: at a budget of 2 or 3 bytes a cut can end on
        /// the very space the second pass would trim (`"a b"` at 2 bytes yields
        /// `"a "`), which is why the domain starts at 4.
        #[test]
        fn sanitized_context_string_is_idempotent(
            input in context_input(),
            max_bytes in 4usize..=140,
        ) {
            let once = sanitize_context_string(&input, max_bytes);
            let twice = sanitize_context_string(&once, max_bytes);

            prop_assert_eq!(
                &twice,
                &once,
                "re-sanitizing {:?} to {} bytes changed it",
                input,
                max_bytes
            );
        }
    }
}
