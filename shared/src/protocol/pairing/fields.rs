//! The per-field helpers both roles apply to a value before it enters the
//! transcript: a device name cut down to the transcript's byte budget, and a
//! 32-byte protobuf `bytes` field parsed as a key.
//!
//! Neither is transcript material — each normalizes one field — so they live here
//! rather than in [`super::transcript`].

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
