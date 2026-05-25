//! Protobuf encoding/decoding helpers for JNI.

use jni::EnvUnowned as JNIEnv;
use prost::Message;

use super::exceptions::throw_io_exception;

/// Decode a protobuf message from bytes.
///
/// ## Returns
///
/// `Some(T)` on success, `None` if decoding fails.
///
/// ## Errors
///
/// Throws `IOException` and returns `None` if protobuf decoding fails.
pub fn decode_message<T: Message + Default>(env: &mut JNIEnv, bytes: &[u8]) -> Option<T> {
    match T::decode(bytes) {
        Ok(msg) => Some(msg),
        Err(err) => {
            throw_io_exception(env, format!("protobuf decode failed: {err}"));
            None
        }
    }
}

/// Encode a protobuf message to bytes.
///
/// ## Returns
///
/// `Some(Vec<u8>)` on success, `None` if encoding fails.
///
/// ## Errors
///
/// Throws `IOException` and returns `None` if protobuf encoding fails.
pub fn encode_message<T: Message>(env: &mut JNIEnv, msg: &T) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    match msg.encode(&mut buf) {
        Ok(()) => Some(buf),
        Err(err) => {
            throw_io_exception(env, format!("protobuf encode failed: {err}"));
            None
        }
    }
}
