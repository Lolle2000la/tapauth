//! JNI helper utilities for Android interop.
//!
//! This module provides reusable helpers for common JNI patterns:
//! - Exception throwing with consistent error mapping
//! - Byte array and string conversions between JNI and Rust
//! - Object array construction
//! - Protobuf encoding/decoding with JNI error handling
//!
//! ## Threading and Safety
//!
//! All functions assume they are called with a valid `JNIEnv` on the
//! thread that owns it. JNI `Env` pointers are not thread-safe and must
//! not be shared across threads.
//!
//! ## Ownership and Lifetimes
//!
//! Values returned via `into_raw()` transfer ownership to the JVM.
//! The JVM's garbage collector manages their lifecycle; Rust code must
//! not attempt to free them.
//!
//! ## Exception Policy
//!
//! Helper functions throw Java exceptions and return `None` on failure.
//! Callers must check `Option` results and return immediately (typically
//! `null` or `false`) after receiving `None`, as a pending exception
//! has been set on the JNI environment.

pub mod arrays;
pub mod conversions;
pub mod exceptions;
pub mod objects;
pub mod protobuf;

pub use arrays::*;
pub use conversions::*;
pub use exceptions::*;
pub use objects::*;
pub use protobuf::*;
