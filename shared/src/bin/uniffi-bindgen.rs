//! Bindings generator for this crate's UniFFI surface.
//!
//! The surface lives in `shared/src/ffi.rs`; this binary turns the metadata
//! compiled into `libshared.so` into Kotlin. Build the library with the `jni`
//! feature first, then:
//!
//! ```text
//! cargo run --features cli --bin uniffi-bindgen -- \
//!     generate ../target/debug/libshared.so --language kotlin --out-dir <dir> --no-format
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
