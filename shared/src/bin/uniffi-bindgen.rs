//! Bindings generator for this crate's UniFFI surface.
//!
//! The surface lives in `shared/src/ffi.rs`; this binary turns the metadata
//! compiled into `libshared.so` into Kotlin. Both features are needed: `cli`
//! builds this binary, and `jni` is what compiles `ffi.rs` at all, so `cli`
//! alone ends in "No UniFFI metadata found".
//!
//! Generate from an **Android** `libshared.so`, never the host one:
//! `init_logging` is exported under `cfg(target_os = "android")` only, so a host
//! library yields bindings whose Kotlin has no `initLogging`, which
//! `TapAuthApplication.onCreate` calls. Run from `shared/` after the Android
//! build produced the library (any ABI — the metadata is architecture-agnostic):
//!
//! ```text
//! cargo run --features cli,jni --bin uniffi-bindgen -- \
//!     generate ../server-android/app/build/rustJniLibs/android/arm64-v8a/libshared.so \
//!     --language kotlin --out-dir <dir> --no-format
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
