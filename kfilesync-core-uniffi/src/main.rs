//! Standalone `uniffi-bindgen` binary.
//!
//! Mobile build scripts invoke this binary to generate Kotlin / Swift
//! bindings from `kfilesync-core/src/kfilesync_core.udl`. The Rust crate
//! itself only does scaffolding generation via `build.rs`.
//!
//! # Usage
//!
//! ```text
//! cargo run -p kfilesync-core-uniffi -- \
//!     generate ../kfilesync-core/src/kfilesync_core.udl \
//!     --language kotlin \
//!     --out-dir ./generated-bindings
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
