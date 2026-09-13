//! UniFFI scaffolding.
//!
//! This module is only compiled when the `ffi` feature is enabled. It is
//! the **only** place where `unsafe` may appear (UniFFI generates `unsafe`
//! code for FFI boundary marshalling).
//!
//! The actual exports are declared with `#[uniffi::export]` attributes on
//! the public API in `domain/`, `service/`, etc. This module exists as a
//! pure scaffolding entry point.

// UniFFI scaffolding macro - generates the C ABI symbols.
uniffi::setup_scaffolding!();

// Re-export key types so the UniFFI bindgen can find them under one path.
//
// Sprint 1 exports - minimal surface to validate the toolchain end-to-end.
#[allow(unused_imports)]
pub use crate::domain::version_vector::VersionVector;
#[allow(unused_imports)]
pub use crate::service::chunking::{compute_chunk_count, compute_chunk_size};

// TODO Sprint 2+: progressively export more types as their implementations land.
