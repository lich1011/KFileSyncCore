//! kfilesync-core
//!
//! Sans-IO core for KFileSync. This crate contains the protocol definitions,
//! domain models, domain services, zero-trust decisions, and cryptographic
//! primitives shared between the desktop (Tauri + Rust) and mobile (KMP)
//! applications.
//!
//! # Design constraints
//!
//! - **No I/O**: no `std::fs`, no `std::net`, no sockets, no databases.
//! - **No async**: every public function is synchronous. Hosts handle their
//!   own concurrency model (tokio on desktop, coroutines on mobile).
//! - **State-passing**: long-lived state is passed in as `&mut` parameters
//!   rather than owned by the library, enabling host-controlled persistence
//!   and lifecycle.
//! - **`no_std` compatible** (modulo the optional `std` feature for ergonomic
//!   error types in hosts that need them).
//!
//! See the design documents in `KFileSync_DOC/` for the complete rationale.

// We use `std` by default for ergonomics, but the core algorithms are
// `no_std`-compatible. Set `default-features = false` in Cargo.toml to
// drop the `std` feature.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)] // most errors are obvious from types

extern crate alloc;

// --- Public modules ---

pub mod crypto;
pub mod domain;
pub mod invariants;
pub mod protocol;
pub mod service;
pub mod trust;

// --- FFI (feature-gated) ---

#[cfg(feature = "ffi")]
#[allow(unsafe_code)] // UniFFI scaffolding requires unsafe internally
mod ffi;

// --- Library metadata ---

/// The wire protocol version this core implements.
pub const PROTOCOL_VERSION: &str = "lansync/1.0";

/// The library version, matching `Cargo.toml`.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");
