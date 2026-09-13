//! Shared constants and invariants enforced across the codebase.
//!
//! These are the values that **MUST** be identical between desktop and
//! mobile hosts. Centralizing them here means a single edit propagates
//! to both sides via the core crate.

pub mod chunk_sizes;
pub mod defaults_syncignore;
pub mod window_size;
