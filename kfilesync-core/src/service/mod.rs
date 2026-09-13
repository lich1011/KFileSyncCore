//! Stateless domain services.
//!
//! Each submodlue provides pure functions that operate on domain types.
//! Long-live state (e.g. the nonce-replay window) is onwned by the host
//! and passed in as `&mut` parameters.

pub mod chunking;
pub mod conflict_resolver;
pub mod ignore_spec;
pub mod nonce_window;
pub mod policy_enforcer;
pub mod sync_plan_generator;
