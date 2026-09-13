//! Anti-replay window size, PIN TTL, tombstone retention, etc.
//!
//! These match [`crate::protocol::conventions`] for spec values, kept here
//! as separate constants so non-protocol code can reference them without
//! pulling in the protocol module.

/// Anti-replay sliding window size, in milliseconds (5 minutes).
pub const ANTI_REPLAY_WINDOW_MS: i64 = 5 * 60 * 1000;

/// Maximum tolerated clock skew between peers, in milliseconds.
pub const CLOCK_SKEW_TOLERANCE_MS: i64 = 5 * 60 * 1000;

/// PIN time-to-live during a pairing ceremony, in milliseconds.
pub const PAIRING_PIN_TTL_MS: i64 = 5 * 60 * 1000;

/// Maximum PIN attempts before a session is abandoned.
pub const PAIRING_MAX_ATTEMPTS: u32 = 3;

/// Tombstone retention before garbage collection, in milliseconds (30 days).
pub const TOMBSTONE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
