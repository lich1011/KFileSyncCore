//! Wire format conventions.
//!
//! Documents the contract between desktop and mobile hosts. Any field that
//! crosses the wire must conform to these rules. New protocol additions
//! must update this module first.

/// Wire protocol family identifier used in `/info` responses.
pub const PROTOCOL_NAME: &str = "Lansync";

/// Wire protocol semver-like version string.
pub const PROTOCOL_VERSION: &str = "1.0";

/// JSON enum values are lowercase snake_case (e.g. `"file"`, `"directory"`,
/// `"read_only"`, `"read_write"`). PascalCase variants from earlier
/// alpha versions are rejected.
pub const ENUM_CASE_IS_LOWERCASE: bool = true;

/// All hex-encoded outputs (BLAKE3, SHA-256, fingerprints) use lowercase
/// without any separators or `0x` prefix.
pub const HEX_IS_LOWERCASE: bool = true;

/// Anti-replay window size in milliseconds.
pub const ANTI_REPLAY_WINDOW_MS: i64 = 5 * 60 * 1000;

/// Maximum tolerated clock skew between peers, in milliseconds.
pub const CLOCK_SKEW_TOLERANCE_MS: i64 = 5 * 60 * 1000;

/// PIN time-to-live during a pairing ceremony, in milliseconds.
pub const PAIRING_PIN_TTL_MS: i64 = 5 * 60 * 1000;

/// Tombstone retention before garbage collection, in milliseconds.
pub const TOMBSTONE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
