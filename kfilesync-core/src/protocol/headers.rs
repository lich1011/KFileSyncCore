//! HTTP header names used by the anti-replay and identity layers.
//!
//! Hosts MUST set these on every mutating request!
//!
//! - [`HEADER_DEVICE_ID`]   - sender's device ID
//! - [`HEADER_TIMESTAMP`]   - milliseconds since epoch (NOT seconds)
//! - [`HEADER_NONCE`]       - fresh random nonce per request
//! - [`HEADER_FINGERPRINT`] - SHA-256 hex of sender's TLS cert DER
//!
//! Chunk upload additionally requires:
//!
//! - [`HEADER_CHUNK_HASH`]  - BLAKE3 hex of the chunk body

/// Sender's device ID (hex string).
pub const HEADER_DEVICE_ID: &str = "X-Device-Id";

/// Request timestamp, milliseconds since the Unix epoch.
///
/// **The unit is milliseconds, not seconds.** See ADR-006 for the migration
/// from the desktop's previous seconds-based scheme.
pub const HEADER_TIMESTAMP: &str = "X-Timestamp";

/// Per-request random nonce.
pub const HEADER_NONCE: &str = "X-Nonce";

/// Sender's TLS certificate fingerprint (SHA-256 hex of DER, lowercase).
pub const HEADER_FINGERPRINT: &str = "X-Fingerprint";

/// BLAKE3 hex of a chunk body (used only on chunk upload routes).
pub const HEADER_CHUNK_HASH: &str = "X-Chunk-Hash";

/// Marker: this codebase uses **milliseconds** for all wire timestamps.
pub const TIMESTAMP_UNIT_IS_MILLIS: bool = true;
