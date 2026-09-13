//! BLAKE3 per-chunk hashing.
//!
//! # Sprint 5 implementation
//!
//! Wraps the `blake3` crate. Returns lowercase hex consistent with the
//! protocol conventions (see [`crate::protocol::conventions::HEX_IS_LOWERCASE`]).

use alloc::string::String;

use crate::crypto::to_hex_lower;

/// Compute the BLAKE3 hash of `data` and return it as lowercase hex.
///
/// # Examples
///
/// ```
/// use kfilesync_core::crypto::chunk_hasher::hash_chunk;
/// let hex = hash_chunk(b"hello");
/// assert_eq!(hex.len(), 64);
/// assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
/// ```
#[must_use]
pub fn hash_chunk(data: &[u8]) -> String {
    let digest = blake3::hash(data);
    to_hex_lower(digest.as_bytes())
}

/// Constant-time verification that `data` hashes to `expected_hex`.
///
/// Used on the receiver side after pulling a chunk from the wire.
#[must_use]
pub fn verify_chunk(data: &[u8], expected_hex: &str) -> bool {
    let actual: String = hash_chunk(data);
    use subtle::ConstantTimeEq;
    actual.as_bytes().ct_eq(expected_hex.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_known_digest() {
        // BLAKE3 of empty input is a well-known constant.
        let expected: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        assert_eq!(hash_chunk(b""), expected);
    }

    #[test]
    fn verify_round_trip() {
        let data: &[u8; 15] = b"some chunk data";
        let hex: String = hash_chunk(data);
        assert!(verify_chunk(data, &hex));
        assert!(!verify_chunk(b"different data", &hex));
    }
}
