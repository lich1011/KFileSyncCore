//! Certificate fingerprint pinning.
//!
//! # Sprint 5 implementation
//!
//! Currently a placeholder.

use subtle::ConstantTimeEq;

/// Constant-time comparison between an asserted fingerprint hex string and
/// an expected one. Returns `true` on byte-equal match.
///
/// Both inputs must be normalized (lowercase hex, no separators). The
/// comparison is constant-time to prevent timing attacks.
#[must_use]
pub fn verify_fingerprint_hex(asserted: &str, expected: &str) -> bool {
    if asserted.len() != expected.len() {
        return false;
    }
    asserted.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_passes() {
        assert!(verify_fingerprint_hex(
            "abcdef0123456789",
            "abcdef0123456789"
        ));
    }

    #[test]
    fn mismatched_length_fails_early() {
        assert!(!verify_fingerprint_hex("abcd", "abcde"));
    }

    #[test]
    fn single_byte_diff_fails() {
        assert!(!verify_fingerprint_hex(
            "abcdef0123456789",
            "abcdef0123456788"
        ));
    }
}
