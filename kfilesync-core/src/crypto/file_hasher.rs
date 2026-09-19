//! Streaming SHA-256 with a state-passing API.
//!
//! Used to compute the full-file SHA-256 across multiple `update` calls,
//! so hosts can stream file content without loading it all into memory.
//!
//! Sans-IO note: the host owns the read loop and feeds chunks. Core never
//! touches the filesystem.
//!
//! # Sprint 5 implementation

use alloc::string::String;
use sha2::{Digest, Sha256};

use crate::crypto::to_hex_lower;

/// Opaque streaming hasher state.
///
/// Pass `&mut self` to `update`, then `finalize` to obtain the digest.
pub struct Sha256State {
    inner: Sha256,
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    /// Create a fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed bytes into the hasher.
    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// Consume the hasher and return the digest as lowercase hex.
    #[must_use]
    pub fn finalize(self) -> String {
        let digest = self.inner.finalize();
        to_hex_lower(&digest)
    }
}

/// One-shot helper for small inputs.
#[must_use]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut s: Sha256State = Sha256State::new();
    s.update(data);
    s.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_known_digest() {
        // SHA-256 of empty input.
        let expected: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(sha256_hex(b""), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: &[u8; 43] = b"the quick brown fox jumps over the lazy dog";
        let one_shot: String = sha256_hex(data);

        let mut s: Sha256State = Sha256State::new();
        s.update(&data[..10]);
        s.update(&data[10..20]);
        s.update(&data[20..]);
        let streamed: String = s.finalize();

        assert_eq!(one_shot, streamed);
    }
}
