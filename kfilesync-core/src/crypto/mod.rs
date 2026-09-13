//! Cryptographic primitives.
//!
//! - [`chunk_hasher`] - BLAKE3 per-chunk hashing
//! - [`file_hasher`]  - SHA-256 streaming hash (state-passing API)
//! - [`device_id`]    - derive `DeviceId` from a TLS certificate DER

pub mod chunk_hasher;
pub mod device_id;
pub mod file_hasher;

use alloc::string::String;

/// Lowercase hex encoder used throughout the crate.
#[must_use]
pub fn to_hex_lower(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding_is_lowercase() {
        assert_eq!(to_hex_lower(&[0x00]), "00");
        assert_eq!(to_hex_lower(&[0xff]), "ff");
        assert_eq!(to_hex_lower(&[0xab, 0xcd, 0xef]), "abcdef");
    }
}
