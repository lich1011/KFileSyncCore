//! Derive a [`DeviceId`] from a TLS certificate DER blob.
//!
//! The canonical formula is `device_id = lowercase_hex(SHA-256(cert.DER))`.
//! Both desktop and mobile MUST produce the same value for the same cert.

use crate::crypto::file_hasher::sha256_hex;
use crate::domain::DeviceId;

/// Compute the device ID from a TLS certificate DER blob.
///
/// # Examples
///
/// ```
/// use kfilesync_core::crypto::device_id::derive_device_id;
/// // Empty input -> SHA-256 of empty.
/// let id = derive_device_id(b"");
/// assert_eq!(id.0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
/// ```
#[must_use]
pub fn derive_device_id(cert_der: &[u8]) -> DeviceId {
    DeviceId(sha256_hex(cert_der))
}

/// First 16 hex chars of the device ID, formatted in 4-4-4-4 dash groups.
///
/// Used as a human-friendly fingerprint short form (e.g. shown in pairing UI).
#[must_use]
pub fn fingerprint_short(device_id: &DeviceId) -> alloc::string::String {
    let head: &str = &device_id.0[..16];
    let mut out: String = alloc::string::String::with_capacity(19);
    for (i, c) in head.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_input() {
        let a: DeviceId = derive_device_id(b"hello world");
        let b: DeviceId = derive_device_id(b"hello world");
        assert_eq!(a.0, b.0);
        assert_eq!(a.0.len(), 64);
    }

    #[test]
    fn different_inputs_diverge() {
        let a: DeviceId = derive_device_id(b"hello world");
        let b: DeviceId = derive_device_id(b"hello world!");
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn fingerprint_short_format() {
        let id: DeviceId = DeviceId("abcdef0123456789ffff".into());
        assert_eq!(fingerprint_short(&id), "abcd-ef01-2345-6789");
    }
}
