//! lansync v1 wire format.
//!
//! This module is the single source of truth for everything that travels
//! over the wire:
//!
//! - [`routes`]      - HTTP path constants
//! - [`headers`]     - HTTP header names and unit conventions
//! - [`conventions`] - enum casing, hex encoding, default port, etc.
//! - [`dto`]         - request/response data transfer objects
//! - [`codec`]       - parse/encode helpers
//!
//! Hosts MUST use the constants and DTOs from this module. Hand-typed
//! route strings or DTO field names are forbidden - code review will
//! reject them.

pub mod codec;
pub mod conventions;
pub mod dto;
pub mod headers;
pub mod routes;

use alloc::string::{String, ToString};

/// Bundled route paths and header names, for hosts that consume core only
/// over the UniFFI boundary and therefore cannot see this crate's plain
/// `pub const &str` items - UniFFI does not export bare constants (see
/// ADR-018). Rust/native consumers should keep using [`routes`] and
/// [`headers`] directly; this exists purely as an FFI bridge.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct WireConstants {
    /// [`routes::API_PREFIX`]
    pub api_prefix: String,
    /// [`routes::INFO`]
    pub route_info: String,
    /// [`routes::HEALTHZ`]
    pub route_healthz: String,
    /// [`routes::REGISTER`]
    pub route_register: String,
    /// [`routes::PAIR_REQUEST`]
    pub route_pair_request: String,
    /// [`routes::PAIR_CONFIRM`]
    pub route_pair_confirm: String,
    /// [`routes::PAIR_REVOKE`]
    pub route_pair_revoke: String,
    /// [`routes::SHARE_INVITE`]
    pub route_share_invite: String,
    /// [`routes::SHARE_AUTHORIZE`]
    pub route_share_authorize: String,
    /// [`routes::SHARE_LEAVE`]
    pub route_share_leave: String,
    /// [`routes::SYNC_INDEX`]
    pub route_sync_index: String,
    /// [`routes::TRANSFER_REQUEST`]
    pub route_transfer_request: String,
    /// [`routes::TRANSFER_CHUNK_PREFIX`]
    pub route_transfer_chunk_prefix: String,
    /// [`routes::TRANSFER_CANCEL`]
    pub route_transfer_cancel: String,
    /// [`routes::DEFAULT_PORT`]
    pub default_port: u16,
    /// [`headers::HEADER_DEVICE_ID`]
    pub header_device_id: String,
    /// [`headers::HEADER_TIMESTAMP`]
    pub header_timestamp: String,
    /// [`headers::HEADER_NONCE`]
    pub header_nonce: String,
    /// [`headers::HEADER_FINGERPRINT`]
    pub header_fingerprint: String,
    /// [`headers::HEADER_CHUNK_HASH`]
    pub header_chunk_hash: String,
    /// [`headers::TIMESTAMP_UNIT_IS_MILLIS`]
    pub timestamp_unit_is_millis: bool,
}

/// Return the single-source-of-truth route/header constants as a UniFFI
/// `Record`. Equivalent to reading [`routes`] and [`headers`] directly
/// only exists so FFI hosts get the same guarantee native Rust callers do.
#[must_use]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn wire_constants() -> WireConstants {
    WireConstants {
        api_prefix: routes::API_PREFIX.to_string(),
        route_info: routes::INFO.to_string(),
        route_healthz: routes::HEALTHZ.to_string(),
        route_register: routes::REGISTER.to_string(),
        route_pair_request: routes::PAIR_REQUEST.to_string(),
        route_pair_confirm: routes::PAIR_CONFIRM.to_string(),
        route_pair_revoke: routes::PAIR_REVOKE.to_string(),
        route_share_invite: routes::SHARE_INVITE.to_string(),
        route_share_authorize: routes::SHARE_AUTHORIZE.to_string(),
        route_share_leave: routes::SHARE_LEAVE.to_string(),
        route_sync_index: routes::SYNC_INDEX.to_string(),
        route_transfer_request: routes::TRANSFER_REQUEST.to_string(),
        route_transfer_chunk_prefix: routes::TRANSFER_CHUNK_PREFIX.to_string(),
        route_transfer_cancel: routes::TRANSFER_CANCEL.to_string(),
        default_port: routes::DEFAULT_PORT,
        header_device_id: headers::HEADER_DEVICE_ID.to_string(),
        header_timestamp: headers::HEADER_TIMESTAMP.to_string(),
        header_nonce: headers::HEADER_NONCE.to_string(),
        header_fingerprint: headers::HEADER_FINGERPRINT.to_string(),
        header_chunk_hash: headers::HEADER_CHUNK_HASH.to_string(),
        timestamp_unit_is_millis: headers::TIMESTAMP_UNIT_IS_MILLIS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_constants_matches_source_consts() {
        let wc = wire_constants();
        assert_eq!(wc.api_prefix, routes::API_PREFIX);
        assert_eq!(wc.route_pair_confirm, routes::PAIR_CONFIRM);
        assert_eq!(wc.header_chunk_hash, headers::HEADER_CHUNK_HASH);
        assert_eq!(wc.default_port, routes::DEFAULT_PORT);
        assert!(wc.timestamp_unit_is_millis);
    }
}