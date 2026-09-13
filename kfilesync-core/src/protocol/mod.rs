//! Lansync v1 wire format.
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
