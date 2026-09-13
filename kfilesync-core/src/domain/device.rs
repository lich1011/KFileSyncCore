//! Device model and trust state machine.
//!
//! # Sprint 3 implementation
//!
//! Currently a placeholder. Full implementation in Sprint 3.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Stable opaque device identifier, derived from `SHA-256(cert.DER)`.
///
/// Represented as 64-char lowercase hex.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub String);

/// Coarse-grained device category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    /// Desktop / laptop running KFileSync (Tauri).
    Desktop,
    /// Mobile device (Android or iOS) running KFileSyncMobile.
    Mobile,
}

/// OS / platform family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    /// Windows desktop.
    Windows,
    /// macOS desktop.
    MacOS,
    /// Linux desktop.
    Linux,
    /// Android phone / tablet.
    Android,
    /// iOS phone / iPad.
    IOS,
}

/// Trust state machine for a peer device.
///
/// State transitions (managed by the trust evaluator and pairing service):
///
/// ```text
/// Discovered ──(/pair/request)──► Pairing ──(PIN verify)──► Paired
///     │                              │                        │
///     └──────────(/pair/reject)──────┴─────(/pair/revoke)─────┤
///                                                             ▼
///                                                          Revoked
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeviceState {
    /// Seen on the network but not yet trusted.
    Discovered,
    /// Pairing in progress; PIN ceremony has started.
    Pairing,
    /// Trusted peer - full sync permitted subject to share permissions.
    Paired,
    /// Trust explicitly revoked.
    Revoked,
}

/// A peer device with its current trust state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    /// Globally unique device identifier.
    pub id: DeviceId,
    /// Human-readable name shown in UI.
    pub alias: String,
    /// Device category (desktop/mobile).
    pub device_type: DeviceType,
    /// OS platform.
    pub platform: DevicePlatform,
    /// Trust state.
    pub state: DeviceState,
    /// TLS certificate fingerprint (SHA-256 hex of cert DER), if known.
    pub cert_fingerprint_hex: Option<String>,
}
