//! Share model.
//!
//! # Sprint 3 implementation
//!
//! Currently a placeholder. Full implementation in Sprint 3.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Stable identifier of a shared folder.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ShareId(pub String);

#[cfg(feature = "ffi")]
uniffi::custom_newtype!(ShareId,String);

/// Permission level for a share member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum SharePermission {
    /// May only receive (pull).
    ReadOnly,
    /// Full bidirectional sync.
    ReadWrite,
}

/// Global direction policy for a share.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// Push and pull.
    TwoWay,
    /// Local -> remote only.
    SendOnly,
    /// Remote -> local only.
    ReceiveOnly,
}

/// Lifecycle status of a share (host-side, not used in wire protocol).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    /// Waiting for the invitee to authorize.
    Pending,
    /// Actively syncing.
    Active,
    /// User explicitly paused.
    Paused,
    /// Share was left or revoked.
    Left,
}

/// A shared folder definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct Share {
    /// Stable identifier.
    pub id: ShareId,
    /// Display name.
    pub name: String,
    /// Direction policy.
    pub sync_mode: SyncMode,
    /// Default permission applied to new members.
    pub default_permission: SharePermission,
    /// Current lifecycle status.
    pub status: ShareStatus,
}
