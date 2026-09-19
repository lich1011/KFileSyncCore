//! Transfer model.
//!
//! # Sprint 3 implementation
//!
//! Currently a placeholder. Full implementation in Sprint 3.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// State machine for a transfer job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    /// Job created locally, not yet handed to the peer (queued, e.g. while
    /// offline or waiting for a network path).
    Pending,
    /// Request handshake sent to the peer, awaiting acceptance.
    Requested,
    /// Peer accepted, chunks being exchanged.
    Active,
    /// Interrupted (user-paused, or connection/process loss). Each item's
    /// `TransferItem::checkpoint` records how far it got, so resuming
    /// re-enters `Active` without re-transferring completed chunks.
    Paused,
    /// All chunks done, verifying integrity.
    Verifying,
    /// Successfully completed.
    Completed,
    /// Failed (see error).
    Failed,
    /// Cancelled by user.
    Cancelled,
}

/// Resume cursor for one [`TransferItem`]: how many of its chunks have
/// already been exchanged and verified. `None` on the item means the item
/// has not started; `Some` records a point a paused/interrupted transfer
/// can resume from instead of re-sending completed chunks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct Checkpoint {
    /// Number of leading chunks (by index into `chunk_hashes`) already
    /// completed and verified.
    pub chunks_done: u32,
}


/// One file inside a transfer job.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferItem {
    /// Stable identifier of this item within the job.
    pub file_id: String,
    /// Relative path inside the share.
    pub path: String,
    /// Total size in bytes.
    pub size: u64,
    /// SHA-256 hex of the full content.
    pub sha256: String,
    /// Chunk size in bytes (0 = unchunked).
    pub chunk_size: u32,
    /// Per-chunk BLAKE3 hex list.
    pub chunk_hashes: Vec<String>,
    /// Resume cursor. `None` until the first chunk completes.
    pub checkpoint: Option<Checkpoint>,
}

/// Which side of a [`TransferJob`] the local host is on.
///
/// `TransferJob::from_device_id` alone cannot answer "am I sending or
/// receiving" without every caller separately comparing it against "my own
/// device id" - this field makes that comparison once, at job-creation
/// time, instead of at every consumption site.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    /// Local device is `from_device_id`; we are sending.
    Outgoing,
    /// Local device is the peer; we are receiving.
    Incoming,
}

/// A transfer job (one direction, possibly multiple files).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferJob {
    /// Job identifier.
    pub id: String,
    /// Session this job belongs to.
    pub session_id: String,
    /// Device initiating the transfer.
    pub from_device_id: String,
    /// Whether the local host is sending or receiving this job.
    pub direction: TransferDirection,
    /// State.
    pub state: TransferState,
    /// Items to transfer.
    pub items: Vec<TransferItem>,
}
