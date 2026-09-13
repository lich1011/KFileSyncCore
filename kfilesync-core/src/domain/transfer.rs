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
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    /// Job created, awaiting peer acceptance.
    Requested,
    /// Peer accepted, chunks being exchanged.
    Active,
    /// All chunks done, verifying integrity.
    Verifying,
    /// Successfully completed.
    Completed,
    /// Failed (see error).
    Failed,
    /// Cancelled by user.
    Cancelled,
}

/// One file inside a transfer job.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

/// A transfer job (one direction, possibly multiple files).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferJob {
    /// Job identifier.
    pub id: String,
    /// Session this job belongs to.
    pub session_id: String,
    /// Device initiating the transfer.
    pub from_device_id: String,
    /// State.
    pub state: TransferState,
    /// Items to transfer.
    pub items: Vec<TransferItem>,
}
