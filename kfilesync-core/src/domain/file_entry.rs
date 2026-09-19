//! File entry model.
//!
//! A [`FileEntry`] represents one path (file, directory, or tombstone) inside
//! a share. It carries the metadata needed for sync planning: size, mtime,
//! per-device version vector, content hash, and chunk hashes.
//!
//! # Sprint 3 implementation
//!
//! This module is currently a placeholder. The full implementation lands in
//! Sprint 3 - see `CORE_DEVELOPMENT_PLAN.md` §2 Sprint 3.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::domain::VersionVector;

/// What kind of filesystem entity this entry describes.
///
/// Wire serialization uses lowercase strings (`"file"`, `"directory"`).
/// Symlinks were dropped in the unified wire format because mobile platforms
/// do not represent them uniformly - see ADR-008.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[serde(rename_all = "lowercase")]
pub enum EntryType {
    /// Regular file.
    File,
    /// Directory.
    Directory,
}

/// Per-chunk metadata used for transfer and dedup.
///
/// `hash` is BLAKE3 hex (lowercase, 64 chars).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct BlockInfo {
    /// Zero-based chunk index inside the file.
    pub index: u32,
    /// Chunk size in bytes (may be smaller for the last chunk).
    pub size: u32,
    /// BLAKE3 hex of the chunk content.
    pub hash: String,
}

/// One row in a share's file index.
///
/// All time fields are **milliseconds since the Unix epoch** - see ADR-006.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FileEntry {
    /// Identifier of the share containing this entry.
    pub share_id: String,
    /// Relative path inside the share root, using `/` separators.
    pub path: String,
    /// File or directory.
    pub entry_type: EntryType,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Last modification time, **milliseconds since epoch**.
    pub modified_at_ms: i64,
    /// Device ID of the last writer.
    pub modified_by: String,
    /// Causal version vector across all devices that have touched this path.
    pub version_vector: VersionVector,
    /// SHA-256 hex of the full file content (`None` for directories).
    pub sha256: Option<String>,
    /// Per-chunk block list (empty for unchunked files and directories).
    pub blocks: Vec<BlockInfo>,
    /// Tombstone marker - `true` means the file was deleted at `deleted_at_ms`.
    pub deleted: bool,
    /// When the tombstone was created (millis since epoch); `None` if alive.
    pub deleted_at_ms: Option<i64>,
}
