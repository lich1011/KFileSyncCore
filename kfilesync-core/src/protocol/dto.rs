//! Wire DTOs for lansync v1.
//!
//! # Sprint 4 implementation
//!
//! Reconciles the desktop/mobile DTO drift documented in
//! `CROSS_VALIDATION_DESKTOP_MOBILE.md` §4.3. Every struct here is the
//! single wire shape both hosts must use from now on - hand-typed,
//! per-host DTOs are retired.
//!
//! **Design choices made while unifying** (see ADR-014 for the full
//! rationale):
//!
//! - Field naming follows mobile's `from_*`/`*_id` conventions where the
//!   two hosts disagreed, because mobile's implementation already tracked
//!   the design docs faithfully (CROSS_VALIDATION §8.2) - desktop is the
//!   side catching up, not the other way around.
//! - `FileEntryDto::blocks` keeps desktop's richer `{index, size, hash}`
//!   object shape (not mobile's bare hash-array), because the domain
//!   `BlockInfo` type already has this shape and a chunk's `size` is
//!   otherwise only recoverable by assuming a fixed `chunk_size` - the
//!   object form is self-describing.
//! - `TransferItemDto::chunk_hashes` keeps mobile's per-chunk hash list
//!   (not desktop's single `chunk_count`), so integrity can be verified
//!   chunk-by-chunk as it arrives, per CROSS_VALIDATION §8.3's P0
//!   recommendation.
//! - `TransferAcceptDto::skip_chunks` keeps mobile's discrete
//!   `{file_id: [chunk_index, ...]}` shape (not desktop's "first N
//!   contiguous chunks" shape), because it can express arbitrary partial
//!   resumption, which is a strict superset of what the contiguous form
//!   can say.
//! - Every timestamp field ends in `_ms` and is milliseconds since the
//!   Unix epoch (ADR-006) - no exceptions.
//! - Every enum-like field is a `String` at the wire boundary, not a
//!   domain enum type - hosts convert to/from their own domain
//!   representation; the protocol layer stays decoupled from `domain`
//!   (see the module-level doc on `protocol`).
//!
//! Field naming convention:
//!
//! - Rust struct fields: `snake_case`
//! - Wire JSON keys: `snake_case` (matches serde default)
//! - UniFFI-generated Kotlin: `camelCase` (automatic translation)

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// UniFFI has no native support for `BTreeMap` (only `HashMap`). A type
// *alias* for a bare `BTreeMap<String, u64>` doesn't work as a
// `uniffi::custom_type!` target either: aliases are transparent, so the
// generated `impl<UT> FfiConverter<UT> for BTreeMap<String, u64>` trips
// Rust's orphan-coherence rule (E0210) - `BTreeMap` is just as foreign as
// `HashMap` is, alias or not. A local newtype sidesteps this the same way
// `domain::ShareId`/`DeviceId` do for `String`: it's a nominal type this
// crate owns, so `uniffi::custom_type!` can legally target it. `#[serde
// (transparent)]` keeps the wire JSON shape identical to a bare map either
// way - this is purely an FFI-bridging concern, invisible on the wire.
/// `{device_id: counter}` map - wraps `BTreeMap` so it can bridge to
/// UniFFI's `HashMap` via [`uniffi::custom_type!`] (see the comment above
/// on why a bare `BTreeMap` can't be a `custom_type!` target directly).
/// `#[serde(transparent)]` keeps the wire JSON shape identical to a bare
/// map - this wrapper is purely an FFI-bridging concern.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct VersionVectorMap(pub BTreeMap<String, u64>);

#[cfg(feature = "ffi")]
uniffi::custom_type!(VersionVectorMap, std::collections::HashMap<String, u64>, {
    lower: |m| m.0.into_iter().collect(),
    try_lift: |v| Ok(VersionVectorMap(v.into_iter().collect())),
});

/// `{file_id: [chunk_index, ...]}` map - see [`VersionVectorMap`] for why
/// this wraps `BTreeMap` instead of exposing it directly.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SkipChunksMap(pub BTreeMap<String, Vec<u32>>);

#[cfg(feature = "ffi")]
uniffi::custom_type!(SkipChunksMap, std::collections::HashMap<String, Vec<u32>>, {
    lower: |m| m.0.into_iter().collect(),
    try_lift: |v| Ok(SkipChunksMap(v.into_iter().collect())),
});

/// Response body for `GET /info`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DeviceInfoDto {
    /// Protocol family - always `"Lansync"`.
    pub protocol: String,
    /// Wire protocol version - currently `"1.0"`.
    pub version: String,
    /// Sender's device ID.
    pub device_id: String,
    /// Display name.
    pub alias: String,
    /// `"desktop"` or `"mobile"`.
    pub device_type: String,
    /// `"windows"` / `"macos"` / `"linux"` / `"android"` / `"ios"`.
    pub platform: String,
    /// SHA-256 hex of sender's TLS cert DER.
    pub fingerprint: String,
    /// HTTPS port (typically 53317).
    pub port: u16,
    /// Whether the device advertises itself via mDNS.
    pub announce: bool,
}

// -----------------------------------------------------------------------------
// Pairing
// -----------------------------------------------------------------------------

/// Body of `POST /pair/request` - initiate a pairing handshake.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PairRequestDto {
    /// Correlates this request with its eventual `/pair/confirm` call.
    pub request_id: String,
    /// Initiator's device ID.
    pub from_device_id: String,
    /// Initiator's display name.
    pub from_alias: String,
    /// `"windows"` / `"macos"` / `"linux"` / `"android"` / `"ios"`.
    pub from_platform: String,
    /// Initiator's full SHA-256 cert fingerprint hex (not truncated -
    /// the desktop alpha's 8-char `fingerprint_short` was dropped: a
    /// bootstrap-mode connection has nothing else to pin against, so the
    /// full value costs nothing and removes a truncation-collision risk).
    pub from_fingerprint: String,
    /// Anti-replay nonce for this specific request.
    pub nonce: String,
    /// When this request stops being acceptable, millis since epoch.
    pub expires_at_ms: i64,
}

/// Body of `POST /pair/confirm` - complete the dual-PIN OOB ceremony (see
/// `trust::pairing_state`, Sprint 5) and exchange certificates.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PairConfirmDto {
    /// Same `request_id` from the original [`PairRequestDto`].
    pub request_id: String,
    /// The PIN the confirming device read from the peer's screen (out of
    /// band) and is now asserting matches.
    pub pin: String,
    /// Confirming device's certificate, PEM-encoded.
    pub certificate_pem: String,
}

/// Body of `POST /pair/revoke` - tell a peer their trust has been revoked.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PairRevokeDto {
    /// Device whose trust is being revoked.
    pub device_id: String,
    /// Optional human-readable reason, shown in the peer's UI.
    pub reason: Option<String>,
    /// When the revocation was issued, millis since epoch.
    pub revoked_at_ms: i64,
}

/// Response body for `POST /pair/confirm` (and the initial ack for
/// `POST /pair/request`, before a PIN has been confirmed - in that case
/// `peer_certificate_pem` and `reason` are both `None` and `accepted` is
/// `false`, meaning "pending", not "rejected"; callers distinguish the two
/// by request state, not by this DTO alone).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PairResultDto {
    /// Same `request_id` from the original [`PairRequestDto`].
    pub request_id: String,
    /// Whether the PIN ceremony succeeded.
    pub accepted: bool,
    /// Present only when `accepted` - the responder's certificate, so the
    /// initiator can pin it going forward.
    pub peer_certificate_pem: Option<String>,
    /// Present only when rejected - a human-readable reason.
    pub reason: Option<String>,
}

// -----------------------------------------------------------------------------
// Shares
// -----------------------------------------------------------------------------

/// Body of `POST /share/invite` - invite an already-paired peer to a share.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ShareInviteDto {
    /// Stable share identifier.
    pub share_id: String,
    /// Display name shown in the invitee's UI.
    pub share_name: String,
    /// Inviter's device ID.
    pub from_device_id: String,
    /// `"read_only"` or `"read_write"` - see `domain::SharePermission`.
    pub default_permission: String,
    /// `"two_way"` / `"send_only"` / `"receive_only"` - see `domain::SyncMode`.
    pub sync_mode: String,
    /// When the invite was sent, millis since epoch.
    pub invited_at_ms: i64,
}

/// Body of `POST /share/authorize` - invitee's response to a
/// [`ShareInviteDto`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ShareAuthorizeDto {
    /// The share being authorized (or declined).
    pub share_id: String,
    /// Whether the invitee accepted.
    pub accepted: bool,
    /// Present only when declined - a human-readable reason.
    pub reason: Option<String>,
}

/// Body of `POST /share/leave` - voluntarily leave a share, or notify a
/// peer that this device has left.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ShareLeaveDto {
    /// The share being left.
    pub share_id: String,
    /// Device that is leaving.
    pub device_id: String,
    /// When the departure happened, millis since epoch.
    pub left_at_ms: i64,
}

// -----------------------------------------------------------------------------
// Sync index
// -----------------------------------------------------------------------------

/// One chunk's metadata within [`FileEntryDto::blocks`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct BlockInfoDto {
    /// Zero-based chunk index within the file.
    pub index: u32,
    /// Chunk size in bytes (may be smaller for the last chunk).
    pub size: u32,
    /// BLAKE3 hex of the chunk content.
    pub hash: String,
}

/// Wire shape of one `domain::FileEntry`, as it travels in an
/// [`IndexResponseDto`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FileEntryDto {
    /// Share containing this entry (repeated per-entry, not just at the
    /// top level, so a client processing entries streamed/paginated
    /// separately from the envelope never loses this association).
    pub share_id: String,
    /// Relative path inside the share root, `/`-separated.
    pub path: String,
    /// `"file"` or `"directory"` - lowercase, no `"symlink"` variant
    /// (ADR-008).
    pub entry_type: String,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Last modification time, millis since epoch.
    pub modified_at_ms: i64,
    /// Device ID of the last writer.
    pub modified_by: String,
    /// Causal version vector, `{"device_id": counter}`.
    pub version_vector: VersionVectorMap,
    /// SHA-256 hex of the full file content (`None` for directories).
    pub sha256: Option<String>,
    /// Per-chunk block list (empty for unchunked files and directories).
    pub blocks: Vec<BlockInfoDto>,
    /// Tombstone marker.
    pub deleted: bool,
    /// When the tombstone was created, millis since epoch; `None` if alive.
    pub deleted_at_ms: Option<i64>,
}

/// Response body for `GET /sync/index`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct IndexResponseDto {
    /// The share this index describes.
    pub share_id: String,
    /// Monotonic version of this index snapshot, so a client can detect
    /// "nothing changed since I last fetched" without comparing every
    /// entry.
    pub index_version: u64,
    /// All entries in the share (including tombstones).
    pub entries: Vec<FileEntryDto>,
}

// -----------------------------------------------------------------------------
// Transfers
// -----------------------------------------------------------------------------

/// One file within a [`TransferRequestDto`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferItemDto {
    /// Stable identifier for this file within the transfer job.
    pub file_id: String,
    /// Relative path inside the share root.
    pub path: String,
    /// Total size in bytes.
    pub size: u64,
    /// SHA-256 hex of the full file, checked once the transfer completes.
    pub sha256: String,
    /// Chunk size used to produce `chunk_hashes` (see
    /// `service::chunking::compute_chunk_size`).
    pub chunk_size: u32,
    /// BLAKE3 hex for every chunk, in order - lets the receiver verify
    /// each chunk as it arrives instead of only at the end.
    pub chunk_hashes: Vec<String>,
}

/// Body of `POST /transfer/request` - propose a transfer job.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferRequestDto {
    /// Stable identifier for this transfer job.
    pub job_id: String,
    /// Correlates this request with the sync session that triggered it.
    pub session_id: String,
    /// Sender's device ID.
    pub from_device_id: String,
    /// Sender's display name.
    pub from_alias: String,
    /// The share these files belong to, if the transfer is share-scoped.
    pub share_id: Option<String>,
    /// Files being offered.
    pub files: Vec<TransferItemDto>,
}

/// Response body for `POST /transfer/request`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferAcceptDto {
    /// Same `session_id` from the [`TransferRequestDto`].
    pub session_id: String,
    /// Same `job_id` from the [`TransferRequestDto`].
    pub job_id: String,
    /// Whether the receiver will proceed with (some or all of) the
    /// transfer.
    pub accepted: bool,
    /// Present only when declined outright - a human-readable reason.
    pub reason: Option<String>,
    /// Per-file list of chunk indices the receiver already has (e.g. from
    /// a previously interrupted transfer) and does not need re-sent.
    /// Keyed by `file_id`.
    pub skip_chunks: SkipChunksMap,
}

/// Small JSON ack sent back after each chunk upload. The chunk body
/// itself travels as raw bytes with a `X-Chunk-Hash` header (not as JSON -
/// see ADR-014), so this DTO only carries the bookkeeping.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferChunkAckDto {
    /// The transfer job this chunk belongs to.
    pub job_id: String,
    /// The file this chunk belongs to.
    pub file_id: String,
    /// Zero-based chunk index that was just uploaded.
    pub chunk_index: u32,
    /// Whether the hash in `X-Chunk-Hash` matched the received bytes.
    pub verified: bool,
}

/// Body of `POST /transfer/cancel`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferCancelDto {
    /// The transfer job being cancelled.
    pub job_id: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}
