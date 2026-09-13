//! Parse/encode helpers for wire DTOs.
//!
//! Hosts use these instead of calling `serde_json` directly, so that the
//! exact JSON shape (snake_case, lowercase enums, millisecond timestamps,
//! etc.) is centrally enforced.

use alloc::string::String;
use alloc::vec::Vec;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Failure modes when decoding a wire payload.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Malformed JSON or unexpected fields.
    #[error("malformed payload: {0}")]
    Malformed(String),
}

/// Failure modes when encoding a wire payload.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// Internal serialization failure.
    #[error("encode failure: {0}")]
    Internal(String),
}

/// Parse a JSON byte slice into a typed DTO.
pub fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ParseError> {
    serde_json::from_slice(bytes).map_err(|e| ParseError::Malformed(e.to_string()))
}

/// Serialize a DTO into JSON bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    serde_json::to_vec(value).map_err(|e| EncodeError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dto::{
        BlockInfoDto, DeviceInfoDto, FileEntryDto, IndexResponseDto, PairConfirmDto,
        PairRequestDto, PairResultDto, PairRevokeDto, ShareAuthorizeDto, ShareInviteDto,
        ShareLeaveDto, TransferAcceptDto, TransferCancelDto, TransferChunkAckDto, TransferItemDto,
        TransferRequestDto,
    };
    use alloc::collections::BTreeMap;

    /// Round-trip every DTO test through the same `encode`/`parse` pair a
    /// real host uses, rather than calling `serde_json` directly — this is
    /// the whole point of routing wire (de)serialization through `codec`
    /// instead of ad hoc `serde_json` calls at each call site.
    fn roundtrip<T>(value: T)
    where
        T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
    {
        let bytes = encode(&value).unwrap();
        let parsed: T = parse(&bytes).unwrap();
        assert_eq!(value, parsed);
    }

    #[test]
    fn device_info_roundtrip() {
        roundtrip(DeviceInfoDto {
            protocol: "lansync".into(),
            version: "1.0".into(),
            device_id: "abcd".into(),
            alias: "phone".into(),
            device_type: "mobile".into(),
            platform: "ios".into(),
            fingerprint: "ffff".into(),
            port: 53317,
            announce: true,
        });
    }

    #[test]
    fn pair_request_roundtrip() {
        roundtrip(PairRequestDto {
            request_id: "req-1".into(),
            from_device_id: "dev-a".into(),
            from_alias: "Alice".into(),
            from_platform: "macos".into(),
            from_fingerprint: "abcdef".into(),
            nonce: "n1".into(),
            expires_at_ms: 1_000,
        });
    }

    #[test]
    fn pair_confirm_roundtrip() {
        roundtrip(PairConfirmDto {
            request_id: "req-1".into(),
            pin: "123456".into(),
            certificate_pem: "-----BEGIN CERT-----".into(),
        });
    }

    #[test]
    fn pair_revoke_roundtrip() {
        roundtrip(PairRevokeDto {
            device_id: "dev-a".into(),
            reason: Some("lost device".into()),
            revoked_at_ms: 2_000,
        });
        // Optional fields must round-trip cleanly through `None` too.
        roundtrip(PairRevokeDto {
            device_id: "dev-a".into(),
            reason: None,
            revoked_at_ms: 2_000,
        });
    }

    #[test]
    fn pair_result_roundtrip() {
        roundtrip(PairResultDto {
            request_id: "req-1".into(),
            accepted: true,
            peer_certificate_pem: Some("-----BEGIN CERT-----".into()),
            reason: None,
        });
        roundtrip(PairResultDto {
            request_id: "req-1".into(),
            accepted: false,
            peer_certificate_pem: None,
            reason: Some("pin mismatch".into()),
        });
    }

    #[test]
    fn share_invite_roundtrip() {
        roundtrip(ShareInviteDto {
            share_id: "share-1".into(),
            share_name: "Photos".into(),
            from_device_id: "dev-a".into(),
            default_permission: "read_write".into(),
            sync_mode: "two_way".into(),
            invited_at_ms: 3_000,
        });
    }

    #[test]
    fn share_authorize_roundtrip() {
        roundtrip(ShareAuthorizeDto {
            share_id: "share-1".into(),
            accepted: true,
            reason: None,
        });
    }

    #[test]
    fn share_leave_roundtrip() {
        roundtrip(ShareLeaveDto {
            share_id: "share-1".into(),
            device_id: "dev-a".into(),
            left_at_ms: 4_000,
        });
    }

    #[test]
    fn index_response_roundtrip() {
        let mut vv = BTreeMap::new();
        vv.insert("dev-a".to_string(), 3u64);
        roundtrip(IndexResponseDto {
            share_id: "share-1".into(),
            index_version: 42,
            entries: alloc::vec![FileEntryDto {
                share_id: "share-1".into(),
                path: "docs/report.pdf".into(),
                entry_type: "file".into(),
                size: 1024,
                modified_at_ms: 1_717_900_000_000,
                modified_by: "dev-a".into(),
                version_vector: vv,
                sha256: Some("deadbeef".into()),
                blocks: alloc::vec![BlockInfoDto {
                    index: 0,
                    size: 131_072,
                    hash: "abc123".into(),
                }],
                deleted: false,
                deleted_at_ms: None,
            }],
        });
    }

    #[test]
    fn index_response_with_tombstone_roundtrip() {
        // Tombstones (deleted entries) must survive the wire just as
        // faithfully as live entries — see ADR-009.
        roundtrip(IndexResponseDto {
            share_id: "share-1".into(),
            index_version: 43,
            entries: alloc::vec![FileEntryDto {
                share_id: "share-1".into(),
                path: "old.txt".into(),
                entry_type: "file".into(),
                size: 0,
                modified_at_ms: 1_000,
                modified_by: "dev-a".into(),
                version_vector: BTreeMap::new(),
                sha256: None,
                blocks: Vec::new(),
                deleted: true,
                deleted_at_ms: Some(1_500),
            }],
        });
    }

    #[test]
    fn transfer_request_roundtrip() {
        roundtrip(TransferRequestDto {
            job_id: "job-1".into(),
            session_id: "sess-1".into(),
            from_device_id: "dev-a".into(),
            from_alias: "Alice".into(),
            share_id: Some("share-1".into()),
            files: alloc::vec![TransferItemDto {
                file_id: "file-1".into(),
                path: "a.txt".into(),
                size: 300_000,
                sha256: "deadbeef".into(),
                chunk_size: 131_072,
                chunk_hashes: alloc::vec!["h1".to_string(), "h2".to_string(), "h3".to_string()],
            }],
        });
    }

    #[test]
    fn transfer_accept_roundtrip() {
        let mut skip = BTreeMap::new();
        skip.insert("file-1".to_string(), alloc::vec![0u32, 2, 5]);
        roundtrip(TransferAcceptDto {
            session_id: "sess-1".into(),
            job_id: "job-1".into(),
            accepted: true,
            reason: None,
            skip_chunks: skip,
        });
    }

    #[test]
    fn transfer_chunk_ack_roundtrip() {
        roundtrip(TransferChunkAckDto {
            job_id: "job-1".into(),
            file_id: "file-1".into(),
            chunk_index: 3,
            verified: true,
        });
    }

    #[test]
    fn transfer_cancel_roundtrip() {
        roundtrip(TransferCancelDto {
            job_id: "job-1".into(),
            reason: Some("user cancelled".into()),
        });
    }
}
