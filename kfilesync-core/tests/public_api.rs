//! Integration tests at the crate boundary.
//!
//! These exercise the public API the same way a host (desktop or mobile)
//! would, so they catch breaking changes to the surface area.

use kfilesync_core::domain::{
    Device, DeviceId, DevicePlatform, DeviceState, DeviceType, EntryType, FileEntry, Share,
    ShareId, SharePermission, ShareStatus, SyncMode, VersionVector,
};
use kfilesync_core::service::chunking::{compute_chunk_count, compute_chunk_size};
use kfilesync_core::service::conflict_resolver::{
    apply_resolution, conflict_copy_name, ConflictResolution,
};
use kfilesync_core::service::nonce_window::{verify_and_record, NonceVerdict, NonceWindowState};
use kfilesync_core::service::policy_enforcer::{evaluate_policy, PolicyDecision, SyncDirection};
use kfilesync_core::service::sync_plan_generator::generate;

#[test]
fn version_vector_public_api() {
    let v0 = VersionVector::new();
    let v1 = v0.increment("device-a");
    assert!(v0.is_ancestor_of(&v1));
}

#[test]
fn chunking_public_api() {
    assert_eq!(compute_chunk_size(0), 0);
    assert_eq!(compute_chunk_count(1_000_000), 8); // 1 MB + 128 KiB ≈ 8
}

#[test]
fn nonce_window_public_api() {
    // A host wires this up roughly like: keep one NonceWindowState per
    // running process, call verify_and_record on every inbound mutating
    // request, periodically call prune_expired.
    let mut state = NonceWindowState::default();
    let verdict = verify_and_record(
        &mut state, "dev-a", 1_000, "nonce-1", 1_000, 300_000, 300_000,
    );
    assert_eq!(verdict, NonceVerdict::Fresh);

    // Replaying the same tuple is rejected.
    let replay = verify_and_record(
        &mut state, "dev-a", 1_010, "nonce-1", 1_010, 300_000, 300_000,
    );
    assert_eq!(replay, NonceVerdict::Replay);
}

#[test]
fn conflict_resolver_public_api() {
    let name: String = conflict_copy_name("shared/notes.md", "abc12345", 0);
    assert_eq!(
        name,
        "shared/notes.sync-conflict-19700101-000000-abc12345.md"
    );

    let local = FileEntry {
        share_id: "share-1".to_string(),
        path: "f.txt".to_string(),
        entry_type: EntryType::File,
        size: 0,
        modified_at_ms: 1_000,
        modified_by: "dev-a".to_string(),
        version_vector: VersionVector::new().increment("dev-a"),
        sha256: None,
        blocks: Vec::new(),
        deleted: false,
        deleted_at_ms: None,
    };

    let mut remote = local.clone();
    remote.modified_by = "dev-b".to_string();
    remote.version_vector = VersionVector::new().increment("dev-b");

    let outcome = apply_resolution(
        &local,
        &remote,
        ConflictResolution::KeepLocal,
        "dev-a",
        2_000,
    );
    assert_eq!(outcome.primary.modified_by, "dev-a");
    assert!(outcome.conflict_copy.is_none());
}

#[test]
fn sync_plan_generator_public_api() {
    // Empty indexes on both sides is the simplest possible call a host
    // could make; it must not panic and must report an empty plan.
    let plan = generate(&[], &[]);
    assert!(plan.to_push.is_empty());
    assert!(plan.to_pull.is_empty());
    assert!(plan.conflicts.is_empty());
    assert!(plan.unchanged.is_empty());
}

#[test]
fn policy_enforcer_public_api() {
    let peer = Device {
        id: DeviceId("dev-a".to_string()),
        alias: "Alice's Laptop".to_string(),
        device_type: DeviceType::Desktop,
        platform: DevicePlatform::Linux,
        state: DeviceState::Paired,
        cert_fingerprint_hex: None,
    };

    let share = Share {
        id: ShareId("share-1".to_string()),
        name: "Photos".to_string(),
        sync_mode: SyncMode::TwoWay,
        default_permission: SharePermission::ReadWrite,
        status: ShareStatus::Active,
    };

    let decision = evaluate_policy(
        &peer,
        Some(share.clone()),
        Some(SharePermission::ReadWrite),
        SyncDirection::Push,
    );
    assert_eq!(decision, PolicyDecision::Allowed);

    // No membership row at all is the most common real-world rejection.
    let rejected = evaluate_policy(&peer, Some(share.clone()), None, SyncDirection::Push);
    assert_eq!(rejected, PolicyDecision::NotAMember);
}

#[test]
fn library_metadata_is_set() {
    assert!(!kfilesync_core::CORE_VERSION.is_empty());
    assert_eq!(kfilesync_core::PROTOCOL_VERSION, "lansync/1.0");
}
