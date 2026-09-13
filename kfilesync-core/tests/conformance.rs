//! Conformance test harness - runs the shared JSON fixtures against the
//! Rust implementation.
//!
//! The same fixtures are run by the Kotlin runner on the mobile side, so
//! both implementations are guaranteed to compute identical outputs.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use kfilesync_core::domain::{BlockInfo, EntryType, FileEntry, VersionVector};
use kfilesync_core::service::chunking::compute_chunk_size;
use kfilesync_core::service::conflict_resolver::{
    apply_resolution, conflict_copy_name, ConflictResolution,
};
use kfilesync_core::service::nonce_window::{verify_and_record, NonceVerdict, NonceWindowState};
use kfilesync_core::service::sync_plan_generator::generate;
use serde::Deserialize;
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    // Tests are run from the crate root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("kfilesync-conformance")
        .join("fixtures")
}

#[derive(Deserialize)]
struct ChunkingCase {
    file_size: u64,
    expected_chunk_size: u32,
}

#[derive(Deserialize)]
struct ChunkingFixture {
    cases: Vec<ChunkingCase>,
}

#[test]
fn chunking_threshold_boundaries() {
    let path = fixtures_dir()
        .join("chunking")
        .join("threshold_boundaries.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read fixture at {}: {e}", path.display()));
    let fixture: ChunkingFixture = serde_json::from_str(&raw).expect("malformed fixture");

    for case in &fixture.cases {
        let actual = compute_chunk_size(case.file_size);
        assert_eq!(
            actual, case.expected_chunk_size,
            "file_size = {} (expected chunk_size = {})",
            case.file_size, case.expected_chunk_size
        );
    }
}

// ----- nonce_window -----

#[derive(Deserialize)]
struct NonceStep {
    device_id: String,
    timestamp_ms: i64,
    nonce: String,
    now_ms: i64,
    expected_verdict: String,
}

#[derive(Deserialize)]
struct NonceCase {
    name: String,
    window_size_ms: i64,
    clock_skew_ms: i64,
    steps: Vec<NonceStep>,
}

#[derive(Deserialize)]
struct NonceFixture {
    cases: Vec<NonceCase>,
}

fn verdict_name(v: NonceVerdict) -> &'static str {
    match v {
        NonceVerdict::Fresh => "fresh",
        NonceVerdict::StaleTimestamp => "stale_timestamp",
        NonceVerdict::FutureTimestamp => "future_timestamp",
        NonceVerdict::Replay => "replay",
        NonceVerdict::BlankNonce => "blank_nonce",
    }
}

#[test]
fn nonce_window_verify_and_record() {
    let path = fixtures_dir()
        .join("nonce_window")
        .join("verify_and_record.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read fixture at {}: {e}", path.display()));
    let fixture: NonceFixture = serde_json::from_str(&raw).expect("malformed fixture");

    for case in &fixture.cases {
        let mut state = NonceWindowState::default();
        for (i, step) in case.steps.iter().enumerate() {
            let verdict = verify_and_record(
                &mut state,
                &step.device_id,
                step.timestamp_ms,
                &step.nonce,
                step.now_ms,
                case.window_size_ms,
                case.clock_skew_ms,
            );
            assert_eq!(
                verdict_name(verdict),
                step.expected_verdict,
                "case '{}' step {}",
                case.name,
                i
            );
        }
    }
}

// ----- conflict_resolver / copy_name -----

#[derive(Deserialize)]
struct CopyNameCase {
    name: String,
    original_path: String,
    losing_device_id: String,
    conflict_at_ms: i64,
    expected_name: String,
}

#[derive(Deserialize)]
struct CopyNameFixture {
    cases: Vec<CopyNameCase>,
}

#[test]
fn conflict_resolver_copy_name() {
    let path = fixtures_dir()
        .join("conflict_resolver")
        .join("copy_name.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read fixture at {}: {e}", path.display()));
    let fixture: CopyNameFixture = serde_json::from_str(&raw).expect("malformed fixture");

    for case in &fixture.cases {
        let actual = conflict_copy_name(
            &case.original_path,
            &case.losing_device_id,
            case.conflict_at_ms,
        );
        assert_eq!(actual, case.expected_name, "case '{}'", case.name);
    }
}

// ----- conflict_resolver / apply_resolution -----

#[derive(Deserialize, Debug)]
struct EntryFixture {
    path: String,
    modified_by: String,
    modified_at_ms: i64,
    version_vector: BTreeMap<String, u64>,
    deleted: bool,
    #[serde(default)]
    deleted_at_ms: Option<i64>,
}

fn build_vv(map: &BTreeMap<String, u64>) -> VersionVector {
    let mut vv = VersionVector::new();
    for (device, count) in map {
        for _ in 0..*count {
            vv = vv.increment(device);
        }
    }
    vv
}

impl EntryFixture {
    fn to_entry(&self) -> FileEntry {
        FileEntry {
            share_id: "share-1".to_string(),
            path: self.path.clone(),
            entry_type: EntryType::File,
            size: 0,
            modified_at_ms: self.modified_at_ms,
            modified_by: self.modified_by.clone(),
            version_vector: build_vv(&self.version_vector),
            sha256: None,
            blocks: Vec::<BlockInfo>::new(),
            deleted: self.deleted,
            deleted_at_ms: self.deleted_at_ms,
        }
    }

    fn matches(&self, entry: &FileEntry) -> bool {
        let actual_vv: BTreeMap<String, u64> = entry
            .version_vector
            .iter()
            .map(|(k, n)| (k.to_string(), n))
            .collect();
        entry.path == self.path
            && entry.modified_by == self.modified_by
            && entry.modified_at_ms == self.modified_at_ms
            && actual_vv == self.version_vector
            && entry.deleted == self.deleted
            && entry.deleted_at_ms == self.deleted_at_ms
    }
}

#[derive(Deserialize)]
struct ApplyResolutionCase {
    name: String,
    local: EntryFixture,
    remote: EntryFixture,
    resolution: String,
    me: String,
    now_ms: i64,
    expected_primary: EntryFixture,
    expected_conflict_copy: Value,
}

#[derive(Deserialize)]
struct ApplyResolutionFixture {
    cases: Vec<ApplyResolutionCase>,
}

#[test]
fn conflict_resolver_apply_resolution() {
    let path = fixtures_dir()
        .join("conflict_resolver")
        .join("apply_resolution.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read fixture at {}: {e}", path.display()));
    let fixture: ApplyResolutionFixture = serde_json::from_str(&raw).expect("malformed fixture");

    for case in &fixture.cases {
        let local = case.local.to_entry();
        let remote = case.remote.to_entry();
        let resolution = match case.resolution.as_str() {
            "keep_local" => ConflictResolution::KeepLocal,
            "keep_remote" => ConflictResolution::KeepRemote,
            "keep_both" => ConflictResolution::KeepBoth,
            other => panic!("case '{}': unknown resolution '{}'", case.name, other),
        };
        let outcome = apply_resolution(&local, &remote, resolution, &case.me, case.now_ms);

        assert!(
            case.expected_primary.matches(&outcome.primary),
            "case '{}': primary mismatch, actual={:?}",
            case.name,
            outcome.primary
        );

        match (&case.expected_conflict_copy, &outcome.conflict_copy) {
            (Value::Null, None) => {}
            (expected_val, Some(actual_copy)) if !expected_val.is_null() => {
                let expected: EntryFixture = serde_json::from_value(expected_val.clone())
                    .unwrap_or_else(|e| {
                        panic!("case '{}': bad expected_conflict_copy: {e}", case.name)
                    });
                assert!(
                    expected.matches(actual_copy),
                    "case '{}': conflict_copy mismatch, actual={:?}",
                    case.name,
                    actual_copy
                );
            }
            (expected_val, actual_val) => panic!(
                "case '{}': conflict_copy presence mismatch, expected_null={} actual_present={}",
                case.name,
                expected_val.is_null(),
                actual_val.is_some()
            ),
        }
    }
}

// ----- sync_plan -----

#[derive(Deserialize)]
struct PartialSyncEntry {
    path: String,
    version_vector: BTreeMap<String, u64>,
    deleted: bool,
}

impl PartialSyncEntry {
    fn to_entry(&self) -> FileEntry {
        FileEntry {
            share_id: "share-1".to_string(),
            path: self.path.clone(),
            entry_type: EntryType::File,
            size: 0,
            modified_at_ms: 0,
            modified_by: "x".to_string(),
            version_vector: build_vv(&self.version_vector),
            sha256: None,
            blocks: Vec::<BlockInfo>::new(),
            deleted: self.deleted,
            deleted_at_ms: if self.deleted { Some(0) } else { None },
        }
    }
}

#[derive(Deserialize)]
struct SyncPlanCase {
    name: String,
    local: Vec<PartialSyncEntry>,
    remote: Vec<PartialSyncEntry>,
    expected_to_push: Vec<String>,
    expected_to_pull: Vec<String>,
    expected_conflicts: Vec<String>,
    expected_unchanged: Vec<String>,
}

#[derive(Deserialize)]
struct SyncPlanFixture {
    cases: Vec<SyncPlanCase>,
}

#[test]
fn sync_plan_tombstone_propagation() {
    let path = fixtures_dir()
        .join("sync_plan")
        .join("tombstone_propagation.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read fixture at {}: {e}", path.display()));
    let fixture: SyncPlanFixture = serde_json::from_str(&raw).expect("malformed fixture");

    for case in &fixture.cases {
        let local: Vec<FileEntry> = case.local.iter().map(PartialSyncEntry::to_entry).collect();
        let remote: Vec<FileEntry> = case.remote.iter().map(PartialSyncEntry::to_entry).collect();
        let plan = generate(&local, &remote);

        let push_paths: Vec<String> = plan.to_push.iter().map(|e| e.path.clone()).collect();
        let pull_paths: Vec<String> = plan.to_pull.iter().map(|e| e.path.clone()).collect();
        let conflict_paths: Vec<String> = plan.conflicts.iter().map(|c| c.path.clone()).collect();
        let unchanged_paths: Vec<String> = plan.unchanged.iter().map(|e| e.path.clone()).collect();

        assert_eq!(
            push_paths, case.expected_to_push,
            "case '{}': to_push",
            case.name
        );
        assert_eq!(
            pull_paths, case.expected_to_pull,
            "case '{}': to_pull",
            case.name
        );
        assert_eq!(
            conflict_paths, case.expected_conflicts,
            "case '{}': conflicts",
            case.name
        );
        assert_eq!(
            unchanged_paths, case.expected_unchanged,
            "case '{}': unchanged",
            case.name
        );
    }
}
