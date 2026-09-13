//! Runs every fixture in `kfilesync-conformance/fixtures/` against the
//! Rust core.
//!
//! Exit code 0 = all passed, 1 = at least one failure. CI uses the exit
//! code; humans get a summary on stdout.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use kfilesync_core::domain::{BlockInfo, EntryType, FileEntry, VersionVector};
use kfilesync_core::protocol::dto::*;
use kfilesync_core::service::chunking::compute_chunk_size;
use kfilesync_core::service::conflict_resolver::{
    apply_resolution, conflict_copy_name, ConflictResolution,
};
use kfilesync_core::service::ignore_spec::IgnoreSpec;
use kfilesync_core::service::nonce_window::{verify_and_record, NonceVerdict, NonceWindowState};
use kfilesync_core::service::sync_plan_generator::generate as generate_sync_plan;
use kfilesync_core::trust::trust_evaluator::{
    evaluate_inbound, PairedDeviceEntry, PairedDeviceSet, RequestMeta, TrustDecision,
};
use serde::Deserialize;
use serde_json::Value;
use walkdir::WalkDir;

fn main() -> Result<()> {
    let fixtures_root = std::env::var("KFILESYNC_FIXTURES_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("fixtures")
        });

    let mut total: usize = 0;
    let mut failed: usize = 0;

    for entry in WalkDir::new(&fixtures_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let category = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

        let ok = match category {
            "chunking" => run_chunking(&raw, path)?,
            "version_vector" => {
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if stem.contains("merge") {
                    run_vv_merge(&raw, path)?
                } else {
                    run_vv_ancestor(&raw, path)?
                }
            }
            "nonce_window" => run_nonce_window(&raw, path)?,
            "sync_plan" => run_sync_plan(&raw, path)?,
            "wire" => run_wire(&raw, path)?,
            "trust" => run_trust(&raw, path)?,
            "ignore_spec" => run_ignore_spec(&raw, path)?,
            "conflict_resolver" => {
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if stem.contains("apply_resolution") {
                    run_apply_resolution(&raw, path)?
                } else {
                    run_copy_name(&raw, path)?
                }
            }
            _ => {
                // Unknown category: skip silently to allow new fixture dirs
                // before their runner is wired up.
                eprintln!("skipping (no runner): {}", path.display());
                continue;
            }
        };

        total += 1;
        if !ok {
            failed += 1;
        }
    }

    println!("\nconformance summary: {}/{} passed", total - failed, total);
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ----- chunking -----

#[derive(Deserialize)]
struct ChunkingCase {
    file_size: u64,
    expected_chunk_size: u32,
}

#[derive(Deserialize)]
struct ChunkingFixture {
    name: String,
    cases: Vec<ChunkingCase>,
}

fn run_chunking(raw: &str, path: &Path) -> Result<bool> {
    let fixture: ChunkingFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;
    for case in &fixture.cases {
        let actual = compute_chunk_size(case.file_size);
        if actual != case.expected_chunk_size {
            eprintln!(
                "FAIL {} / {}: file_size={} expected={} actual={}",
                fixture.name,
                path.display(),
                case.file_size,
                case.expected_chunk_size,
                actual
            );
            ok = false;
        }
    }
    if ok {
        println!("PASS {}", fixture.name);
    }
    Ok(ok)
}

// ----- ignore_spec -----

#[derive(Deserialize)]
struct IgnoreCheck {
    path: String,
    is_directory: bool,
    expected_ignored: bool,
}

#[derive(Deserialize)]
struct IgnoreCase {
    name: String,
    is_mobile: bool,
    #[serde(default)]
    syncignore_content: Option<String>,
    #[serde(default)]
    extra_user_rules: Vec<String>,
    checks: Vec<IgnoreCheck>,
}

#[derive(Deserialize)]
struct IgnoreFixture {
    name: String,
    cases: Vec<IgnoreCase>,
}

fn run_ignore_spec(raw: &str, path: &Path) -> Result<bool> {
    let fixture: IgnoreFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;

    for case in &fixture.cases {
        let rules: Vec<&str> = case.extra_user_rules.iter().map(String::as_str).collect();
        let spec = IgnoreSpec::build(
            "/share",
            case.syncignore_content.as_deref(),
            &rules,
            case.is_mobile,
        )
        .with_context(|| format!("building IgnoreSpec for case '{}'", case.name))?;

        for check in &case.checks {
            let actual = spec.is_ignored(&check.path, check.is_directory);
            if actual != check.expected_ignored {
                eprintln!(
                    "FAIL {} -> {}: path={} expected={} actual={}",
                    path.display(),
                    case.name,
                    check.path,
                    check.expected_ignored,
                    actual
                );
                ok = false;
            }
        }
    }

    if ok {
        println!("PASS {}", fixture.name);
    }
    Ok(ok)
}

// ----- trust (evaluate_inbound) -----

#[derive(Deserialize)]
struct PairedDeviceFixture {
    device_id: String,
    cert_fingerprint_hex: String,
}

#[derive(Deserialize)]
struct ExpectedTrustOutcome {
    kind: String,
    peer_device_id: Option<String>,
    peer_fingerprint: Option<String>,
    http_status: Option<u16>,
    error_code: Option<String>,
}

#[derive(Deserialize)]
struct TrustRequestCase {
    route: String,
    device_id_header: Option<String>,
    timestamp_ms_header: Option<i64>,
    nonce_header: Option<String>,
    fingerprint_header: Option<String>,
    clock_now_ms: i64,
    expected: ExpectedTrustOutcome,
}

#[derive(Deserialize)]
struct TrustCase {
    name: String,
    window_size_ms: i64,
    clock_skew_ms: i64,
    paired_devices: Vec<PairedDeviceFixture>,
    requests: Vec<TrustRequestCase>,
}

#[derive(Deserialize)]
struct TrustFixture {
    name: String,
    cases: Vec<TrustCase>,
}

/// Each case runs its `requests` in order against ONE freshly-created
/// `NonceWindowState` and `PairedDeviceSet` - state is intentionally not
/// shared across cases, only across requests WITHIN a case (needed for
/// the replay-detection cases).
fn run_trust(raw: &str, path: &Path) -> Result<bool> {
    let fixture: TrustFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;

    for case in &fixture.cases {
        let paired = PairedDeviceSet::new(
            case.paired_devices
                .iter()
                .map(|d| PairedDeviceEntry {
                    device_id: d.device_id.clone(),
                    cert_fingerprint_hex: d.cert_fingerprint_hex.clone(),
                })
                .collect(),
        );
        let mut state = NonceWindowState::default();

        for (i, req) in case.requests.iter().enumerate() {
            let meta = RequestMeta {
                route: req.route.clone(),
                device_id_header: req.device_id_header.clone(),
                timestamp_ms_header: req.timestamp_ms_header,
                nonce_header: req.nonce_header.clone(),
                fingerprint_header: req.fingerprint_header.clone(),
            };
            let decision = evaluate_inbound(
                &meta,
                &paired,
                &mut state,
                req.clock_now_ms,
                case.window_size_ms,
                case.clock_skew_ms,
            );

            let case_ok = match req.expected.kind.as_str() {
                "allow" => {
                    matches!(&decision, TrustDecision::Allow { peer_device_id, peer_fingerprint }
                    if Some(peer_device_id.as_str()) == req.expected.peer_device_id.as_deref()
                    && Some(peer_fingerprint.as_str()) == req.expected.peer_fingerprint.as_deref())
                }
                "allow_unpaired" => matches!(decision, TrustDecision::AllowUnpairedForPairing),
                "reject" => {
                    matches!(&decision, TrustDecision::Reject { http_status, error_code, .. }
                    if Some(*http_status) == req.expected.http_status
                    && Some((*error_code).to_string()) == req.expected.error_code)
                }
                other => {
                    eprintln!(
                        "FAIL {} -> {} step {}: unknown expected kind '{}'",
                        path.display(),
                        case.name,
                        i,
                        other
                    );
                    false
                }
            };

            if !case_ok {
                eprintln!(
                    "FAIL {} -> {} step {}: expected kind={} actual={:?}",
                    path.display(),
                    case.name,
                    i,
                    req.expected.kind,
                    decision
                );
                ok = false;
            }
        }
    }

    if ok {
        println!("PASS {}", fixture.name);
    }
    Ok(ok)
}

// ----- wire (protocol DTO round-trip) -----

#[derive(Deserialize)]
struct WireCase {
    name: String,
    dto: String,
    json: Value,
}

#[derive(Deserialize)]
struct WireFixture {
    name: String,
    cases: Vec<WireCase>,
}

/// Parse `json` as the named DTO type, re-encode it, and check the result
/// is structurally identical to the input. This is a schema-conformance
/// check (does this exact wire shape round-trip losslessly through our
/// DTO), not a logic check like the other fixture categories - there is
/// no "expected output" other than "you get back what you put in."
fn run_wire(raw: &str, path: &Path) -> Result<bool> {
    let fixture: WireFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;

    macro_rules! rt {
        ($ty:ty, $json:expr) => {{
            match serde_json::from_value::<$ty>($json.clone()) {
                Ok(parsed) => match serde_json::to_value(&parsed) {
                    Ok(back) if &back == $json => true,
                    Ok(back) => {
                        eprintln!(
                            "FAIL {} re-encoded value differs: original={} reencoded={}",
                            path.display(),
                            $json,
                            back
                        );
                        false
                    }
                    Err(e) => {
                        eprintln!("FAIL {} re-encode error: {}", path.display(), e);
                        false
                    }
                },
                Err(e) => {
                    eprintln!("FAIL {} parse error: {}", path.display(), e);
                    false
                }
            }
        }};
    }

    for case in &fixture.cases {
        let case_ok = match case.dto.as_str() {
            "DeviceInfoDto" => rt!(DeviceInfoDto, &case.json),
            "PairRequestDto" => rt!(PairRequestDto, &case.json),
            "PairConfirmDto" => rt!(PairConfirmDto, &case.json),
            "PairRevokeDto" => rt!(PairRevokeDto, &case.json),
            "PairResultDto" => rt!(PairResultDto, &case.json),
            "ShareInviteDto" => rt!(ShareInviteDto, &case.json),
            "ShareAuthorizeDto" => rt!(ShareAuthorizeDto, &case.json),
            "ShareLeaveDto" => rt!(ShareLeaveDto, &case.json),
            "IndexResponseDto" => rt!(IndexResponseDto, &case.json),
            "TransferRequestDto" => rt!(TransferRequestDto, &case.json),
            "TransferAcceptDto" => rt!(TransferAcceptDto, &case.json),
            "TransferChunkAckDto" => rt!(TransferChunkAckDto, &case.json),
            "TransferCancelDto" => rt!(TransferCancelDto, &case.json),
            other => {
                eprintln!(
                    "FAIL {} -> {}: unknown dto type '{}'",
                    path.display(),
                    case.name,
                    other
                );
                false
            }
        };
        if !case_ok {
            ok = false;
        }
    }
    if ok {
        println!("PASS {}", fixture.name);
    }
    Ok(ok)
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

fn run_sync_plan(raw: &str, path: &Path) -> Result<bool> {
    let fixture: SyncPlanFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;
    for case in &fixture.cases {
        let local: Vec<FileEntry> = case.local.iter().map(PartialSyncEntry::to_entry).collect();
        let remote: Vec<FileEntry> = case.remote.iter().map(PartialSyncEntry::to_entry).collect();
        let plan = generate_sync_plan(&local, &remote);

        let push_paths: Vec<String> = plan.to_push.iter().map(|e| e.path.clone()).collect();
        let pull_paths: Vec<String> = plan.to_pull.iter().map(|e| e.path.clone()).collect();
        let conflict_paths: Vec<String> = plan.conflicts.iter().map(|c| c.path.clone()).collect();
        let unchanged_paths: Vec<String> = plan.unchanged.iter().map(|e| e.path.clone()).collect();

        let mut case_ok = true;
        if push_paths != case.expected_to_push {
            eprintln!(
                "FAIL {} -> {}: push expected={:?} actual={:?}",
                path.display(),
                case.name,
                case.expected_to_push,
                push_paths
            );
            case_ok = false;
        }
        if pull_paths != case.expected_to_pull {
            eprintln!(
                "FAIL {} -> {}: pull expected={:?} actual={:?}",
                path.display(),
                case.name,
                case.expected_to_pull,
                pull_paths
            );
            case_ok = false;
        }
        if conflict_paths != case.expected_conflicts {
            eprintln!(
                "FAIL {} -> {}: conflicts expected={:?} actual={:?}",
                path.display(),
                case.name,
                case.expected_conflicts,
                conflict_paths
            );
            case_ok = false;
        }
        if unchanged_paths != case.expected_unchanged {
            eprintln!(
                "FAIL {} -> {}: unchanged expected={:?} actual={:?}",
                path.display(),
                case.name,
                case.expected_unchanged,
                unchanged_paths
            );
            case_ok = false;
        }
        if !case_ok {
            ok = false;
        }
    }
    if ok {
        println!("PASS sync_plan tombstone propagation");
    }
    Ok(ok)
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

/// Each case replays its `steps` in order against ONE freshly-created
/// `NonceWindowState` - state is intentionally not shared across cases.
fn run_nonce_window(raw: &str, path: &Path) -> Result<bool> {
    let fixture: NonceFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;
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
            let actual: &str = verdict_name(verdict);
            if actual != step.expected_verdict {
                eprintln!(
                    "FAIL {} -> {} (step {}): expected={} actual={}",
                    path.display(),
                    case.name,
                    i,
                    step.expected_verdict,
                    actual
                );
                ok = false;
            }
        }
    }
    if ok {
        println!("PASS nonce window verify_and_record");
    }
    Ok(ok)
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

fn run_copy_name(raw: &str, path: &Path) -> Result<bool> {
    let fixture: CopyNameFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;
    for case in &fixture.cases {
        let actual = conflict_copy_name(
            &case.original_path,
            &case.losing_device_id,
            case.conflict_at_ms,
        );
        if actual != case.expected_name {
            eprintln!(
                "FAIL {} -> {}: expected={} actual={}",
                path.display(),
                case.name,
                case.expected_name,
                actual
            );
            ok = false;
        }
    }
    if ok {
        println!("PASS conflict copy filename generation");
    }
    Ok(ok)
}

// ----- conflict_resolver / apply_resolution -----

/// Partial `FileEntry` shape used by fixtures: only the fields that
/// `apply_resolution` actually reads or produces. `to_entry` fills in
/// irrelevant fields (size/sha256/blocks/entry_type) with placeholders;
/// `matches` compares only these same fields against a real `FileEntry`.
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

fn run_apply_resolution(raw: &str, path: &Path) -> Result<bool> {
    let fixture: ApplyResolutionFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;
    for case in &fixture.cases {
        let local: FileEntry = case.local.to_entry();
        let remote: FileEntry = case.remote.to_entry();
        let resolution = match case.resolution.as_str() {
            "keep_local" => ConflictResolution::KeepLocal,
            "keep_remote" => ConflictResolution::KeepRemote,
            "keep_both" => ConflictResolution::KeepBoth,
            other => {
                eprintln!(
                    "FAIL {} -> {}: unknown resolution '{}'",
                    path.display(),
                    case.name,
                    other
                );
                ok = false;
                continue;
            }
        };
        let outcome = apply_resolution(&local, &remote, resolution, &case.me, case.now_ms);

        let mut case_ok = true;
        if !case.expected_primary.matches(&outcome.primary) {
            eprintln!(
                "FAIL {} -> {}: primary mismatch, actual={:?}",
                path.display(),
                case.name,
                outcome.primary
            );
            case_ok = false;
        }

        match (&case.expected_conflict_copy, &outcome.conflict_copy) {
            (Value::Null, None) => {}
            (Value::Null, Some(_)) => {
                eprintln!(
                    "FAIL {} -> {}: expected no conflict_copy but got one",
                    path.display(),
                    case.name
                );
                case_ok = false;
            }
            (_, None) => {
                eprintln!(
                    "FAIL {} -> {}: expected a conflict_copy but got none",
                    path.display(),
                    case.name
                );
                case_ok = false;
            }
            (expected_val, Some(actual_copy)) => {
                let expected: EntryFixture = serde_json::from_value(expected_val.clone())
                    .with_context(|| format!("parse expected_conflict_copy in {}", case.name))?;
                if !expected.matches(actual_copy) {
                    eprintln!(
                        "FAIL {} -> {}: conflict_copy mismatch, actual={:?}",
                        path.display(),
                        case.name,
                        actual_copy
                    );
                    case_ok = false;
                }
            }
        }

        if !case_ok {
            ok = false;
        }
    }
    if ok {
        println!("PASS conflict_resolver apply_resolution");
    }
    Ok(ok)
}

// ----- version_vector ancestor -----

#[derive(Deserialize)]
struct VvAncestorCase {
    name: String,
    a: BTreeMap<String, u64>,
    b: BTreeMap<String, u64>,
    expected_a_ancestor_of_b: bool,
    expected_b_ancestor_of_a: bool,
    expected_conflict: bool,
}

#[derive(Deserialize)]
struct VvAncestorFixture {
    name: String,
    cases: Vec<VvAncestorCase>,
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

fn run_vv_ancestor(raw: &str, path: &Path) -> Result<bool> {
    let fixture: VvAncestorFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;
    for case in &fixture.cases {
        let a = build_vv(&case.a);
        let b = build_vv(&case.b);
        let actual_a_anc_b = a.is_ancestor_of(&b);
        let actual_b_anc_a = b.is_ancestor_of(&a);
        let actual_conflict = a.conflicts_with(&b);

        let mut case_ok = true;
        if actual_a_anc_b != case.expected_a_ancestor_of_b {
            eprintln!(
                "FAIL {} -> {}: a.is_ancestor_of(b) expected={} actual={}",
                fixture.name, case.name, case.expected_a_ancestor_of_b, actual_a_anc_b
            );
            case_ok = false;
        }
        if actual_b_anc_a != case.expected_b_ancestor_of_a {
            eprintln!(
                "FAIL {} -> {}: b.is_ancestor_of(a) expected={} actual={}",
                fixture.name, case.name, case.expected_b_ancestor_of_a, actual_b_anc_a
            );
            case_ok = false;
        }
        if actual_conflict != case.expected_conflict {
            eprintln!(
                "FAIL {} -> {}: conflicts_with expected={} actual={}",
                fixture.name, case.name, case.expected_conflict, actual_conflict
            );
            case_ok = false;
        }
        if !case_ok {
            ok = false;
        }
    }
    if ok {
        println!("PASS {}", fixture.name);
    }
    Ok(ok)
}

// ----- version_vector merge -----

#[derive(Deserialize)]
struct VvMergeCase {
    name: String,
    a: BTreeMap<String, u64>,
    b: BTreeMap<String, u64>,
    expected_merged: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
struct VvMergeFixture {
    name: String,
    cases: Vec<VvMergeCase>,
}

fn run_vv_merge(raw: &str, path: &Path) -> Result<bool> {
    let fixture: VvMergeFixture =
        serde_json::from_str(raw).with_context(|| format!("parse {}", path.display()))?;
    let mut ok = true;
    for case in &fixture.cases {
        let a = build_vv(&case.a);
        let b = build_vv(&case.b);
        let merged = a.merge(&b);

        let mut case_ok = true;
        for (device, expected_count) in &case.expected_merged {
            let actual = merged.get(device);
            if actual != *expected_count {
                eprintln!(
                    "FAIL {} -> {}: merged[{}] expected={} actual={}",
                    fixture.name, case.name, device, expected_count, actual
                );
                case_ok = false;
            }
        }
        if !case_ok {
            ok = false;
        }
    }
    if ok {
        println!("PASS {}", fixture.name);
    }
    Ok(ok)
}
