//! Sync plan generation from local/remote file indexes.
//!
//! # Sprint 3 implementation
//!
//! **Important**: the desktop's previous implementation had a bug that
//! filtered tombstones out of the push/pull plans, causing deletions to
//! never propagate. The core version explicitly propagates tombstones -
//! see `CROSS_VALIDATION_DESKTOP_MOBILE.md` §3.3 and ADR-009.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::domain::FileEntry;

/// The output of `generate`.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SyncPlan {
    /// Entries to pull from remote to local.
    pub to_pull: Vec<FileEntry>,
    /// Entries to push from local to remote.
    pub to_push: Vec<FileEntry>,
    /// Entries with conflicting concurrent edits.
    pub conflicts: Vec<SyncConflict>,
    /// Entries that match on both sides - included for diagnostics.
    pub unchanged: Vec<FileEntry>,
}

/// A pair of entries with conflicting version vectors.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SyncConflict {
    /// Share containing the conflict.
    pub share_id: String,
    /// Path that is in conflict.
    pub path: String,
    /// Local version.
    pub local: FileEntry,
    /// Remote version.
    pub remote: FileEntry,
}

/// Compute the sync plan from local and remote file indexes.
///
/// This function is pure and deterministic - given the same inputs, it
/// always produces the same output, with entries inside each list sorted
/// by path.
///
/// **Tombstone propagation**: deletions (`FileEntry` with `deleted == true`)
/// are treated as ordinary entries. If only the local side has a tombstone,
/// it is still pushed; if only remote, it is still pulled. This is
/// intentional - see ADR-009 for why the desktop's previous behavior (which
/// filtered tombstones out of exactly these two branches) was a bug: a
/// deletion that is never pushed/pulled never teaches the other side to
/// delete, so files thought-deleted keep reappearing after every sync.
///
/// **Classification per path** (mirrors `CROSS_VALIDATION_DESKTOP_MOBILE.md`
/// §3.3's six-case table):
/// - only local has the path                -> push
/// - only remote has the path               -> pull
/// - both, version vectors equal            -> unchanged
/// - both, local is an ancestor of remote   -> pull (remote is causally newer)
/// - both, remote is an ancestor of local   -> push (local is causally newer)
/// - both, neither is an ancestor           -> conflict (concurrent edits)
///
/// If the same path appears more than once within a single index (which a
/// well-behaved host should never produce), the later entry in iteration
/// order wins for that index - this function does not attempt to detect or
/// report duplicate paths.
#[must_use]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn generate(local_index: &[FileEntry], remote_index: &[FileEntry]) -> SyncPlan {
    let local_by_path: BTreeMap<&str, &FileEntry> =
        local_index.iter().map(|e| (e.path.as_str(), e)).collect();
    let remote_by_path: BTreeMap<&str, &FileEntry> =
        remote_index.iter().map(|e| (e.path.as_str(), e)).collect();

    let all_paths: BTreeSet<&str> = local_by_path
        .keys()
        .copied()
        .chain(remote_by_path.keys().copied())
        .collect();

    let mut plan = SyncPlan::default();

    for path in all_paths {
        match (local_by_path.get(path), remote_by_path.get(path)) {
            (Some(local), None) => {
                // Tombstone or not, this side's state is not reflected on
                // the other side at all yet - push it.
                plan.to_push.push((*local).clone());
            }
            (None, Some(remote)) => {
                plan.to_pull.push((*remote).clone());
            }
            (Some(local), Some(remote)) => {
                let local_anc_remote = local.version_vector.is_ancestor_of(&remote.version_vector);
                let remote_anc_local = remote.version_vector.is_ancestor_of(&local.version_vector);
                match (local_anc_remote, remote_anc_local) {
                    (true, true) => plan.unchanged.push((*local).clone()),
                    (true, false) => plan.to_pull.push((*remote).clone()),
                    (false, true) => plan.to_push.push((*local).clone()),
                    (false, false) => plan.conflicts.push(SyncConflict {
                        share_id: local.share_id.clone(),
                        path: local.path.clone(),
                        local: (*local).clone(),
                        remote: (*remote).clone(),
                    }),
                }
            }
            (None, None) => unreachable!("path came from the union of both key sets"),
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{BlockInfo, EntryType, VersionVector};

    fn vv(pairs: &[(&str, u64)]) -> VersionVector {
        let mut v = VersionVector::new();
        for (d, n) in pairs {
            for _ in 0..*n {
                v = v.increment(d);
            }
        }
        v
    }

    fn entry(path: &str, vv_pairs: &[(&str, u64)], deleted: bool) -> FileEntry {
        FileEntry {
            share_id: "share-1".to_string(),
            path: path.to_string(),
            entry_type: EntryType::File,
            size: 10,
            modified_at_ms: 1000,
            modified_by: "dev-a".to_string(),
            version_vector: vv(vv_pairs),
            sha256: None,
            blocks: Vec::<BlockInfo>::new(),
            deleted,
            deleted_at_ms: if deleted { Some(1000) } else { None },
        }
    }

    #[test]
    fn local_only_is_pushed() {
        let local = [entry("a.txt", &[("dev-a", 1)], false)];
        let plan = generate(&local, &[]);
        assert_eq!(plan.to_push.len(), 1);
        assert_eq!(plan.to_push[0].path, "a.txt");
        assert!(plan.to_pull.is_empty());
        assert!(plan.conflicts.is_empty());
        assert!(plan.unchanged.is_empty());
    }

    #[test]
    fn remote_only_is_pulled() {
        let remote = [entry("b.txt", &[("dev-b", 1)], false)];
        let plan = generate(&[], &remote);
        assert_eq!(plan.to_pull.len(), 1);
        assert_eq!(plan.to_pull[0].path, "b.txt");
    }

    #[test]
    fn local_only_tombstone_is_still_pushed_the_desktop_bug_regression() {
        // This is the exact regression CROSS_VALIDATION_DESKTOP_MOBILE.md
        // §3.3 flagged: the desktop's old code had `if !local.deleted` here,
        // silently dropping deletions instead of propagating them.
        let local = [entry("gone.txt", &[("dev-a", 1)], true)];
        let plan = generate(&local, &[]);
        assert_eq!(plan.to_push.len(), 1);
        assert!(plan.to_push[0].deleted);
    }

    #[test]
    fn remote_only_tombstone_is_still_pulled_the_desktop_bug_regression() {
        let remote = [entry("gone.txt", &[("dev-b", 1)], true)];
        let plan = generate(&[], &remote);
        assert_eq!(plan.to_pull.len(), 1);
        assert!(plan.to_pull[0].deleted);
    }

    #[test]
    fn equal_version_vectors_are_unchanged() {
        let local = [entry("a.txt", &[("dev-a", 2), ("dev-b", 1)], false)];
        let remote = [entry("a.txt", &[("dev-a", 2), ("dev-b", 1)], false)];
        let plan = generate(&local, &remote);
        assert_eq!(plan.unchanged.len(), 1);
        assert!(plan.to_push.is_empty());
        assert!(plan.to_pull.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn local_ancestor_of_remote_is_pulled() {
        let local = [entry("a.txt", &[("dev-a", 1)], false)];
        let remote = [entry("a.txt", &[("dev-a", 2)], false)];
        let plan = generate(&local, &remote);
        assert_eq!(plan.to_pull.len(), 1);
        assert!(plan.to_push.is_empty());
    }

    #[test]
    fn remote_ancestor_of_local_is_pushed() {
        let local = [entry("a.txt", &[("dev-a", 2)], false)];
        let remote = [entry("a.txt", &[("dev-a", 1)], false)];
        let plan = generate(&local, &remote);
        assert_eq!(plan.to_push.len(), 1);
        assert!(plan.to_pull.is_empty());
    }

    #[test]
    fn concurrent_edits_are_a_conflict() {
        let local = [entry("a.txt", &[("dev-a", 1)], false)];
        let remote = [entry("a.txt", &[("dev-b", 1)], false)];
        let plan = generate(&local, &remote);
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].share_id, "share-1");
        assert_eq!(plan.conflicts[0].path, "a.txt");
    }

    #[test]
    fn tombstone_plus_concurrent_modification_is_still_a_conflict_not_silently_dropped() {
        // Deleted-on-one-side + modified-on-the-other, with divergent
        // version vectors, must surface as a conflict so the host can
        // decide (not silently resolved by this layer).
        let local = entry("a.txt", &[("dev-a", 1)], true);
        let remote = entry("a.txt", &[("dev-b", 1)], false);
        let plan = generate(&[local], &[remote]);
        assert_eq!(plan.conflicts.len(), 1);
    }

    #[test]
    fn results_are_sorted_by_path() {
        let local = [
            entry("zebra.txt", &[("dev-a", 1)], false),
            entry("apple.txt", &[("dev-a", 1)], false),
            entry("mango.txt", &[("dev-a", 1)], false),
        ];
        let plan = generate(&local, &[]);
        let paths: Vec<&str> = plan.to_push.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["apple.txt", "mango.txt", "zebra.txt"]);
    }

    #[test]
    fn empty_indexes_produce_an_empty_plan() {
        let plan = generate(&[], &[]);
        assert!(plan.to_push.is_empty());
        assert!(plan.to_pull.is_empty());
        assert!(plan.conflicts.is_empty());
        assert!(plan.unchanged.is_empty());
    }

    #[test]
    fn mixed_index_classifies_each_path_independently() {
        let local = [
            entry("only_local.txt", &[("dev-a", 1)], false),
            entry("newer_local.txt", &[("dev-a", 2)], false),
            entry("same.txt", &[("dev-a", 1)], false),
            entry("conflict.txt", &[("dev-a", 1)], false),
        ];
        let remote = [
            entry("only_remote.txt", &[("dev-b", 1)], false),
            entry("newer_local.txt", &[("dev-a", 1)], false),
            entry("same.txt", &[("dev-a", 1)], false),
            entry("conflict.txt", &[("dev-b", 1)], false),
        ];
        let plan = generate(&local, &remote);
        assert_eq!(
            plan.to_push
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["newer_local.txt", "only_local.txt"]
        );
        assert_eq!(
            plan.to_pull
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["only_remote.txt"]
        );
        assert_eq!(
            plan.unchanged
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["same.txt"]
        );
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].path, "conflict.txt");
    }

    // --- symmetry: generate(A, B) must mirror generate(B, A) ---

    fn assert_symmetric(local: &[FileEntry], remote: &[FileEntry]) {
        let ab = generate(local, remote);
        let ba = generate(remote, local);

        let push_paths = |p: &SyncPlan| -> Vec<String> {
            let mut v: Vec<String> = p.to_push.iter().map(|e| e.path.clone()).collect();
            v.sort();
            v
        };
        let pull_paths = |p: &SyncPlan| -> Vec<String> {
            let mut v: Vec<String> = p.to_pull.iter().map(|e| e.path.clone()).collect();
            v.sort();
            v
        };
        let conflict_paths = |p: &SyncPlan| -> Vec<String> {
            let mut v: Vec<String> = p.conflicts.iter().map(|c| c.path.clone()).collect();
            v.sort();
            v
        };
        let unchanged_paths = |p: &SyncPlan| -> Vec<String> {
            let mut v: Vec<String> = p.unchanged.iter().map(|e| e.path.clone()).collect();
            v.sort();
            v
        };

        assert_eq!(
            push_paths(&ab),
            pull_paths(&ba),
            "A's push must equal B's pull"
        );
        assert_eq!(
            pull_paths(&ab),
            push_paths(&ba),
            "A's pull must equal B's push"
        );
        assert_eq!(
            conflict_paths(&ab),
            conflict_paths(&ba),
            "conflict sets must match"
        );
        assert_eq!(
            unchanged_paths(&ab),
            unchanged_paths(&ba),
            "unchanged sets must match"
        );
    }

    #[test]
    fn symmetry_holds_for_hand_picked_cases() {
        let local = [
            entry("only_local.txt", &[("dev-a", 1)], false),
            entry("newer_local.txt", &[("dev-a", 2)], false),
            entry("same.txt", &[("dev-a", 1)], false),
            entry("conflict.txt", &[("dev-a", 1)], false),
            entry("deleted_local.txt", &[("dev-a", 1)], true),
        ];
        let remote = [
            entry("only_remote.txt", &[("dev-b", 1)], false),
            entry("newer_local.txt", &[("dev-a", 1)], false),
            entry("same.txt", &[("dev-a", 1)], false),
            entry("conflict.txt", &[("dev-b", 1)], false),
            entry("deleted_remote.txt", &[("dev-b", 1)], true),
        ];
        assert_symmetric(&local, &remote);
    }

    #[test]
    fn symmetry_holds_across_many_pseudo_random_index_pairs() {
        // No proptest dependency available in this sandbox (see Sprint 2's
        // notes on the edition2024 transitive-dep issue) - a small
        // fixed-seed xorshift stands in for a property test across many
        // generated (local, remote) pairs.
        let mut state: u64 = 0x2026_0609_1530_0007;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..200 {
            let path_count = 1 + (next() % 6) as usize;
            let mut local: Vec<FileEntry> = Vec::new();
            let mut remote: Vec<FileEntry> = Vec::new();
            for i in 0..path_count {
                let path = alloc::format!("f{i}.txt");
                let in_local = next() % 2 == 0;
                let in_remote = next() % 2 == 0;
                let a_count = next() % 3;
                let b_count = next() % 3;
                let deleted = next() % 4 == 0;
                if in_local {
                    local.push(entry(
                        &path,
                        &[("dev-a", a_count), ("dev-b", b_count)],
                        deleted,
                    ));
                }
                if in_remote {
                    let a_count2 = next() % 3;
                    let b_count2 = next() % 3;
                    remote.push(entry(
                        &path,
                        &[("dev-a", a_count2), ("dev-b", b_count2)],
                        deleted,
                    ));
                }
            }
            assert_symmetric(&local, &remote);
        }
    }
}
