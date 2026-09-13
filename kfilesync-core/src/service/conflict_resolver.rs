//! Conflict resolution and conflict-copy naming.
//!
//! # Sprint 2 implementation
//!
//! This module is intentionally *mechanical*: it does not decide which side
//! of a conflict should win. That decision belongs to the host application
//! (desktop UI prompt, mobile auto-resolve setting, "last writer wins"
//! policy, whatever) - see
//! [ADR-007](../../docs/adr/0007-conflict-resolver-caller-decides-strategy.md)
//! for why strategy selection was deliberately pulled out of core.
//!
//! Given a `resolution` the host has already chosen, [`apply_resolution`]
//! performs it deterministically so that two peers applying the same
//! resolution to the same `(local, remote)` pair independently compute
//! byte-identical results.

use alloc::string::{String, ToString};

use crate::domain::FileEntry;

/// How a conflict should be resolved. The caller (host application) picks
/// one of these; this module only carries it out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictResolution {
    /// Keep the local entry as-is; remote's conflicting write is discarded
    /// (only its version-vector history is absorbed, to stop the same
    /// conflict from being re-detected on the next sync).
    KeepLocal,
    /// Keep the remote entry; local's conflicting write is discarded in the
    /// same sense as above.
    KeepRemote,
    /// Keep both: `local` keeps the canonical path, and `remote`'s content
    /// is preserved under a new conflict-copy path (see
    /// [`conflict_copy_name`]). Swap the arguments if the opposite
    /// orientation is wanted - the function itself is symmetric in what it
    /// computes, only the parameter *names* pick which side keeps the path.
    KeepBoth,
}

/// Outcome of applying a [`ConflictResolution`] to a `(local, remote)` pair.
pub struct ResolutionOutcome {
    /// The new state at the original path.
    pub primary: FileEntry,
    /// Conflict-copy entry at a new path; only present when
    /// `resolution == KeepBoth`. The host must persist this entry **and**
    /// physically rename/copy the underlying file to
    /// `conflict_copy.path` before the next sync pass runs.
    pub conflict_copy: Option<FileEntry>,
}

/// Compute the deterministic conflict-copy filename for the losing side.
///
/// Format: `<dir/><stem>.sync-conflict-YYYYMMDD-HHMMSS-<deviceShort8>[.<ext>]`
///
/// - `original_path` uses `/` separators (see [`FileEntry::path`]); any
///   directory prefix is preserved verbatim.
/// - The extension is taken from the last `.` in the filename, ignoring a
///   leading dot (so `.gitignore` has no extension, but `archive.tar.gz`
///   has extension `gz`). Files with no extension omit the trailing `.<ext>`.
/// - `losing_device_id` is the device whose write is being moved aside;
///   only its first 8 hex characters are used (a short, human-scannable tag
///   - full disambiguation is unnecessary since the timestamp already
///     narrows things down to the second). Shorter IDs are used in full
///     rather than panicking.
/// - `conflict_at_ms` **MUST** be the losing entry's `modified_at_ms` (not
///   `now`), formatted as UTC, so that both peers - who may have different
///   wall clocks and apply the resolution at different real times - compute
///   the exact same name independently.
///
/// This function is pure: the same inputs always produce the same output.
#[must_use]
pub fn conflict_copy_name(
    original_path: &str,
    losing_device_id: &str,
    conflict_at_ms: i64,
) -> String {
    let (dir, filename) = split_dir_filename(original_path);
    let (stem, ext) = split_stem_ext(filename);
    let stamp = format_utc_compact(conflict_at_ms);
    let short = short_device_tag(losing_device_id);

    let mut out = String::with_capacity(original_path.len() + stamp.len() + short.len() + 16);
    out.push_str(dir);
    out.push_str(stem);
    out.push_str(".sync-conflict-");
    out.push_str(&stamp);
    out.push('-');
    out.push_str(short);
    if !ext.is_empty() {
        out.push('.');
        out.push_str(ext);
    }
    out
}

/// Apply `resolution` to a `(local, remote)` pair, producing the new
/// entry/entries.
///
/// - `KeepLocal` / `KeepRemote`: The winning side's content is kept
///   unchanged (its `modified_at_ms`/`modified_by` are **not** touched,
///   since no file is actually rewritten); only the version vector is
///   merged so this exact conflict is not re-detected on the next sync.
/// - `KeepBoth`: `local` keeps the canonical path (version vector merged,
///   same reasoning as above). `remote`'s content is preserved at a new
///   conflict-copy path computed by [`conflict_copy_name`] using
///   `remote.path`, `remote.modified_by`, and `remote.modified_at_ms` - this
///   is a genuinely new file, physically written by `me` right now, so its
///   `modified_at_ms`/`modified_by` are stamped with `now_ms`/`me` and its
///   version vector is `remote`'s history incremented by `me`.
///
/// `me` and `now_ms` are unused by the `KeepLocal`/`KeepRemote` branches -
/// this is intentional: resolving a conflict without a physical rewrite is
/// not a new causal write, so it must not appear as one to peers on the
/// next sync (see ADR-007).
#[must_use]
pub fn apply_resolution(
    local: &FileEntry,
    remote: &FileEntry,
    resolution: ConflictResolution,
    me: &str,
    now_ms: i64,
) -> ResolutionOutcome {
    let merged_vv = local.version_vector.merge(&remote.version_vector);

    match resolution {
        ConflictResolution::KeepLocal => {
            let mut primary = local.clone();
            primary.version_vector = merged_vv;
            ResolutionOutcome {
                primary,
                conflict_copy: None,
            }
        }
        ConflictResolution::KeepRemote => {
            let mut primary = remote.clone();
            primary.version_vector = merged_vv;
            ResolutionOutcome {
                primary,
                conflict_copy: None,
            }
        }
        ConflictResolution::KeepBoth => {
            let copy_path =
                conflict_copy_name(&remote.path, &remote.modified_by, remote.modified_at_ms);

            let mut primary = local.clone();
            primary.version_vector = merged_vv;

            let mut conflict_copy = remote.clone();
            conflict_copy.path = copy_path;
            conflict_copy.modified_at_ms = now_ms;
            conflict_copy.modified_by = me.to_string();
            conflict_copy.version_vector = remote.version_vector.increment(me);

            ResolutionOutcome {
                primary,
                conflict_copy: Some(conflict_copy),
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

/// Split `path` into `(dir_including_trailing_slash, filename)`, `dir` is
/// `""` when there is no `/`.
fn split_dir_filename(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(idx) => (&path[..=idx], &path[idx + 1..]),
        None => ("", path),
    }
}

/// Split a filename into `(stem, ext)` on the last `.`, treating a leading
/// dot as part of the stem (so dotfiles like `.gitignore` have no
/// extension). `ext` is `""` when there is no (non-leading) dot.
fn split_stem_ext(filename: &str) -> (&str, &str) {
    match filename.rfind('.') {
        Some(idx) if idx > 0 => (&filename[..idx], &filename[idx + 1..]),
        _ => (filename, ""),
    }
}

/// First 8 characters of a device ID (device IDs are lowercase hex, so this
/// is always a valid, cheap byte-slice; a shorter ID degrades gracefully to
/// the whole string rather than panicking).
fn short_device_tag(device_id: &str) -> &str {
    let end = device_id
        .char_indices()
        .nth(8)
        .map_or(device_id.len(), |(idx, _)| idx);
    &device_id[..end]
}

/// Format milliseconds-since-epoch as a compact `YYYYMMDD-HHMMSS` UTC
/// timestamp, with no external date/time dependency (this crate is
/// `no_std + alloc`; pulling in `chrono` for one call site was rejected on
/// the desktop side too - see `dependency_review.md` §6).
fn format_utc_compact(epoch_ms: i64) -> String {
    let days = epoch_ms.div_euclid(86_400_000);
    let ms_of_day = epoch_ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let secs_of_day = ms_of_day / 1000;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    format_ymd_hms(year, month, day, hour, minute, second)
}

/// Manual decimal formatting for the compact timestamp (keeps this testable
/// independent of `alloc::format!`'s exact output shape).
fn format_ymd_hms(year: i64, month: u32, day: u32, hour: i64, minute: i64, second: i64) -> String {
    fn push2(out: &mut String, v: i64) {
        out.push((b'0' + (v / 10) as u8) as char);
        out.push((b'0' + (v % 10) as u8) as char);
    }
    fn push4(out: &mut String, v: i64) {
        out.push((b'0' + (v / 1000 % 10) as u8) as char);
        out.push((b'0' + (v / 100 % 10) as u8) as char);
        out.push((b'0' + (v / 10 % 10) as u8) as char);
        out.push((b'0' + (v % 10) as u8) as char);
    }

    let mut out = String::with_capacity(15);
    push4(&mut out, year);
    push2(&mut out, i64::from(month));
    push2(&mut out, i64::from(day));
    out.push('-');
    push2(&mut out, hour);
    push2(&mut out, minute);
    push2(&mut out, second);
    out
}

/// Convert days-since-1970-01-01 to a proleptic-Gregorian `(year, month,
/// day)` triple. This is Howard Hinnant's well-known `civil_from_days`
/// algorithm (public domain), valid across the full `i64` range in both
/// directions - see <https://howardhinnant.github.io/date_algorithms.html>.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{BlockInfo, EntryType, VersionVector};

    fn entry(path: &str, device: &str, modified_at_ms: i64) -> FileEntry {
        FileEntry {
            share_id: "share-1".to_string(),
            path: path.to_string(),
            entry_type: EntryType::File,
            size: 42,
            modified_at_ms,
            modified_by: device.to_string(),
            version_vector: VersionVector::new().increment(device),
            sha256: Some("deadbeef".to_string()),
            blocks: alloc::vec::Vec::<BlockInfo>::new(),
            deleted: false,
            deleted_at_ms: None,
        }
    }

    // --- civil_from_days / format_utc_compact ---

    #[test]
    fn epoch_zero_is_1970_01_01() {
        assert_eq!(format_utc_compact(0), "19700101-000000");
    }

    #[test]
    fn known_reference_date() {
        // 2026-06-09 15:30:00 UTC. Cross-checked against
        // `date -u -d '2026-06-09 15:30:00' +%s` => 1781019000.
        assert_eq!(format_utc_compact(1_781_019_000_000), "20260609-153000");
    }

    #[test]
    fn end_of_day_boundary() {
        // 1970-01-01 23:59:59.999 UTC - one ms before the day rolls over.
        assert_eq!(format_utc_compact(86_399_999), "19700101-235959");
        // Exactly the next day.
        assert_eq!(format_utc_compact(86_400_000), "19700102-000000");
    }

    #[test]
    fn leap_day_is_handled() {
        // 2024-02-29 00:00:00 UTC = 1709164800000 ms.
        assert_eq!(format_utc_compact(1_709_164_800_000), "20240229-000000");
    }

    // --- split_dir_filename / split_stem_ext (via conflict_copy_name) ---

    #[test]
    fn simple_file_with_extension() {
        let name = conflict_copy_name("report.pdf", "abcd1234ef567890", 0);
        assert_eq!(name, "report.sync-conflict-19700101-000000-abcd1234.pdf");
    }

    #[test]
    fn nested_path_preserves_directory() {
        let name = conflict_copy_name("docs/team/report.pdf", "abcd1234ef567890", 0);
        assert_eq!(
            name,
            "docs/team/report.sync-conflict-19700101-000000-abcd1234.pdf"
        );
    }

    #[test]
    fn file_with_no_extension() {
        let name = conflict_copy_name("README", "abcd1234ef567890", 0);
        assert_eq!(name, "README.sync-conflict-19700101-000000-abcd1234");
    }

    #[test]
    fn dotfile_has_no_extension() {
        let name = conflict_copy_name(".gitignore", "abcd1234ef567890", 0);
        assert_eq!(name, ".gitignore.sync-conflict-19700101-000000-abcd1234");
    }

    #[test]
    fn multi_dot_filename_splits_on_last_dot_only() {
        let name = conflict_copy_name("archive.tar.gz", "abcd1234ef567890", 0);
        assert_eq!(
            name,
            "archive.tar.sync-conflict-19700101-000000-abcd1234.gz"
        );
    }

    #[test]
    fn device_id_shorter_than_8_chars_does_not_panic() {
        let name = conflict_copy_name("f.txt", "ab", 0);
        assert_eq!(name, "f.sync-conflict-19700101-000000-ab.txt");
    }

    #[test]
    fn same_inputs_always_produce_the_same_name() {
        let a = conflict_copy_name("docs/report.pdf", "abcd1234ef567890", 1_781_019_000_000);
        let b = conflict_copy_name("docs/report.pdf", "abcd1234ef567890", 1_781_019_000_000);
        assert_eq!(a, b);
    }

    // --- apply_resolution ---

    #[test]
    fn keep_local_preserves_local_content_and_merges_versions() {
        let local = entry("f.txt", "dev-a", 1_000);
        let remote = entry("f.txt", "dev-b", 2_000);

        let outcome = apply_resolution(
            &local,
            &remote,
            ConflictResolution::KeepLocal,
            "dev-a",
            9_999,
        );

        assert!(outcome.conflict_copy.is_none());
        assert_eq!(outcome.primary.modified_by, "dev-a");
        assert_eq!(outcome.primary.modified_at_ms, 1_000); // untouched by `now_ms`
        assert!(local
            .version_vector
            .is_ancestor_of(&outcome.primary.version_vector));
        assert!(remote
            .version_vector
            .is_ancestor_of(&outcome.primary.version_vector));
    }

    #[test]
    fn keep_remote_preserves_remote_content_and_merges_versions() {
        let local = entry("f.txt", "dev-a", 1_000);
        let remote = entry("f.txt", "dev-b", 2_000);

        let outcome = apply_resolution(
            &local,
            &remote,
            ConflictResolution::KeepRemote,
            "dev-a",
            9_999,
        );

        assert!(outcome.conflict_copy.is_none());
        assert_eq!(outcome.primary.modified_by, "dev-b");
        assert_eq!(outcome.primary.modified_at_ms, 2_000);
        assert!(local
            .version_vector
            .is_ancestor_of(&outcome.primary.version_vector));
        assert!(remote
            .version_vector
            .is_ancestor_of(&outcome.primary.version_vector));
    }

    #[test]
    fn keep_both_creates_a_conflict_copy_for_remote() {
        let local = entry("f.txt", "dev-a", 1_000);
        let remote = entry("f.txt", "dev-b", 2_000);

        let outcome = apply_resolution(
            &local,
            &remote,
            ConflictResolution::KeepBoth,
            "dev-a",
            9_999,
        );

        // Local stays at the canonical path.
        assert_eq!(outcome.primary.path, "f.txt");
        assert_eq!(outcome.primary.modified_by, "dev-a");

        let copy = outcome.conflict_copy.expect("KeepBoth must produce a copy");
        assert_eq!(copy.path, conflict_copy_name("f.txt", "dev-b", 2_000));
        // The copy is a fresh write performed by `me`, right now.
        assert_eq!(copy.modified_by, "dev-a");
        assert_eq!(copy.modified_at_ms, 9_999);
        // Its version history descends from remote's, plus this new write.
        assert!(remote.version_vector.is_ancestor_of(&copy.version_vector));
        assert_eq!(
            copy.version_vector.get("dev-a"),
            remote.version_vector.get("dev-a") + 1
        );
    }

    #[test]
    fn keep_both_is_deterministic_across_independent_computations() {
        let local = entry("shared/notes.md", "dev-a", 1_000);
        let remote = entry("shared/notes.md", "dev-b", 2_000);

        let a = apply_resolution(
            &local,
            &remote,
            ConflictResolution::KeepBoth,
            "dev-a",
            5_000,
        );
        let b = apply_resolution(
            &local,
            &remote,
            ConflictResolution::KeepBoth,
            "dev-a",
            5_000,
        );

        assert_eq!(a.primary, b.primary);
        assert_eq!(a.conflict_copy.unwrap().path, b.conflict_copy.unwrap().path);
    }
}
