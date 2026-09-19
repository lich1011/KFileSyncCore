//!
//! 
//! A [`VersionVector`] maps device IDs to monotonically-increasing counters.
//! Two vectors `a` and `b` relate causally in exactly one of three ways:
//!
//! - `a.is_ancestor_of(b)` (and not vice-versa) -> `b` is causally newer
//! - `b.is_ancestor_of(a)` (and not vice-versa) -> `a` is causally newer
//! - neither                                     -> concurrent edits (conflict)
//!
//! This is the foundation of KFileSync's three-state sync decision (pull /
//! push / conflict).
//!
//! # Determinism
//!
//! Internally a [`BTreeMap`] keyed by device ID is used to guarantee
//! deterministic iteration order - important because both peers in a sync
//! must compute the same merged vector independently.
//!
//! # Examples
//!
//! ```
//! use kfilesync_core::domain::VersionVector;
//!
//! let v0 = VersionVector::new();
//! let v1 = v0.increment("device-a");
//! let v2 = v1.increment("device-a");
//!
//! assert!(v0.is_ancestor_of(&v1));
//! assert!(v1.is_ancestor_of(&v2));
//! assert!(!v2.is_ancestor_of(&v1));
//! assert!(!v1.conflicts_with(&v2));
//! ```

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

/// A per-device causal counter map.
///
/// See module docs for semantics.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionVector {
    entries: BTreeMap<String, u64>,
}

// UniFFI has no native `BTreeMap` support; bridge through its builtin
// `HashMap` wire type. Iteration order does not matter across the FFI
// boundary since the map is rebuilt into a `BTreeMap` on lift.
#[cfg(feature = "ffi")]
uniffi::custom_type!(VersionVector, std::collections::HashMap<String, u64>, {
    lower: |vv| vv.entries.into_iter().collect(),
    try_lift: |v| Ok(VersionVector { entries: v.into_iter().collect() }),
});

impl VersionVector {
    /// Construct an empty vector - represents "no device has written yet".
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Returns the counter for `device`, defaulting to 0 when absent.
    #[must_use]
    pub fn get(&self, device: &str) -> u64 {
        self.entries.get(device).copied().unwrap_or(0)
    }

    /// True iff every component of `self` is `<=` the corresponding component
    /// of `other`. Devices present in `self` but absent in `other` are
    /// treated as having counter 0 on the other side, so a non-zero counter
    /// in `self` breaks ancestry.
    #[must_use]
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        for (device, &self_count) in &self.entries {
            if self_count > other.get(device) {
                return false;
            }
        }
        true
    }

    /// True iff neither vector is an ancestor of the other.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        !self.is_ancestor_of(other) && !other.is_ancestor_of(self)
    }

    /// Returns a new vector with `device`'s counter incremented by one.
    ///
    /// If `device` is absent, the result has `device -> 1`.
    #[must_use]
    pub fn increment(&self, device: &str) -> Self {
        let mut result = self.clone();
        let entry = result.entries.entry(device.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
        result
    }

    /// Component-wise maximum of two vectors.
    ///
    /// Used to advance a vector past a peer's vector during a merge.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (device, &other_count) in &other.entries {
            let entry = result.entries.entry(device.clone()).or_insert(0);
            if other_count > *entry {
                *entry = other_count;
            }
        }
        result
    }

    /// Iterate (device, counter) pairs in sorted device order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.entries.iter().map(|(k, &v)| (k.as_str(), v))
    }

    /// True when no device has any non-zero counter.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.values().all(|&c| c == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_vector_is_ancestor_of_anything() {
        let empty = VersionVector::new();
        let v = empty.increment("a").increment("b");
        assert!(empty.is_ancestor_of(&v));
        assert!(empty.is_ancestor_of(&empty));
    }

    #[test]
    fn linear_history_has_no_conflicts() {
        let v0 = VersionVector::new();
        let v1 = v0.increment("a");
        let v2 = v1.increment("a");
        let v3 = v2.increment("b");

        assert!(v0.is_ancestor_of(&v3));
        assert!(v1.is_ancestor_of(&v2));
        assert!(v2.is_ancestor_of(&v3));
        assert!(!v1.conflicts_with(&v3));
    }

    #[test]
    fn concurrent_edits_conflict() {
        let v0 = VersionVector::new();
        let a = v0.increment("a");
        let b = v0.increment("b");

        assert!(a.conflicts_with(&b));
        assert!(b.conflicts_with(&a));
        assert!(!a.is_ancestor_of(&b));
        assert!(!b.is_ancestor_of(&a));
    }

    #[test]
    fn merge_takes_per_device_max() {
        let a = VersionVector::new()
            .increment("a")
            .increment("a")
            .increment("b");
        let b = VersionVector::new().increment("a").increment("c");
        let merged = a.merge(&b);

        assert_eq!(merged.get("a"), 2);
        assert_eq!(merged.get("b"), 1);
        assert_eq!(merged.get("c"), 1);
    }

    #[test]
    fn merge_is_commutative() {
        let a = VersionVector::new().increment("a").increment("b");
        let b = VersionVector::new()
            .increment("b")
            .increment("c")
            .increment("c");
        assert_eq!(a.merge(&b), b.merge(&a));
    }

    #[test]
    fn merge_resolves_conflict() {
        let v0 = VersionVector::new();
        let a = v0.increment("a");
        let b = v0.increment("b");
        assert!(a.conflicts_with(&b));

        let merged = a.merge(&b);
        assert!(a.is_ancestor_of(&merged));
        assert!(b.is_ancestor_of(&merged));
        assert!(!a.conflicts_with(&merged));
        assert!(!b.conflicts_with(&merged));
    }

    #[test]
    fn serde_roundtrip() {
        let v = VersionVector::new()
            .increment("device-1")
            .increment("device-2")
            .increment("device-2");
        let json = serde_json::to_string(&v).unwrap();
        let parsed: VersionVector = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
        // The serde(transparent) form serializes to a flat object.
        assert!(json.starts_with('{'));
    }

    #[test]
    fn deterministic_iteration_order() {
        // Insertions in random order should still produce sorted iteration.
        let v = VersionVector::new()
            .increment("zebra")
            .increment("apple")
            .increment("mango");
        let order: alloc::vec::Vec<&str> = v.iter().map(|(k, _)| k).collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order, sorted);
    }
}
