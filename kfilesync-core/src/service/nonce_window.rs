//! Nonce-replay window for anti-replay enforcement.
//!
//! # Sprint 2 implementation
//!
//! Each paired device gets its own nonce namespace. A `(device_id, nonce)`
//! tuple is accepted at most once per acceptance window; presenting it again
//! while it is still "live" (within `window_size_ms` of when it was first
//! observed) is rejected as [`NonceVerdict::Replay`].
//!
//! Storage keys on **server-observed time** (`now_ms` at the moment
//! [`verify_and_record`] is called), not the client-supplied `timestamp_ms`.
//! This keeps expiry bookkeeping honest even though the timestamp itself is
//! also validated against the same window (see rule ordering below) -
//! relying on the attacker-supplied value for expiry math would let a
//! replay "refresh" its own lifetime.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

/// Per-device map of `(nonce -> first-seen-at-ms)`, where "first-seen-at" is
/// the host's own clock reading at the time the nonce was accepted (not the
/// client-supplied timestamp).
///
/// Hosts own this state and pass `&mut` to [`verify_and_record`]. It is
/// `Serialize`/`Deserialize` so a host can persist it across restarts if it
/// wants replay protection to survive a crash; an empty (default) state is
/// always a safe starting point (worst case: a handful of legitimate
/// requests from the last window get re-checked from scratch).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NonceWindowState {
    per_device: BTreeMap<String, BTreeMap<String, i64>>,
}

impl NonceWindowState {
    /// Number of devices currently tracked. Exposed for host-side metrics
    /// and tests; not required for correctness.
    #[must_use]
    pub fn tracked_device_count(&self) -> usize {
        self.per_device.len()
    }

    /// Number of live nonces tracked for `device_id`. Returns 0 for unknown
    /// devices.
    #[must_use]
    pub fn tracked_nonce_count(&self, device_id: &str) -> usize {
        self.per_device
            .get(device_id)
            .map_or(0, |nonces| nonces.len())
    }
}

/// Result of verifying a request's anti-replay tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceVerdict {
    /// Tuple is acceptable and has been recorded.
    Fresh,
    /// Timestamp is older than `now - window_size_ms`.
    StaleTimestamp,
    /// Timestamp is farther in the future than `now + clock_skew_ms`.
    FutureTimestamp,
    /// Nonce already recorded for this device within the window.
    Replay,
    /// Empty / whitespace-only nonce.
    BlankNonce,
}

/// Verify and (if fresh) record an anti-replay tuple.
///
/// Checks run in a fixed order so the verdict is deterministic and callers
/// can log a single, unambiguous reason:
///
/// 1. `nonce` is non-blank                           -> [`NonceVerdict::BlankNonce`]
/// 2. `timestamp_ms` is not older than `now_ms - window_size_ms` -> [`NonceVerdict::StaleTimestamp`]
/// 3. `timestamp_ms` is not newer than `now_ms + clock_skew_ms`  -> [`NonceVerdict::FutureTimestamp`]
/// 4. `(device_id, nonce)` has not been seen within the live window -> [`NonceVerdict::Replay`]
///
/// Returns [`NonceVerdict::Fresh`] and mutates `state` on success; returns a
/// rejection verdict and leaves `state` unchanged otherwise.
///
/// Both window bounds are **inclusive**: a timestamp exactly at
/// `now_ms - window_size_ms` or `now_ms + clock_skew_ms` is accepted.
#[must_use]
pub fn verify_and_record(
    state: &mut NonceWindowState,
    device_id: &str,
    timestamp_ms: i64,
    nonce: &str,
    now_ms: i64,
    window_size_ms: i64,
    clock_skew_ms: i64,
) -> NonceVerdict {
    if nonce.trim().is_empty() {
        return NonceVerdict::BlankNonce;
    }

    let earliest_valid = now_ms.saturating_sub(window_size_ms);
    if timestamp_ms < earliest_valid {
        return NonceVerdict::StaleTimestamp;
    }

    let latest_valid = now_ms.saturating_add(clock_skew_ms);
    if timestamp_ms > latest_valid {
        return NonceVerdict::FutureTimestamp;
    }

    let device_nonces = state.per_device.entry(device_id.to_string()).or_default();

    // A nonce that was recorded but has since aged out of the window is no
    // longer "live" - it is logically expired even if `prune_expired`
    // hasn't physically removed it yet, so treat re-use as Fresh, not a
    // replay. Real clients never legitimately reuse a nonce, so this only
    // matters for keeping memory-bounded state and tests honest.
    let is_live_replay = device_nonces
        .get(nonce)
        .is_some_and(|&first_seen_at| first_seen_at >= earliest_valid);

    if is_live_replay {
        return NonceVerdict::Replay;
    }

    device_nonces.insert(nonce.to_string(), now_ms);
    NonceVerdict::Fresh
}

/// Opportunistically drop nonces older than `now_ms - window_size_ms` for
/// every device, and drop any device whose nonce set becomes empty as a
/// result. Hosts call this periodically (e.g. once a minute) to keep memory
/// use bounded; correctness does not depend on calling it, since
/// [`verify_and_record`] already ignores expired entries.
///
/// Returns the number of nonce entries removed.
#[must_use]
pub fn prune_expired(state: &mut NonceWindowState, now_ms: i64, window_size_ms: i64) -> usize {
    let cutoff = now_ms.saturating_sub(window_size_ms);
    let mut removed = 0;

    state.per_device.retain(|_, nonces| {
        let before = nonces.len();
        nonces.retain(|_, &mut first_seen_at| first_seen_at >= cutoff);
        removed += before - nonces.len();
        !nonces.is_empty()
    });

    removed
}

/// Clear all nonces tracked for a device. Used on trust revocation so a
/// re-paired device starts with a clean replay window.
pub fn clear_device(state: &mut NonceWindowState, device_id: &str) {
    state.per_device.remove(device_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: i64 = 300_000; // 5 minutes, per spec §9.1
    const SKEW: i64 = 300_000;

    #[test]
    fn fresh_tuple_is_accepted_and_recorded() {
        let mut state = NonceWindowState::default();
        let verdict = verify_and_record(&mut state, "dev-a", 1_000, "n1", 1_000, WINDOW, SKEW);
        assert_eq!(verdict, NonceVerdict::Fresh);
        assert_eq!(state.tracked_nonce_count("dev-a"), 1);
    }

    #[test]
    fn blank_or_whitespace_nonce_is_rejected() {
        let mut state = NonceWindowState::default();
        assert_eq!(
            verify_and_record(&mut state, "dev-a", 1_000, "", 1_000, WINDOW, SKEW),
            NonceVerdict::BlankNonce
        );
        assert_eq!(
            verify_and_record(&mut state, "dev-a", 1_000, "   ", 1_000, WINDOW, SKEW),
            NonceVerdict::BlankNonce
        );
        assert_eq!(state.tracked_nonce_count("dev-a"), 0);
    }

    #[test]
    fn replay_of_the_same_nonce_is_rejected() {
        let mut state = NonceWindowState::default();
        let now = 1_000;
        assert_eq!(
            verify_and_record(&mut state, "dev-a", now, "n1", now, WINDOW, SKEW),
            NonceVerdict::Fresh
        );
        // Same device, same nonce, slightly later request.
        assert_eq!(
            verify_and_record(&mut state, "dev-a", now + 10, "n1", now + 10, WINDOW, SKEW),
            NonceVerdict::Replay
        );
        // State is unchanged by the rejected attempt.
        assert_eq!(state.tracked_nonce_count("dev-a"), 1);
    }

    #[test]
    fn same_nonce_from_different_devices_does_not_collide() {
        let mut state = NonceWindowState::default();
        let now = 1_000;
        assert_eq!(
            verify_and_record(&mut state, "dev-a", now, "shared", now, WINDOW, SKEW),
            NonceVerdict::Fresh
        );
        assert_eq!(
            verify_and_record(&mut state, "dev-b", now, "shared", now, WINDOW, SKEW),
            NonceVerdict::Fresh
        );
    }

    #[test]
    fn stale_timestamp_is_rejected_but_boundary_is_inclusive() {
        let mut state = NonceWindowState::default();
        let now = 1_000_000;

        // Exactly at the boundary: accepted.
        assert_eq!(
            verify_and_record(
                &mut state,
                "dev-a",
                now - WINDOW,
                "at-edge",
                now,
                WINDOW,
                SKEW
            ),
            NonceVerdict::Fresh
        );
        // One ms past the boundary: rejected.
        assert_eq!(
            verify_and_record(
                &mut state,
                "dev-a",
                now - WINDOW - 1,
                "past-edge",
                now,
                WINDOW,
                SKEW
            ),
            NonceVerdict::StaleTimestamp
        );
    }

    #[test]
    fn future_timestamp_is_rejected_but_boundary_is_inclusive() {
        let mut state = NonceWindowState::default();
        let now = 1_000_000;

        assert_eq!(
            verify_and_record(
                &mut state,
                "dev-a",
                now + SKEW,
                "at-edge",
                now,
                WINDOW,
                SKEW
            ),
            NonceVerdict::Fresh
        );
        assert_eq!(
            verify_and_record(
                &mut state,
                "dev-a",
                now + SKEW + 1,
                "past-edge",
                now,
                WINDOW,
                SKEW
            ),
            NonceVerdict::FutureTimestamp
        );
    }

    #[test]
    fn stale_check_takes_priority_over_replay_check() {
        // A very old, already-expired nonce re-appearing with a stale
        // timestamp should be reported as stale, not replay - the caller
        // gets the more specific, actionable reason.
        let mut state = NonceWindowState::default();
        let now = 10_000_000;
        assert_eq!(
            verify_and_record(&mut state, "dev-a", now, "n1", now, WINDOW, SKEW),
            NonceVerdict::Fresh
        );
        assert_eq!(
            verify_and_record(
                &mut state,
                "dev-a",
                now - WINDOW - 1,
                "n1",
                now,
                WINDOW,
                SKEW
            ),
            NonceVerdict::StaleTimestamp
        );
    }

    #[test]
    fn nonce_becomes_fresh_again_once_it_ages_out_of_the_window() {
        let mut state = NonceWindowState::default();
        assert_eq!(
            verify_and_record(&mut state, "dev-a", 0, "n1", 0, WINDOW, SKEW),
            NonceVerdict::Fresh
        );

        // Time has moved far enough that the original recording is no
        // longer "live"; the same nonce presented with a fresh, in-window
        // timestamp is accepted again rather than reported as replay.
        let later = WINDOW + 1;
        assert_eq!(
            verify_and_record(&mut state, "dev-a", later, "n1", later, WINDOW, SKEW),
            NonceVerdict::Fresh
        );
    }

    #[test]
    fn prune_expired_removes_only_aged_out_entries_and_reports_count() {
        let mut state = NonceWindowState::default();
        let _ = verify_and_record(&mut state, "dev-a", 0, "old", 0, WINDOW, SKEW);
        let _ = verify_and_record(&mut state, "dev-a", 500_000, "fresh", 500_000, WINDOW, SKEW);
        let _ = verify_and_record(&mut state, "dev-b", 0, "also-old", 0, WINDOW, SKEW);

        let removed = prune_expired(&mut state, 500_000, WINDOW);

        assert_eq!(removed, 2); // dev-a/"old" and dev-b/"also-old"
        assert_eq!(state.tracked_nonce_count("dev-a"), 1);
        // dev-b has no nonces left, so the whole device entry is dropped.
        assert_eq!(state.tracked_device_count(), 1);
    }

    #[test]
    fn clear_device_removes_all_of_its_nonces_only() {
        let mut state = NonceWindowState::default();
        let _ = verify_and_record(&mut state, "dev-a", 0, "n1", 0, WINDOW, SKEW);
        let _ = verify_and_record(&mut state, "dev-b", 0, "n2", 0, WINDOW, SKEW);

        clear_device(&mut state, "dev-a");

        assert_eq!(state.tracked_nonce_count("dev-a"), 0);
        assert_eq!(state.tracked_nonce_count("dev-b"), 1);
    }

    #[test]
    fn state_survives_a_json_round_trip() {
        let mut state = NonceWindowState::default();
        let _ = verify_and_record(&mut state, "dev-a", 0, "n1", 0, WINDOW, SKEW);
        let _ = verify_and_record(&mut state, "dev-b", 100, "n2", 100, WINDOW, SKEW);

        let json = serde_json::to_string(&state).unwrap();
        let restored: NonceWindowState = serde_json::from_str(&json).unwrap();

        assert_eq!(
            restored.tracked_device_count(),
            state.tracked_device_count()
        );
        assert_eq!(
            restored.tracked_nonce_count("dev-a"),
            state.tracked_nonce_count("dev-a")
        );
    }
}
