//! Thin wrapper around [`crate::service::nonce_window`] that surfaces
//! reasons in trust-evaluator terms.
//!
//! # Sprint 5 implementation
//!
//! Currently a placeholder.

use crate::service::nonce_window::{verify_and_record, NonceVerdict, NonceWindowState};

/// Outcome of replay-guard verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayGuardOutcome {
    /// Tuple accepted and recorded.
    Ok,
    /// Timestamp is outside the acceptance window.
    StaleOrFutureTimestamp,
    /// Nonce already seen within the window.
    Replay,
    /// Empty / blank nonce.
    BlankNonce,
}

/// Check a request's anti-replay headers and record the nonce on success.
pub fn check_and_record(
    state: &mut NonceWindowState,
    device_id: &str,
    timestamp_ms: i64,
    nonce: &str,
    now_ms: i64,
    window_size_ms: i64,
    clock_skew_ms: i64,
) -> ReplayGuardOutcome {
    match verify_and_record(
        state,
        device_id,
        timestamp_ms,
        nonce,
        now_ms,
        window_size_ms,
        clock_skew_ms,
    ) {
        NonceVerdict::Fresh => ReplayGuardOutcome::Ok,
        NonceVerdict::StaleTimestamp | NonceVerdict::FutureTimestamp => {
            ReplayGuardOutcome::StaleOrFutureTimestamp
        }
        NonceVerdict::Replay => ReplayGuardOutcome::Replay,
        NonceVerdict::BlankNonce => ReplayGuardOutcome::BlankNonce,
    }
}
