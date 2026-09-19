//! The central zero-trust gate.
//!
//! Every mutating inbound request flows through [`evaluate_inbound`]. The
//! five rules and their stable error codes are documented inline.
//!
//! # Sprint 5 implementation

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::protocol::routes::is_bootstrap_route;
use crate::service::nonce_window::NonceWindowState;
use crate::trust::cert_pin;
use crate::trust::replay_guard::{self, ReplayGuardOutcome};

/// Request metadata extracted from headers by the host before calling
/// [`evaluate_inbound`].
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct RequestMeta {
    /// HTTP path being handled (e.g. "/api/lansync/v1/pair/request").
    pub route: String,
    /// `X-Device-Id` header value (may be missing).
    pub device_id_header: Option<String>,
    /// `X-Timestamp` header value (parsed to millis).
    pub timestamp_ms_header: Option<i64>,
    /// `X-Nonce` header value.
    pub nonce_header: Option<String>,
    /// `X-Fingerprint` header value, lowercase hex.
    pub fingerprint_header: Option<String>,
}

/// Snapshot of paired devices loaded by host from DB before each evaluation.
#[derive(Clone, Default)]
pub struct PairedDeviceSet {
    entries: Vec<PairedDeviceEntry>,
}

/// One paired device's identifying data (fingerprint comparison only).
#[derive(Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PairedDeviceEntry {
    /// Peer's stable device ID.
    pub device_id: String,
    /// SHA-256 hex of peer's TLS cert DER, lowercase.
    pub cert_fingerprint_hex: String,
}

impl PairedDeviceSet {
    /// Build a snapshot from a list of entries.
    #[must_use]
    pub fn new(entries: Vec<PairedDeviceEntry>) -> Self {
        Self { entries }
    }

    /// Look up an entry by device ID.
    #[must_use]
    pub fn find(&self, device_id: &str) -> Option<&PairedDeviceEntry> {
        self.entries.iter().find(|e| e.device_id == device_id)
    }
}

/// Outcome of `evaluate_inbound`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustDecision {
    /// Request fully authorized; host may execute the business logic.
    Allow {
        /// Peer's device ID (already verified).
        peer_device_id: String,
        /// Peer's pinned fingerprint.
        peer_fingerprint: String,
    },
    /// Permitted for bootstrap routes (`/pair/request`, `/pair/confirm`, `/register`)
    /// - anti-replay rules 1-3 still passed, but rule 4 (paired-device
    ///   check) is intentionally skipped because the PIN ceremony is the
    ///   real authenticator at this stage.
    AllowUnpairedForPairing,
    /// Reject - host must return the given HTTP status and error code.
    Reject {
        /// HTTP status to return.
        http_status: u16,
        /// Stable error code (see module docs).
        error_code: &'static str,
        /// Human-readable reason for logs.
        reason: String,
    },
}

/// THE central zero-trust gate.
///
/// Rules run in a fixed order, each with its own stable `error_code` so
/// hosts can log (or the caller can test) a specific, actionable reason:
///
/// 1. anti-replay headers present                     -> `missing_anti_replay_headers`
/// 2. timestamp within +-window_size_ms                 -> `stale_or_future_timestamp`
/// 3. (device_id, nonce) not seen within window       -> `nonce_replay`
/// 4. device_id is paired (unless bootstrap route)    -> `unknown_peer`
/// 5. fingerprint matches paired cert (if provided)   -> `fingerprint_mismatch`
/// 6. otherwise                                       -> `Allow` (or
///    `AllowUnpairedForPairing` on a bootstrap route, which stops at rule 3)
///
/// **Rule 5 is conditional**: `fingerprint_header` is optional (per
/// `CROSS_VALIDATION_DESKTOP_MOBILE.md` §3.8 - both hosts already treat it
/// as an optional extra check, not a hard requirement, since TLS-level
/// cert pinning is the host's primary defense here; this header is a
/// belt-and-suspenders app-layer check on top of it). If absent, rule 5 is
/// skipped rather than treated as a failure.
///
/// On success, mutates `nonce_state` to record the nonce (so a replay of
/// this exact request is rejected next time); on any rejection,
/// `nonce_state` is left exactly as `replay_guard::check_and_record`
/// leaves it (unchanged, since none of the rejection paths reach a state
/// where recording would be correct).
#[must_use]
pub fn evaluate_inbound(
    request_meta: &RequestMeta,
    paired_devices: &PairedDeviceSet,
    nonce_state: &mut NonceWindowState,
    clock_now_ms: i64,
    window_size_ms: i64,
    clock_skew_ms: i64,
) -> TrustDecision {
    // Rule 1: all three anti-replay headers must be present.
    let (Some(device_id), Some(timestamp_ms), Some(nonce)) = (
        request_meta.device_id_header.as_deref(),
        request_meta.timestamp_ms_header,
        request_meta.nonce_header.as_deref(),
    ) else {
        return TrustDecision::Reject {
            http_status: 401,
            error_code: "missing_anti_replay_headers",
            reason: "X-Device-Id, X-Timestamp, and X-Nonce must all be present".to_string(),
        };
    };

    // Rules 2 + 3: timestamp window and nonce replay, via the same
    // NonceWindowState every route shares.
    match replay_guard::check_and_record(
        nonce_state,
        device_id,
        timestamp_ms,
        nonce,
        clock_now_ms,
        window_size_ms,
        clock_skew_ms,
    ) {
        ReplayGuardOutcome::Ok => {}
        ReplayGuardOutcome::BlankNonce => {
            return TrustDecision::Reject {
                http_status: 401,
                error_code: "missing_anti_replay_headers",
                reason: "X-Nonce is present but blank".to_string(),
            };
        }
        ReplayGuardOutcome::StaleOrFutureTimestamp => {
            return TrustDecision::Reject {
                http_status: 401,
                error_code: "stale_or_future_timestamp",
                reason: "X-Timestamp is outside the acceptance window".to_string(),
            };
        }
        ReplayGuardOutcome::Replay => {
            return TrustDecision::Reject {
                http_status: 401,
                error_code: "nonce_replay",
                reason: "this (device_id, nonce) pair was already used".to_string(),
            };
        }
    }

    // Bootstrap routes stop here: the PIN ceremony is the real
    // authenticator, not paired-device trust.
    if is_bootstrap_route(&request_meta.route) {
        return TrustDecision::AllowUnpairedForPairing;
    }

    // Rule 4: device must be paired.
    let Some(entry) = paired_devices.find(device_id) else {
        return TrustDecision::Reject {
            http_status: 403,
            error_code: "unknown_peer",
            reason: alloc::format!("device_id '{device_id}' is not a paired peer"),
        };
    };

    // Rule 5: fingerprint cross-check, only if the header was supplied.
    if let Some(asserted_fp) = &request_meta.fingerprint_header {
        if !cert_pin::verify_fingerprint_hex(asserted_fp, &entry.cert_fingerprint_hex) {
            return TrustDecision::Reject {
                http_status: 403,
                error_code: "fingerprint_mismatch",
                reason: "X-Fingerprint does not match the pinned certificate".to_string(),
            };
        }
    }

    TrustDecision::Allow {
        peer_device_id: device_id.to_string(),
        peer_fingerprint: entry.cert_fingerprint_hex.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: i64 = 300_000;
    const SKEW: i64 = 300_000;

    fn meta(
        route: &str,
        device_id: Option<&str>,
        ts: Option<i64>,
        nonce: Option<&str>,
        fp: Option<&str>,
    ) -> RequestMeta {
        RequestMeta {
            route: route.to_string(),
            device_id_header: device_id.map(|s| s.to_string()),
            timestamp_ms_header: ts,
            nonce_header: nonce.map(|s| s.to_string()),
            fingerprint_header: fp.map(|s| s.to_string()),
        }
    }

    fn paired_set() -> PairedDeviceSet {
        PairedDeviceSet::new(alloc::vec![PairedDeviceEntry {
            device_id: "dev-a".to_string(),
            cert_fingerprint_hex: "aabbccdd".to_string(),
        }])
    }

    // --- Rule 1: missing headers ---

    #[test]
    fn rule1_missing_device_id_header_is_rejected() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            None,
            Some(1000),
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "missing_anti_replay_headers",
                http_status: 401,
                ..
            }
        ));
    }

    #[test]
    fn rule1_missing_timestamp_header_is_rejected() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            None,
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "missing_anti_replay_headers",
                ..
            }
        ));
    }

    #[test]
    fn rule1_missing_nonce_header_is_rejected() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1000),
            None,
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "missing_anti_replay_headers",
                ..
            }
        ));
    }

    #[test]
    fn rule1_blank_nonce_header_is_rejected() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1000),
            Some("  "),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "missing_anti_replay_headers",
                ..
            }
        ));
    }

    // --- Rule 2: timestamp window ---

    #[test]
    fn rule2_stale_timestamp_is_rejected() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(0),
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1_000_000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "stale_or_future_timestamp",
                http_status: 401,
                ..
            }
        ));
    }

    #[test]
    fn rule2_future_timestamp_is_rejected() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(2_000_000),
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1_000_000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "stale_or_future_timestamp",
                ..
            }
        ));
    }

    #[test]
    fn rule2_timestamp_exactly_at_the_boundary_passes() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(700_000),
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1_000_000, WINDOW, SKEW);
        assert!(!matches!(
            d,
            TrustDecision::Reject {
                error_code: "stale_or_future_timestamp",
                ..
            }
        ));
    }

    // --- Rule 3: nonce replay ---

    #[test]
    fn rule3_replayed_nonce_is_rejected_on_second_use() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1000),
            Some("n1"),
            None,
        );
        let first = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(!matches!(first, TrustDecision::Reject { .. }));

        let m2 = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1010),
            Some("n1"),
            None,
        );
        let second = evaluate_inbound(&m2, &paired_set(), &mut state, 1010, WINDOW, SKEW);
        assert!(matches!(
            second,
            TrustDecision::Reject {
                error_code: "nonce_replay",
                http_status: 401,
                ..
            }
        ));
    }

    #[test]
    fn rule3_different_nonces_from_the_same_device_are_both_accepted() {
        let mut state = NonceWindowState::default();
        let m1 = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1000),
            Some("n1"),
            None,
        );
        let m2 = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1010),
            Some("n2"),
            None,
        );
        assert!(!matches!(
            evaluate_inbound(&m1, &paired_set(), &mut state, 1000, WINDOW, SKEW),
            TrustDecision::Reject { .. }
        ));
        assert!(!matches!(
            evaluate_inbound(&m2, &paired_set(), &mut state, 1010, WINDOW, SKEW),
            TrustDecision::Reject { .. }
        ));
    }

    // --- Rule 4: paired-device check (and bootstrap bypass) ---

    #[test]
    fn rule4_unpaired_device_is_rejected_on_a_normal_route() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-unknown"),
            Some(1000),
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "unknown_peer",
                http_status: 403,
                ..
            }
        ));
    }

    #[test]
    fn rule4_is_skipped_entirely_on_a_bootstrap_route() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/pair/request",
            Some("dev-unknown"),
            Some(1000),
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert_eq!(d, TrustDecision::AllowUnpairedForPairing);
    }

    #[test]
    fn rule4_bootstrap_route_still_enforces_rules_1_to_3() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/pair/request",
            Some("dev-unknown"),
            None,
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "missing_anti_replay_headers",
                ..
            }
        ));
    }

    // --- Rule 5: fingerprint cross-check ---

    #[test]
    fn rule5_matching_fingerprint_is_allowed() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1000),
            Some("n1"),
            Some("aabbccdd"),
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert_eq!(
            d,
            TrustDecision::Allow {
                peer_device_id: "dev-a".to_string(),
                peer_fingerprint: "aabbccdd".to_string()
            }
        );
    }

    #[test]
    fn rule5_mismatched_fingerprint_is_rejected() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1000),
            Some("n1"),
            Some("00000000"),
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert!(matches!(
            d,
            TrustDecision::Reject {
                error_code: "fingerprint_mismatch",
                http_status: 403,
                ..
            }
        ));
    }

    #[test]
    fn rule5_is_skipped_when_the_header_is_absent() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/sync/index",
            Some("dev-a"),
            Some(1000),
            Some("n1"),
            None,
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert_eq!(
            d,
            TrustDecision::Allow {
                peer_device_id: "dev-a".to_string(),
                peer_fingerprint: "aabbccdd".to_string()
            }
        );
    }

    // --- End-to-end happy path ---

    #[test]
    fn fully_valid_request_on_a_normal_route_is_allowed() {
        let mut state = NonceWindowState::default();
        let m = meta(
            "/api/lansync/v1/transfer/request",
            Some("dev-a"),
            Some(1000),
            Some("n1"),
            Some("aabbccdd"),
        );
        let d = evaluate_inbound(&m, &paired_set(), &mut state, 1000, WINDOW, SKEW);
        assert_eq!(
            d,
            TrustDecision::Allow {
                peer_device_id: "dev-a".to_string(),
                peer_fingerprint: "aabbccdd".to_string()
            }
        );
    }
}
