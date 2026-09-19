//! UniFFI scaffolding.
//!
//! This module is only compiled when the `ffi` feature is enabled. It is
//! the **only** place where `unsafe` may appear (UniFFI generates `unsafe`
//! code for FFI boundary marshalling) - `uniffi::setup_scaffolding!()` is
//! invoked separately at crate-root scope in `lib.rs` (see the comment
//! there for why).
//!
//! Pure, stateless core functions are exported directly with
//! `#[cfg_attr(feature = "ffi", uniffi::export)]` attributes at their
//! original definitions in `domain/`, `service/`, `trust/`, and `crypto/`.
//! This module holds only the FFI-specific glue that has no natural home
//! in the sans-io core: version metadata, and `uniffi::Object` wrappers
//! around the crate's few genuinely stateful, `&mut`-based APIs.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use parking_lot::Mutex;

use crate::domain::PairingSession;
use crate::service::nonce_window::{self, NonceWindowState};
use crate::trust::pairing_state;
use crate::trust::trust_evaluator::{PairedDeviceEntry, PairedDeviceSet, RequestMeta};

/// The wire protocol version this core implements.
#[uniffi::export]
pub fn protocol_version() -> String {
    crate::PROTOCOL_VERSION.into()
}

/// The library version, matching `Cargo.toml`.
#[uniffi::export]
pub fn core_version() -> String {
    crate::CORE_VERSION.into()
}

/// FFI mirror of [`crate::trust::trust_evaluator::TrustDecision`].
///
/// The core type carries a `&'static str` `error_code` field, which cannot
/// cross the FFI boundary; this mirror owns the string instead.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum FfiTrustDecision {
    /// Request is from a paired device - allow.
    Allow {
        /// The peer's device ID.
        peer_device_id: String,
        /// The peer's certificate fingerprint.
        peer_fingerprint: String,
    },
    /// Request is from an unpaired device, but the route allows pairing.
    AllowUnpairedForPairing,
    /// Request is rejected.
    Reject {
        /// HTTP status code to return.
        http_status: u16,
        /// Machine-readable error code.
        error_code: String,
        /// Human-readable reason (not for display to end users).
        reason: String,
    },
}

impl From<crate::trust::trust_evaluator::TrustDecision> for FfiTrustDecision {
    fn from(decision: crate::trust::trust_evaluator::TrustDecision) -> Self {
        use crate::trust::trust_evaluator::TrustDecision;
        match decision {
            TrustDecision::Allow {
                peer_device_id,
                peer_fingerprint,
            } => Self::Allow {
                peer_device_id,
                peer_fingerprint,
            },
            TrustDecision::AllowUnpairedForPairing => Self::AllowUnpairedForPairing,
            TrustDecision::Reject {
                http_status,
                error_code,
                reason,
            } => Self::Reject {
                http_status,
                error_code: error_code.into(),
                reason,
            },
        }
    }
}

/// FFI-visible wrapper around [`NonceWindowState`].
///
/// The core state type is mutated in place via `&mut` parameters by design
/// (see `service::mod` docs); this object gives hosts a handle they can
/// hold and mutate through method calls instead.
#[derive(uniffi::Object, Default)]
pub struct FfiNonceWindowState {
    inner: Mutex<NonceWindowState>,
}

#[uniffi::export]
impl FfiNonceWindowState {
    /// Construct an empty nonce-replay window.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Evaluate trust for one inbound request, consulting and updating this
    /// nonce window as needed.
    #[must_use]
    pub fn evaluate_inbound(
        &self,
        request_meta: &RequestMeta,
        paired_devices: Vec<PairedDeviceEntry>,
        clock_now_ms: i64,
        window_size_ms: i64,
        clock_skew_ms: i64,
    ) -> FfiTrustDecision {
        let paired = PairedDeviceSet::new(paired_devices);
        let mut state = self.inner.lock();
        crate::trust::trust_evaluator::evaluate_inbound(
            request_meta,
            &paired,
            &mut state,
            clock_now_ms,
            window_size_ms,
            clock_skew_ms,
        )
        .into()
    }

    /// Remove expired nonce entries older than `window_size_ms` relative to
    /// `now_ms`. Returns the number of entries removed.
    pub fn prune_expired(&self, now_ms: i64, window_size_ms: i64) -> u64 {
        let mut state = self.inner.lock();
        nonce_window::prune_expired(&mut state, now_ms, window_size_ms) as u64
    }

    /// Forget all nonce history for one device (e.g. on revoke).
    pub fn clear_device(&self, device_id: &str) {
        let mut state = self.inner.lock();
        nonce_window::clear_device(&mut state, device_id);
    }
}

/// FFI-visible wrapper around [`PairingSession`].
///
/// Wraps the mutating pairing-state operations (`record_peer_pin`,
/// `verify_peer_pin`) behind a handle, since the core functions take
/// `&mut PairingSession` by design.
#[derive(uniffi::Object)]
pub struct FfiPairingSession {
    inner: Mutex<PairingSession>,
}

#[uniffi::export]
impl FfiPairingSession {
    /// Wrap an existing session (e.g. one produced by `start_outbound` or
    /// `receive_incoming`).
    #[uniffi::constructor]
    #[must_use]
    pub fn new(session: PairingSession) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(session),
        })
    }

    /// Snapshot the current session state.
    #[must_use]
    pub fn snapshot(&self) -> PairingSession {
        self.inner.lock().clone()
    }

    /// Record the peer's PIN as entered by the human user.
    pub fn record_peer_pin(&self, peer_pin_from_human: &str) {
        let mut session = self.inner.lock();
        pairing_state::record_peer_pin(&mut session, peer_pin_from_human);
    }

    /// Verify a candidate PIN against the expected value, tracking attempts.
    #[must_use]
    pub fn verify_peer_pin(&self, provided_pin: &str, now_ms: i64) -> pairing_state::PinVerdict {
        let mut session = self.inner.lock();
        pairing_state::verify_peer_pin(&mut session, provided_pin, now_ms)
    }
}