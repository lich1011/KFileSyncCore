//! Pairing session state.
//!
//! # Sprint 5 implementation
//!
//! Currently a placeholder. Full implementation in Sprint 5.

use alloc::string::String;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper around a PIN string that zeroes its memory on drop and
/// redacts itself in `Debug`/`Display`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretPin(String);

impl SecretPin {
    /// Wrap a freshly-generated PIN.
    #[must_use]
    pub fn new(pin: String) -> Self {
        Self(pin)
    }

    /// Borrow the underlying string. Only use this when you actually need
    /// to compare or transmit the PIN - never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SecretPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretPin(***)")
    }
}

/// Pairing session, serializable so hosts can persist it across restarts.
///
/// See ADR-010 for the dual-PIN OOB protocol design.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingSession {
    /// Stable request identifier,
    pub request_id: String,
    /// The peer device we are pairing with,
    pub target_device_id: String,
    /// Our local PIN - shown to the user, transmitted OOB.
    pub our_pin: SecretPin,
    /// Their PIN, learned via OOB and entered by the user.
    /// `None` until the user types it in.
    pub expected_their_pin: Option<SecretPin>,
    /// Wall-clock expiry, millis since epoch.
    pub expires_at_ms: i64,
    /// Number of PIN attempts so far.
    pub attempts: u32,
    /// Maximum allowed attempts.
    pub max_attempts: u32,
}
