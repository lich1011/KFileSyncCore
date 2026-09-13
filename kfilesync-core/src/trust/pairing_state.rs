//! Pairing state machine.
//!
//! Implements the dual-PIN OOB protocol - see ADR-010.
//!
//! # Sprint 5 implementation
//!
//! Both peers independently generate a PIN and display it to the user, who
//! reads each device's PIN and relays it to the other device (in person, or
//! over a trusted voice channel). This module does not generate randomness
//! itself - `our_pin`, `nonce`, and `request_id` are supplied by the host,
//! consistent with `service::nonce_window` (which likewise never generates
//! its own nonces). See ADR-010 for why.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::domain::{PairingSession, SecretPin};
use crate::protocol::codec::{self, EncodeError};
use crate::protocol::dto::{PairConfirmDto, PairRequestDto};
use crate::protocol::headers;
use crate::trust::cert_pin;

/// Outcome of verifying a PIN against a session's own generated PIN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinVerdict {
    /// PIN matched; pairing may proceed.
    Accepted,
    /// PIN was wrong but more attempts remain.
    Wrong,
    /// Session expired (TTL elapsed).
    Expired,
    /// Exceeded `max_attempts`.
    MaxAttemptsExceeded,
}

/// A fully-prepared outbound HTTP request: body bytes plus the headers a
/// host must attach. Core does not perform the HTTP call itself.
#[derive(Clone, Debug)]
pub struct PreparedRequest {
    /// Serialized JSON body (UTF-8 bytes).
    pub body: Vec<u8>,
    /// Headers to send with the request, including anti-replay headers.
    pub headers: Vec<(String, String)>,
}

fn anti_replay_headers(device_id: &str, timestamp_ms: i64, nonce: &str) -> Vec<(String, String)> {
    alloc::vec![
        (headers::HEADER_DEVICE_ID.to_string(), device_id.to_string()),
        (
            headers::HEADER_TIMESTAMP.to_string(),
            timestamp_ms.to_string()
        ),
        (headers::HEADER_NONCE.to_string(), nonce.to_string()),
    ]
}

/// Initiator side: start a new pairing session and prepare the
/// `POST /pair/request` body.
///
/// `our_pin`, `nonce`, and `request_id` are host-supplied (see module
/// docs) - typically a 6-digit PIN and a fresh random nonce/UUID from the
/// host's own CSPRNG.
#[allow(clippy::too_many_arguments)]
pub fn start_outbound(
    request_id: &str,
    nonce: &str,
    target_device_id: &str,
    from_device_id: &str,
    from_alias: &str,
    from_platform: &str,
    from_fingerprint_hex: &str,
    our_pin: SecretPin,
    max_attempts: u32,
    now_ms: i64,
    pin_ttl_ms: i64,
) -> Result<(PairingSession, PreparedRequest), EncodeError> {
    let expires_at_ms: i64 = now_ms + pin_ttl_ms;

    let session = PairingSession {
        request_id: request_id.to_string(),
        target_device_id: target_device_id.to_string(),
        our_pin,
        expected_their_pin: None,
        expires_at_ms,
        attempts: 0,
        max_attempts,
    };

    let dto = PairRequestDto {
        request_id: request_id.to_string(),
        from_device_id: from_device_id.to_string(),
        from_alias: from_alias.to_string(),
        from_platform: from_platform.to_string(),
        from_fingerprint: from_fingerprint_hex.to_string(),
        nonce: nonce.to_string(),
        expires_at_ms,
    };

    let body: Vec<u8> = codec::encode(&dto)?;
    let headers: Vec<(String, String)> = anti_replay_headers(from_device_id, now_ms, nonce);

    Ok((session, PreparedRequest { body, headers }))
}

/// Responder side: an inbound `PairRequestDto` has already passed
/// `trust::trust_evaluator::evaluate_inbound` (as `AllowUnpairedForPairing`)
/// by the time this is called. Creates a session tracking the initiator,
/// under the *same* `request_id` the initiator generated (so both sides'
/// sessions correlate without a second round-trip).
///
/// `our_pin` is again host-supplied.
#[must_use]
pub fn receive_incoming(
    incoming: &PairRequestDto,
    our_pin: SecretPin,
    max_attempts: u32,
    now_ms: i64,
    pin_ttl_ms: i64,
) -> PairingSession {
    PairingSession {
        request_id: incoming.request_id.clone(),
        target_device_id: incoming.from_device_id.clone(),
        our_pin,
        expected_their_pin: None,
        expires_at_ms: now_ms + pin_ttl_ms,
        attempts: 0,
        max_attempts,
    }
}

/// Record what the human read off the peer's screen and typed in locally.
/// This does not verify anything by itself - it only fills in the value
/// [`prepare_confirm`] needs to tell the peer "here is the PIN I saw on
/// your screen," so the peer can check it against their own ground truth.
pub fn record_peer_pin(session: &mut PairingSession, peer_pin_from_human: &str) {
    session.expected_their_pin = Some(SecretPin::new(peer_pin_from_human.to_string()));
}

/// Prepare the `POST /pair/confirm` body. `session.expected_their_pin`
/// must already be set via [`record_peer_pin`] - `None` means the host
/// asked before the human finished the OOB step, which is a caller bug,
/// not a runtime condition to recover from silently, so this returns
/// `None` rather than sending a confirm with an empty PIN.
pub fn prepare_confirm(
    session: &PairingSession,
    device_id: &str,
    timestamp_ms: i64,
    nonce: &str,
    certificate_pem: &str,
) -> Option<Result<PreparedRequest, EncodeError>> {
    let peer_pin: &SecretPin = session.expected_their_pin.as_ref()?;

    let dto = PairConfirmDto {
        request_id: session.request_id.clone(),
        pin: peer_pin.expose().to_string(),
        certificate_pem: certificate_pem.to_string(),
    };

    Some(codec::encode(&dto).map(|body: Vec<u8>| PreparedRequest {
        body,
        headers: anti_replay_headers(device_id, timestamp_ms, nonce),
    }))
}

/// Verify a PIN against this session's own generated PIN
/// (`session.our_pin`) - the ground truth only this device knows.
///
/// `provided_pin` is whatever value needs checking: extracted from an
/// incoming `PairConfirmDto::pin` when handling the peer's confirm
/// request, or typed directly by a human in a purely local UI flow. Core
/// treats both sources identically; only the *comparison* is its concern.
///
/// Uses constant-time comparison via [`cert_pin::verify_fingerprint_hex`]
/// (despite the name, it is a generic constant-time byte-equality check -
/// reused here rather than duplicated).
pub fn verify_peer_pin(
    session: &mut PairingSession,
    provided_pin: &str,
    now_ms: i64,
) -> PinVerdict {
    if now_ms > session.expires_at_ms {
        return PinVerdict::Expired;
    }
    if session.attempts >= session.max_attempts {
        return PinVerdict::MaxAttemptsExceeded;
    }

    session.attempts += 1;

    if cert_pin::verify_fingerprint_hex(provided_pin, session.our_pin.expose()) {
        PinVerdict::Accepted
    } else {
        PinVerdict::Wrong
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(our_pin: &str, max_attempts: u32, expires_at_ms: i64) -> PairingSession {
        PairingSession {
            request_id: "req-1".to_string(),
            target_device_id: "dev-b".to_string(),
            our_pin: SecretPin::new(our_pin.to_string()),
            expected_their_pin: None,
            expires_at_ms,
            attempts: 0,
            max_attempts,
        }
    }

    #[test]
    fn start_outbound_produces_a_session_and_a_valid_request_body() {
        let (session, req) = start_outbound(
            "req-1",
            "nonce-1",
            "dev-b",
            "dev-a",
            "Alice's Laptop",
            "macos",
            "abcd1234",
            SecretPin::new("482913".to_string()),
            3,
            1_000,
            300_000,
        )
        .unwrap();

        assert_eq!(session.request_id, "req-1");
        assert_eq!(session.target_device_id, "dev-b");
        assert_eq!(session.our_pin.expose(), "482913");
        assert_eq!(session.expires_at_ms, 301_000);
        assert_eq!(session.attempts, 0);
        assert!(session.expected_their_pin.is_none());

        let parsed: PairRequestDto = codec::parse(&req.body).unwrap();
        assert_eq!(parsed.request_id, "req-1");
        assert_eq!(parsed.from_device_id, "dev-a");
        assert_eq!(parsed.from_platform, "macos");
        assert_eq!(parsed.expires_at_ms, 301_000);

        let header_names: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(header_names.contains(&headers::HEADER_DEVICE_ID));
        assert!(header_names.contains(&headers::HEADER_TIMESTAMP));
        assert!(header_names.contains(&headers::HEADER_NONCE));
    }

    #[test]
    fn receive_incoming_correlates_via_the_same_request_id() {
        let incoming = PairRequestDto {
            request_id: "req-1".to_string(),
            from_device_id: "dev-a".to_string(),
            from_alias: "Alice".to_string(),
            from_platform: "macos".to_string(),
            from_fingerprint: "abcd1234".to_string(),
            nonce: "nonce-1".to_string(),
            expires_at_ms: 301_000,
        };

        let session = receive_incoming(
            &incoming,
            SecretPin::new("998877".to_string()),
            3,
            1_000,
            300_000,
        );

        assert_eq!(session.request_id, "req-1");
        assert_eq!(session.target_device_id, "dev-a");
        assert_eq!(session.our_pin.expose(), "998877");
        assert_eq!(session.expires_at_ms, 301_000);
    }

    #[test]
    fn correct_pin_is_accepted() {
        let mut s = session("482913", 3, 10_000);
        assert_eq!(
            verify_peer_pin(&mut s, "482913", 1_000),
            PinVerdict::Accepted
        );
        assert_eq!(s.attempts, 1);
    }

    #[test]
    fn wrong_pin_is_rejected_and_counts_as_an_attempt() {
        let mut s = session("482913", 3, 10_000);
        assert_eq!(verify_peer_pin(&mut s, "000000", 1_000), PinVerdict::Wrong);
        assert_eq!(s.attempts, 1);
    }

    #[test]
    fn expired_session_is_rejected_before_touching_attempts() {
        let mut s = session("482913", 3, 10_000);
        assert_eq!(
            verify_peer_pin(&mut s, "482913", 10_001),
            PinVerdict::Expired
        );
        assert_eq!(
            s.attempts, 0,
            "an expired check must not consume an attempt"
        );
    }

    #[test]
    fn exhausting_attempts_locks_out_further_tries_even_with_the_correct_pin() {
        let mut s = session("482913", 2, 10_000);
        assert_eq!(verify_peer_pin(&mut s, "wrong-1", 1_000), PinVerdict::Wrong);
        assert_eq!(verify_peer_pin(&mut s, "wrong-2", 1_000), PinVerdict::Wrong);
        // Third call: attempts (2) >= max_attempts (2), locked out - even
        // though this call finally supplies the right PIN.
        assert_eq!(
            verify_peer_pin(&mut s, "482913", 1_000),
            PinVerdict::MaxAttemptsExceeded
        );
    }

    #[test]
    fn record_and_prepare_confirm_round_trip() {
        let mut s = session("482913", 3, 10_000);
        assert!(prepare_confirm(&s, "dev-a", 1_000, "n2", "CERT").is_none());

        record_peer_pin(&mut s, "998877");
        assert_eq!(s.expected_their_pin.as_ref().unwrap().expose(), "998877");

        let req = prepare_confirm(&s, "dev-a", 1_000, "n2", "-----BEGIN CERT-----")
            .unwrap()
            .unwrap();

        let parsed: PairConfirmDto = codec::parse(&req.body).unwrap();
        assert_eq!(parsed.request_id, "req-1");
        assert_eq!(parsed.pin, "998877");
        assert_eq!(parsed.certificate_pem, "-----BEGIN CERT-----");
    }

    #[test]
    fn secret_pin_debug_never_leaks_the_value() {
        let pin = SecretPin::new("482913".to_string());
        let debug_output = alloc::format!("{pin:?}");
        assert!(!debug_output.contains("482913"));
    }

    #[test]
    fn pairing_session_serde_roundtrip_preserves_pin_values() {
        let mut s = session("482913", 3, 10_000);
        record_peer_pin(&mut s, "998877");

        let json = serde_json::to_string(&s).unwrap();
        let restored: PairingSession = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.our_pin.expose(), "482913");
        assert_eq!(restored.expected_their_pin.unwrap().expose(), "998877");
        assert_eq!(restored.request_id, s.request_id);
    }
}
