//! HTTP path constants for the lansync v1 protocol.
//!
//! All hosts (desktop and mobile) MUST reference these constants instead of
//! typing path strings.

/// Top-level prefix shared by every endpoint.
pub const API_PREFIX: &str = "/api/lansync/v1";

// --- Discovery ---

/// `GET` - return [`crate::protocol::dto::DeviceInfoDto`].
pub const INFO: &str = "/api/lansync/v1/info";

/// `GET` - liveness probe, returns `200 OK` with empty body.
pub const HEALTHZ: &str = "/api/lansync/v1/healthz";

/// `POST` - register self with a peer's discovery registry.
pub const REGISTER: &str = "/api/lansync/v1/register";

// --- Pairing ---

/// `POST` - initiate a pairing handshake.
pub const PAIR_REQUEST: &str = "/api/lansync/v1/pair/request";

/// `POST` - confirm pairing with a PIN and exchange certificates.
pub const PAIR_CONFIRM: &str = "/api/lansync/v1/pair/confirm";

/// `POST` - revoke an established pairing.
pub const PAIR_REVOKE: &str = "/api/lansync/v1/pair/revoke";

// --- Shares ---

/// `POST` - invite a paired peer to a share.
pub const SHARE_INVITE: &str = "/api/lansync/v1/share/invite";

/// `POST` - authorize an inbound share invitation.
pub const SHARE_AUTHORIZE: &str = "/api/lansync/v1/share/authorize";

/// `POST` - voluntarily leave a share.
pub const SHARE_LEAVE: &str = "/api/lansync/v1/share/leave";

// --- Sync ---

/// `GET` - fetch a share's file index.
pub const SYNC_INDEX: &str = "/api/lansync/v1/sync/index";

// --- Transfers ---

/// `POST` - propose a transfer job.
pub const TRANSFER_REQUEST: &str = "/api/lansync/v1/transfer/request";

/// `POST` - chunk upload. Full URL pattern:
/// `/api/lansync/v1/transfer/{job_id}/chunk/{file_id}/{chunk_index}`
///
/// Body is the raw chunk bytes; `X-Chunk-Hash` header carries the BLAKE3 hex.
pub const TRANSFER_CHUNK_PREFIX: &str = "/api/lansync/v1/transfer/";

/// `POST` - cancel an active transfer.
pub const TRANSFER_CANCEL: &str = "/api/lansync/v1/transfer/cancel";

// --- Defaults ---

/// Default HTTPS port for the lansync service.
pub const DEFAULT_PORT: u16 = 53317;

/// Routes that bypass the paired-device check (Rule 4 in the trust evaluator)
/// because the PIN ceremony is the real authenticator at this stage.
pub const BOOTSTRAP_ROUTES: &[&str] = &[PAIR_REQUEST, PAIR_CONFIRM, REGISTER];

/// True iff `route` is a bootstrap route (allowed without paired peer).
#[must_use]
pub fn is_bootstrap_route(route: &str) -> bool {
    BOOTSTRAP_ROUTES.contains(&route)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_routes_start_with_prefix() {
        let routes: &[&str; 12] = &[
            INFO,
            HEALTHZ,
            REGISTER,
            PAIR_REQUEST,
            PAIR_CONFIRM,
            PAIR_REVOKE,
            SHARE_INVITE,
            SHARE_AUTHORIZE,
            SHARE_LEAVE,
            SYNC_INDEX,
            TRANSFER_REQUEST,
            TRANSFER_CANCEL,
        ];
        for r in routes {
            assert!(r.starts_with(API_PREFIX), "{r} missing API_PREFIX");
        }
    }

    #[test]
    fn bootstrap_routes_recognized() {
        assert!(is_bootstrap_route(PAIR_REQUEST));
        assert!(is_bootstrap_route(PAIR_CONFIRM));
        assert!(!is_bootstrap_route(SYNC_INDEX));
        assert!(!is_bootstrap_route(TRANSFER_REQUEST));
    }
}
