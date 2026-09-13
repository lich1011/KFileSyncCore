//! Policy enforcement: device trust * share status * membership * permission
//! * direction * sync-mode direction.
//!
//! # Sprint 3 implementation
//!
//! The unified implementation checks BOTH the desktop's `SyncMode` global
//! gate AND the mobile's `ShareStatus` check - see
//! `CROSS_VALIDATION_DESKTOP_MOBILE.md` §3.5 and ADR-013 for why the
//! function signature below differs from the illustrative one in
//! `CORE_DEVELOPMENT_PLAN.md` (an explicit `member_permission` parameter,
//! and `share` taken as `Option<&Share>`).

use crate::domain::{Device, DeviceState, Share, SharePermission, ShareStatus, SyncMode};

/// Direction of an attempted sync action, **from the peer's point of
/// view**: `Push` = peer sends data to us (we would receive); `Pull` =
/// peer requests data from us (we would send). See ADR-013.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncDirection {
    /// Peer -> us.
    Push,
    /// Us -> peer.
    Pull,
}

/// Decision returned by `evaluate_policy`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    /// Action permitted.
    Allowed,
    /// Peer is not in the paired trust set.
    DeviceNotPaired,
    /// Share does not exist on this device.
    ShareNotFound,
    /// Share is not in `Active` status (covers `Paused`, `Pending`, and
    /// `Left` alike - from a "may sync happen right now" standpoint they
    /// are all equally blocking; see ADR-013).
    SharePaused,
    /// Peer is not a member of this share.
    NotAMember,
    /// Member's permission forbids the requested direction.
    PermissionDeniedForDirection,
    /// Share-level `SyncMode` forbids the requested direction.
    SyncModeForbidsDirection,
}

/// Decide whether `peer` may perform `direction` on `share`.
///
/// Checks run in a fixed order, each with its own decision so the caller
/// can log or surface a specific, actionable reason:
///
/// 1. `peer.state == Paired`                                         -> else [`PolicyDecision::DeviceNotPaired`]
/// 2. `share` is `Some`                                              -> else [`PolicyDecision::ShareNotFound`]
/// 3. `share.status == Active`                                       -> else [`PolicyDecision::SharePaused`]
/// 4. `member_permission` is `Some`                                  -> else [`PolicyDecision::NotAMember`]
/// 5. permission allows `direction` (`ReadOnly` forbids `Push`)       -> else [`PolicyDecision::PermissionDeniedForDirection`]
/// 6. `share.sync_mode` allows `direction`                           -> else [`PolicyDecision::SyncModeForbidsDirection`]
/// 7. otherwise                                                      -> [`PolicyDecision::Allowed`]
///
/// `member_permission` is the permission the host has already looked up
/// for `peer` on this specific `share` (from its own `share_members`
/// storage - core does not own membership data, see ADR-013); pass `None`
/// if the peer has no membership row at all.
#[must_use]
pub fn evaluate_policy(
    peer: &Device,
    share: Option<&Share>,
    member_permission: Option<SharePermission>,
    direction: SyncDirection,
) -> PolicyDecision {
    if peer.state != DeviceState::Paired {
        return PolicyDecision::DeviceNotPaired;
    }

    let Some(share) = share else {
        return PolicyDecision::ShareNotFound;
    };

    if share.status != ShareStatus::Active {
        return PolicyDecision::SharePaused;
    }

    let Some(permission) = member_permission else {
        return PolicyDecision::NotAMember;
    };

    if permission == SharePermission::ReadOnly && direction == SyncDirection::Push {
        return PolicyDecision::PermissionDeniedForDirection;
    }

    let sync_mode_forbids: bool = matches!(
        (share.sync_mode, direction),
        (SyncMode::SendOnly, SyncDirection::Push) | (SyncMode::ReceiveOnly, SyncDirection::Pull)
    );
    if sync_mode_forbids {
        return PolicyDecision::SyncModeForbidsDirection;
    }

    PolicyDecision::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DeviceId, DevicePlatform, DeviceType, ShareId};

    fn device(state: DeviceState) -> Device {
        Device {
            id: DeviceId("dev-a".to_string()),
            alias: "Test Device".to_string(),
            device_type: DeviceType::Desktop,
            platform: DevicePlatform::Linux,
            state,
            cert_fingerprint_hex: None,
        }
    }

    fn share(sync_mode: SyncMode, status: ShareStatus) -> Share {
        Share {
            id: ShareId("share-1".to_string()),
            name: "Test Share".to_string(),
            sync_mode,
            default_permission: SharePermission::ReadWrite,
            status,
        }
    }

    #[test]
    fn unpaired_device_is_rejected_before_anything_else_is_checked() {
        let d = device(DeviceState::Discovered);
        let s = share(SyncMode::TwoWay, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Push
            ),
            PolicyDecision::DeviceNotPaired
        );
    }

    #[test]
    fn missing_share_is_rejected() {
        let d = device(DeviceState::Paired);
        assert_eq!(
            evaluate_policy(
                &d,
                None,
                Some(SharePermission::ReadWrite),
                SyncDirection::Push
            ),
            PolicyDecision::ShareNotFound
        );
    }

    #[test]
    fn paused_share_is_rejected() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::TwoWay, ShareStatus::Paused);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Push
            ),
            PolicyDecision::SharePaused
        );
    }

    #[test]
    fn pending_share_is_also_rejected_as_share_paused() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::TwoWay, ShareStatus::Pending);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Pull
            ),
            PolicyDecision::SharePaused
        );
    }

    #[test]
    fn non_member_is_rejected() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::TwoWay, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(&d, Some(&s), None, SyncDirection::Push),
            PolicyDecision::NotAMember
        );
    }

    #[test]
    fn read_only_member_cannot_push() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::TwoWay, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadOnly),
                SyncDirection::Push
            ),
            PolicyDecision::PermissionDeniedForDirection
        );
    }

    #[test]
    fn read_only_member_can_pull() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::TwoWay, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadOnly),
                SyncDirection::Pull
            ),
            PolicyDecision::Allowed
        );
    }

    #[test]
    fn send_only_share_rejects_peer_push() {
        // SendOnly: this share only ever sends out; an inbound push from a
        // peer (which would mean we receive) must be rejected.
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::SendOnly, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Push
            ),
            PolicyDecision::SyncModeForbidsDirection
        );
    }

    #[test]
    fn send_only_share_allows_peer_pull() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::SendOnly, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Pull
            ),
            PolicyDecision::Allowed
        );
    }

    #[test]
    fn receive_only_share_rejects_peer_pull() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::ReceiveOnly, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Pull
            ),
            PolicyDecision::SyncModeForbidsDirection
        );
    }

    #[test]
    fn receive_only_share_allows_peer_push() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::ReceiveOnly, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Push
            ),
            PolicyDecision::Allowed
        );
    }

    #[test]
    fn two_way_active_read_write_member_is_allowed_both_directions() {
        let d = device(DeviceState::Paired);
        let s = share(SyncMode::TwoWay, ShareStatus::Active);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Push
            ),
            PolicyDecision::Allowed
        );
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadWrite),
                SyncDirection::Pull
            ),
            PolicyDecision::Allowed
        );
    }

    #[test]
    fn checks_run_in_priority_order_not_all_at_once() {
        // An unpaired device with a read-only permission on a paused share
        // must report DeviceNotPaired, not any of the later-stage reasons -
        // this pins the check ordering documented on `evaluate_policy`.
        let d = device(DeviceState::Revoked);
        let s = share(SyncMode::SendOnly, ShareStatus::Paused);
        assert_eq!(
            evaluate_policy(
                &d,
                Some(&s),
                Some(SharePermission::ReadOnly),
                SyncDirection::Push
            ),
            PolicyDecision::DeviceNotPaired
        );
    }
}
