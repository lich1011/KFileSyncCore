//! Pure data models (no behavior beyond construction and accessors).
//!
//! Each submodule corresponds to one aggregate root in the KFileSync domain.
//! These types are serializable so they can be persisted by the host or sent
//! over the wire by the protocol layer.

pub mod device;
pub mod file_entry;
pub mod pairing;
pub mod share;
pub mod transfer;
pub mod version_vector;

// Re-exports at the `domain::` level for convenience.
pub use device::{Device, DeviceId, DevicePlatform, DeviceState, DeviceType};
pub use file_entry::{BlockInfo, EntryType, FileEntry};
pub use pairing::{PairingSession, SecretPin};
pub use share::{Share, ShareId, SharePermission, ShareStatus, SyncMode};
pub use transfer::{Checkpoint, TransferDirection, TransferItem, TransferJob, TransferState};
pub use version_vector::VersionVector;
