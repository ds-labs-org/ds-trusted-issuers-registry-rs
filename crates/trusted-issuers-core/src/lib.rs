//! Trusted issuers registry domain, network-free so any verifier can embed
//! it: [`model`] (records), [`registry`] (write rules and the
//! accreditation-chain trust check) and [`snapshot`] (the signed,
//! offline-cacheable trust list).

pub mod model;
pub mod registry;
pub mod snapshot;

pub use model::{ANY_CREDENTIAL_TYPE, IssuerRecord, Role, Status};
pub use registry::{MAX_CHAIN_DEPTH, Registry, RegistryError, TrustDecision, canonical_did};
pub use snapshot::{
    SNAPSHOT_TYP, SnapshotError, SnapshotPayload, TrustList, sign_snapshot, snapshot_kid,
    verify_snapshot,
};
