//! Trusted issuers registry domain, network-free so any verifier can embed
//! it: [`model`] (records), [`registry`] (write rules and the
//! accreditation-chain trust check) and [`snapshot`] (the signed,
//! offline-cacheable trust list).

pub mod accreditation;
pub mod audit;
pub mod model;
pub mod registry;
pub mod snapshot;
pub mod x509;

pub use accreditation::{
    ACCREDITATION_TYP, AccreditationChain, AccreditationError, issue_accreditations,
    verify_accreditations,
};
pub use audit::{
    AuditAction, AuditEntry, AuditError, AuditRecord, GENESIS_HASH, verify_audit_chain,
};
pub use model::{ANY_CREDENTIAL_TYPE, IdKind, IssuerRecord, Role, Status};
pub use registry::{
    MAX_CHAIN_DEPTH, Registry, RegistryError, TrustDecision, canonical_did, canonical_id,
    is_credential_issuer_id, is_did_web_port, is_dns_name, is_port,
};
pub use snapshot::{
    SNAPSHOT_CLOCK_SKEW_SECS, SNAPSHOT_TYP, SnapshotError, SnapshotPayload, TrustList,
    sign_snapshot, snapshot_kid, verify_snapshot,
};
pub use x509::{MAX_ANCHOR_BYTES, MAX_ANCHORS_PER_RECORD, oid_der};
