//! The audit log: one [`AuditEntry`] per successful write, recording who
//! changed which record, how, and what it looked like before and after.
//!
//! Entries form a hash chain. Each one carries the SHA-256 of its own
//! content ([`AuditEntry::hash`]) and the hash of the entry before it
//! ([`AuditEntry::prev_hash`], [`GENESIS_HASH`] for the first), so editing,
//! inserting or removing a past entry breaks every link after it and
//! [`verify_audit_chain`] reports where. The chain makes tampering
//! detectable, not impossible: whoever can rewrite the whole log can
//! recompute it, so keep a copy of a recent head (`seq`, `hash`) elsewhere
//! if that matters.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::IssuerRecord;

/// `prev_hash` of the first entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What a write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// `PUT`: a record was created (`before` is `None`) or replaced.
    Put,
    /// `PATCH .../status`: only the status changed.
    Status,
    /// `DELETE`: the record was removed (`after` is `None`).
    Delete,
}

/// One write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// 1 for the first entry, then one more per entry.
    pub seq: u64,
    /// Unix seconds.
    pub at: u64,
    /// Who made the write, as the admin API saw it.
    pub actor: String,
    pub action: AuditAction,
    /// The record written, in canonical form.
    pub id: String,
    #[serde(default)]
    pub before: Option<IssuerRecord>,
    #[serde(default)]
    pub after: Option<IssuerRecord>,
    /// The registry's `version` after the write.
    pub version: u64,
    /// Hex SHA-256 of the previous entry, [`GENESIS_HASH`] for the first.
    pub prev_hash: String,
    /// Hex SHA-256 of this entry with `hash` itself left empty.
    pub hash: String,
}

/// The parts of an entry the writer supplies; [`AuditEntry::next`] adds the
/// chain fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub at: u64,
    pub actor: String,
    pub action: AuditAction,
    pub id: String,
    pub before: Option<IssuerRecord>,
    pub after: Option<IssuerRecord>,
    pub version: u64,
}

impl AuditEntry {
    /// The entry that follows `prev` (or starts the chain), with `seq`,
    /// `prev_hash` and `hash` filled in.
    pub fn next(prev: Option<&AuditEntry>, record: AuditRecord) -> AuditEntry {
        let _ = (prev, record);
        todo!()
    }

    /// What [`AuditEntry::hash`] should be for this entry's content.
    pub fn expected_hash(&self) -> String {
        String::new()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit entry {seq}: its hash does not match its content")]
    BadHash { seq: u64 },
    #[error("audit entry {seq}: it does not follow entry {prev} (seq or prev_hash)")]
    BrokenLink { seq: u64, prev: u64 },
    #[error("audit entry 1 does not start the chain (prev_hash is not the genesis hash)")]
    BadGenesis,
}

/// Checks that `entries` are a well-formed stretch of the chain: every hash
/// matches its entry, each entry follows the one before it (`seq` one
/// higher, `prev_hash` its hash), and an entry with `seq` 1 starts from
/// [`GENESIS_HASH`]. A page that starts later is checked from its first
/// entry on.
pub fn verify_audit_chain(entries: &[AuditEntry]) -> Result<(), AuditError> {
    let _ = entries;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Role, Status};

    fn rec(id: &str, status: Status) -> IssuerRecord {
        IssuerRecord {
            id: id.into(),
            role: Role::Ti,
            name: None,
            credential_types: vec!["MembershipCredential".into()],
            accredited_by: Some("did:web:authority.example".into()),
            valid_from: None,
            valid_until: None,
            status,
            updated_at: 7,
        }
    }

    fn chain() -> Vec<AuditEntry> {
        let first = AuditEntry::next(
            None,
            AuditRecord {
                at: 10,
                actor: "admin".into(),
                action: AuditAction::Put,
                id: "did:web:issuer.example".into(),
                before: None,
                after: Some(rec("did:web:issuer.example", Status::Active)),
                version: 1,
            },
        );
        let second = AuditEntry::next(
            Some(&first),
            AuditRecord {
                at: 11,
                actor: "alice@authority.example".into(),
                action: AuditAction::Status,
                id: "did:web:issuer.example".into(),
                before: Some(rec("did:web:issuer.example", Status::Active)),
                after: Some(rec("did:web:issuer.example", Status::Suspended)),
                version: 2,
            },
        );
        vec![first, second]
    }

    #[test]
    fn entries_are_chained_by_hash() {
        let c = chain();
        assert_eq!((c[0].seq, c[1].seq), (1, 2));
        assert_eq!(c[0].prev_hash, GENESIS_HASH);
        assert_eq!(c[1].prev_hash, c[0].hash);
        assert_eq!(c[0].hash.len(), 64);
        assert!(c[0].hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(c[0].hash, c[1].hash);
        assert_eq!(verify_audit_chain(&c), Ok(()));
        // A page that starts later verifies from its first entry.
        assert_eq!(verify_audit_chain(&c[1..]), Ok(()));
    }

    #[test]
    fn the_hash_survives_a_json_round_trip() {
        let c = chain();
        let json = serde_json::to_string(&c).unwrap();
        let back: Vec<AuditEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
        assert_eq!(verify_audit_chain(&back), Ok(()));
    }

    #[test]
    fn tampering_is_detected() {
        let mut c = chain();
        c[1].actor = "mallory".into();
        assert_eq!(verify_audit_chain(&c), Err(AuditError::BadHash { seq: 2 }));

        // Rewriting an entry and its own hash still breaks the next link.
        let mut c = chain();
        c[0].actor = "mallory".into();
        c[0].hash = c[0].expected_hash();
        assert_eq!(
            verify_audit_chain(&c),
            Err(AuditError::BrokenLink { seq: 2, prev: 1 })
        );

        // Dropping an entry breaks the sequence.
        let c = chain();
        let third = AuditEntry::next(
            Some(&c[1]),
            AuditRecord {
                at: 12,
                actor: "admin".into(),
                action: AuditAction::Delete,
                id: "did:web:issuer.example".into(),
                before: Some(rec("did:web:issuer.example", Status::Suspended)),
                after: None,
                version: 3,
            },
        );
        assert_eq!(
            verify_audit_chain(&[c[0].clone(), third]),
            Err(AuditError::BrokenLink { seq: 3, prev: 1 })
        );

        let mut c = chain();
        c[0].prev_hash = c[1].hash.clone();
        c[0].hash = c[0].expected_hash();
        assert_eq!(verify_audit_chain(&c[..1]), Err(AuditError::BadGenesis));
    }
}
