//! The registry itself: a DID-keyed set of [`IssuerRecord`]s, the
//! write-time rules that keep it consistent, and the read-time trust check
//! that walks an issuer's accreditation chain up to a Root TAO.
//!
//! The write-time rules alone are not enough: a TAO can be suspended,
//! expire, or have its scope narrowed after it accredited someone, so
//! [`Registry::check`] re-validates every link on every call instead of
//! trusting what was true when the child was written.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{ANY_CREDENTIAL_TYPE, IssuerRecord, Role, Status};

/// Longest accreditation chain [`Registry::check`] will walk, root
/// included. Real chains are 2-3 links; the cap only bounds a malformed
/// (e.g. imported) registry.
pub const MAX_CHAIN_DEPTH: usize = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("'{0}' is not a DID")]
    InvalidDid(String),
    #[error("credentialTypes must list at least one non-empty type")]
    NoCredentialTypes,
    #[error("only a root_tao may use the '*' credential type")]
    WildcardNotAllowed,
    #[error("validFrom must be before validUntil")]
    InvalidValidity,
    #[error("a root_tao must not have accreditedBy")]
    RootWithAccreditor,
    #[error("a {0:?} record needs accreditedBy")]
    MissingAccreditor(Role),
    #[error("accreditor '{0}' is not in the registry")]
    UnknownAccreditor(String),
    #[error("accreditor '{0}' is a trusted issuer and cannot accredit others")]
    AccreditorCannotAccredit(String),
    #[error("accreditor '{accreditor}' is not scoped for credential type '{credential_type}'")]
    AccreditorScope {
        accreditor: String,
        credential_type: String,
    },
    #[error("accreditedBy '{0}' would create an accreditation cycle")]
    Cycle(String),
    #[error("the accreditation chain would be longer than {MAX_CHAIN_DEPTH} links")]
    ChainTooLong,
    #[error("'{0}' is listed more than once")]
    Duplicate(String),
    #[error("'{did}' still accredits {dependents:?}; reassign or remove them first")]
    HasDependents {
        did: String,
        dependents: Vec<String>,
    },
    #[error("'{0}' is not in the registry")]
    NotFound(String),
}

/// Outcome of [`Registry::check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustDecision {
    pub trusted: bool,
    /// The DIDs walked, starting at the issuer. On success it ends at a
    /// Root TAO; on failure it ends at the link that failed.
    pub chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl TrustDecision {
    fn deny(chain: Vec<String>, reason: impl Into<String>) -> Self {
        Self {
            trusted: false,
            chain,
            reason: Some(reason.into()),
        }
    }
}

/// The registry contents. `version` increases by one on every successful
/// write, so a verifier holding a snapshot can tell whether it is stale.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub version: u64,
    #[serde(with = "records_as_list", default)]
    pub issuers: BTreeMap<String, IssuerRecord>,
}

impl Registry {
    pub fn get(&self, did: &str) -> Option<&IssuerRecord> {
        self.issuers.get(&canonical_did(did))
    }

    pub fn list(&self) -> impl Iterator<Item = &IssuerRecord> {
        self.issuers.values()
    }

    /// DIDs of the records whose `accredited_by` is `did`.
    pub fn dependents_of(&self, did: &str) -> Vec<String> {
        let did = canonical_did(did);
        self.issuers
            .values()
            .filter(|r| r.accredited_by.as_deref() == Some(did.as_str()))
            .map(|r| r.did.clone())
            .collect()
    }

    /// Inserts or replaces a record after validating it against the
    /// registry's current contents. `now` becomes its `updated_at`. The
    /// record's `did` and `accredited_by` are stored in [`canonical_did`]
    /// form, so a rewrite in another spelling replaces instead of
    /// duplicating.
    pub fn upsert(&mut self, mut record: IssuerRecord, now: u64) -> Result<(), RegistryError> {
        canonicalize(&mut record);
        self.validate(&record)?;
        record.updated_at = now;
        self.issuers.insert(record.did.clone(), record);
        self.version += 1;
        Ok(())
    }

    /// Changes only a record's status. Suspending or revoking a TAO
    /// immediately distrusts everything it accredited, via
    /// [`Registry::check`].
    pub fn set_status(&mut self, did: &str, status: Status, now: u64) -> Result<(), RegistryError> {
        let did = canonical_did(did);
        let record = self
            .issuers
            .get_mut(&did)
            .ok_or(RegistryError::NotFound(did))?;
        record.status = status;
        record.updated_at = now;
        self.version += 1;
        Ok(())
    }

    /// Removes a record. Refused while other records name it as their
    /// accreditor, so a removal never leaves a dangling `accreditedBy`.
    pub fn remove(&mut self, did: &str) -> Result<IssuerRecord, RegistryError> {
        let did = canonical_did(did);
        let dependents = self.dependents_of(&did);
        if !dependents.is_empty() {
            return Err(RegistryError::HasDependents { did, dependents });
        }
        let removed = self
            .issuers
            .remove(&did)
            .ok_or(RegistryError::NotFound(did))?;
        self.version += 1;
        Ok(removed)
    }

    /// Longest line of records below `did` (0 when nothing names it as
    /// accreditor). Stops counting past [`MAX_CHAIN_DEPTH`].
    fn descendant_height(&self, did: &str, depth: usize) -> usize {
        if depth > MAX_CHAIN_DEPTH {
            return depth;
        }
        self.issuers
            .values()
            .filter(|r| r.accredited_by.as_deref() == Some(did))
            .map(|r| 1 + self.descendant_height(&r.did, depth + 1))
            .max()
            .unwrap_or(0)
    }

    /// Re-applies every write rule to a registry that did not come through
    /// [`Registry::upsert`] (a data file loaded from disk, a snapshot),
    /// inserting accreditors before the records they accredit. Keeps
    /// `version` and each record's `updated_at`. Records are brought to
    /// [`canonical_did`] form first, and two that collapse to the same DID
    /// are refused as [`RegistryError::Duplicate`] rather than one silently
    /// shadowing the other.
    pub fn revalidated(self) -> Result<Registry, RegistryError> {
        let mut out = Registry {
            version: self.version,
            issuers: BTreeMap::new(),
        };
        let mut pending: Vec<IssuerRecord> = Vec::with_capacity(self.issuers.len());
        let mut seen = BTreeSet::new();
        for mut record in self.issuers.into_values() {
            canonicalize(&mut record);
            if !seen.insert(record.did.clone()) {
                return Err(RegistryError::Duplicate(record.did));
            }
            pending.push(record);
        }
        while !pending.is_empty() {
            let (ready, rest): (Vec<_>, Vec<_>) = pending.into_iter().partition(|r| {
                r.accredited_by
                    .as_deref()
                    .is_none_or(|a| out.issuers.contains_key(a))
            });
            if ready.is_empty() {
                // Whatever is left points at a missing accreditor or forms
                // a cycle; `validate` names the first problem.
                let first = &rest[0];
                return Err(out.validate(first).err().unwrap_or_else(|| {
                    RegistryError::UnknownAccreditor(
                        first.accredited_by.clone().unwrap_or_default(),
                    )
                }));
            }
            for record in ready {
                out.validate(&record)?;
                out.issuers.insert(record.did.clone(), record);
            }
            pending = rest;
        }
        Ok(out)
    }

    fn validate(&self, record: &IssuerRecord) -> Result<(), RegistryError> {
        if !is_did(&record.did) {
            return Err(RegistryError::InvalidDid(record.did.clone()));
        }
        if record.credential_types.is_empty()
            || record.credential_types.iter().any(String::is_empty)
        {
            return Err(RegistryError::NoCredentialTypes);
        }
        if record.role != Role::RootTao
            && record
                .credential_types
                .iter()
                .any(|t| t == ANY_CREDENTIAL_TYPE)
        {
            return Err(RegistryError::WildcardNotAllowed);
        }
        if let (Some(from), Some(until)) = (record.valid_from, record.valid_until)
            && from >= until
        {
            return Err(RegistryError::InvalidValidity);
        }
        // A record that still accredits others must keep the ability to.
        if !record.role.can_accredit() {
            let dependents = self.dependents_of(&record.did);
            if !dependents.is_empty() {
                return Err(RegistryError::HasDependents {
                    did: record.did.clone(),
                    dependents,
                });
            }
        }

        match (&record.role, &record.accredited_by) {
            (Role::RootTao, None) => Ok(()),
            (Role::RootTao, Some(_)) => Err(RegistryError::RootWithAccreditor),
            (role, None) => Err(RegistryError::MissingAccreditor(*role)),
            (_, Some(accreditor_did)) => {
                if accreditor_did == &record.did {
                    return Err(RegistryError::Cycle(accreditor_did.clone()));
                }
                let accreditor = self
                    .issuers
                    .get(accreditor_did)
                    .ok_or_else(|| RegistryError::UnknownAccreditor(accreditor_did.clone()))?;
                if !accreditor.role.can_accredit() {
                    return Err(RegistryError::AccreditorCannotAccredit(
                        accreditor_did.clone(),
                    ));
                }
                if let Some(t) = record
                    .credential_types
                    .iter()
                    .find(|t| !accreditor.covers(t))
                {
                    return Err(RegistryError::AccreditorScope {
                        accreditor: accreditor_did.clone(),
                        credential_type: t.clone(),
                    });
                }
                // Walk up from the accreditor; reaching this record again
                // means the update would close a loop.
                let mut seen = BTreeSet::new();
                let mut cursor = Some(accreditor);
                while let Some(current) = cursor {
                    if current.did == record.did || !seen.insert(current.did.as_str()) {
                        return Err(RegistryError::Cycle(accreditor_did.clone()));
                    }
                    cursor = current
                        .accredited_by
                        .as_deref()
                        .and_then(|d| self.issuers.get(d));
                }
                // Refuse chains `check` would always reject: this record's
                // ancestors, itself, and its longest line of descendants.
                if seen.len() + 1 + self.descendant_height(&record.did, 0) > MAX_CHAIN_DEPTH {
                    return Err(RegistryError::ChainTooLong);
                }
                Ok(())
            }
        }
    }

    /// Whether `did` may issue a credential of `credential_type` at `now`
    /// (unix seconds): the issuer and every accreditor up to a Root TAO
    /// must be listed, `Active`, inside their validity window, and scoped
    /// for the type.
    pub fn check(&self, did: &str, credential_type: &str, now: u64) -> TrustDecision {
        let mut chain = Vec::new();
        let mut cursor = canonical_did(did);
        loop {
            chain.push(cursor.clone());
            if chain.len() > MAX_CHAIN_DEPTH {
                return TrustDecision::deny(chain, "accreditation chain is too long");
            }
            let Some(record) = self.issuers.get(&cursor) else {
                return TrustDecision::deny(chain, format!("'{cursor}' is not in the registry"));
            };
            if chain.len() > 1 && !record.role.can_accredit() {
                return TrustDecision::deny(
                    chain,
                    format!("'{cursor}' is a trusted issuer and cannot accredit others"),
                );
            }
            if !record.is_usable_at(now) {
                return TrustDecision::deny(
                    chain,
                    format!("'{cursor}' is not active or outside its validity period"),
                );
            }
            if !record.covers(credential_type) {
                return TrustDecision::deny(
                    chain,
                    format!("'{cursor}' is not scoped for credential type '{credential_type}'"),
                );
            }
            match (&record.role, &record.accredited_by) {
                (Role::RootTao, _) => {
                    return TrustDecision {
                        trusted: true,
                        chain,
                        reason: None,
                    };
                }
                (_, Some(next)) => {
                    if chain.contains(next) {
                        return TrustDecision::deny(chain, "accreditation chain has a cycle");
                    }
                    cursor = next.clone();
                }
                (_, None) => {
                    return TrustDecision::deny(
                        chain,
                        format!("'{cursor}' has no accreditor and is not a root_tao"),
                    );
                }
            }
        }
    }
}

/// The canonical spelling of `did`, which is what the registry stores and
/// looks up by.
///
/// Matching is by exact string, but `did:web` resolution is not: DNS hosts
/// are case-insensitive and percent-escapes (`%3a` vs `%3A`, the port
/// separator) are the same byte either way. Without one spelling, a record
/// written as `did:web:Issuer.example` would never match a credential whose
/// issuer says `did:web:issuer.example`, silently distrusting a listed
/// issuer. So for `did:web` the host (first segment) is lowercased and every
/// percent-escape's hex digits are uppercased. Path segments keep their case
/// because servers treat paths as case-sensitive. Other methods define their
/// own equivalence, so they are returned unchanged.
pub fn canonical_did(did: &str) -> String {
    let Some(rest) = did.strip_prefix("did:web:") else {
        return did.to_string();
    };
    let segments: Vec<String> = rest
        .split(':')
        .enumerate()
        .map(|(i, segment)| {
            if i == 0 {
                uppercase_escapes(&segment.to_ascii_lowercase())
            } else {
                uppercase_escapes(segment)
            }
        })
        .collect();
    format!("did:web:{}", segments.join(":"))
}

/// Puts a record's DID references in [`canonical_did`] form.
fn canonicalize(record: &mut IssuerRecord) {
    record.did = canonical_did(&record.did);
    record.accredited_by = record.accredited_by.as_deref().map(canonical_did);
}

/// Uppercases the two hex digits of every `%xx` escape in `s`.
fn uppercase_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push(bytes[i + 1].to_ascii_uppercase() as char);
            out.push(bytes[i + 2].to_ascii_uppercase() as char);
            i += 3;
        } else {
            // Not an escape: copy the whole char (`i` is on a boundary).
            let c = s[i..].chars().next().expect("i < len");
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// `did:<method>:<method-specific-id>`, both parts non-empty.
fn is_did(s: &str) -> bool {
    let mut parts = s.splitn(3, ':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("did"), Some(method), Some(id))
            if !method.is_empty()
                && method.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && !id.is_empty()
    )
}

/// Serializes the DID-keyed map as a plain array of records (the DID is
/// already inside each record), which is the shape the API and the
/// snapshot expose.
mod records_as_list {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serializer};

    use crate::model::IssuerRecord;

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<String, IssuerRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(map.values())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, IssuerRecord>, D::Error> {
        let list = Vec::<IssuerRecord>::deserialize(deserializer)?;
        let mut map = BTreeMap::new();
        for record in list {
            if map.contains_key(&record.did) {
                return Err(serde::de::Error::custom(format!(
                    "'{}' is listed more than once",
                    record.did
                )));
            }
            map.insert(record.did.clone(), record);
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "did:web:authority.example";
    const TAO: &str = "did:web:tao.example";
    const TI: &str = "did:web:issuer.example";

    fn record(did: &str, role: Role, types: &[&str], by: Option<&str>) -> IssuerRecord {
        IssuerRecord {
            did: did.into(),
            role,
            name: None,
            credential_types: types.iter().map(|t| t.to_string()).collect(),
            accredited_by: by.map(Into::into),
            valid_from: None,
            valid_until: None,
            status: Status::Active,
            updated_at: 0,
        }
    }

    fn three_tier() -> Registry {
        let mut r = Registry::default();
        r.upsert(record(ROOT, Role::RootTao, &["*"], None), 1)
            .unwrap();
        r.upsert(
            record(
                TAO,
                Role::Tao,
                &["MembershipCredential", "DataProcessorCredential"],
                Some(ROOT),
            ),
            1,
        )
        .unwrap();
        r.upsert(
            record(TI, Role::Ti, &["MembershipCredential"], Some(TAO)),
            1,
        )
        .unwrap();
        r
    }

    #[test]
    fn full_chain_is_trusted() {
        let r = three_tier();
        let d = r.check(TI, "MembershipCredential", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec![TI, TAO, ROOT]);
        assert_eq!(r.version, 3);
    }

    #[test]
    fn type_outside_issuer_scope_is_denied() {
        let d = three_tier().check(TI, "DataProcessorCredential", 10);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![TI]);
    }

    #[test]
    fn unknown_issuer_is_denied() {
        assert!(
            !three_tier()
                .check("did:web:nobody.example", "MembershipCredential", 10)
                .trusted
        );
    }

    #[test]
    fn suspending_an_accreditor_distrusts_its_issuers() {
        let mut r = three_tier();
        r.set_status(TAO, Status::Suspended, 5).unwrap();
        let d = r.check(TI, "MembershipCredential", 10);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![TI, TAO]);
        r.set_status(TAO, Status::Active, 6).unwrap();
        assert!(r.check(TI, "MembershipCredential", 10).trusted);
    }

    #[test]
    fn validity_window_is_enforced() {
        let mut r = three_tier();
        let mut ti = r.get(TI).unwrap().clone();
        ti.valid_from = Some(100);
        ti.valid_until = Some(200);
        r.upsert(ti, 2).unwrap();
        assert!(!r.check(TI, "MembershipCredential", 99).trusted);
        assert!(r.check(TI, "MembershipCredential", 100).trusted);
        assert!(!r.check(TI, "MembershipCredential", 200).trusted);
    }

    #[test]
    fn narrowing_an_accreditor_scope_is_rechecked_at_read_time() {
        let mut r = three_tier();
        r.upsert(
            record(TAO, Role::Tao, &["DataProcessorCredential"], Some(ROOT)),
            2,
        )
        .unwrap();
        let d = r.check(TI, "MembershipCredential", 10);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![TI, TAO]);
    }

    #[test]
    fn write_rules() {
        let mut r = three_tier();
        assert_eq!(
            r.upsert(record(ROOT, Role::RootTao, &["*"], Some(TAO)), 2),
            Err(RegistryError::RootWithAccreditor)
        );
        assert_eq!(
            r.upsert(record("did:web:x.example", Role::Ti, &["A"], None), 2),
            Err(RegistryError::MissingAccreditor(Role::Ti))
        );
        assert_eq!(
            r.upsert(record("did:web:x.example", Role::Ti, &["*"], Some(ROOT)), 2),
            Err(RegistryError::WildcardNotAllowed)
        );
        assert_eq!(
            r.upsert(record("did:web:x.example", Role::Ti, &["A"], Some(TI)), 2),
            Err(RegistryError::AccreditorCannotAccredit(TI.into()))
        );
        assert!(matches!(
            r.upsert(
                record("did:web:x.example", Role::Ti, &["Other"], Some(TAO)),
                2
            ),
            Err(RegistryError::AccreditorScope { .. })
        ));
        assert_eq!(
            r.upsert(record("not-a-did", Role::Ti, &["A"], Some(ROOT)), 2),
            Err(RegistryError::InvalidDid("not-a-did".into()))
        );
        // Demoting a TAO that still accredits someone would orphan them.
        assert!(matches!(
            r.upsert(
                record(TAO, Role::Ti, &["MembershipCredential"], Some(ROOT)),
                2
            ),
            Err(RegistryError::HasDependents { .. })
        ));
        assert!(matches!(
            r.remove(TAO),
            Err(RegistryError::HasDependents { .. })
        ));
        assert_eq!(r.version, 3, "failed writes must not bump the version");
    }

    #[test]
    fn cycles_are_refused() {
        let mut r = three_tier();
        let sub = "did:web:sub-tao.example";
        r.upsert(
            record(sub, Role::Tao, &["MembershipCredential"], Some(TAO)),
            2,
        )
        .unwrap();
        assert_eq!(
            r.upsert(
                record(TAO, Role::Tao, &["MembershipCredential"], Some(sub)),
                3
            ),
            Err(RegistryError::Cycle(sub.into()))
        );
    }

    #[test]
    fn chains_longer_than_the_check_allows_are_refused_at_write() {
        let mut r = Registry::default();
        r.upsert(record("did:web:t0.example", Role::RootTao, &["*"], None), 1)
            .unwrap();
        for i in 1..MAX_CHAIN_DEPTH {
            r.upsert(
                record(
                    &format!("did:web:t{i}.example"),
                    Role::Tao,
                    &["A"],
                    Some(&format!("did:web:t{}.example", i - 1)),
                ),
                1,
            )
            .unwrap();
        }
        let last = format!("did:web:t{}.example", MAX_CHAIN_DEPTH - 1);
        assert!(r.check(&last, "A", 1).trusted);
        assert_eq!(
            r.upsert(
                record("did:web:too-deep.example", Role::Ti, &["A"], Some(&last)),
                1
            ),
            Err(RegistryError::ChainTooLong)
        );
        // Re-parenting a subtree deeper is caught too: t1 under a new TAO
        // at depth 2 would push the bottom of t1's subtree past the limit.
        r.upsert(
            record(
                "did:web:side.example",
                Role::Tao,
                &["A"],
                Some("did:web:t0.example"),
            ),
            1,
        )
        .unwrap();
        assert_eq!(
            r.upsert(
                record(
                    "did:web:t1.example",
                    Role::Tao,
                    &["A"],
                    Some("did:web:side.example")
                ),
                1
            ),
            Err(RegistryError::ChainTooLong)
        );
    }

    #[test]
    fn revalidation_rejects_files_that_break_the_rules() {
        let good = three_tier();
        assert_eq!(good.clone().revalidated().unwrap(), good);

        let mut wildcard = three_tier();
        wildcard.issuers.get_mut(TI).unwrap().credential_types = vec!["*".into()];
        assert_eq!(
            wildcard.revalidated(),
            Err(RegistryError::WildcardNotAllowed)
        );

        let mut orphan = three_tier();
        orphan.issuers.remove(TAO);
        assert_eq!(
            orphan.revalidated(),
            Err(RegistryError::UnknownAccreditor(TAO.into()))
        );

        let json = serde_json::json!({"version": 1, "issuers": [
            record(ROOT, Role::RootTao, &["*"], None),
            record(ROOT, Role::RootTao, &["*"], None),
        ]});
        assert!(serde_json::from_value::<Registry>(json).is_err());
    }

    #[test]
    fn canonical_did_normalizes_did_web_only() {
        for (input, want) in [
            ("did:web:issuer.example", "did:web:issuer.example"),
            ("did:web:Issuer.EXAMPLE", "did:web:issuer.example"),
            ("did:web:host.example%3a8443", "did:web:host.example%3A8443"),
            ("did:web:HOST.example%3a8443", "did:web:host.example%3A8443"),
            // Path segments are case-sensitive; only their escapes change.
            (
                "did:web:Example.com:Users:Alice%2fx",
                "did:web:example.com:Users:Alice%2Fx",
            ),
            // Other methods are returned unchanged.
            ("did:key:z6MkAbC%3a", "did:key:z6MkAbC%3a"),
            ("did:ebsi:zAbC", "did:ebsi:zAbC"),
            ("not-a-did", "not-a-did"),
        ] {
            assert_eq!(canonical_did(input), want, "{input}");
            assert_eq!(canonical_did(want), want, "idempotent: {want}");
        }
    }

    #[test]
    fn lookups_accept_non_canonical_dids() {
        let mut r = Registry::default();
        r.upsert(record(ROOT, Role::RootTao, &["*"], None), 1)
            .unwrap();
        r.upsert(
            record("did:web:host.example%3A8443", Role::Tao, &["A"], Some(ROOT)),
            1,
        )
        .unwrap();
        let mixed = "did:web:HOST.example%3a8443";
        assert!(r.get(mixed).is_some());
        let d = r.check(mixed, "A", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec!["did:web:host.example%3A8443", ROOT]);
        assert_eq!(r.dependents_of("did:web:AUTHORITY.example").len(), 1);
        r.set_status(mixed, Status::Suspended, 5).unwrap();
        assert!(!r.check(mixed, "A", 10).trusted);
        assert!(matches!(
            r.remove("did:web:AUTHORITY.example"),
            Err(RegistryError::HasDependents { .. })
        ));
        r.remove(mixed).unwrap();
        assert!(r.get("did:web:host.example%3A8443").is_none());
    }

    #[test]
    fn upsert_stores_the_canonical_form() {
        let mut r = three_tier();
        r.upsert(
            record(
                "did:web:New.Example%3a8443",
                Role::Ti,
                &["MembershipCredential"],
                Some("did:web:TAO.example"),
            ),
            2,
        )
        .unwrap();
        let stored = r.get("did:web:new.example%3A8443").unwrap();
        assert_eq!(stored.did, "did:web:new.example%3A8443");
        assert_eq!(stored.accredited_by.as_deref(), Some(TAO));
        // Writing the same DID in another spelling replaces, not duplicates.
        let before = r.issuers.len();
        r.upsert(
            record(
                "did:web:NEW.example%3A8443",
                Role::Ti,
                &["MembershipCredential"],
                Some(TAO),
            ),
            3,
        )
        .unwrap();
        assert_eq!(r.issuers.len(), before);
        assert!(r.issuers.keys().all(|k| k == &canonical_did(k)));
    }

    #[test]
    fn non_canonical_accredited_by_still_resolves() {
        let mut r = three_tier();
        r.upsert(
            record(
                "did:web:other.example",
                Role::Ti,
                &["MembershipCredential"],
                Some("did:web:Tao.Example"),
            ),
            2,
        )
        .unwrap();
        let d = r.check("did:web:other.example", "MembershipCredential", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec!["did:web:other.example", TAO, ROOT]);
    }

    #[test]
    fn revalidation_canonicalizes_and_rejects_collisions() {
        let mut loose = three_tier();
        let mut ti = loose.issuers.remove(TI).unwrap();
        ti.did = "did:web:Issuer.example".into();
        ti.accredited_by = Some("did:web:TAO.example".into());
        loose.issuers.insert(ti.did.clone(), ti);
        let fixed = loose.revalidated().unwrap();
        assert!(fixed.issuers.contains_key(TI));
        assert_eq!(fixed.get(TI).unwrap().accredited_by.as_deref(), Some(TAO));

        let mut dup = three_tier();
        let mut twin = dup.get(TI).unwrap().clone();
        twin.did = "did:web:ISSUER.example".into();
        dup.issuers.insert(twin.did.clone(), twin);
        assert_eq!(dup.revalidated(), Err(RegistryError::Duplicate(TI.into())));
    }

    #[test]
    fn serializes_as_a_list() {
        let r = three_tier();
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["issuers"].as_array().unwrap().len(), 3);
        let back: Registry = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);
    }
}
