//! The signed trust-list snapshot: the whole registry as one ES256 compact
//! JWS, signed by the registry's own `did:web` key. A verifier fetches it
//! once, verifies it against the key in the registry's DID document, and
//! then answers [`Registry::check`] locally until `exp`, without calling
//! the registry per credential (the same offline-cacheable idea as Gaia-X's
//! published trust-anchor list and ETSI trusted lists).
//!
//! Payload:
//!
//! ```json
//! { "iss": "did:web:registry.example", "iat": 1760000000, "exp": 1760003600,
//!   "version": 42, "issuers": [ { "id": "...", "role": "ti", ... } ] }
//! ```

use dcp_core::{DcpKeyPair, decode_jws_unverified, verify_jws_signature};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::IssuerRecord;
use crate::registry::{Registry, TrustDecision};

/// `typ` header value, so a snapshot can't be confused with another JWS
/// the same key signs.
pub const SNAPSHOT_TYP: &str = "trust-list+jwt";

/// How far in the future a snapshot's `iat` may be, in seconds, before
/// [`verify_snapshot`] refuses it as not yet valid. Covers ordinary clock
/// drift between the registry and a verifier.
pub const SNAPSHOT_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPayload {
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub version: u64,
    pub issuers: Vec<IssuerRecord>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotError {
    #[error("malformed snapshot: {0}")]
    Malformed(String),
    #[error("snapshot must be ES256 with typ '{SNAPSHOT_TYP}'")]
    WrongHeader,
    #[error("snapshot was issued by '{0}', not the expected registry")]
    WrongIssuer(String),
    #[error("snapshot kid does not belong to the registry DID")]
    WrongKid,
    #[error("snapshot signature is invalid: {0}")]
    BadSignature(String),
    #[error("snapshot expired at {0}")]
    Expired(u64),
    #[error("snapshot is issued in the future (iat {0})")]
    NotYetValid(u64),
}

/// Signs the registry's current contents, valid for `ttl_secs` from `now`.
pub fn sign_snapshot(registry: &Registry, key: &DcpKeyPair, now: u64, ttl_secs: u64) -> String {
    let payload = SnapshotPayload {
        iss: key.own_did.clone(),
        iat: now,
        exp: now.saturating_add(ttl_secs),
        version: registry.version,
        issuers: registry.list().cloned().collect(),
    };
    let payload = serde_json::to_value(&payload).expect("snapshot payload always serializes");
    sign_with_typ(&payload, key)
}

/// Same as `dcp_core::sign_jws`, plus a `typ` header (which `sign_jws`
/// does not let the caller set).
fn sign_with_typ(payload: &serde_json::Value, key: &DcpKeyPair) -> String {
    use dcp_core::b64_encode;
    use p256::ecdsa::Signature;
    use p256::ecdsa::signature::Signer;

    let header = serde_json::json!({"kid": key.own_key_id, "alg": "ES256", "typ": SNAPSHOT_TYP});
    let signing_input = format!(
        "{}.{}",
        b64_encode(header.to_string()),
        b64_encode(payload.to_string())
    );
    let signature: Signature = key.signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64_encode(signature.to_bytes()))
}

/// A verified snapshot. [`TrustList::check`] answers like
/// [`Registry::check`] but refuses everything once the snapshot expires, so
/// a verifier that keeps one around can't keep trusting a stale list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustList {
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub version: u64,
    registry: Registry,
}

impl TrustList {
    pub fn check(&self, id: &str, credential_type: &str, now: u64) -> TrustDecision {
        if now >= self.exp {
            return TrustDecision {
                trusted: false,
                chain: vec![],
                reason: Some(format!(
                    "the trust list expired at {}; fetch a new snapshot",
                    self.exp
                )),
            };
        }
        self.registry.check(id, credential_type, now)
    }

    /// [`Registry::check_x5c`] against the snapshot, refused once it
    /// expired, like [`TrustList::check`].
    pub fn check_x5c(
        &self,
        x5c: &[String],
        credential_type: &str,
        now: u64,
        eku: Option<&str>,
    ) -> TrustDecision {
        let _ = (x5c, credential_type, now, eku);
        TrustDecision {
            trusted: false,
            chain: vec![],
            reason: Some("not implemented".into()),
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

/// Verifies a snapshot from the registry `expected_iss` and returns it as a
/// [`TrustList`] that answers trust checks locally until it expires. The
/// contents are re-checked against the registry's write rules too.
///
/// `verifying_key` is the registry's key, normally looked up with
/// `dcp_core::find_verifying_key` on its resolved DID document using the
/// header `kid` (see [`snapshot_kid`]).
pub fn verify_snapshot(
    token: &str,
    expected_iss: &str,
    verifying_key: &VerifyingKey,
    now: u64,
) -> Result<TrustList, SnapshotError> {
    let (_, header, payload) = decode_jws_unverified(token).map_err(SnapshotError::Malformed)?;
    if header["alg"] != "ES256" || header["typ"] != SNAPSHOT_TYP {
        return Err(SnapshotError::WrongHeader);
    }
    let kid = header["kid"].as_str().unwrap_or_default();
    if !kid.starts_with(&format!("{expected_iss}#")) {
        return Err(SnapshotError::WrongKid);
    }
    verify_jws_signature(token, verifying_key).map_err(SnapshotError::BadSignature)?;
    let payload: SnapshotPayload =
        serde_json::from_value(payload).map_err(|e| SnapshotError::Malformed(e.to_string()))?;
    if payload.iss != expected_iss {
        return Err(SnapshotError::WrongIssuer(payload.iss));
    }
    if payload.iat >= payload.exp {
        return Err(SnapshotError::Malformed(format!(
            "iat {} is not before exp {}",
            payload.iat, payload.exp
        )));
    }
    if now >= payload.exp {
        return Err(SnapshotError::Expired(payload.exp));
    }
    // A signed `iat` in the future means the registry's clock is wrong or
    // the token was minted ahead of time; either way its `exp` window can't
    // be trusted to start now, so allow only a little clock skew.
    if payload.iat > now.saturating_add(SNAPSHOT_CLOCK_SKEW_SECS) {
        return Err(SnapshotError::NotYetValid(payload.iat));
    }
    let mut issuers = std::collections::BTreeMap::new();
    for record in payload.issuers {
        let did = record.id.clone();
        if issuers.insert(did.clone(), record).is_some() {
            return Err(SnapshotError::Malformed(format!(
                "'{did}' is listed more than once"
            )));
        }
    }
    let registry = Registry {
        version: payload.version,
        issuers,
    }
    .revalidated()
    .map_err(|e| SnapshotError::Malformed(e.to_string()))?;
    Ok(TrustList {
        iss: payload.iss,
        iat: payload.iat,
        exp: payload.exp,
        version: payload.version,
        registry,
    })
}

/// The `kid` header of a snapshot, without verifying it, so the caller can
/// pick the matching key from the registry's DID document.
pub fn snapshot_kid(token: &str) -> Result<String, SnapshotError> {
    let (_, header, _) = decode_jws_unverified(token).map_err(SnapshotError::Malformed)?;
    header["kid"]
        .as_str()
        .map(str::to_string)
        .ok_or(SnapshotError::WrongKid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Role, Status};

    const REGISTRY_DID: &str = "did:web:registry.example";

    fn registry() -> Registry {
        let mut r = Registry::default();
        r.upsert(
            IssuerRecord {
                id: "did:web:authority.example".into(),
                role: Role::RootTao,
                name: Some("Authority".into()),
                credential_types: vec!["*".into()],
                accredited_by: None,
                valid_from: None,
                valid_until: None,
                status: Status::Active,
                x509_certificates: Vec::new(),
                updated_at: 0,
            },
            1,
        )
        .unwrap();
        r
    }

    fn vk(key: &DcpKeyPair) -> VerifyingKey {
        VerifyingKey::from(&key.signing_key())
    }

    #[test]
    fn round_trip() {
        let key = DcpKeyPair::generate(REGISTRY_DID.into());
        let token = sign_snapshot(&registry(), &key, 1000, 60);
        assert_eq!(snapshot_kid(&token).unwrap(), key.own_key_id);
        let list = verify_snapshot(&token, REGISTRY_DID, &vk(&key), 1059).unwrap();
        assert_eq!(list.exp, 1060);
        assert_eq!(list.registry(), &registry());
        assert!(
            list.check("did:web:authority.example", "Anything", 1059)
                .trusted
        );
        // A kept TrustList stops trusting anyone once it expires.
        assert!(
            !list
                .check("did:web:authority.example", "Anything", 1060)
                .trusted
        );
    }

    /// Signs a hand-built payload the way `sign_snapshot` does.
    fn token_with_times(key: &DcpKeyPair, iat: u64, exp: u64) -> String {
        let payload = SnapshotPayload {
            iss: key.own_did.clone(),
            iat,
            exp,
            version: 1,
            issuers: registry().list().cloned().collect(),
        };
        sign_with_typ(&serde_json::to_value(&payload).unwrap(), key)
    }

    #[test]
    fn iat_within_the_clock_skew_is_accepted() {
        let key = DcpKeyPair::generate(REGISTRY_DID.into());
        let token = token_with_times(&key, 1000 + SNAPSHOT_CLOCK_SKEW_SECS, 5000);
        assert!(verify_snapshot(&token, REGISTRY_DID, &vk(&key), 1000).is_ok());
    }

    #[test]
    fn iat_beyond_the_clock_skew_is_not_yet_valid() {
        let key = DcpKeyPair::generate(REGISTRY_DID.into());
        let iat = 1000 + SNAPSHOT_CLOCK_SKEW_SECS + 1;
        let token = token_with_times(&key, iat, 5000);
        assert_eq!(
            verify_snapshot(&token, REGISTRY_DID, &vk(&key), 1000).unwrap_err(),
            SnapshotError::NotYetValid(iat)
        );
    }

    #[test]
    fn iat_at_or_after_exp_is_malformed() {
        let key = DcpKeyPair::generate(REGISTRY_DID.into());
        for (iat, exp) in [(2000, 2000), (2001, 2000)] {
            let token = token_with_times(&key, iat, exp);
            assert!(
                matches!(
                    verify_snapshot(&token, REGISTRY_DID, &vk(&key), 1990),
                    Err(SnapshotError::Malformed(_))
                ),
                "iat {iat} exp {exp}"
            );
        }
    }

    #[test]
    fn rejects_expired_foreign_and_tampered() {
        let key = DcpKeyPair::generate(REGISTRY_DID.into());
        let token = sign_snapshot(&registry(), &key, 1000, 60);
        assert_eq!(
            verify_snapshot(&token, REGISTRY_DID, &vk(&key), 1060).unwrap_err(),
            SnapshotError::Expired(1060)
        );
        assert_eq!(
            verify_snapshot(&token, "did:web:other.example", &vk(&key), 1000).unwrap_err(),
            SnapshotError::WrongKid
        );
        let other = DcpKeyPair::generate(REGISTRY_DID.into());
        assert!(matches!(
            verify_snapshot(&token, REGISTRY_DID, &vk(&other), 1000),
            Err(SnapshotError::BadSignature(_))
        ));
        // A plain dcp_core JWS from the same key (e.g. a self-issued token)
        // has no `typ` and must not pass as a snapshot.
        let untyped = dcp_core::sign_jws(
            &serde_json::json!({"iss": REGISTRY_DID}),
            &key.signing_key(),
            &key.own_key_id,
        );
        assert_eq!(
            verify_snapshot(&untyped, REGISTRY_DID, &vk(&key), 1000).unwrap_err(),
            SnapshotError::WrongHeader
        );
    }
}
