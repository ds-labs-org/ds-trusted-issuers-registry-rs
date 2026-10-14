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
//!   "version": 42, "issuers": [ { "did": "...", "role": "ti", ... } ] }
//! ```

use dcp_core::{DcpKeyPair, decode_jws_unverified, verify_jws_signature};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::IssuerRecord;
use crate::registry::Registry;

/// `typ` header value, so a snapshot can't be confused with another JWS
/// the same key signs.
pub const SNAPSHOT_TYP: &str = "trust-list+jwt";

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

/// Verifies a snapshot from the registry `expected_iss` and returns its
/// contents as a [`Registry`] that answers [`Registry::check`] locally.
///
/// `verifying_key` is the registry's key, normally looked up with
/// `dcp_core::find_verifying_key` on its resolved DID document using the
/// header `kid` (see [`snapshot_kid`]).
pub fn verify_snapshot(
    token: &str,
    expected_iss: &str,
    verifying_key: &VerifyingKey,
    now: u64,
) -> Result<(SnapshotPayload, Registry), SnapshotError> {
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
    if now >= payload.exp {
        return Err(SnapshotError::Expired(payload.exp));
    }
    let registry = Registry {
        version: payload.version,
        issuers: payload
            .issuers
            .iter()
            .map(|r| (r.did.clone(), r.clone()))
            .collect(),
    };
    Ok((payload, registry))
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
                did: "did:web:authority.example".into(),
                role: Role::RootTao,
                name: Some("Authority".into()),
                credential_types: vec!["*".into()],
                accredited_by: None,
                valid_from: None,
                valid_until: None,
                status: Status::Active,
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
        let (payload, back) = verify_snapshot(&token, REGISTRY_DID, &vk(&key), 1059).unwrap();
        assert_eq!(payload.exp, 1060);
        assert_eq!(back, registry());
        assert!(
            back.check("did:web:authority.example", "Anything", 1059)
                .trusted
        );
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
