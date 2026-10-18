//! Accreditations as Verifiable Credentials, so an issuer can prove its
//! accreditation chain to a verifier without the verifier calling the
//! registry: [`issue_accreditations`] returns one JWT VC per link of the
//! chain (the issuer, its accreditor, ... up to the Root TAO), and
//! [`verify_accreditations`] turns a set of them back into an
//! [`AccreditationChain`] that answers the same trust check as the registry.
//!
//! The VCs conform to EBSI's Verifiable Accreditation schema
//! (`@cef-ebsi/vcdm1.1-accreditation-schema` 2.0.0, checked by the
//! conformance suite): types `VerifiableAccreditationToAttest` for a TI,
//! `...ToAccredit` for a TAO, `VerifiableAuthorisationForTrustChain` for the
//! Root TAO; one `credentialSubject.accreditedFor` entry per credential type
//! in scope; the accreditor in an `IssuanceCertificate` `termsOfUse` (the
//! Root TAO's points at the registry as a `TrustFrameworkPolicy`), encoded
//! as a VCDM 1.1 JWT (`vc` claim, as `jwt_vc_json`). Differences from EBSI:
//!
//! - Each accreditation is signed by the registry, not by the accreditor,
//!   since the registry does not hold the accreditors' keys. A verifier
//!   therefore needs only the registry's key, as for the snapshot.
//! - `accreditedFor[].schemaId` must be a URI, but a credential type is
//!   often a bare name (`MembershipCredential`) with no schema registered
//!   anywhere: a type that is already an absolute URI (an SD-JWT VC `vct`)
//!   is its own `schemaId`, any other gets one under [`CREDENTIAL_TYPE_BASE`].
//! - `reservedAttributeId` (EBSI's registry attribute) is the SHA-256 of the
//!   party's id, hex, so it is stable per party.
//! - There is no `credentialStatus`: an accreditation lives no longer than
//!   the snapshot TTL instead.

use std::collections::BTreeMap;

use dcp_core::{DcpKeyPair, decode_jws_unverified, verify_jws_signature};
use p256::ecdsa::VerifyingKey;
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{IssuerRecord, Role, Status};
use crate::registry::{MAX_CHAIN_DEPTH, Registry, TrustDecision, canonical_id};
use crate::snapshot::sign_with_typ;

/// `typ` of an accreditation JWT.
pub const ACCREDITATION_TYP: &str = "JWT";

/// `credentialSchema` of every accreditation: EBSI's Verifiable
/// Accreditation schema as published to the pilot Trusted Schemas Registry
/// (its multibase id, from the schema's npm package).
pub const ACCREDITATION_SCHEMA_ID: &str = "https://api-pilot.ebsi.eu/trusted-schemas-registry/v3/schemas/zHXHLkJpZg4w9nt2GbEBbyE8uhkfirbmT3nF7mJ9kFnjv";

/// Base of the `schemaId` given to a credential type that is not itself a
/// URI: the type, percent-encoded, follows it.
pub const CREDENTIAL_TYPE_BASE: &str =
    "https://ds42.org/ontologies/ds-trusted-issuers-registry-rs/credential-types/";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccreditationError {
    #[error("'{0}' is not in the registry")]
    NotFound(String),
    #[error("'{id}' is not currently accredited: {reason}")]
    NotAccredited { id: String, reason: String },
    #[error("malformed accreditation: {0}")]
    Malformed(String),
    #[error("accreditation was issued by '{0}', not the expected registry")]
    WrongIssuer(String),
    #[error("accreditation signature is invalid: {0}")]
    BadSignature(String),
    #[error("accreditation of '{id}' is not valid at this time")]
    NotValidNow { id: String },
}

/// Signs one accreditation VC per link of `id`'s chain, issuer first, each
/// valid from `now` until the earliest of `now + ttl_secs` and every link's
/// `validUntil`. Refused when a link is unlisted, not active or outside its
/// validity window now, so the registry never vouches for a broken chain.
pub fn issue_accreditations(
    registry: &Registry,
    id: &str,
    key: &DcpKeyPair,
    now: u64,
    ttl_secs: u64,
) -> Result<Vec<String>, AccreditationError> {
    let id = canonical_id(id);
    if registry.get(&id).is_none() {
        return Err(AccreditationError::NotFound(id));
    }
    // The chain the trust check walks, refused unless every link is usable
    // now; "*" asks only whether each link is in scope for something, which
    // every record is.
    let mut links: Vec<&IssuerRecord> = Vec::new();
    let mut cursor = Some(id.clone());
    while let Some(current) = cursor {
        let not_accredited = |reason: String| AccreditationError::NotAccredited {
            id: id.clone(),
            reason,
        };
        if links.len() >= MAX_CHAIN_DEPTH || links.iter().any(|l| l.id == current) {
            return Err(not_accredited(
                "the accreditation chain is malformed".into(),
            ));
        }
        let record = registry
            .get(&current)
            .ok_or_else(|| not_accredited(format!("'{current}' is not in the registry")))?;
        if !links.is_empty() && !record.role.can_accredit() {
            return Err(not_accredited(format!(
                "'{current}' cannot accredit others"
            )));
        }
        if !record.is_usable_at(now) {
            return Err(not_accredited(format!(
                "'{current}' is not active or outside its validity period"
            )));
        }
        cursor = match record.role {
            Role::RootTao => None,
            _ => Some(
                record
                    .accredited_by
                    .clone()
                    .ok_or_else(|| not_accredited(format!("'{current}' has no accreditor")))?,
            ),
        };
        links.push(record);
    }
    let exp = links
        .iter()
        .filter_map(|l| l.valid_until)
        .fold(now.saturating_add(ttl_secs), u64::min);
    Ok(links
        .iter()
        .map(|record| {
            let payload = accreditation_payload(record, &key.own_did, now, exp);
            sign_with_typ(&payload, key, ACCREDITATION_TYP)
        })
        .collect())
}

/// The EBSI-shaped VC type that says what a link may do.
fn link_type(role: Role) -> &'static str {
    match role {
        Role::RootTao => "VerifiableAuthorisationForTrustChain",
        Role::Tao => "VerifiableAccreditationToAccredit",
        Role::Ti => "VerifiableAccreditationToAttest",
    }
}

/// Whether `s` is an absolute URI: a scheme (RFC 3986 section 3.1), a
/// colon, and nothing a URI may not hold.
fn is_absolute_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut scheme_chars = scheme.chars();
    scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme_chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        && !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"\"<>\\^`{|}".contains(&b))
}

/// The `schemaId` standing for `credential_type`.
fn schema_id(credential_type: &str) -> String {
    if is_absolute_uri(credential_type) {
        return credential_type.to_string();
    }
    let mut id = CREDENTIAL_TYPE_BASE.to_string();
    for b in credential_type.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            id.push(b as char);
        } else {
            id.push_str(&format!("%{b:02X}"));
        }
    }
    id
}

fn accreditation_payload(record: &IssuerRecord, iss: &str, now: u64, exp: u64) -> Value {
    use sha2::{Digest, Sha256};
    let accredited_for: Vec<Value> = record
        .credential_types
        .iter()
        .map(|t| json!({"schemaId": schema_id(t), "types": [t]}))
        .collect();
    let reserved_attribute_id: String = Sha256::digest(record.id.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut subject = json!({
        "id": record.id,
        "reservedAttributeId": reserved_attribute_id,
        "role": record.role,
        "accreditedFor": accredited_for,
    });
    if let Some(name) = &record.name {
        subject["name"] = json!(name);
    }
    if !record.x509_certificates.is_empty() {
        subject["x509Certificates"] = json!(record.x509_certificates);
    }
    let mut types = vec!["VerifiableCredential", "VerifiableAttestation"];
    if record.role != Role::RootTao {
        types.push("VerifiableAccreditation");
    }
    types.push(link_type(record.role));
    let terms_of_use = match &record.accredited_by {
        Some(by) => json!({"id": by, "type": "IssuanceCertificate"}),
        None => json!({"id": iss, "type": "TrustFrameworkPolicy"}),
    };
    let issued = crate::iso8601_utc(now);
    let vc = json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": types,
        "issuer": iss,
        "issuanceDate": issued,
        "issued": issued,
        "validFrom": issued,
        "expirationDate": crate::iso8601_utc(exp),
        "credentialSubject": subject,
        "credentialSchema": {"id": ACCREDITATION_SCHEMA_ID, "type": "FullJsonSchemaValidator2021"},
        "termsOfUse": terms_of_use,
    });
    json!({"iss": iss, "sub": record.id, "iat": now, "nbf": now, "exp": exp, "vc": vc})
}

/// A verified set of accreditations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccreditationChain {
    registry: Registry,
}

impl AccreditationChain {
    /// Like [`Registry::check`], over the accreditations alone: each VC's
    /// validity period stands in for the record's.
    pub fn check(&self, id: &str, credential_type: &str, now: u64) -> TrustDecision {
        self.registry.check(id, credential_type, now)
    }
}

/// Verifies accreditation JWTs signed by the registry `expected_iss` with
/// `verifying_key` (from its DID document, as for the snapshot): signature,
/// issuer, shape, and validity at `now`. The chains they form are then
/// re-checked against the registry's write rules.
pub fn verify_accreditations(
    tokens: &[String],
    expected_iss: &str,
    verifying_key: &VerifyingKey,
    now: u64,
) -> Result<AccreditationChain, AccreditationError> {
    let mut issuers = BTreeMap::new();
    for token in tokens {
        let record = verify_one(token, expected_iss, verifying_key, now)?;
        if issuers.insert(record.id.clone(), record).is_some() {
            return Err(AccreditationError::Malformed(
                "two accreditations of the same party".into(),
            ));
        }
    }
    let registry = Registry {
        version: 0,
        issuers,
    }
    .revalidated()
    .map_err(|e| AccreditationError::Malformed(e.to_string()))?;
    Ok(AccreditationChain { registry })
}

/// Verifies one accreditation and returns the record it stands for, with
/// the VC's validity period as the record's.
fn verify_one(
    token: &str,
    expected_iss: &str,
    verifying_key: &VerifyingKey,
    now: u64,
) -> Result<IssuerRecord, AccreditationError> {
    let malformed = |what: &str| AccreditationError::Malformed(what.to_string());
    let (_, header, payload) =
        decode_jws_unverified(token).map_err(AccreditationError::Malformed)?;
    if header["alg"] != "ES256" || header["typ"] != ACCREDITATION_TYP {
        return Err(malformed("not an ES256 JWT"));
    }
    let iss = payload["iss"].as_str().unwrap_or_default();
    let kid = header["kid"].as_str().unwrap_or_default();
    if iss != expected_iss || !kid.starts_with(&format!("{expected_iss}#")) {
        return Err(AccreditationError::WrongIssuer(iss.to_string()));
    }
    verify_jws_signature(token, verifying_key).map_err(AccreditationError::BadSignature)?;
    let vc = &payload["vc"];
    let types: Vec<&str> = vc["type"]
        .as_array()
        .map(|t| t.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let role = [Role::RootTao, Role::Tao, Role::Ti]
        .into_iter()
        .find(|role| types.contains(&link_type(*role)))
        .ok_or_else(|| malformed("not an accreditation (no accreditation type)"))?;
    let subject = &vc["credentialSubject"];
    let id = payload["sub"].as_str().ok_or_else(|| malformed("no sub"))?;
    if subject["id"] != id || vc["issuer"] != iss {
        return Err(malformed("sub/credentialSubject.id or iss/issuer disagree"));
    }
    let nbf = payload["nbf"].as_u64().ok_or_else(|| malformed("no nbf"))?;
    let exp = payload["exp"].as_u64().ok_or_else(|| malformed("no exp"))?;
    if now < nbf || now >= exp {
        return Err(AccreditationError::NotValidNow { id: id.to_string() });
    }
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    // EBSI allows one entry or a list for both; the scope is the union of
    // every entry's types, the accreditor the IssuanceCertificate's id.
    let entries = |v: &Value| match v {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    };
    let mut credential_types: Vec<String> = Vec::new();
    for entry in entries(&subject["accreditedFor"]) {
        for t in strings(&entry["types"]) {
            if !credential_types.contains(&t) {
                credential_types.push(t);
            }
        }
    }
    let accredited_by = entries(&vc["termsOfUse"])
        .iter()
        .find(|terms| terms["type"] == "IssuanceCertificate")
        .and_then(|terms| terms["id"].as_str().map(str::to_string));
    Ok(IssuerRecord {
        id: id.to_string(),
        role,
        name: subject["name"].as_str().map(str::to_string),
        credential_types,
        accredited_by,
        valid_from: Some(nbf),
        valid_until: Some(exp),
        status: Status::Active,
        x509_certificates: strings(&subject["x509Certificates"]),
        postal_address: None,
        updated_at: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY_DID: &str = "did:web:registry.example";
    const ROOT: &str = "did:web:authority.example";
    const TAO: &str = "did:web:tao.example";
    const TI: &str = "https://issuer.example/tenants/acme";
    const NOW: u64 = 1_792_000_000;

    fn rec(id: &str, role: Role, types: &[&str], by: Option<&str>) -> IssuerRecord {
        IssuerRecord {
            id: id.into(),
            role,
            name: Some(format!("{id} name")),
            credential_types: types.iter().map(|t| t.to_string()).collect(),
            accredited_by: by.map(Into::into),
            valid_from: None,
            valid_until: None,
            status: Status::Active,
            x509_certificates: Vec::new(),
            postal_address: None,
            updated_at: 0,
        }
    }

    fn registry() -> Registry {
        let mut r = Registry::default();
        r.upsert(rec(ROOT, Role::RootTao, &["*"], None), 1).unwrap();
        let mut tao = rec(TAO, Role::Tao, &["MembershipCredential", "PID"], Some(ROOT));
        tao.valid_until = Some(NOW + 100);
        r.upsert(tao, 1).unwrap();
        r.upsert(rec(TI, Role::Ti, &["MembershipCredential"], Some(TAO)), 1)
            .unwrap();
        r
    }

    fn key() -> DcpKeyPair {
        DcpKeyPair::generate(REGISTRY_DID.into())
    }

    fn vk(key: &DcpKeyPair) -> VerifyingKey {
        VerifyingKey::from(&key.signing_key())
    }

    fn payload(token: &str) -> serde_json::Value {
        dcp_core::decode_jws_unverified(token).unwrap().2
    }

    #[test]
    fn an_issuer_proves_its_chain_with_its_accreditations_alone() {
        let key = key();
        let tokens = issue_accreditations(&registry(), TI, &key, NOW, 3600).unwrap();
        assert_eq!(tokens.len(), 3);
        let chain = verify_accreditations(&tokens, REGISTRY_DID, &vk(&key), NOW + 1).unwrap();
        let d = chain.check(TI, "MembershipCredential", NOW + 1);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec![TI, TAO, ROOT]);
        // Scope is carried: the TAO may do PID, the TI may not.
        assert!(!chain.check(TI, "PID", NOW + 1).trusted);
        assert!(chain.check(TAO, "PID", NOW + 1).trusted);
        // Order does not matter.
        let reversed: Vec<String> = tokens.iter().rev().cloned().collect();
        let chain = verify_accreditations(&reversed, REGISTRY_DID, &vk(&key), NOW + 1).unwrap();
        assert!(chain.check(TI, "MembershipCredential", NOW + 1).trusted);
    }

    #[test]
    fn accreditations_are_ebsi_shaped_jwt_vcs() {
        let key = key();
        let tokens = issue_accreditations(&registry(), TI, &key, NOW, 3600).unwrap();
        let (_, header, _) = dcp_core::decode_jws_unverified(&tokens[0]).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], ACCREDITATION_TYP);
        assert_eq!(header["kid"], key.own_key_id.as_str());
        let ti = payload(&tokens[0]);
        assert_eq!(ti["iss"], REGISTRY_DID);
        assert_eq!(ti["sub"], TI);
        assert_eq!(ti["nbf"], NOW);
        let types = ti["vc"]["type"].as_array().unwrap();
        for t in [
            "VerifiableCredential",
            "VerifiableAttestation",
            "VerifiableAccreditation",
            "VerifiableAccreditationToAttest",
        ] {
            assert!(types.iter().any(|x| x == t), "{t} in {types:?}");
        }
        assert_eq!(ti["vc"]["issuer"], REGISTRY_DID);
        assert_eq!(ti["vc"]["credentialSubject"]["id"], TI);
        assert_eq!(
            ti["vc"]["credentialSubject"]["accreditedFor"],
            serde_json::json!([{
                "schemaId": format!("{CREDENTIAL_TYPE_BASE}MembershipCredential"),
                "types": ["MembershipCredential"]
            }])
        );
        assert!(ti["vc"]["id"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(ti["vc"]["credentialSchema"]["id"], ACCREDITATION_SCHEMA_ID);
        assert_eq!(ti["vc"]["validFrom"], ti["vc"]["issuanceDate"]);
        assert_eq!(
            ti["vc"]["credentialSubject"]["reservedAttributeId"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(ti["vc"]["termsOfUse"]["id"], TAO);
        assert_eq!(ti["vc"]["termsOfUse"]["type"], "IssuanceCertificate");
        assert!(ti["vc"]["issuanceDate"].as_str().unwrap().ends_with('Z'));
        let tao_types = payload(&tokens[1])["vc"]["type"].clone();
        assert!(
            tao_types
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x == "VerifiableAccreditationToAccredit")
        );
        let root = payload(&tokens[2]);
        assert!(
            root["vc"]["type"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x == "VerifiableAuthorisationForTrustChain")
        );
        assert_eq!(
            root["vc"]["termsOfUse"],
            serde_json::json!({"id": REGISTRY_DID, "type": "TrustFrameworkPolicy"})
        );
    }

    #[test]
    fn credential_types_get_a_uri_schema_id() {
        assert_eq!(
            schema_id("https://credentials.example/pid"),
            "https://credentials.example/pid"
        );
        assert_eq!(
            schema_id("urn:eu.europa.ec.eudi:pid:1"),
            "urn:eu.europa.ec.eudi:pid:1"
        );
        assert_eq!(schema_id("*"), format!("{CREDENTIAL_TYPE_BASE}%2A"));
        assert_eq!(
            schema_id("Diploma 2:x"),
            format!("{CREDENTIAL_TYPE_BASE}Diploma%202%3Ax")
        );
        assert_eq!(schema_id("1x:y"), format!("{CREDENTIAL_TYPE_BASE}1x%3Ay"));
    }

    #[test]
    fn every_link_expires_with_the_shortest_validity_in_the_chain() {
        let key = key();
        let tokens = issue_accreditations(&registry(), TI, &key, NOW, 3600).unwrap();
        // The TAO's validUntil (NOW + 100) caps the whole chain.
        for t in &tokens {
            assert_eq!(payload(t)["exp"], NOW + 100, "{}", payload(t)["sub"]);
        }
        let chain = verify_accreditations(&tokens, REGISTRY_DID, &vk(&key), NOW + 99).unwrap();
        assert!(chain.check(TI, "MembershipCredential", NOW + 99).trusted);
        assert!(!chain.check(TI, "MembershipCredential", NOW + 100).trusted);
        assert_eq!(
            verify_accreditations(&tokens, REGISTRY_DID, &vk(&key), NOW + 100),
            Err(AccreditationError::NotValidNow { id: TI.into() })
        );
        // Without validUntil, the TTL bounds it.
        let root = issue_accreditations(&registry(), ROOT, &key, NOW, 60).unwrap();
        assert_eq!(payload(&root[0])["exp"], NOW + 60);
    }

    #[test]
    fn a_broken_chain_is_not_vouched_for() {
        let key = key();
        let mut r = registry();
        r.set_status(TAO, Status::Suspended, 2).unwrap();
        assert!(matches!(
            issue_accreditations(&r, TI, &key, NOW, 3600),
            Err(AccreditationError::NotAccredited { .. })
        ));
        assert_eq!(
            issue_accreditations(&registry(), "did:web:nobody.example", &key, NOW, 3600),
            Err(AccreditationError::NotFound(
                "did:web:nobody.example".into()
            ))
        );
        // Past the TAO's validUntil.
        assert!(matches!(
            issue_accreditations(&registry(), TI, &key, NOW + 100, 3600),
            Err(AccreditationError::NotAccredited { .. })
        ));
    }

    #[test]
    fn forged_or_foreign_accreditations_are_refused() {
        let key = key();
        let tokens = issue_accreditations(&registry(), TI, &key, NOW, 3600).unwrap();
        // Another key.
        assert!(matches!(
            verify_accreditations(&tokens, REGISTRY_DID, &vk(&self::key()), NOW),
            Err(AccreditationError::BadSignature(_))
        ));
        // Another registry.
        assert!(matches!(
            verify_accreditations(&tokens, "did:web:other.example", &vk(&key), NOW),
            Err(AccreditationError::WrongIssuer(_))
        ));
        // A widened scope in the payload breaks the signature.
        let parts: Vec<&str> = tokens[0].split('.').collect();
        let mut p = payload(&tokens[0]);
        p["vc"]["credentialSubject"]["accreditedFor"][0]["types"] = serde_json::json!(["*"]);
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            dcp_core::b64_encode(p.to_string()),
            parts[2]
        );
        assert!(matches!(
            verify_accreditations(&[forged], REGISTRY_DID, &vk(&key), NOW),
            Err(AccreditationError::BadSignature(_))
        ));
        // A snapshot is not an accreditation.
        let snapshot = crate::sign_snapshot(&registry(), &key, NOW, 60);
        assert!(matches!(
            verify_accreditations(&[snapshot], REGISTRY_DID, &vk(&key), NOW),
            Err(AccreditationError::Malformed(_))
        ));
    }

    #[test]
    fn a_missing_link_leaves_the_chain_unproven() {
        let key = key();
        let tokens = issue_accreditations(&registry(), TI, &key, NOW, 3600).unwrap();
        // Without the root's accreditation the TAO's accreditor is unknown:
        // the write rules refuse such a set, so it proves nothing.
        assert!(verify_accreditations(&tokens[..2], REGISTRY_DID, &vk(&key), NOW).is_err());
        assert!(
            verify_accreditations(&[], REGISTRY_DID, &vk(&key), NOW)
                .unwrap()
                .check(TI, "MembershipCredential", NOW)
                .reason
                .is_some()
        );
    }
}
