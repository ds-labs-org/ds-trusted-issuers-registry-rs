//! The registry as an ETSI TS 119 602 List of Trusted Entities (LoTE), in
//! the JSON binding (the `{"LoTE": {...}}` document of the standard's JSON
//! schema), so off-the-shelf EUDI wallets and verifiers that read LoTEs can
//! consume it next to the registry's own snapshot.
//!
//! What the list says:
//!
//! - One `TrustedEntity` per party whose accreditation chain is valid at
//!   the list's issue time. Suspended, revoked, expired or orphaned parties
//!   are left out: in a LoTE without status (anything but the Pub-EAA
//!   profile), presence means trusted.
//! - One `TrustedEntityService` per credential type the party is trusted
//!   for at that time (`ServiceName` = the type), of service type
//!   [`SERVICE_TYPE_ISSUANCE`] for a TI and [`SERVICE_TYPE_ACCREDITATION`]
//!   for a TAO or Root TAO.
//! - `ServiceDigitalIdentity.OtherIds` holds the party's id (its DID, or
//!   OID4VCI credential issuer URL); `X509Certificates` its trust anchors.
//! - `LoTESequenceNumber` is the registry version plus one (an empty
//!   registry publishes 1), `NextUpdate` the issue time plus the TTL.
//!
//! None of the EU LoTE types (PID providers, wallet providers, ...) fits a
//! dataspace's issuer list, so `LoTEType` is a dataspace-defined URI
//! ([`DEFAULT_LOTE_TYPE`] unless configured).

use serde_json::{Value, json};

use crate::model::IdKind;
use crate::registry::Registry;

/// `LoTEVersionIdentifier` of the lists produced here.
pub const LOTE_VERSION: u64 = 1;

/// `LoTEType` used unless the operator configures another.
pub const DEFAULT_LOTE_TYPE: &str =
    "https://ds42.org/ontologies/ds-trusted-issuers-registry-rs#TrustedIssuersList";

/// `ServiceTypeIdentifier` of a TI's services: it issues the credential type.
pub const SERVICE_TYPE_ISSUANCE: &str =
    "https://ds42.org/ontologies/ds-trusted-issuers-registry-rs#CredentialIssuance";

/// `ServiceTypeIdentifier` of a TAO's or Root TAO's services: it accredits
/// issuers for (and may issue) the credential type.
pub const SERVICE_TYPE_ACCREDITATION: &str =
    "https://ds42.org/ontologies/ds-trusted-issuers-registry-rs#Accreditation";

/// `typ` of the signed LoTE (a compact JWS of the JSON document).
pub const LOTE_TYP: &str = "lote+jwt";

/// Who publishes the list and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoteOptions {
    /// `SchemeOperatorName` (English).
    pub operator_name: String,
    /// Base URL of the registry's public API (`https://registry.example`):
    /// the operator's electronic address, `SchemeInformationURI`, each
    /// entity's `TEInformationURI` and the `DistributionPoints`.
    pub base_url: String,
    pub lote_type: String,
    /// `SchemeTerritory` (ISO 3166-1 alpha-2, or `EU`), when given.
    pub territory: Option<String>,
}

/// The LoTE document for `registry` at `now`, next update after `ttl_secs`.
pub fn build_lote(registry: &Registry, options: &LoteOptions, now: u64, ttl_secs: u64) -> Value {
    let base = options.base_url.trim_end_matches('/');
    let en = |value: &str| json!([{"lang": "en", "value": value}]);
    let uri = |value: &str| json!([{"lang": "en", "uriValue": value}]);
    let mut info = json!({
        "LoTEVersionIdentifier": LOTE_VERSION,
        "LoTESequenceNumber": registry.version + 1,
        "LoTEType": options.lote_type,
        "SchemeOperatorName": en(&options.operator_name),
        "SchemeOperatorAddress": {
            "SchemeOperatorPostalAddress": [],
            "SchemeOperatorElectronicAddress": uri(base),
        },
        "SchemeName": en(&format!("{}: trusted issuers", options.operator_name)),
        "SchemeInformationURI": uri(base),
        "ListIssueDateTime": crate::iso8601_utc(now),
        "NextUpdate": crate::iso8601_utc(now.saturating_add(ttl_secs)),
        "DistributionPoints": [format!("{base}/v1/lote")],
    });
    if let Some(territory) = &options.territory {
        info["SchemeTerritory"] = json!(territory);
    }
    let entities: Vec<Value> = registry
        .list()
        .filter_map(|record| {
            let trusted: Vec<&String> = record
                .credential_types
                .iter()
                .filter(|t| registry.check(&record.id, t, now).trusted)
                .collect();
            if trusted.is_empty() {
                return None;
            }
            let record_uri = format!("{base}/v1/issuers/{}", encode_component(&record.id));
            let web_address = match IdKind::of(&record.id) {
                IdKind::Url => record.id.clone(),
                IdKind::Did => record_uri.clone(),
            };
            let service_type = if record.role.can_accredit() {
                SERVICE_TYPE_ACCREDITATION
            } else {
                SERVICE_TYPE_ISSUANCE
            };
            let mut identity = json!({"OtherIds": [record.id]});
            if !record.x509_certificates.is_empty() {
                identity["X509Certificates"] = record
                    .x509_certificates
                    .iter()
                    .map(|der| json!({"val": der}))
                    .collect();
            }
            let services: Vec<Value> = trusted
                .iter()
                .map(|credential_type| {
                    json!({"ServiceInformation": {
                        "ServiceName": en(credential_type),
                        "ServiceDigitalIdentity": identity,
                        "ServiceTypeIdentifier": service_type,
                    }})
                })
                .collect();
            Some(json!({
                "TrustedEntityInformation": {
                    "TEName": en(record.name.as_deref().unwrap_or(&record.id)),
                    "TEAddress": {
                        "TEPostalAddress": [],
                        "TEElectronicAddress": uri(&web_address),
                    },
                    "TEInformationURI": uri(&record_uri),
                },
                "TrustedEntityServices": services,
            }))
        })
        .collect();
    json!({"LoTE": {
        "ListAndSchemeInformation": info,
        "TrustedEntitiesList": entities,
    }})
}

/// The LoTE document signed by the registry as a compact ES256 JWS
/// (`typ` [`LOTE_TYP`], `kid` the registry's key), verifiable against the
/// registry's DID document like the snapshot. Not a JAdES baseline
/// signature: the registry signs with its DID key and has no X.509
/// certificate to put in `x5c`.
pub fn sign_lote(lote: &Value, key: &dcp_core::DcpKeyPair) -> String {
    crate::snapshot::sign_with_typ(lote, key, LOTE_TYP)
}

/// Percent-encodes `s` as one URI path segment: everything but RFC 3986
/// unreserved characters is escaped, so an id's `:`, `/` and `%` stay
/// inside the segment (as the registry API expects).
fn encode_component(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IssuerRecord, Role, Status};

    const ROOT: &str = "did:web:authority.example";
    const TAO: &str = "did:web:tao.example";
    const TI: &str = "https://issuer.example/tenants/acme";
    const ORPHAN: &str = "did:web:orphan.example";
    const NOW: u64 = 1_792_000_000;

    fn rec(id: &str, role: Role, types: &[&str], by: Option<&str>) -> IssuerRecord {
        IssuerRecord {
            id: id.into(),
            role,
            name: None,
            credential_types: types.iter().map(|t| t.to_string()).collect(),
            accredited_by: by.map(Into::into),
            valid_from: None,
            valid_until: None,
            status: Status::Active,
            x509_certificates: Vec::new(),
            updated_at: 0,
        }
    }

    fn options() -> LoteOptions {
        LoteOptions {
            operator_name: "Example Dataspace Authority".into(),
            base_url: "https://registry.example".into(),
            lote_type: DEFAULT_LOTE_TYPE.into(),
            territory: Some("EU".into()),
        }
    }

    fn registry() -> Registry {
        let mut r = Registry::default();
        let mut root = rec(ROOT, Role::RootTao, &["*"], None);
        root.name = Some("Example Dataspace Authority".into());
        r.upsert(root, 1).unwrap();
        r.upsert(
            rec(TAO, Role::Tao, &["MembershipCredential", "PID"], Some(ROOT)),
            1,
        )
        .unwrap();
        let mut ti = rec(TI, Role::Ti, &["MembershipCredential", "PID"], Some(TAO));
        ti.name = Some("ACME".into());
        r.upsert(ti, 1).unwrap();
        r.upsert(rec(ORPHAN, Role::Ti, &["PID"], Some(TAO)), 1)
            .unwrap();
        r
    }

    fn entity<'a>(lote: &'a Value, id: &str) -> Option<&'a Value> {
        lote["LoTE"]["TrustedEntitiesList"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| {
                e["TrustedEntityServices"][0]["ServiceInformation"]["ServiceDigitalIdentity"]
                    ["OtherIds"][0]
                    == id
            })
    }

    #[test]
    fn the_scheme_information_follows_the_json_binding() {
        let lote = build_lote(&registry(), &options(), NOW, 3600);
        let info = &lote["LoTE"]["ListAndSchemeInformation"];
        assert_eq!(info["LoTEVersionIdentifier"], LOTE_VERSION);
        assert_eq!(info["LoTESequenceNumber"], registry().version + 1);
        assert_eq!(info["LoTEType"], DEFAULT_LOTE_TYPE);
        assert_eq!(
            info["SchemeOperatorName"],
            json!([{"lang": "en", "value": "Example Dataspace Authority"}])
        );
        assert_eq!(
            info["SchemeOperatorAddress"]["SchemeOperatorElectronicAddress"][0]["uriValue"],
            "https://registry.example"
        );
        assert!(info["SchemeOperatorAddress"]["SchemeOperatorPostalAddress"].is_array());
        assert_eq!(info["SchemeName"][0]["lang"], "en");
        assert_eq!(
            info["SchemeInformationURI"][0]["uriValue"],
            "https://registry.example"
        );
        assert_eq!(info["SchemeTerritory"], "EU");
        assert_eq!(info["ListIssueDateTime"], "2026-10-14T17:46:40Z");
        assert_eq!(info["NextUpdate"], "2026-10-14T18:46:40Z");
        assert_eq!(
            info["DistributionPoints"],
            json!(["https://registry.example/v1/lote"])
        );
        // No ServiceStatus outside the Pub-EAA profile, so no status approach.
        assert!(info.get("StatusDeterminationApproach").is_none());
    }

    #[test]
    fn trusted_parties_are_entities_with_one_service_per_trusted_type() {
        let mut r = registry();
        r.set_status(ORPHAN, Status::Revoked, 2).unwrap();
        let lote = build_lote(&r, &options(), NOW, 3600);
        assert_eq!(
            lote["LoTE"]["TrustedEntitiesList"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert!(
            entity(&lote, ORPHAN).is_none(),
            "revoked parties are left out"
        );

        let ti = entity(&lote, TI).expect("the TI is listed");
        let info = &ti["TrustedEntityInformation"];
        assert_eq!(info["TEName"], json!([{"lang": "en", "value": "ACME"}]));
        assert_eq!(
            info["TEInformationURI"][0]["uriValue"],
            "https://registry.example/v1/issuers/https%3A%2F%2Fissuer.example%2Ftenants%2Facme"
        );
        assert_eq!(info["TEAddress"]["TEElectronicAddress"][0]["uriValue"], TI);
        assert!(info["TEAddress"]["TEPostalAddress"].is_array());
        let services = ti["TrustedEntityServices"].as_array().unwrap();
        let names: Vec<&str> = services
            .iter()
            .map(|s| {
                s["ServiceInformation"]["ServiceName"][0]["value"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert_eq!(names, vec!["MembershipCredential", "PID"]);
        let svc = &services[0]["ServiceInformation"];
        assert_eq!(svc["ServiceTypeIdentifier"], SERVICE_TYPE_ISSUANCE);
        assert!(svc.get("ServiceStatus").is_none());
        assert_eq!(svc["ServiceDigitalIdentity"]["OtherIds"], json!([TI]));

        let tao = entity(&lote, TAO).unwrap();
        assert_eq!(
            tao["TrustedEntityServices"][0]["ServiceInformation"]["ServiceTypeIdentifier"],
            SERVICE_TYPE_ACCREDITATION
        );
        // A DID has no web address of its own: the registry record stands in.
        assert_eq!(
            tao["TrustedEntityInformation"]["TEAddress"]["TEElectronicAddress"][0]["uriValue"],
            "https://registry.example/v1/issuers/did%3Aweb%3Atao.example"
        );
    }

    #[test]
    fn a_broken_chain_or_a_narrowed_scope_drops_entities_and_services() {
        let mut r = registry();
        // Narrow the TAO: the TI keeps only MembershipCredential.
        let mut tao = r.get(TAO).unwrap().clone();
        tao.credential_types = vec!["MembershipCredential".into()];
        r.issuers.insert(TAO.into(), tao);
        let lote = build_lote(&r, &options(), NOW, 3600);
        let ti = entity(&lote, TI).unwrap();
        assert_eq!(ti["TrustedEntityServices"].as_array().unwrap().len(), 1);
        assert!(entity(&lote, ORPHAN).is_none(), "nothing left it may issue");

        r.set_status(TAO, Status::Suspended, 3).unwrap();
        let lote = build_lote(&r, &options(), NOW, 3600);
        assert!(entity(&lote, TI).is_none());
        assert!(entity(&lote, TAO).is_none());
        assert!(entity(&lote, ROOT).is_some());
    }

    #[test]
    fn x509_anchors_are_service_digital_identities() {
        let mut r = registry();
        let iaca = crate::x509::tests::b64(crate::x509::tests::ca("IACA", None).der());
        let mut ti = r.get(TI).unwrap().clone();
        ti.x509_certificates = vec![iaca.clone()];
        r.upsert(ti, 2).unwrap();
        let lote = build_lote(&r, &options(), NOW, 3600);
        let sdi = &entity(&lote, TI).unwrap()["TrustedEntityServices"][0]["ServiceInformation"]["ServiceDigitalIdentity"];
        assert_eq!(sdi["X509Certificates"], json!([{"val": iaca}]));
    }

    #[test]
    fn the_root_wildcard_is_one_service() {
        let lote = build_lote(&registry(), &options(), NOW, 3600);
        let root = entity(&lote, ROOT).unwrap();
        let services = root["TrustedEntityServices"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(
            services[0]["ServiceInformation"]["ServiceName"][0]["value"],
            "*"
        );
    }
}
