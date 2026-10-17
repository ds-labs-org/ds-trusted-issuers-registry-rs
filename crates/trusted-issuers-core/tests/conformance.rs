//! Conformance against third-party suites and schemas, fetched (pinned and
//! checksummed) by `conformance/fetch.sh` into `target/conformance` (or
//! `$CONFORMANCE_DIR`). Ignored by default, since they need that material:
//!
//! ```sh
//! conformance/fetch.sh
//! cargo test -p trusted-issuers-core --test conformance -- --ignored
//! ```
//!
//! - ETSI TS 119 602: `build_lote`'s output against the standard's JSON
//!   schema (`1960201_json_schema.json`).
//! - EBSI: every link `issue_accreditations` signs against the official
//!   Verifiable Accreditation schema (`@cef-ebsi/vcdm1.1-accreditation-schema`).

use std::path::PathBuf;

use serde_json::Value;
use trusted_issuers_core::{
    IssuerRecord, LoteOptions, PostalAddress, Registry, Role, Status, build_lote,
    issue_accreditations,
};

const NOW: u64 = 1_792_000_000;

fn material(path: &str) -> PathBuf {
    let dir = std::env::var_os("CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance")
        });
    let file = dir.join(path);
    assert!(
        file.exists(),
        "{} is missing: run conformance/fetch.sh first",
        file.display()
    );
    file
}

fn json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(material(path)).unwrap()).unwrap()
}

fn record(id: &str, role: Role, types: &[&str], by: Option<&str>) -> IssuerRecord {
    IssuerRecord {
        id: id.into(),
        role,
        name: Some(format!("{id} (name)")),
        credential_types: types.iter().map(|t| t.to_string()).collect(),
        accredited_by: by.map(Into::into),
        valid_from: None,
        valid_until: None,
        status: Status::Active,
        x509_certificates: Vec::new(),
        postal_address: Some(address()),
        updated_at: 0,
    }
}

/// A three-tier registry with a DCP issuer, an OID4VCI issuer and an X.509
/// anchor: every shape the exports produce.
fn registry() -> Registry {
    let mut r = Registry::default();
    r.upsert(
        record("did:web:authority.example", Role::RootTao, &["*"], None),
        1,
    )
    .unwrap();
    r.upsert(
        record(
            "did:web:tao.example%3A8443",
            Role::Tao,
            &["MembershipCredential", "https://credentials.example/pid"],
            Some("did:web:authority.example"),
        ),
        1,
    )
    .unwrap();
    r.upsert(
        record(
            "did:web:issuer.example",
            Role::Ti,
            &["MembershipCredential"],
            Some("did:web:tao.example%3A8443"),
        ),
        1,
    )
    .unwrap();
    let mut oid4vci = record(
        "https://issuer.example/tenants/acme",
        Role::Ti,
        &["https://credentials.example/pid"],
        Some("did:web:tao.example%3A8443"),
    );
    oid4vci.x509_certificates = vec![self_signed_ca()];
    r.upsert(oid4vci, 1).unwrap();
    r
}

fn self_signed_ca() -> String {
    use base64::Engine;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example IACA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

fn address() -> PostalAddress {
    PostalAddress {
        street_address: "Rue de la Loi 200".into(),
        locality: "Brussels".into(),
        postal_code: Some("1049".into()),
        state_or_province: None,
        country: "BE".into(),
    }
}

fn lote_options() -> LoteOptions {
    LoteOptions {
        operator_name: "Example Dataspace Authority".into(),
        base_url: "https://registry.example".into(),
        lote_type: trusted_issuers_core::DEFAULT_LOTE_TYPE.into(),
        territory: Some("EU".into()),
        operator_address: address(),
    }
}

/// Serves the schemas the official ones reference by relative URI:
///
/// - ETSI's `rfcs/rfc7517.json#/definitions/jwk` (RFC 7517 JWK, only under
///   `PublicKeyValues`, which the LoTE export never emits) is not shipped
///   with the schema; it resolves to "any object".
/// - EBSI's accreditation schema extends
///   `./node_modules/@cef-ebsi/vcdm1.1-attestation-schema/schema.json`,
///   the attestation schema fetched next to it.
struct Schemas;

impl jsonschema::Retrieve for Schemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let path = uri.path().as_str();
        if path.ends_with("/rfcs/rfc7517.json") {
            Ok(serde_json::json!({"definitions": {"jwk": {"type": "object"}}}))
        } else if path.ends_with("/vcdm1.1-attestation-schema/schema.json") {
            Ok(json("ebsi/attestation.json"))
        } else {
            Err(format!("no local copy of {uri}").into())
        }
    }
}

/// Every schema violation in `instance`, as "pointer: message".
fn violations(schema: &Value, instance: &Value) -> Vec<String> {
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .with_base_uri("https://conformance.invalid/schemas/")
        .with_retriever(Schemas)
        .build(schema)
        .expect("a valid schema");
    validator
        .iter_errors(instance)
        .map(|e| format!("{}: {e}", e.instance_path))
        .collect()
}

#[test]
#[ignore = "needs conformance/fetch.sh"]
fn the_lote_conforms_to_the_etsi_ts_119_602_json_schema() {
    let schema = json("etsi/1960201_json_schema.json");
    let lote = build_lote(&registry(), &lote_options(), NOW, 3600);
    assert_eq!(
        lote["LoTE"]["TrustedEntitiesList"]
            .as_array()
            .unwrap()
            .len(),
        4,
        "every party is published: {lote:#}"
    );
    let errors = violations(&schema, &lote);
    assert!(errors.is_empty(), "{errors:#?}\n{lote:#}");
}

#[test]
#[ignore = "needs conformance/fetch.sh"]
fn accreditations_conform_to_the_ebsi_verifiable_accreditation_schema() {
    let schema = json("ebsi/accreditation.json");
    // EBSI's own examples pass, so a failure below is ours, not the setup's.
    for example in ["accredited-to-accredit", "accredited-to-attest"] {
        let errors = violations(&schema, &json(&format!("ebsi/examples/{example}.json")));
        assert!(errors.is_empty(), "{example}: {errors:#?}");
    }
    let registry = registry();
    let key = dcp_core::DcpKeyPair::generate("did:web:registry.example".into());
    let mut links = std::collections::BTreeMap::new();
    for issuer in [
        "did:web:issuer.example",
        "https://issuer.example/tenants/acme",
    ] {
        for token in issue_accreditations(&registry, issuer, &key, NOW, 3600).unwrap() {
            let (_, _, payload) = dcp_core::decode_jws_unverified(&token).unwrap();
            links.insert(payload["sub"].as_str().unwrap().to_string(), payload);
        }
    }
    assert_eq!(links.len(), 4, "the root, the TAO and both issuers");
    for (id, payload) in links {
        let errors = violations(&schema, &payload["vc"]);
        assert!(errors.is_empty(), "{id}: {errors:#?}\n{:#}", payload["vc"]);
    }
}
