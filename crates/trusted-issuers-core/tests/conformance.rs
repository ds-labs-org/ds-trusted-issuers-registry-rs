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
//! - C2SP x509-limbo: `check_x5c` against every path validation case it
//!   applies to (see [`limbo_skip`] for the ones it does not).

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

/// The base64 DER inside a PEM certificate: what a record's
/// `x509Certificates` and an `x5c` hold.
fn pem_body(pem: &str) -> String {
    pem.lines().filter(|l| !l.starts_with("-----")).collect()
}

/// Unix seconds of an RFC 3339 UTC time such as `2024-01-01T00:00:00+00:00`
/// (fractions of a second are dropped).
fn unix_time(rfc3339: &str) -> u64 {
    let field = |range: std::ops::Range<usize>| -> i64 { rfc3339[range].parse().unwrap() };
    assert!(rfc3339.ends_with("+00:00"), "{rfc3339} is not UTC");
    let (y, m, d) = (field(0..4), field(5..7), field(8..10));
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (days * 86_400 + field(11..13) * 3600 + field(14..16) * 60 + field(17..19)) as u64
}

const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// Why a limbo case does not apply to `check_x5c`, if it does not.
fn limbo_skip(case: &Value) -> Option<&'static str> {
    let features: Vec<&str> = case["features"]
        .as_array()
        .map(|f| f.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let has = |f: &str| features.contains(&f);
    if has("has-crl") {
        Some("revocation: the registry's own status replaces CRLs")
    } else if has("has-mldsa") {
        Some("ML-DSA: not among webpki's algorithms")
    } else if has("max-chain-depth") {
        Some("a caller-chosen maximum chain depth, which check_x5c does not take")
    } else if features.iter().any(|f| f.starts_with("pedantic-")) {
        Some("pedantic: rules limbo itself marks as beyond what validators enforce")
    } else if case["key_usage"].as_array().is_some_and(|k| !k.is_empty()) {
        Some("a required key usage, which check_x5c does not take")
    } else {
        None
    }
}

/// `check_x5c`'s verdict on a limbo case, plus the name check a TLS
/// client would add (the registry identifies an issuer by its anchor, not
/// by a name in its certificate, so that part is the harness's).
fn limbo_verdict(case: &Value) -> Result<(), String> {
    use base64::Engine;
    let at = case["validation_time"]
        .as_str()
        .map(unix_time)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|pem| pem_body(pem.as_str().unwrap()))
            .collect()
    };
    let mut root = record("did:web:limbo.example", Role::RootTao, &["*"], None);
    root.x509_certificates = strings(&case["trusted_certs"]);
    let mut registry = Registry::default();
    registry
        .upsert(root, at)
        .map_err(|e| format!("anchor refused: {e}"))?;
    let peer = pem_body(case["peer_certificate"].as_str().unwrap());
    let mut x5c = vec![peer.clone()];
    x5c.extend(strings(&case["untrusted_intermediates"]));
    let ekus: Vec<&str> = case["extended_key_usage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| match e.as_str().unwrap() {
            "serverAuth" => SERVER_AUTH,
            "clientAuth" => CLIENT_AUTH,
            other => panic!("unmapped EKU {other}"),
        })
        .collect();
    let eku = match (ekus.as_slice(), case["validation_kind"].as_str()) {
        ([], Some("SERVER")) => SERVER_AUTH,
        ([], Some("CLIENT")) => CLIENT_AUTH,
        ([one], _) => one,
        (more, kind) => panic!("{more:?} for {kind:?}"),
    };
    let decision = registry.check_x5c(&x5c, "AnyCredential", at, Some(eku));
    if !decision.trusted {
        return Err(decision.reason.unwrap_or_default());
    }
    let Some(name) = case["expected_peer_name"].as_object() else {
        return Ok(());
    };
    let der = base64::engine::general_purpose::STANDARD
        .decode(&peer)
        .unwrap();
    let der = rustls_pki_types::CertificateDer::from(der);
    let leaf = webpki::EndEntityCert::try_from(&der).map_err(|e| e.to_string())?;
    let value = name["value"].as_str().unwrap();
    let server_name = match name["kind"].as_str().unwrap() {
        "DNS" => rustls_pki_types::ServerName::try_from(value)
            .map_err(|e| format!("{value}: {e}"))?
            .to_owned(),
        "IP" => rustls_pki_types::ServerName::IpAddress(
            value
                .parse::<std::net::IpAddr>()
                .map_err(|e| format!("{value}: {e}"))?
                .into(),
        ),
        other => panic!("unmapped peer name kind {other}"),
    };
    leaf.verify_is_valid_for_subject_name(&server_name)
        .map_err(|e| format!("name {value}: {e}"))
}

/// Limbo cases `check_x5c` knowingly decides otherwise, by reason. The test
/// fails on any other disagreement, and on a listed case that agrees again,
/// so the list stays exact.
const LIMBO_DIVERGENCES: &[(&str, &[&str])] = &[
    (
        "check_x5c requires the asked-for EKU on the leaf, as ISO 18013-5 does \
         for document signers, where RFC 5280 reads no EKU as any",
        &[
            "pathlen::validation-ignores-pathlen-in-leaf",
            "rfc5280::eku::ee-without-eku",
            "rfc5280::ca-as-leaf",
        ],
    ),
    (
        "webpki does not build paths through self-issued intermediates (key rollover)",
        &[
            "pathlen::self-issued-certs-pathlen",
            "rfc5280::nc::permitted-self-issued",
        ],
    ),
    (
        "webpki supports neither email nor directory-name constraints, so it refuses them",
        &[
            "rfc5280::nc::permitted-dn-match",
            "rfc5280::nc::nc-permits-email-exact",
            "rfc5280::nc::nc-permits-email-domain",
            "rfc5280::nc::nc-permits-email-literal-asterisk-exact-match",
            "rfc5280::nc::nc-permits-email-literal-double-asterisk",
            "rfc5280::nc::nc-permits-email-literal-mid-asterisk",
        ],
    ),
    (
        "webpki does not require AKI/SKI, nor check their criticality",
        &[
            "rfc5280::aki::critical-aki",
            "rfc5280::aki::leaf-missing-aki",
            "rfc5280::aki::intermediate-missing-aki",
            "rfc5280::ski::critical-ski",
            "rfc5280::ski::root-missing-ski",
            "rfc5280::ski::intermediate-missing-ski",
        ],
    ),
    (
        "webpki does not check the criticality or encoding of these extensions",
        &[
            "rfc5280::nc::permitted-dns-match-noncritical",
            "rfc5280::nc::invalid-dnsname-leading-period",
            "rfc5280::nc::not-allowed-in-ee-noncritical",
            "rfc5280::nc::not-allowed-in-ee-critical",
            "rfc5280::pc::ica-noncritical-pc",
            "rfc5280::san::noncritical-with-empty-subject",
            "rfc5280::ca-empty-subject",
            "rfc5280::leaf-ku-keycertsign",
            "webpki::nc::intermediate-permitted-excluded-subtrees-both-null",
            "webpki::nc::intermediate-permitted-excluded-subtrees-both-empty-sequences",
            "webpki::san::san-critical-with-nonempty-subject",
            "webpki::malformed-aia",
        ],
    ),
    (
        "webpki accepts underscores in DNS names (the name check is the harness's)",
        &["rfc5280::san::underscore-dns"],
    ),
    (
        "CA/Browser Forum rules on the subject CN, a Web PKI profile: an issuer \
         is named by its registry record, not its certificate",
        &[
            "webpki::cn::ipv4-hex-mismatch",
            "webpki::cn::ipv4-leading-zeros-mismatch",
            "webpki::cn::ipv6-uppercase-mismatch",
            "webpki::cn::ipv6-uncompressed-mismatch",
            "webpki::cn::ipv6-non-rfc5952-mismatch",
            "webpki::cn::punycode-not-in-san",
            "webpki::cn::utf8-vs-punycode-mismatch",
            "webpki::cn::not-in-san",
            "webpki::cn::case-mismatch",
        ],
    ),
    (
        "a trust anchor's own extensions and key are not checked: the registry \
         admin vouches for it by listing it (its validity period and CA flag are)",
        &[
            "rfc5280::unknown-critical-extension-root",
            "rfc5280::root-non-critical-basic-constraints",
            "rfc5280::root-inconsistent-ca-extensions",
            "webpki::aki::root-with-aki-missing-keyidentifier",
            "webpki::aki::root-with-aki-authoritycertissuer",
            "webpki::aki::root-with-aki-authoritycertserialnumber",
            "webpki::aki::root-with-aki-all-fields",
            "webpki::aki::root-with-aki-ski-mismatch",
            "webpki::forbidden-rsa-not-divisible-by-8-in-root",
        ],
    ),
];

#[test]
#[ignore = "needs conformance/fetch.sh"]
fn check_x5c_agrees_with_x509_limbo() {
    let limbo = json("limbo/limbo.json");
    let mut skipped: std::collections::BTreeMap<&str, usize> = Default::default();
    let known: std::collections::BTreeSet<&str> = LIMBO_DIVERGENCES
        .iter()
        .flat_map(|(_, ids)| ids.iter().copied())
        .collect();
    let mut mismatches = Vec::new();
    let mut agreeing_again = Vec::new();
    let mut ran = 0;
    for case in limbo["testcases"].as_array().unwrap() {
        if let Some(reason) = limbo_skip(case) {
            *skipped.entry(reason).or_default() += 1;
            continue;
        }
        ran += 1;
        let expected = case["expected_result"] == "SUCCESS";
        let verdict = limbo_verdict(case);
        let id = case["id"].as_str().unwrap();
        match (verdict.is_ok() != expected, known.contains(id)) {
            (true, false) => mismatches.push(format!(
                "{id}: expected {}, got {verdict:?}",
                case["expected_result"]
            )),
            (false, true) => agreeing_again.push(id),
            _ => {}
        }
    }
    eprintln!(
        "x509-limbo: {ran} cases run, {} known divergences, skipped {skipped:#?}",
        known.len()
    );
    assert!(
        mismatches.is_empty(),
        "{} of {ran} disagree:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert!(
        agreeing_again.is_empty(),
        "listed as divergences but agree with limbo now: {agreeing_again:?}"
    );
}
