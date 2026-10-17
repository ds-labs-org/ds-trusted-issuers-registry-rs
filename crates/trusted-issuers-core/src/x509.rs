//! X.509 trust anchors: for credentials whose issuer is proven by a
//! certificate chain rather than by a DID or OID4VCI issuer metadata, such
//! as an ISO mdoc/mDL (its document signer certificate chains to the
//! issuing authority's IACA root) or an SD-JWT VC signed with an `x5c`
//! header.
//!
//! A record lists its anchors in `x509Certificates`. [`Registry::check_x5c`]
//! finds the record whose anchor the presented chain validates against
//! (with `rustls-webpki`: signatures, validity periods, CA constraints,
//! path length and name constraints, and optionally an extended key usage),
//! then runs the ordinary accreditation-chain check on that record. Both
//! must pass: a valid chain to the anchor of a suspended party, or of one
//! not scoped for the credential type, is not trusted.

use std::time::Duration;

use base64::Engine;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeId, KeyPurposeIdIter};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::ext::pkix::ExtendedKeyUsage;

use crate::model::IssuerRecord;
use crate::registry::{Registry, RegistryError, TrustDecision};

/// Most anchors one record may list.
pub const MAX_ANCHORS_PER_RECORD: usize = 10;

/// Largest anchor certificate accepted, in DER bytes.
pub const MAX_ANCHOR_BYTES: usize = 16 * 1024;

/// The DER encoding of a dotted OID such as `1.0.18013.5.1.2` (the mDL
/// document signer extended key usage), or `None` when it isn't one.
pub fn oid_der(dotted: &str) -> Option<Vec<u8>> {
    parse_oid(dotted).map(|oid| oid.as_bytes().to_vec())
}

/// A dotted OID written one way only: arcs of ASCII digits, none empty and
/// none with a leading zero. `const-oid` alone reads `1..2` as `1.2`.
fn parse_oid(dotted: &str) -> Option<ObjectIdentifier> {
    let well_formed = dotted.split('.').all(|arc| {
        !arc.is_empty()
            && arc.bytes().all(|c| c.is_ascii_digit())
            && (arc == "0" || !arc.starts_with('0'))
    });
    well_formed
        .then(|| ObjectIdentifier::new(dotted).ok())
        .flatten()
}

/// Standard, padded base64 as in a JOSE `x5c`.
fn decode(b64: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("not base64: {e}"))
}

/// Checks a record's `x509Certificates` on write: each decodes, is at most
/// [`MAX_ANCHOR_BYTES`], parses as a trust anchor and is listed once, at
/// most [`MAX_ANCHORS_PER_RECORD`] of them, and none is listed under
/// another record (one anchor, one party, so a chain never proves two
/// issuers).
pub(crate) fn check_anchors(
    registry: &Registry,
    record: &IssuerRecord,
) -> Result<(), RegistryError> {
    let invalid = |index, reason: String| RegistryError::InvalidCertificate { index, reason };
    if record.x509_certificates.len() > MAX_ANCHORS_PER_RECORD {
        return Err(invalid(
            MAX_ANCHORS_PER_RECORD,
            format!("at most {MAX_ANCHORS_PER_RECORD} anchors per record"),
        ));
    }
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for (index, b64) in record.x509_certificates.iter().enumerate() {
        let der = decode(b64).map_err(|e| invalid(index, e))?;
        if der.len() > MAX_ANCHOR_BYTES {
            return Err(invalid(
                index,
                format!("larger than {MAX_ANCHOR_BYTES} bytes"),
            ));
        }
        let cert = CertificateDer::from(der.as_slice());
        webpki::anchor_from_trusted_cert(&cert)
            .map_err(|e| invalid(index, format!("not an X.509 certificate: {e}")))?;
        if seen.contains(&der) {
            return Err(invalid(index, "listed twice".into()));
        }
        seen.push(der);
    }
    for other in registry.list().filter(|o| o.id != record.id) {
        let shared = other
            .x509_certificates
            .iter()
            .filter_map(|b64| decode(b64).ok())
            .any(|der| seen.contains(&der));
        if shared {
            return Err(RegistryError::DuplicateAnchor {
                other: other.id.clone(),
            });
        }
    }
    Ok(())
}

/// The EKU rule applied to every certificate of a path: one with no EKU
/// extension passes, one with EKUs must list `required` (when given). The
/// leaf must additionally carry it, which [`leaf_has_eku`] checks; webpki
/// runs this validator on intermediates too, and CAs commonly have no EKU.
struct EkuPolicy<'a> {
    required: Option<&'a [u8]>,
}

impl ExtendedKeyUsageValidator for EkuPolicy<'_> {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        let Some(required) = self.required else {
            return Ok(());
        };
        let wanted = KeyPurposeId::new(required);
        let mut empty = true;
        for id in iter {
            empty = false;
            if id? == wanted {
                return Ok(());
            }
        }
        if empty {
            Ok(())
        } else {
            #[allow(deprecated)]
            Err(webpki::Error::RequiredEkuNotFound)
        }
    }
}

/// Whether the leaf certificate lists `oid` among its extended key usages.
fn leaf_has_eku(leaf: &[u8], oid: &ObjectIdentifier) -> bool {
    let Ok(cert) = Certificate::from_der(leaf) else {
        return false;
    };
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|ext| ext.extn_id == ExtendedKeyUsage::OID)
        .filter_map(|ext| ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).ok())
        .any(|eku| eku.0.contains(oid))
}

fn untrusted(reason: impl Into<String>) -> TrustDecision {
    TrustDecision {
        trusted: false,
        chain: Vec::new(),
        reason: Some(reason.into()),
    }
}

impl Registry {
    /// Whether the certificate chain `x5c` (base64 DER, leaf first, as in a
    /// JOSE `x5c` header or an mdoc `x5chain`) proves an issuer trusted for
    /// `credential_type` at `now`: it must validate against a listed
    /// anchor, and the record holding that anchor must pass
    /// [`Registry::check`]. With `eku` (a dotted OID), the leaf must carry
    /// that extended key usage; without it any (or no) EKU is accepted.
    ///
    /// On success the decision's chain starts at the matched record's id.
    pub fn check_x5c(
        &self,
        x5c: &[String],
        credential_type: &str,
        now: u64,
        eku: Option<&str>,
    ) -> TrustDecision {
        let Some((leaf_b64, rest)) = x5c.split_first() else {
            return untrusted("the certificate chain is empty");
        };
        let eku_oid = match eku {
            None => None,
            Some(dotted) => match parse_oid(dotted) {
                Some(oid) => Some(oid),
                None => return untrusted(format!("'{dotted}' is not an OID")),
            },
        };
        let decoded: Result<Vec<Vec<u8>>, String> = std::iter::once(leaf_b64)
            .chain(rest)
            .map(|b| decode(b))
            .collect();
        let decoded = match decoded {
            Ok(d) => d,
            Err(e) => return untrusted(format!("the certificate chain is malformed: {e}")),
        };
        let leaf_der = CertificateDer::from(decoded[0].as_slice());
        let leaf = match EndEntityCert::try_from(&leaf_der) {
            Ok(leaf) => leaf,
            Err(e) => return untrusted(format!("the leaf is not an X.509 certificate: {e}")),
        };
        if let Some(oid) = &eku_oid
            && !leaf_has_eku(&decoded[0], oid)
        {
            return untrusted(format!(
                "the leaf certificate lacks extended key usage {oid}"
            ));
        }
        let intermediates: Vec<CertificateDer<'_>> = decoded[1..]
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        let policy = EkuPolicy {
            required: eku_oid.as_ref().map(|oid| oid.as_bytes()),
        };
        let time = UnixTime::since_unix_epoch(Duration::from_secs(now));
        let mut last_error = None;
        for record in self.list().filter(|r| !r.x509_certificates.is_empty()) {
            let ders: Vec<CertificateDer<'static>> = record
                .x509_certificates
                .iter()
                .filter_map(|b64| decode(b64).ok())
                .map(CertificateDer::from)
                .collect();
            let anchors: Vec<TrustAnchor<'_>> = ders
                .iter()
                .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
                .collect();
            match leaf.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediates,
                time,
                &policy,
                None,
                None,
            ) {
                Ok(_) => return self.check(&record.id, credential_type, now),
                Err(e) => last_error = Some(e),
            }
        }
        untrusted(match last_error {
            None => "no record lists an X.509 trust anchor".to_string(),
            Some(e) => format!(
                "the certificate chain does not validate against a listed trust anchor: {e}"
            ),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{IssuerRecord, Role, Status};
    use crate::registry::RegistryError;
    use base64::Engine;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    const ROOT: &str = "did:web:authority.example";
    const MDL_ISSUER: &str = "https://mdl.example";
    pub(crate) const MDL_DS_EKU: &str = "1.0.18013.5.1.2";
    const NOW: u64 = 1_792_000_000;

    pub(crate) fn b64(der: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// A CA (an IACA root, or an intermediate when `parent` is given).
    pub(crate) fn ca(
        cn: &str,
        parent: Option<&CertifiedIssuer<'static, KeyPair>>,
    ) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let key = KeyPair::generate().unwrap();
        match parent {
            None => CertifiedIssuer::self_signed(params, key).unwrap(),
            Some(parent) => CertifiedIssuer::signed_by(params, key, parent).unwrap(),
        }
    }

    /// A leaf (a document signer) issued by `issuer`.
    pub(crate) fn leaf(
        issuer: &CertifiedIssuer<'static, KeyPair>,
        eku: Option<&[u64]>,
        not_after: (i32, u8, u8),
    ) -> String {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Document Signer");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if let Some(oid) = eku {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(oid.to_vec())];
        }
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = KeyPair::generate().unwrap();
        b64(params.signed_by(&key, issuer).unwrap().der())
    }

    const MDL_DS: &[u64] = &[1, 0, 18013, 5, 1, 2];

    fn record(
        id: &str,
        role: Role,
        types: &[&str],
        by: Option<&str>,
        anchors: Vec<String>,
    ) -> IssuerRecord {
        IssuerRecord {
            id: id.into(),
            role,
            name: None,
            credential_types: types.iter().map(|t| t.to_string()).collect(),
            accredited_by: by.map(Into::into),
            valid_from: None,
            valid_until: None,
            status: Status::Active,
            x509_certificates: anchors,
            postal_address: None,
            updated_at: 0,
        }
    }

    struct Pki {
        iaca: CertifiedIssuer<'static, KeyPair>,
        registry: Registry,
    }

    fn pki() -> Pki {
        let iaca = ca("Example IACA", None);
        let mut registry = Registry::default();
        registry
            .upsert(record(ROOT, Role::RootTao, &["*"], None, vec![]), 1)
            .unwrap();
        registry
            .upsert(
                record(
                    MDL_ISSUER,
                    Role::Ti,
                    &["org.iso.18013.5.1.mDL"],
                    Some(ROOT),
                    vec![b64(iaca.der())],
                ),
                1,
            )
            .unwrap();
        Pki { iaca, registry }
    }

    #[test]
    fn oids_are_der_encoded() {
        assert_eq!(
            oid_der("1.0.18013.5.1.2"),
            Some(vec![0x28, 0x81, 0x8c, 0x5d, 0x05, 0x01, 0x02])
        );
        assert_eq!(
            oid_der("1.3.6.1.5.5.7.3.1"),
            Some(vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])
        );
        for bad in [
            "", "1", "3.1", "1.40", "1.2.x", "1..2", "1.2.", "1.02", ".1.2",
        ] {
            assert_eq!(oid_der(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_chain_to_a_listed_anchor_of_a_trusted_party_is_trusted() {
        let p = pki();
        let ds = leaf(&p.iaca, Some(MDL_DS), (2030, 1, 1));
        let d = p.registry.check_x5c(
            std::slice::from_ref(&ds),
            "org.iso.18013.5.1.mDL",
            NOW,
            None,
        );
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec![MDL_ISSUER, ROOT]);
        // With the mDL document signer EKU required.
        let d = p
            .registry
            .check_x5c(&[ds], "org.iso.18013.5.1.mDL", NOW, Some(MDL_DS_EKU));
        assert!(d.trusted, "{d:?}");
    }

    #[test]
    fn a_chain_through_an_intermediate_is_trusted() {
        let p = pki();
        let intermediate = ca("Example intermediate", Some(&p.iaca));
        let ds = leaf(&intermediate, None, (2030, 1, 1));
        let d = p.registry.check_x5c(
            &[ds, b64(intermediate.der())],
            "org.iso.18013.5.1.mDL",
            NOW,
            None,
        );
        assert!(d.trusted, "{d:?}");
    }

    #[test]
    fn chains_that_do_not_validate_are_not_trusted() {
        let p = pki();
        let other = ca("Someone else's CA", None);
        for (why, x5c, eku) in [
            ("unlisted CA", vec![leaf(&other, None, (2030, 1, 1))], None),
            (
                "expired leaf",
                vec![leaf(&p.iaca, None, (2026, 1, 1))],
                None,
            ),
            (
                "missing EKU",
                vec![leaf(&p.iaca, None, (2030, 1, 1))],
                Some(MDL_DS_EKU),
            ),
            ("not base64", vec!["%%%".to_string()], None),
            ("not a certificate", vec![b64(b"hello")], None),
            ("empty chain", vec![], None),
        ] {
            let d = p
                .registry
                .check_x5c(&x5c, "org.iso.18013.5.1.mDL", NOW, eku);
            assert!(!d.trusted, "{why}: {d:?}");
            assert!(d.chain.is_empty(), "{why}: {d:?}");
            assert!(d.reason.is_some(), "{why}");
        }
    }

    #[test]
    fn the_accreditation_chain_still_decides() {
        let mut p = pki();
        let ds = leaf(&p.iaca, None, (2030, 1, 1));
        // Out of scope.
        let d = p
            .registry
            .check_x5c(std::slice::from_ref(&ds), "MembershipCredential", NOW, None);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![MDL_ISSUER]);
        // Suspended accreditor.
        p.registry.set_status(ROOT, Status::Suspended, 2).unwrap();
        let d = p
            .registry
            .check_x5c(&[ds], "org.iso.18013.5.1.mDL", NOW, None);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![MDL_ISSUER, ROOT]);
    }

    #[test]
    fn anchors_are_checked_on_write() {
        let p = pki();
        let iaca = b64(p.iaca.der());
        let other = b64(ca("Other", None).der());
        let by_root = |anchors: Vec<String>| {
            record("https://x.example", Role::Ti, &["T"], Some(ROOT), anchors)
        };
        for (why, anchors) in [
            ("not base64", vec!["%%%".to_string()]),
            ("not a certificate", vec![b64(b"hello")]),
            ("too many", vec![other.clone(); MAX_ANCHORS_PER_RECORD + 1]),
            ("too big", vec![b64(&vec![0u8; MAX_ANCHOR_BYTES + 1])]),
        ] {
            let mut r = p.registry.clone();
            assert!(
                matches!(
                    r.upsert(by_root(anchors), 2),
                    Err(RegistryError::InvalidCertificate { .. })
                ),
                "{why}"
            );
        }
        // One anchor, one party: an anchor listed under another record is
        // refused, so a chain never proves two issuers at once.
        let mut r = p.registry.clone();
        assert_eq!(
            r.upsert(by_root(vec![iaca.clone()]), 2),
            Err(RegistryError::DuplicateAnchor {
                other: MDL_ISSUER.into()
            })
        );
        // Re-writing the record that holds it is fine.
        let mut again = p.registry.get(MDL_ISSUER).unwrap().clone();
        again.name = Some("renamed".into());
        assert_eq!(r.upsert(again, 3), Ok(()));
        // A different, valid anchor is fine.
        assert_eq!(r.upsert(by_root(vec![other]), 4), Ok(()));
    }

    #[test]
    fn a_snapshot_answers_x5c_checks_offline() {
        let p = pki();
        let key = dcp_core::DcpKeyPair::generate("did:web:registry.example".into());
        let token = crate::sign_snapshot(&p.registry, &key, NOW, 600);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(
            &[&[4u8][..], &key.public_key_xy.0, &key.public_key_xy.1].concat(),
        )
        .unwrap();
        let list = crate::verify_snapshot(&token, "did:web:registry.example", &vk, NOW).unwrap();
        let ds = leaf(&p.iaca, Some(MDL_DS), (2030, 1, 1));
        assert!(
            list.check_x5c(
                std::slice::from_ref(&ds),
                "org.iso.18013.5.1.mDL",
                NOW,
                Some(MDL_DS_EKU)
            )
            .trusted
        );
        assert!(
            !list
                .check_x5c(&[ds], "org.iso.18013.5.1.mDL", NOW + 601, None)
                .trusted
        );
    }
}
