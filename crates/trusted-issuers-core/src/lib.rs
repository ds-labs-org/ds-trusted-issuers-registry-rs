//! Trusted issuers registry domain, network-free so any verifier can embed
//! it: [`model`] (records), [`registry`] (write rules and the
//! accreditation-chain trust check) and [`snapshot`] (the signed,
//! offline-cacheable trust list).

pub mod accreditation;
pub mod audit;
pub mod lote;
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
pub use lote::{
    DEFAULT_LOTE_TYPE, LOTE_TYP, LOTE_VERSION, LoteOptions, SERVICE_TYPE_ACCREDITATION,
    SERVICE_TYPE_ISSUANCE, build_lote,
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

/// Unix seconds as an ISO 8601 / `xsd:dateTime` UTC timestamp
/// (`2026-10-17T06:00:00Z`), as VC dates and PROV times use.
pub fn iso8601_utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso8601_utc_formats_unix_seconds() {
        assert_eq!(super::iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::iso8601_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::iso8601_utc(1_792_000_000), "2026-10-14T17:46:40Z");
    }
}
