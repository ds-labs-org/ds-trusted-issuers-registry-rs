//! Implements Contreforts' [`ContrefortsConnector`] trait for the registry
//! graph (`trusted-issuers-graph`), so the registry's issuer records and its
//! audit log are reachable through Contreforts' connector interface, the
//! same way `ds-identity-hub-rs` exposes its credential graph
//! (`identity-hub-contreforts`).
//!
//! Like the hub's connector, it reuses only Contreforts' interface (the
//! trait and the declaration mechanism) and mints its own entity kinds
//! ([`ISSUER_RECORD_KIND`], [`AUDIT_ENTRY_KIND`]) and namespace
//! (`declaration.ttl`). It is read-only: [`ContrefortsConnector::push`] is
//! refused, because a registry write must pass the registry's own rules
//! and land in its audit log, which only the admin API does.

use std::sync::Arc;

use chrono::NaiveDateTime;
use contreforts_core::{ConnectorError, ContrefortsConnector, Document, EntityKind};
use trusted_issuers_core::{AuditEntry, IdKind, IssuerRecord};
use trusted_issuers_graph::RegistryGraph;

/// A party in the registry; `remote_id` is its id (DID or URL).
pub const ISSUER_RECORD_KIND: &str = "ds-trusted-issuers-registry-rs:issuer-record";
/// One audited write; `remote_id` is its sequence number.
pub const AUDIT_ENTRY_KIND: &str = "ds-trusted-issuers-registry-rs:audit-entry";

fn to_api_err(e: trusted_issuers_graph::GraphError) -> ConnectorError {
    ConnectorError::Api {
        message: e.to_string(),
    }
}

/// Unix seconds as the naive UTC time Contreforts uses for `modified` and
/// `since`.
fn naive(unix: u64) -> Option<NaiveDateTime> {
    chrono::DateTime::from_timestamp(i64::try_from(unix).ok()?, 0).map(|t| t.naive_utc())
}

fn record_document(kind: EntityKind, source: &str, record: &IssuerRecord) -> Document {
    let mut fields = serde_json::to_value(record).expect("a record always serializes");
    fields["idKind"] = serde_json::to_value(IdKind::of(&record.id)).expect("a unit enum");
    Document {
        name: record.name.clone().unwrap_or_else(|| record.id.clone()),
        remote_id: record.id.clone(),
        kind,
        source: source.to_string(),
        modified: naive(record.updated_at),
        fields,
    }
}

fn entry_document(kind: EntityKind, source: &str, entry: &AuditEntry) -> Document {
    Document {
        name: format!("audit entry {}: {:?} {}", entry.seq, entry.action, entry.id),
        remote_id: entry.seq.to_string(),
        kind,
        source: source.to_string(),
        modified: naive(entry.at),
        fields: serde_json::to_value(entry).expect("an audit entry always serializes"),
    }
}

/// Whether a change at `modified` is newer than `since` (everything is,
/// without `since`).
fn after(modified: Option<NaiveDateTime>, since: Option<NaiveDateTime>) -> bool {
    since.is_none_or(|since| modified.is_some_and(|m| m > since))
}

/// Adapts a [`RegistryGraph`] to Contreforts' connector interface.
/// Recognises exactly [`ISSUER_RECORD_KIND`] and [`AUDIT_ENTRY_KIND`]; any
/// other kind is [`ConnectorError::UnsupportedKind`], never a silent empty
/// result. `since` keeps records whose `updatedAt`, and entries whose time,
/// is later.
pub struct RegistryGraphConnector {
    graph: Arc<RegistryGraph>,
}

impl RegistryGraphConnector {
    pub fn new(graph: Arc<RegistryGraph>) -> Self {
        Self { graph }
    }

    fn unsupported_kind(&self, kind: &EntityKind) -> ConnectorError {
        ConnectorError::UnsupportedKind {
            connector: self.source_name().to_string(),
            kind: kind.as_str().to_string(),
        }
    }
}

#[async_trait::async_trait]
impl ContrefortsConnector for RegistryGraphConnector {
    fn source_name(&self) -> &str {
        "ds-trusted-issuers-registry-rs"
    }

    fn declaration_ttl(&self) -> &'static str {
        include_str!("declaration.ttl")
    }

    async fn pull(
        &self,
        kind: EntityKind,
        since: Option<NaiveDateTime>,
    ) -> Result<Vec<Document>, ConnectorError> {
        let source = self.source_name();
        match kind.as_str() {
            ISSUER_RECORD_KIND => {
                let registry = self.graph.load().map_err(to_api_err)?;
                Ok(registry
                    .list()
                    .map(|r| record_document(kind.clone(), source, r))
                    .filter(|d| after(d.modified, since))
                    .collect())
            }
            AUDIT_ENTRY_KIND => {
                let entries = self.graph.audit().map_err(to_api_err)?;
                Ok(entries
                    .iter()
                    .map(|e| entry_document(kind.clone(), source, e))
                    .filter(|d| after(d.modified, since))
                    .collect())
            }
            _ => Err(self.unsupported_kind(&kind)),
        }
    }

    async fn get(&self, kind: EntityKind, remote_id: &str) -> Result<Document, ConnectorError> {
        let not_found = || ConnectorError::NotFound {
            kind: kind.as_str().to_string(),
            id: remote_id.to_string(),
        };
        match kind.as_str() {
            ISSUER_RECORD_KIND => {
                let registry = self.graph.load().map_err(to_api_err)?;
                let record = registry.get(remote_id).ok_or_else(not_found)?;
                Ok(record_document(kind.clone(), self.source_name(), record))
            }
            AUDIT_ENTRY_KIND => {
                let seq: u64 = remote_id.parse().map_err(|_| not_found())?;
                let entry = self
                    .graph
                    .audit_entry(seq)
                    .map_err(to_api_err)?
                    .ok_or_else(not_found)?;
                Ok(entry_document(kind.clone(), self.source_name(), &entry))
            }
            _ => Err(self.unsupported_kind(&kind)),
        }
    }

    /// Refused: a registry write must pass the registry's rules and land in
    /// its audit log, which only the admin API does.
    async fn push(&self, doc: &Document) -> Result<Document, ConnectorError> {
        Err(ConnectorError::Unsupported {
            connector: self.source_name().to_string(),
            operation: format!("push (kind: {})", doc.kind),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_issuers_core::{AuditAction, AuditRecord, Registry, Role, Status};

    const ROOT: &str = "did:web:authority.example";
    const TI: &str = "https://issuer.example/tenants/acme";

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

    /// ROOT written at t=1000, TI at t=2000 (updatedAt and audit time).
    fn graph() -> Arc<RegistryGraph> {
        let graph = RegistryGraph::open_in_memory().unwrap();
        let mut registry = Registry::default();
        let mut prev: Option<AuditEntry> = None;
        for (record, at) in [
            (rec(ROOT, Role::RootTao, &["*"], None), 1000),
            (
                rec(TI, Role::Ti, &["MembershipCredential"], Some(ROOT)),
                2000,
            ),
        ] {
            let id = record.id.clone();
            registry.upsert(record, at).unwrap();
            let entry = AuditEntry::next(
                prev.as_ref(),
                AuditRecord {
                    at,
                    actor: "alice".into(),
                    action: AuditAction::Put,
                    before: None,
                    after: registry.get(&id).cloned(),
                    id,
                    version: registry.version,
                },
            );
            graph.commit(&registry, &entry).unwrap();
            prev = Some(entry);
        }
        Arc::new(graph)
    }

    fn at(secs: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(secs, 0)
            .unwrap()
            .naive_utc()
    }

    #[tokio::test]
    async fn pull_returns_issuer_records_with_their_fields() {
        let c = RegistryGraphConnector::new(graph());
        let mut docs = c
            .pull(EntityKind::new(ISSUER_RECORD_KIND), None)
            .await
            .unwrap();
        docs.sort_by(|a, b| a.remote_id.cmp(&b.remote_id));
        assert_eq!(docs.len(), 2);
        let ti = &docs[1];
        assert_eq!(ti.remote_id, TI);
        assert_eq!(ti.name, format!("{TI} name"));
        assert_eq!(ti.source, "ds-trusted-issuers-registry-rs");
        assert_eq!(ti.modified, Some(at(2000)));
        assert_eq!(ti.fields["role"], "ti");
        assert_eq!(ti.fields["accreditedBy"], ROOT);
        assert_eq!(ti.fields["credentialTypes"][0], "MembershipCredential");
        assert_eq!(ti.fields["idKind"], "url");
        assert_eq!(docs[0].fields["idKind"], "did");
    }

    #[tokio::test]
    async fn pull_since_returns_only_newer_changes() {
        let c = RegistryGraphConnector::new(graph());
        let docs = c
            .pull(EntityKind::new(ISSUER_RECORD_KIND), Some(at(1500)))
            .await
            .unwrap();
        assert_eq!(
            docs.iter()
                .map(|d| d.remote_id.as_str())
                .collect::<Vec<_>>(),
            vec![TI]
        );
        let docs = c
            .pull(EntityKind::new(AUDIT_ENTRY_KIND), Some(at(1500)))
            .await
            .unwrap();
        assert_eq!(
            docs.iter()
                .map(|d| d.remote_id.as_str())
                .collect::<Vec<_>>(),
            vec!["2"]
        );
    }

    #[tokio::test]
    async fn pull_returns_the_audit_log_in_order() {
        let c = RegistryGraphConnector::new(graph());
        let docs = c
            .pull(EntityKind::new(AUDIT_ENTRY_KIND), None)
            .await
            .unwrap();
        assert_eq!(
            docs.iter()
                .map(|d| d.remote_id.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2"]
        );
        assert_eq!(docs[1].fields["actor"], "alice");
        assert_eq!(docs[1].fields["action"], "put");
        assert_eq!(docs[1].fields["id"], TI);
        assert_eq!(docs[1].fields["prevHash"], docs[0].fields["hash"]);
        assert_eq!(docs[1].modified, Some(at(2000)));
    }

    #[tokio::test]
    async fn get_fetches_one_record_or_entry() {
        let c = RegistryGraphConnector::new(graph());
        let doc = c
            .get(EntityKind::new(ISSUER_RECORD_KIND), TI)
            .await
            .unwrap();
        assert_eq!(doc.fields["status"], "active");
        // Any spelling of the id finds the record.
        let doc = c
            .get(
                EntityKind::new(ISSUER_RECORD_KIND),
                "HTTPS://Issuer.example/tenants/acme",
            )
            .await
            .unwrap();
        assert_eq!(doc.remote_id, TI);
        let doc = c.get(EntityKind::new(AUDIT_ENTRY_KIND), "1").await.unwrap();
        assert_eq!(doc.fields["id"], ROOT);
    }

    #[tokio::test]
    async fn get_errors_not_found_for_unknown_ids() {
        let c = RegistryGraphConnector::new(graph());
        for (kind, id) in [
            (ISSUER_RECORD_KIND, "did:web:nobody.example"),
            (AUDIT_ENTRY_KIND, "99"),
            (AUDIT_ENTRY_KIND, "not-a-number"),
        ] {
            let err = c.get(EntityKind::new(kind), id).await.expect_err(id);
            assert!(
                matches!(err, ConnectorError::NotFound { .. }),
                "{id}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn unsupported_kinds_error_naming_kind_and_connector() {
        let c = RegistryGraphConnector::new(graph());
        match c.pull(EntityKind::new("customer"), None).await {
            Err(ConnectorError::UnsupportedKind { connector, kind }) => {
                assert_eq!(connector, "ds-trusted-issuers-registry-rs");
                assert_eq!(kind, "customer");
            }
            other => panic!("expected UnsupportedKind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn push_is_refused() {
        let c = RegistryGraphConnector::new(graph());
        let doc = Document {
            name: "n".into(),
            remote_id: "did:web:new.example".into(),
            kind: EntityKind::new(ISSUER_RECORD_KIND),
            source: "s".into(),
            modified: None,
            fields: serde_json::json!({}),
        };
        assert!(matches!(
            c.push(&doc).await,
            Err(ConnectorError::Unsupported { .. })
        ));
    }
}
