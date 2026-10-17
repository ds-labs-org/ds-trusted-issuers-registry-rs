use std::path::Path;

use oxigraph::store::Store;
use trusted_issuers_core::{AuditEntry, Registry};

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("graph store error: {0}")]
    Storage(#[from] oxigraph::store::StorageError),
    #[error("invalid IRI: {0}")]
    Iri(#[from] oxigraph::model::IriParseError),
    #[error("SPARQL query failed: {0}")]
    Query(#[from] oxigraph::sparql::QueryEvaluationError),
    #[error("SPARQL query failed to parse: {0}")]
    Syntax(#[from] oxigraph::sparql::SparqlSyntaxError),
    #[error("the graph holds a malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },
    #[error("the registry in the graph breaks the write rules: {0}")]
    Rules(#[from] trusted_issuers_core::RegistryError),
    #[error("the graph's audit log is broken: {0}")]
    Audit(#[from] trusted_issuers_core::AuditError),
    #[error("cannot import into a graph that already holds a registry")]
    NotEmpty,
}

/// The registry graph. See the crate docs.
pub struct RegistryGraph {
    store: Store,
}

impl RegistryGraph {
    /// A fresh store in memory (tests, development).
    pub fn open_in_memory() -> Result<Self, GraphError> {
        Ok(Self {
            store: Store::new()?,
        })
    }

    /// Opens (or creates) the on-disk store in directory `path`, and checks
    /// the audit log's hash chain: a broken chain is an error, so a
    /// tampered log stops the registry from starting.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GraphError> {
        let _ = path;
        todo!()
    }

    /// The registry the graph holds, re-checked against the write rules.
    /// Empty (version 0) for a fresh graph.
    pub fn load(&self) -> Result<Registry, GraphError> {
        todo!()
    }

    /// Makes `registry` the stored registry and appends `entry` to the audit
    /// log, in one transaction flushed to disk.
    pub fn commit(&self, registry: &Registry, entry: &AuditEntry) -> Result<(), GraphError> {
        let _ = (registry, entry);
        todo!()
    }

    /// Stores `registry` in a graph that holds none yet, without an audit
    /// entry: the one-time move from a JSON data file.
    pub fn import(&self, registry: &Registry) -> Result<(), GraphError> {
        let _ = registry;
        todo!()
    }

    /// The whole audit log, oldest first.
    pub fn audit(&self) -> Result<Vec<AuditEntry>, GraphError> {
        todo!()
    }

    /// One audit entry by `seq`.
    pub fn audit_entry(&self, seq: u64) -> Result<Option<AuditEntry>, GraphError> {
        let _ = seq;
        todo!()
    }

    /// Ids of the records whose accreditation chain passes through `id`
    /// (its direct and indirect dependents), found by a SPARQL property
    /// path over `tir:accreditedBy` links.
    pub fn accredited_under(&self, id: &str) -> Result<Vec<String>, GraphError> {
        let _ = id;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_issuers_core::{AuditAction, AuditRecord, IssuerRecord, Role, Status};

    const ROOT: &str = "did:web:authority.example";
    const TAO: &str = "did:web:tao.example%3A8443:tenants:x";
    const TI: &str = "https://issuer.example/tenants/acme";

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
            updated_at: 0,
        }
    }

    /// Applies `upsert` and returns the audit entry a real write would.
    fn write(
        registry: &mut Registry,
        prev: Option<&AuditEntry>,
        record: IssuerRecord,
    ) -> AuditEntry {
        let id = record.id.clone();
        let before = registry.get(&id).cloned();
        registry.upsert(record, 100 + registry.version).unwrap();
        AuditEntry::next(
            prev,
            AuditRecord {
                at: 1_792_000_000 + registry.version,
                actor: "alice@authority.example".into(),
                action: AuditAction::Put,
                before,
                after: registry.get(&id).cloned(),
                id,
                version: registry.version,
            },
        )
    }

    /// A three-tier registry written through `graph`, every field used.
    fn populate(graph: &RegistryGraph) -> (Registry, Vec<AuditEntry>) {
        let mut registry = Registry::default();
        let mut log: Vec<AuditEntry> = Vec::new();
        let mut root = rec(ROOT, Role::RootTao, &["*"], None);
        root.name = Some("Dataspace \"Authority\" — ünïcode".into());
        let mut tao = rec(
            TAO,
            Role::Tao,
            &["Z-Credential", "A-Credential"],
            Some(ROOT),
        );
        tao.valid_from = Some(1_700_000_000);
        tao.valid_until = Some(1_900_000_000);
        let mut ti = rec(
            TI,
            Role::Ti,
            &["https://credentials.example/pid", "Z-Credential"],
            Some(TAO),
        );
        ti.status = Status::Suspended;
        for record in [root, tao, ti] {
            let entry = write(&mut registry, log.last(), record);
            graph.commit(&registry, &entry).unwrap();
            log.push(entry);
        }
        (registry, log)
    }

    #[test]
    fn a_registry_round_trips_through_the_graph_exactly() {
        let graph = RegistryGraph::open_in_memory().unwrap();
        assert_eq!(graph.load().unwrap(), Registry::default());
        let (registry, _) = populate(&graph);
        // Every field, including credential type order and the name's
        // quotes and non-ASCII, comes back as written.
        assert_eq!(graph.load().unwrap(), registry);
        assert_eq!(graph.load().unwrap().version, 3);
    }

    #[test]
    fn the_audit_log_is_stored_as_a_verifiable_chain() {
        let graph = RegistryGraph::open_in_memory().unwrap();
        let (_, log) = populate(&graph);
        let stored = graph.audit().unwrap();
        assert_eq!(stored, log);
        assert_eq!(trusted_issuers_core::verify_audit_chain(&stored), Ok(()));
        assert_eq!(graph.audit_entry(2).unwrap().as_ref(), Some(&log[1]));
        assert_eq!(graph.audit_entry(9).unwrap(), None);
    }

    #[test]
    fn a_removed_record_leaves_no_triples_behind() {
        let graph = RegistryGraph::open_in_memory().unwrap();
        let (mut registry, log) = populate(&graph);
        let before = registry.get(TI).cloned();
        registry.remove(TI).unwrap();
        let entry = AuditEntry::next(
            log.last(),
            AuditRecord {
                at: 1_792_000_100,
                actor: "admin".into(),
                action: AuditAction::Delete,
                id: TI.into(),
                before,
                after: None,
                version: registry.version,
            },
        );
        graph.commit(&registry, &entry).unwrap();
        assert_eq!(graph.load().unwrap(), registry);
        let ti = oxigraph::model::NamedNode::new(TI).unwrap();
        let left: Vec<_> = graph
            .store
            .quads_for_pattern(Some(ti.as_ref().into()), None, None, None)
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(left.is_empty(), "{left:?}");
        assert_eq!(graph.audit().unwrap().len(), 4);
    }

    #[test]
    fn the_accreditation_tree_is_walkable_in_sparql() {
        let graph = RegistryGraph::open_in_memory().unwrap();
        populate(&graph);
        let mut under_root = graph.accredited_under(ROOT).unwrap();
        under_root.sort();
        assert_eq!(under_root, vec![TI.to_string(), TAO.to_string()]);
        assert_eq!(graph.accredited_under(TAO).unwrap(), vec![TI.to_string()]);
        assert!(graph.accredited_under(TI).unwrap().is_empty());
        // An id is a value, never SPARQL text.
        assert!(
            graph
                .accredited_under("> } ; DROP ALL ; {")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_graph_is_durable_and_a_tampered_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, log) = {
            let graph = RegistryGraph::open(dir.path()).unwrap();
            populate(&graph)
        };
        let graph = RegistryGraph::open(dir.path()).unwrap();
        assert_eq!(graph.load().unwrap(), registry);
        assert_eq!(graph.audit().unwrap(), log);

        // Rewrite one audit entry's actor behind the registry's back.
        let actor = oxigraph::model::NamedNode::new(crate::vocab::tir("actor")).unwrap();
        let quad = graph
            .store
            .quads_for_pattern(None, Some(actor.as_ref()), None, None)
            .next()
            .unwrap()
            .unwrap();
        graph.store.remove(&quad).unwrap();
        graph
            .store
            .insert(&oxigraph::model::Quad::new(
                quad.subject.clone(),
                quad.predicate.clone(),
                oxigraph::model::Literal::new_simple_literal("mallory"),
                quad.graph_name.clone(),
            ))
            .unwrap();
        graph.store.flush().unwrap();
        drop(graph);
        let err = RegistryGraph::open(dir.path()).err().expect("tampered log");
        assert!(matches!(err, GraphError::Audit(_)), "{err}");
    }

    #[test]
    fn a_json_registry_can_be_imported_once() {
        let source = RegistryGraph::open_in_memory().unwrap();
        let (registry, _) = populate(&source);

        let graph = RegistryGraph::open_in_memory().unwrap();
        graph.import(&registry).unwrap();
        assert_eq!(graph.load().unwrap(), registry);
        assert!(graph.audit().unwrap().is_empty());
        assert!(matches!(graph.import(&registry), Err(GraphError::NotEmpty)));
    }
}
