use std::collections::BTreeMap;
use std::path::Path;

use oxigraph::model::{
    BlankNode, GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term, Variable,
};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::{Store, Transaction};
use trusted_issuers_core::{
    AuditAction, AuditEntry, IssuerRecord, Registry, Role, Status, verify_audit_chain,
};

use crate::vocab::{prov, rdf, rdfs, tir, xsd};

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

fn malformed(what: &'static str, detail: impl Into<String>) -> GraphError {
    GraphError::Malformed {
        what,
        detail: detail.into(),
    }
}

/// The registry graph. See the crate docs.
pub struct RegistryGraph {
    store: Store,
}

/// The fixed IRIs this store writes, built once.
struct Terms {
    records: GraphName,
    audit: GraphName,
    registry: NamedNode,
    rdf_type: NamedNode,
    issuer_record: NamedNode,
    audit_entry: NamedNode,
    activity: NamedNode,
    role: NamedNode,
    label: NamedNode,
    credential_type: NamedNode,
    value: NamedNode,
    order: NamedNode,
    accredited_by: NamedNode,
    valid_from: NamedNode,
    valid_until: NamedNode,
    status: NamedNode,
    updated_at: NamedNode,
    version: NamedNode,
    seq: NamedNode,
    at: NamedNode,
    ended_at: NamedNode,
    actor: NamedNode,
    action: NamedNode,
    subject_id: NamedNode,
    subject: NamedNode,
    before: NamedNode,
    after: NamedNode,
    prev_hash: NamedNode,
    hash: NamedNode,
    integer: NamedNode,
    date_time: NamedNode,
}

impl Terms {
    fn new() -> Self {
        let n = |iri: String| NamedNode::new(iri).expect("a fixed vocabulary IRI");
        Self {
            records: GraphName::NamedNode(n(tir("records"))),
            audit: GraphName::NamedNode(n(tir("audit"))),
            registry: n(tir("registry")),
            rdf_type: n(rdf("type")),
            issuer_record: n(tir("IssuerRecord")),
            audit_entry: n(tir("AuditEntry")),
            activity: n(prov("Activity")),
            role: n(tir("role")),
            label: n(rdfs("label")),
            credential_type: n(tir("credentialType")),
            value: n(tir("value")),
            order: n(tir("order")),
            accredited_by: n(tir("accreditedBy")),
            valid_from: n(tir("validFrom")),
            valid_until: n(tir("validUntil")),
            status: n(tir("status")),
            updated_at: n(tir("updatedAt")),
            version: n(tir("version")),
            seq: n(tir("seq")),
            at: n(tir("at")),
            ended_at: n(prov("endedAtTime")),
            actor: n(tir("actor")),
            action: n(tir("action")),
            subject_id: n(tir("subjectId")),
            subject: n(tir("subject")),
            before: n(tir("before")),
            after: n(tir("after")),
            prev_hash: n(tir("prevHash")),
            hash: n(tir("hash")),
            integer: n(xsd("integer")),
            date_time: n(xsd("dateTime")),
        }
    }

    fn int(&self, value: u64) -> Literal {
        Literal::new_typed_literal(value.to_string(), self.integer.clone())
    }

    fn audit_node(seq: u64) -> NamedNode {
        NamedNode::new(format!("{}{seq}", tir("audit/"))).expect("a fixed IRI and a number")
    }
}

/// A role, status or action as the snake_case string serde uses.
fn token<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => unreachable!("a unit enum serializes as a string"),
    }
}

fn from_token<T: serde::de::DeserializeOwned>(
    what: &'static str,
    s: &str,
) -> Result<T, GraphError> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| malformed(what, format!("unknown value '{s}'")))
}

/// `xsd:dateTime` (UTC) for unix seconds, for `prov:endedAtTime`.
fn date_time(unix: u64) -> String {
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

/// The literal value of `term`, or `None` for an IRI or blank node.
fn literal(term: &Term) -> Option<&str> {
    match term {
        Term::Literal(l) => Some(l.value()),
        _ => None,
    }
}

fn int_value(what: &'static str, term: &Term) -> Result<u64, GraphError> {
    literal(term)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| malformed(what, format!("not a non-negative integer: {term}")))
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
        let graph = Self {
            store: Store::open(path)?,
        };
        verify_audit_chain(&graph.audit()?)?;
        Ok(graph)
    }

    /// The registry the graph holds, re-checked against the write rules.
    /// Empty (version 0) for a fresh graph.
    pub fn load(&self) -> Result<Registry, GraphError> {
        let t = Terms::new();
        let records = GraphNameRef::from(&t.records);
        let quad_err = |e| GraphError::Storage(e);
        let version = self
            .store
            .quads_for_pattern(
                Some(t.registry.as_ref().into()),
                Some(t.version.as_ref()),
                None,
                Some(records),
            )
            .next()
            .transpose()
            .map_err(quad_err)?
            .map(|q| int_value("registry version", &q.object))
            .transpose()?
            .unwrap_or(0);
        let mut issuers = BTreeMap::new();
        for quad in self.store.quads_for_pattern(
            None,
            Some(t.rdf_type.as_ref()),
            Some(t.issuer_record.as_ref().into()),
            Some(records),
        ) {
            let NamedOrBlankNode::NamedNode(node) = quad.map_err(quad_err)?.subject else {
                return Err(malformed("issuer record", "a blank node"));
            };
            let record = self.record(&t, &node)?;
            issuers.insert(record.id.clone(), record);
        }
        Ok(Registry { version, issuers }.revalidated()?)
    }

    /// Rebuilds the record whose node is `node`.
    fn record(&self, t: &Terms, node: &NamedNode) -> Result<IssuerRecord, GraphError> {
        let records = GraphNameRef::from(&t.records);
        let mut record = IssuerRecord {
            id: node.as_str().to_string(),
            role: Role::Ti,
            name: None,
            credential_types: Vec::new(),
            accredited_by: None,
            valid_from: None,
            valid_until: None,
            status: Status::Active,
            x509_certificates: Vec::new(),
            updated_at: 0,
        };
        let (mut role, mut status) = (None, None);
        let mut types: Vec<(u64, String)> = Vec::new();
        for quad in
            self.store
                .quads_for_pattern(Some(node.as_ref().into()), None, None, Some(records))
        {
            let quad = quad?;
            let p = &quad.predicate;
            let o = &quad.object;
            let text = || {
                literal(o)
                    .map(str::to_string)
                    .ok_or_else(|| malformed("issuer record", format!("{p} is not a literal")))
            };
            if *p == t.role {
                role = Some(from_token::<Role>("role", &text()?)?);
            } else if *p == t.status {
                status = Some(from_token::<Status>("status", &text()?)?);
            } else if *p == t.label {
                record.name = Some(text()?);
            } else if *p == t.accredited_by {
                let Term::NamedNode(by) = o else {
                    return Err(malformed("issuer record", "accreditedBy is not an IRI"));
                };
                record.accredited_by = Some(by.as_str().to_string());
            } else if *p == t.valid_from {
                record.valid_from = Some(int_value("validFrom", o)?);
            } else if *p == t.valid_until {
                record.valid_until = Some(int_value("validUntil", o)?);
            } else if *p == t.updated_at {
                record.updated_at = int_value("updatedAt", o)?;
            } else if *p == t.credential_type {
                let Term::BlankNode(item) = o else {
                    return Err(malformed("issuer record", "credentialType is not a node"));
                };
                types.push(self.ordered_value(t, item, records)?);
            }
        }
        record.role = role.ok_or_else(|| malformed("issuer record", "no role"))?;
        record.status = status.ok_or_else(|| malformed("issuer record", "no status"))?;
        types.sort();
        record.credential_types = types.into_iter().map(|(_, v)| v).collect();
        Ok(record)
    }

    /// The `(tir:order, tir:value)` of a list item node.
    fn ordered_value(
        &self,
        t: &Terms,
        item: &BlankNode,
        graph: GraphNameRef<'_>,
    ) -> Result<(u64, String), GraphError> {
        let (mut order, mut value) = (None, None);
        for quad in
            self.store
                .quads_for_pattern(Some(item.as_ref().into()), None, None, Some(graph))
        {
            let quad = quad?;
            if quad.predicate == t.order {
                order = Some(int_value("list order", &quad.object)?);
            } else if quad.predicate == t.value {
                value = literal(&quad.object).map(str::to_string);
            }
        }
        order
            .zip(value)
            .ok_or_else(|| malformed("list item", "no tir:order or tir:value"))
    }

    /// Makes `registry` the stored registry and appends `entry` to the audit
    /// log, in one transaction flushed to disk.
    pub fn commit(&self, registry: &Registry, entry: &AuditEntry) -> Result<(), GraphError> {
        let t = Terms::new();
        let mut tx = self.store.start_transaction()?;
        write_registry(&t, &mut tx, registry)?;
        write_audit_entry(&t, &mut tx, entry)?;
        tx.commit()?;
        self.flush()
    }

    /// Stores `registry` in a graph that holds none yet, without an audit
    /// entry: the one-time move from a JSON data file.
    pub fn import(&self, registry: &Registry) -> Result<(), GraphError> {
        let t = Terms::new();
        let mut tx = self.store.start_transaction()?;
        let occupied = tx
            .quads_for_pattern(None, None, None, Some(GraphNameRef::from(&t.records)))
            .next()
            .is_some()
            || tx
                .quads_for_pattern(None, None, None, Some(GraphNameRef::from(&t.audit)))
                .next()
                .is_some();
        if occupied {
            return Err(GraphError::NotEmpty);
        }
        write_registry(&t, &mut tx, registry)?;
        tx.commit()?;
        self.flush()
    }

    /// Makes committed writes durable: RocksDB does not sync its write-ahead
    /// log on every transaction, and a registry write must survive a power
    /// loss like the JSON store's fsync does. Writes are rare.
    fn flush(&self) -> Result<(), GraphError> {
        Ok(self.store.flush()?)
    }

    /// The whole audit log, oldest first.
    pub fn audit(&self) -> Result<Vec<AuditEntry>, GraphError> {
        let t = Terms::new();
        let mut entries = Vec::new();
        for quad in self.store.quads_for_pattern(
            None,
            Some(t.rdf_type.as_ref()),
            Some(t.audit_entry.as_ref().into()),
            Some(GraphNameRef::from(&t.audit)),
        ) {
            let NamedOrBlankNode::NamedNode(node) = quad?.subject else {
                return Err(malformed("audit entry", "a blank node"));
            };
            entries.push(self.entry_at(&t, &node)?);
        }
        entries.sort_by_key(|e| e.seq);
        Ok(entries)
    }

    /// One audit entry by `seq`.
    pub fn audit_entry(&self, seq: u64) -> Result<Option<AuditEntry>, GraphError> {
        let t = Terms::new();
        let node = Terms::audit_node(seq);
        let exists = self
            .store
            .quads_for_pattern(
                Some(node.as_ref().into()),
                Some(t.rdf_type.as_ref()),
                Some(t.audit_entry.as_ref().into()),
                Some(GraphNameRef::from(&t.audit)),
            )
            .next()
            .is_some();
        if !exists {
            return Ok(None);
        }
        self.entry_at(&t, &node).map(Some)
    }

    fn entry_at(&self, t: &Terms, node: &NamedNode) -> Result<AuditEntry, GraphError> {
        let mut fields: BTreeMap<String, Term> = BTreeMap::new();
        for quad in self.store.quads_for_pattern(
            Some(node.as_ref().into()),
            None,
            None,
            Some(GraphNameRef::from(&t.audit)),
        ) {
            let quad = quad?;
            fields.insert(quad.predicate.as_str().to_string(), quad.object);
        }
        let get = |p: &NamedNode| {
            fields
                .get(p.as_str())
                .ok_or_else(|| malformed("audit entry", format!("{node} has no {p}")))
        };
        let text = |p: &NamedNode| -> Result<String, GraphError> {
            literal(get(p)?)
                .map(str::to_string)
                .ok_or_else(|| malformed("audit entry", format!("{p} is not a literal")))
        };
        let record = |p: &NamedNode| -> Result<Option<IssuerRecord>, GraphError> {
            match fields.get(p.as_str()) {
                None => Ok(None),
                Some(term) => serde_json::from_str(literal(term).unwrap_or_default())
                    .map(Some)
                    .map_err(|e| malformed("audit entry record", e.to_string())),
            }
        };
        Ok(AuditEntry {
            seq: int_value("audit seq", get(&t.seq)?)?,
            at: int_value("audit time", get(&t.at)?)?,
            actor: text(&t.actor)?,
            action: from_token::<AuditAction>("audit action", &text(&t.action)?)?,
            id: text(&t.subject_id)?,
            before: record(&t.before)?,
            after: record(&t.after)?,
            version: int_value("audit version", get(&t.version)?)?,
            prev_hash: text(&t.prev_hash)?,
            hash: text(&t.hash)?,
        })
    }

    /// Ids of the records whose accreditation chain passes through `id`
    /// (its direct and indirect dependents), found by a SPARQL property
    /// path over `tir:accreditedBy` links. `id` is bound as a term, never
    /// spliced into the query text; one that is not an IRI names nothing.
    pub fn accredited_under(&self, id: &str) -> Result<Vec<String>, GraphError> {
        let Ok(node) = NamedNode::new(id) else {
            return Ok(Vec::new());
        };
        let query = format!(
            "SELECT DISTINCT ?child ?accreditor WHERE {{ GRAPH <{records}> {{ ?child <{by}>+ ?accreditor }} }} ORDER BY ?child",
            records = tir("records"),
            by = tir("accreditedBy"),
        );
        let results = SparqlEvaluator::new()
            .parse_query(&query)?
            .substitute_variable(Variable::new_unchecked("accreditor"), node)
            .on_store(&self.store)
            .execute()?;
        let QueryResults::Solutions(solutions) = results else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for solution in solutions {
            if let Some(Term::NamedNode(child)) = solution?.get("child") {
                out.push(child.as_str().to_string());
            }
        }
        Ok(out)
    }
}

/// Replaces the records graph with `registry`.
fn write_registry(
    t: &Terms,
    tx: &mut Transaction<'_>,
    registry: &Registry,
) -> Result<(), GraphError> {
    tx.clear_graph(GraphNameRef::from(&t.records))?;
    let g = &t.records;
    tx.insert(&Quad::new(
        t.registry.clone(),
        t.version.clone(),
        t.int(registry.version),
        g.clone(),
    ));
    for record in registry.list() {
        tx.extend(&record_quads(t, record)?);
    }
    Ok(())
}

/// The quads describing `record` in the records graph.
fn record_quads(t: &Terms, record: &IssuerRecord) -> Result<Vec<Quad>, GraphError> {
    let g = &t.records;
    let node = NamedNode::new(record.id.as_str())?;
    let mut quads = Vec::new();
    let mut add = |s: NamedOrBlankNode, p: &NamedNode, o: Term| {
        quads.push(Quad::new(s, p.clone(), o, g.clone()));
    };
    let subject = || NamedOrBlankNode::from(node.clone());
    add(subject(), &t.rdf_type, t.issuer_record.clone().into());
    add(
        subject(),
        &t.role,
        Literal::new_simple_literal(token(&record.role)).into(),
    );
    add(
        subject(),
        &t.status,
        Literal::new_simple_literal(token(&record.status)).into(),
    );
    add(subject(), &t.updated_at, t.int(record.updated_at).into());
    if let Some(name) = &record.name {
        add(
            subject(),
            &t.label,
            Literal::new_simple_literal(name).into(),
        );
    }
    if let Some(by) = &record.accredited_by {
        add(
            subject(),
            &t.accredited_by,
            NamedNode::new(by.as_str())?.into(),
        );
    }
    if let Some(from) = record.valid_from {
        add(subject(), &t.valid_from, t.int(from).into());
    }
    if let Some(until) = record.valid_until {
        add(subject(), &t.valid_until, t.int(until).into());
    }
    for (i, credential_type) in record.credential_types.iter().enumerate() {
        let item = BlankNode::default();
        add(subject(), &t.credential_type, item.clone().into());
        add(item.clone().into(), &t.order, t.int(i as u64).into());
        add(
            item.into(),
            &t.value,
            Literal::new_simple_literal(credential_type).into(),
        );
    }
    Ok(quads)
}

/// Adds `entry` to the audit graph as a `prov:Activity`.
fn write_audit_entry(
    t: &Terms,
    tx: &mut Transaction<'_>,
    entry: &AuditEntry,
) -> Result<(), GraphError> {
    let node = Terms::audit_node(entry.seq);
    let g = &t.audit;
    let mut add = |p: &NamedNode, o: Term| {
        tx.insert(&Quad::new(node.clone(), p.clone(), o, g.clone()));
    };
    let text = |s: &str| -> Term { Literal::new_simple_literal(s).into() };
    add(&t.rdf_type, t.audit_entry.clone().into());
    add(&t.rdf_type, t.activity.clone().into());
    add(&t.seq, t.int(entry.seq).into());
    add(&t.at, t.int(entry.at).into());
    add(
        &t.ended_at,
        Literal::new_typed_literal(date_time(entry.at), t.date_time.clone()).into(),
    );
    add(&t.actor, text(&entry.actor));
    add(&t.action, text(&token(&entry.action)));
    add(&t.subject_id, text(&entry.id));
    if let Ok(subject) = NamedNode::new(entry.id.as_str()) {
        add(&t.subject, subject.into());
    }
    for (p, record) in [(&t.before, &entry.before), (&t.after, &entry.after)] {
        if let Some(record) = record {
            let json = serde_json::to_string(record).expect("a record always serializes");
            add(p, text(&json));
        }
    }
    add(&t.version, t.int(entry.version).into());
    add(&t.prev_hash, text(&entry.prev_hash));
    add(&t.hash, text(&entry.hash));
    Ok(())
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
            x509_certificates: Vec::new(),
            updated_at: 0,
        }
    }

    /// A self-signed CA certificate, base64 DER.
    fn self_signed_ca(cn: &str) -> String {
        use base64::Engine;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(cert.der())
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
            &[
                "Z-Credential",
                "https://credentials.example/pid",
                "A-Credential",
            ],
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
        ti.x509_certificates = vec![self_signed_ca("IACA A"), self_signed_ca("IACA B")];
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
        assert_eq!(under_root, vec![TAO.to_string(), TI.to_string()]);
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
