//! The registry graph: an embedded Oxigraph store holding the trusted
//! issuers registry as real RDF, durable on disk, and reachable through
//! Contreforts' connector interface via `trusted-issuers-contreforts`.
//!
//! Follows `ds-identity-hub-rs`'s `identity-hub-graph` (decompose into
//! quads on write, rebuild in Rust on read, values as typed literals and
//! never interpolated into SPARQL text), with one difference: the hub's
//! graph is in memory, while this one is the registry's store of record,
//! so [`RegistryGraph::open`] keeps it in RocksDB and every commit is one
//! transaction, flushed to disk before it returns.
//!
//! Two named graphs:
//!
//! - `tir:records`: one node per party, named by the party's own id (a DID
//!   or an https URL, both IRIs), with `tir:accreditedBy` as a link to the
//!   accreditor's node, so the accreditation tree can be walked in SPARQL.
//! - `tir:audit`: one `prov:Activity` per write, carrying the hash chain
//!   (see `trusted_issuers_core::audit`).

mod store;
pub mod vocab;

pub use store::{GraphError, RegistryGraph};
