//! RDF terms for the registry graph: W3C PROV-O where it genuinely fits (an
//! audit entry is a `prov:Activity`), RDFS for a party's display name, and
//! this project's own small vocabulary for the accreditation model (roles,
//! scopes, status) and the audit log's chain fields, which have no existing
//! term.

pub const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
pub const RDFS: &str = "http://www.w3.org/2000/01/rdf-schema#";
pub const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
pub const PROV: &str = "http://www.w3.org/ns/prov#";

/// This project's vocabulary.
pub const TIR: &str = "https://ds42.org/ontologies/ds-trusted-issuers-registry-rs#";

pub fn rdf(term: &str) -> String {
    format!("{RDF}{term}")
}

pub fn rdfs(term: &str) -> String {
    format!("{RDFS}{term}")
}

pub fn xsd(term: &str) -> String {
    format!("{XSD}{term}")
}

pub fn prov(term: &str) -> String {
    format!("{PROV}{term}")
}

pub fn tir(term: &str) -> String {
    format!("{TIR}{term}")
}
