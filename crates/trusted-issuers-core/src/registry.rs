//! The registry itself: an issuer-id-keyed set of [`IssuerRecord`]s, the
//! write-time rules that keep it consistent, and the read-time trust check
//! that walks an issuer's accreditation chain up to a Root TAO.
//!
//! The write-time rules alone are not enough: a TAO can be suspended,
//! expire, or have its scope narrowed after it accredited someone, so
//! [`Registry::check`] re-validates every link on every call instead of
//! trusting what was true when the child was written.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{ANY_CREDENTIAL_TYPE, IssuerRecord, Role, Status};

/// Longest accreditation chain [`Registry::check`] will walk, root
/// included. Real chains are 2-3 links; the cap only bounds a malformed
/// (e.g. imported) registry.
pub const MAX_CHAIN_DEPTH: usize = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("'{0}' is neither a DID nor an OID4VCI credential issuer identifier")]
    InvalidId(String),
    #[error("credentialTypes must list at least one non-empty type")]
    NoCredentialTypes,
    #[error("only a root_tao may use the '*' credential type")]
    WildcardNotAllowed,
    #[error("validFrom must be before validUntil")]
    InvalidValidity,
    #[error("a root_tao must not have accreditedBy")]
    RootWithAccreditor,
    #[error("a {0:?} record needs accreditedBy")]
    MissingAccreditor(Role),
    #[error("accreditor '{0}' is not in the registry")]
    UnknownAccreditor(String),
    #[error("accreditor '{0}' is a trusted issuer and cannot accredit others")]
    AccreditorCannotAccredit(String),
    #[error("accreditor '{accreditor}' is not scoped for credential type '{credential_type}'")]
    AccreditorScope {
        accreditor: String,
        credential_type: String,
    },
    #[error("accreditedBy '{0}' would create an accreditation cycle")]
    Cycle(String),
    #[error("the accreditation chain would be longer than {MAX_CHAIN_DEPTH} links")]
    ChainTooLong,
    #[error("'{0}' is listed more than once")]
    Duplicate(String),
    #[error("'{id}' still accredits {dependents:?}; reassign or remove them first")]
    HasDependents { id: String, dependents: Vec<String> },
    #[error("'{0}' is not in the registry")]
    NotFound(String),
    #[error("x509Certificates[{index}] is not a usable trust anchor: {reason}")]
    InvalidCertificate { index: usize, reason: String },
    #[error("that X.509 trust anchor is already listed for '{other}'")]
    DuplicateAnchor { other: String },
}

/// Outcome of [`Registry::check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustDecision {
    pub trusted: bool,
    /// The issuer ids walked, starting at the issuer. On success it ends at a
    /// Root TAO; on failure it ends at the link that failed.
    pub chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl TrustDecision {
    fn deny(chain: Vec<String>, reason: impl Into<String>) -> Self {
        Self {
            trusted: false,
            chain,
            reason: Some(reason.into()),
        }
    }
}

/// The registry contents. `version` increases by one on every successful
/// write, so a verifier holding a snapshot can tell whether it is stale.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub version: u64,
    #[serde(with = "records_as_list", default)]
    pub issuers: BTreeMap<String, IssuerRecord>,
}

impl Registry {
    pub fn get(&self, id: &str) -> Option<&IssuerRecord> {
        self.issuers.get(&canonical_id(id))
    }

    pub fn list(&self) -> impl Iterator<Item = &IssuerRecord> {
        self.issuers.values()
    }

    /// Ids of the records whose `accredited_by` is `id`.
    pub fn dependents_of(&self, id: &str) -> Vec<String> {
        let id = canonical_id(id);
        self.issuers
            .values()
            .filter(|r| r.accredited_by.as_deref() == Some(id.as_str()))
            .map(|r| r.id.clone())
            .collect()
    }

    /// Inserts or replaces a record after validating it against the
    /// registry's current contents. `now` becomes its `updated_at`. The
    /// record's `id` and `accredited_by` are stored in [`canonical_id`]
    /// form, so a rewrite in another spelling replaces instead of
    /// duplicating.
    pub fn upsert(&mut self, mut record: IssuerRecord, now: u64) -> Result<(), RegistryError> {
        canonicalize(&mut record);
        self.validate(&record)?;
        record.updated_at = now;
        self.issuers.insert(record.id.clone(), record);
        self.version += 1;
        Ok(())
    }

    /// Changes only a record's status. Suspending or revoking a TAO
    /// immediately distrusts everything it accredited, via
    /// [`Registry::check`].
    pub fn set_status(&mut self, id: &str, status: Status, now: u64) -> Result<(), RegistryError> {
        let id = canonical_id(id);
        let record = self
            .issuers
            .get_mut(&id)
            .ok_or(RegistryError::NotFound(id))?;
        record.status = status;
        record.updated_at = now;
        self.version += 1;
        Ok(())
    }

    /// Removes a record. Refused while other records name it as their
    /// accreditor, so a removal never leaves a dangling `accreditedBy`.
    pub fn remove(&mut self, id: &str) -> Result<IssuerRecord, RegistryError> {
        let id = canonical_id(id);
        let dependents = self.dependents_of(&id);
        if !dependents.is_empty() {
            return Err(RegistryError::HasDependents { id, dependents });
        }
        let removed = self
            .issuers
            .remove(&id)
            .ok_or(RegistryError::NotFound(id))?;
        self.version += 1;
        Ok(removed)
    }

    /// Longest line of records below `id` (0 when nothing names it as
    /// accreditor). Stops counting past [`MAX_CHAIN_DEPTH`].
    fn descendant_height(&self, id: &str, depth: usize) -> usize {
        if depth > MAX_CHAIN_DEPTH {
            return depth;
        }
        self.issuers
            .values()
            .filter(|r| r.accredited_by.as_deref() == Some(id))
            .map(|r| 1 + self.descendant_height(&r.id, depth + 1))
            .max()
            .unwrap_or(0)
    }

    /// Re-applies every write rule to a registry that did not come through
    /// [`Registry::upsert`] (a data file loaded from disk, a snapshot),
    /// inserting accreditors before the records they accredit. Keeps
    /// `version` and each record's `updated_at`. Records are brought to
    /// [`canonical_id`] form first, and two that collapse to the same id
    /// are refused as [`RegistryError::Duplicate`] rather than one silently
    /// shadowing the other.
    pub fn revalidated(self) -> Result<Registry, RegistryError> {
        let mut out = Registry {
            version: self.version,
            issuers: BTreeMap::new(),
        };
        let mut pending: Vec<IssuerRecord> = Vec::with_capacity(self.issuers.len());
        let mut seen = BTreeSet::new();
        for mut record in self.issuers.into_values() {
            canonicalize(&mut record);
            if !seen.insert(record.id.clone()) {
                return Err(RegistryError::Duplicate(record.id));
            }
            pending.push(record);
        }
        while !pending.is_empty() {
            let (ready, rest): (Vec<_>, Vec<_>) = pending.into_iter().partition(|r| {
                r.accredited_by
                    .as_deref()
                    .is_none_or(|a| out.issuers.contains_key(a))
            });
            if ready.is_empty() {
                // Whatever is left points at a missing accreditor or forms
                // a cycle; `validate` names the first problem.
                let first = &rest[0];
                return Err(out.validate(first).err().unwrap_or_else(|| {
                    RegistryError::UnknownAccreditor(
                        first.accredited_by.clone().unwrap_or_default(),
                    )
                }));
            }
            for record in ready {
                out.validate(&record)?;
                out.issuers.insert(record.id.clone(), record);
            }
            pending = rest;
        }
        Ok(out)
    }

    fn validate(&self, record: &IssuerRecord) -> Result<(), RegistryError> {
        if !is_issuer_id(&record.id) {
            return Err(RegistryError::InvalidId(record.id.clone()));
        }
        if record.credential_types.is_empty()
            || record.credential_types.iter().any(String::is_empty)
        {
            return Err(RegistryError::NoCredentialTypes);
        }
        crate::x509::check_anchors(self, record)?;
        if record.role != Role::RootTao
            && record
                .credential_types
                .iter()
                .any(|t| t == ANY_CREDENTIAL_TYPE)
        {
            return Err(RegistryError::WildcardNotAllowed);
        }
        if let (Some(from), Some(until)) = (record.valid_from, record.valid_until)
            && from >= until
        {
            return Err(RegistryError::InvalidValidity);
        }
        // A record that still accredits others must keep the ability to.
        if !record.role.can_accredit() {
            let dependents = self.dependents_of(&record.id);
            if !dependents.is_empty() {
                return Err(RegistryError::HasDependents {
                    id: record.id.clone(),
                    dependents,
                });
            }
        }

        match (&record.role, &record.accredited_by) {
            (Role::RootTao, None) => Ok(()),
            (Role::RootTao, Some(_)) => Err(RegistryError::RootWithAccreditor),
            (role, None) => Err(RegistryError::MissingAccreditor(*role)),
            (_, Some(accreditor_did)) => {
                if accreditor_did == &record.id {
                    return Err(RegistryError::Cycle(accreditor_did.clone()));
                }
                let accreditor = self
                    .issuers
                    .get(accreditor_did)
                    .ok_or_else(|| RegistryError::UnknownAccreditor(accreditor_did.clone()))?;
                if !accreditor.role.can_accredit() {
                    return Err(RegistryError::AccreditorCannotAccredit(
                        accreditor_did.clone(),
                    ));
                }
                if let Some(t) = record
                    .credential_types
                    .iter()
                    .find(|t| !accreditor.covers(t))
                {
                    return Err(RegistryError::AccreditorScope {
                        accreditor: accreditor_did.clone(),
                        credential_type: t.clone(),
                    });
                }
                // Walk up from the accreditor; reaching this record again
                // means the update would close a loop.
                let mut seen = BTreeSet::new();
                let mut cursor = Some(accreditor);
                while let Some(current) = cursor {
                    if current.id == record.id || !seen.insert(current.id.as_str()) {
                        return Err(RegistryError::Cycle(accreditor_did.clone()));
                    }
                    cursor = current
                        .accredited_by
                        .as_deref()
                        .and_then(|d| self.issuers.get(d));
                }
                // Refuse chains `check` would always reject: this record's
                // ancestors, itself, and its longest line of descendants.
                if seen.len() + 1 + self.descendant_height(&record.id, 0) > MAX_CHAIN_DEPTH {
                    return Err(RegistryError::ChainTooLong);
                }
                Ok(())
            }
        }
    }

    /// Whether `id` may issue a credential of `credential_type` at `now`
    /// (unix seconds): the issuer and every accreditor up to a Root TAO
    /// must be listed, `Active`, inside their validity window, and scoped
    /// for the type.
    pub fn check(&self, id: &str, credential_type: &str, now: u64) -> TrustDecision {
        let mut chain = Vec::new();
        let mut cursor = canonical_id(id);
        loop {
            chain.push(cursor.clone());
            if chain.len() > MAX_CHAIN_DEPTH {
                return TrustDecision::deny(chain, "accreditation chain is too long");
            }
            let Some(record) = self.issuers.get(&cursor) else {
                return TrustDecision::deny(chain, format!("'{cursor}' is not in the registry"));
            };
            if chain.len() > 1 && !record.role.can_accredit() {
                return TrustDecision::deny(
                    chain,
                    format!("'{cursor}' is a trusted issuer and cannot accredit others"),
                );
            }
            if !record.is_usable_at(now) {
                return TrustDecision::deny(
                    chain,
                    format!("'{cursor}' is not active or outside its validity period"),
                );
            }
            if !record.covers(credential_type) {
                return TrustDecision::deny(
                    chain,
                    format!("'{cursor}' is not scoped for credential type '{credential_type}'"),
                );
            }
            match (&record.role, &record.accredited_by) {
                (Role::RootTao, _) => {
                    return TrustDecision {
                        trusted: true,
                        chain,
                        reason: None,
                    };
                }
                (_, Some(next)) => {
                    if chain.contains(next) {
                        return TrustDecision::deny(chain, "accreditation chain has a cycle");
                    }
                    cursor = next.clone();
                }
                (_, None) => {
                    return TrustDecision::deny(
                        chain,
                        format!("'{cursor}' has no accreditor and is not a root_tao"),
                    );
                }
            }
        }
    }
}

/// The canonical spelling of `did`, which is what the registry stores and
/// looks up by.
///
/// Matching is by exact string, but `did:web` resolution is not: DNS hosts
/// are case-insensitive and percent-escapes (`%3a` vs `%3A`, the port
/// separator) are the same byte either way. Without one spelling, a record
/// written as `did:web:Issuer.example` would never match a credential whose
/// issuer says `did:web:issuer.example`, silently distrusting a listed
/// issuer. So for `did:web` the DNS host (the first segment up to its first
/// `%` escape) is lowercased and every percent-escape's hex digits are
/// uppercased. Path segments keep their case, and so does anything after an
/// escape in the first segment.
///
/// That last rule decides no match. `is_did` allows no escape in the first
/// segment but the port's `%3A` followed by digits, and this function only
/// changes letter case: it never decodes, adds or drops an escape. So a
/// lookup with any other escape there (`%2F`, `%40`, `%3F`, `%23`, `%2E`)
/// can't equal a stored DID, whatever the case of the text after it. The case
/// is kept so that the DID echoed back for such a lookup (in a
/// [`TrustDecision`]'s chain or in an error) is the canonical form of the one
/// that was asked for (host lowercased, hex digits uppercased, nothing else
/// changed) and not one whose text after the escape was folded too, and so the
/// rule stays right if `is_did` ever admits such an escape: a resolver that
/// decodes `%2F`, `%40`, `%3F` or `%23` turns the text after it into a
/// case-sensitive path, userinfo or query.
///
/// Other methods define their own equivalence, so they are returned
/// unchanged.
pub fn canonical_did(did: &str) -> String {
    let Some(rest) = did.strip_prefix("did:web:") else {
        return did.to_string();
    };
    let segments: Vec<String> = rest
        .split(':')
        .enumerate()
        .map(|(i, segment)| {
            if i == 0 {
                let (host, tail) = segment.split_at(segment.find('%').unwrap_or(segment.len()));
                if host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
                {
                    uppercase_escapes(&(host.to_ascii_lowercase() + tail))
                } else {
                    uppercase_escapes(segment)
                }
            } else {
                uppercase_escapes(segment)
            }
        })
        .collect();
    format!("did:web:{}", segments.join(":"))
}

/// The canonical spelling of an issuer id, which is what the registry
/// stores and looks up by: [`canonical_did`] for a DID, and for an https URL
/// (an OID4VCI credential issuer identifier) the scheme and host lowercased
/// and every percent-escape's hex digits uppercased.
///
/// Every URL parser treats the scheme and the DNS host as case-insensitive,
/// and an escape's hex digits are too (RFC 3986, section 6.2.2.1), so
/// `HTTPS://Issuer.example` names the same issuer as
/// `https://issuer.example`. OID4VCI calls the identifier case sensitive,
/// meaning the issuer's metadata must repeat it exactly; folding case here
/// only stops the registry from listing one party twice or missing a listed
/// one. The path keeps its case, and nothing is decoded, added or dropped,
/// as in [`canonical_did`]: the other spellings that fetch the same metadata
/// (`:443`, a trailing `/`, dot segments, ...) are refused at write instead.
///
/// The host is only lowercased when the authority holds nothing but host and
/// port characters, so a lookup with userinfo (refused at write) is echoed
/// with its case.
pub fn canonical_id(id: &str) -> String {
    let Some(rest) = id
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
        .map(|_| &id[8..])
    else {
        return canonical_did(id);
    };
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let authority = if authority
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b':'))
    {
        authority.to_ascii_lowercase()
    } else {
        authority.to_string()
    };
    format!("https://{}", uppercase_escapes(&(authority + tail)))
}

/// Puts a record's id references in [`canonical_id`] form.
fn canonicalize(record: &mut IssuerRecord) {
    record.id = canonical_id(&record.id);
    record.accredited_by = record.accredited_by.as_deref().map(canonical_id);
}

/// Uppercases the two hex digits of every `%xx` escape in `s`.
fn uppercase_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push(bytes[i + 1].to_ascii_uppercase() as char);
            out.push(bytes[i + 2].to_ascii_uppercase() as char);
            i += 3;
        } else {
            // Not an escape: copy the whole char (`i` is on a boundary).
            let c = s[i..].chars().next().expect("i < len");
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// Whether `s` is a DID per DID Core's syntax, not a DID URL:
/// `did:` method `:` method-specific-id, where the method is one or more of
/// `[a-z0-9]` and the id is `*( *idchar ":" ) 1*idchar` with
/// `idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded`.
///
/// A fragment, query or path (`#key-1`, `?versionId=1`, `/x`) makes it a DID
/// URL, which names a resource of a DID and not a party that can be listed;
/// accepting one would store a record no credential's issuer DID can match.
/// Empty segments between colons are legal in the grammar, a trailing colon
/// is not.
///
/// `did:web` is stricter: its first segment is a DNS host, optionally
/// followed by `%3A` and a port (see [`is_did_web_host`]), and the others
/// are non-empty path segments with one spelling each (see
/// [`is_did_web_path_segment`]). The path as a whole may not be the sole
/// segment `.well-known`: the resolver turns a DID without a path into
/// `https://<host>/.well-known/did.json`, and that path into the same URL, so
/// `did:web:host` and `did:web:host:.well-known` would be two spellings of
/// one party. Anywhere else in a path `.well-known` is an ordinary directory
/// name.
fn is_did(s: &str) -> bool {
    is_did_core(s)
        && s.strip_prefix("did:web:").is_none_or(|rest| {
            let mut segments = rest.split(':');
            let host = segments.next();
            let path: Vec<&str> = segments.collect();
            host.is_some_and(is_did_web_host)
                && path != [".well-known"]
                && path.iter().all(|segment| is_did_web_path_segment(segment))
        })
}

/// Whether `s` may name a party: a DID ([`is_did`]), as DCP issuers are
/// named, or an OID4VCI Credential Issuer Identifier
/// ([`is_credential_issuer_id`]).
fn is_issuer_id(s: &str) -> bool {
    is_did(s) || is_credential_issuer_id(s)
}

/// Whether `s` is an OID4VCI Credential Issuer Identifier: "a case sensitive
/// URL using the https scheme that contains scheme, host and, optionally,
/// port number and path components, but no query or fragment components"
/// (OpenID for Verifiable Credential Issuance 1.0, section 12.2.1).
///
/// Like a did:web, each party has one spelling, in [`canonical_id`] form
/// (lowercase scheme and host). The host follows the did:web rules
/// ([`is_dns_name`]): no IP address, no trailing dot and no userinfo, so the
/// party is always named by a DNS name. The port is an [`is_port`] that is
/// not 443, which https already implies. The path is empty or made of
/// `/`-led non-empty segments (`is_url_path_segment`), so it never ends in
/// `/`: OID4VCI strips a trailing `/` before building the metadata URL
/// (`/.well-known/openid-credential-issuer` + path), and URL parsers add one
/// to a bare origin, so `https://issuer.example/` and
/// `https://issuer.example` fetch the same metadata.
pub fn is_credential_issuer_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    is_dns_name(host)
        && !host.bytes().any(|c| c.is_ascii_uppercase())
        && port.is_none_or(|p| is_port(p) && p != "443")
        && path
            .strip_prefix('/')
            .is_none_or(|path| path.split('/').all(is_url_path_segment))
}

/// Whether `segment` is one segment of a credential issuer identifier's
/// path, written one way only: unreserved characters (letters, digits, `-`,
/// `.`, `_`, `~`) and percent-escapes of anything else. That leaves out what
/// a URL parser rewrites (spaces, `\`, raw non-ASCII) and reserved
/// characters some servers give a meaning (`;` path parameters), which must
/// be escaped.
///
/// The rest follows [`is_did_web_path_segment`], for the same reasons: an
/// empty segment (`//`, which servers that merge slashes drop), `.` and `..`
/// (which URL parsing removes), an escaped unreserved character (`%61`,
/// `%2E`, `%7E`, which servers decode) and an escaped `/` (`%2F`, which
/// hides a path separator) would each give a party a second spelling.
fn is_url_path_segment(segment: &str) -> bool {
    if matches!(segment, "" | "." | "..") {
        return false;
    }
    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                match escaped_byte(&bytes[i..]) {
                    Some(c) if c != b'/' && !is_unreserved(c) => {}
                    _ => return false,
                }
                i += 3;
            }
            c if is_unreserved(c) => i += 1,
            _ => return false,
        }
    }
    true
}

/// The byte a `%xx` escape at the start of `bytes` stands for, or `None`
/// when `bytes` does not start with a well-formed escape.
fn escaped_byte(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [b'%', hi, lo, ..] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
            u8::from_str_radix(std::str::from_utf8(&[*hi, *lo]).ok()?, 16).ok()
        }
        _ => None,
    }
}

/// RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~".
fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// Whether a `did:web` first segment is `host` or `host%3Aport`, with the
/// host an [`is_dns_name`] and the port an [`is_did_web_port`] (the same
/// rules `--did-host` applies to the registry's own DID).
///
/// The did:web method only percent-encodes the `:` before a port. Any other
/// escape (`%2F`, `%40`, `%2E`, ...) decodes to a path, userinfo or a
/// character a resolver may or may not decode, so the same party could be
/// spelled several ways that [`canonical_did`] can't safely merge; such a
/// DID is refused instead of stored under one spelling.
fn is_did_web_host(segment: &str) -> bool {
    let (host, port) = match segment.find('%') {
        Some(i) => (&segment[..i], Some(&segment[i..])),
        None => (segment, None),
    };
    is_dns_name(host)
        && port.is_none_or(|p| {
            p.get(..3)
                .is_some_and(|sep| sep.eq_ignore_ascii_case("%3A"))
                && is_did_web_port(&p[3..])
        })
}

/// Whether a `did:web` path segment names its directory one way only.
///
/// The resolver joins the path segments with `/` into a URL. URL parsing
/// removes the dot segments `.` and `..`, also written with `%2E`, so
/// `did:web:host:.:alice`, `did:web:host:bob:..:alice` and
/// `did:web:host:bob:%2E%2E:alice` are fetched as `did:web:host:alice`. It
/// keeps every other escape as written, but a server applies RFC 3986
/// normalization (section 6.2.2.2) and treats an escaped unreserved
/// character as the character itself, so it serves the document of
/// `did:web:host:alice` for `did:web:host:%61lice` too. [`canonical_did`]
/// doesn't decode escapes to merge any of these. Such a DID is refused
/// instead of stored as a second record for the same party, or one that
/// reads as another tenant.
///
/// A segment is refused when it is empty, `.` or `..`, or holds an escape of
/// an ALPHA, DIGIT, `-`, `.` or `_`, or of `/` (`%2F`, either case).
///
/// An empty segment (`did:web:host::alice`) makes `//` in the URL, which a
/// server that merges slashes serves as the path without it. An encoded
/// slash lets a path hide a `/`: `bob%2F..%2Falice` is one segment to the
/// resolver, but a server that decodes `%2F` before it removes dot segments
/// serves the document of `alice` for it. Neither can appear in a
/// well-formed did:web, so they are refused instead of proving what each
/// server does.
///
/// Escapes of other reserved characters (`%3A`, `%40`, ...) and of `~` stay
/// legal: DID Core's idchar has no `~`, so `%7E` is the only way to write
/// it. Assumes [`is_did_core`] already accepted the escapes as well formed.
fn is_did_web_path_segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | "..")
        && !segment.as_bytes().windows(3).any(|w| {
            // A `%` and the two hex digits after it.
            w[0] == b'%'
                && std::str::from_utf8(&w[1..])
                    .ok()
                    .filter(|hex| hex.bytes().all(|c| c.is_ascii_hexdigit()))
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                    .is_some_and(|v| {
                        v == b'/' || v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_')
                    })
        })
}

/// Whether `host` is a DNS host name that did:web can use: dot-separated
/// labels of `[A-Za-z0-9-]`, each 1-63 characters and not starting or
/// ending with `-`, and not an IPv4 address.
///
/// Empty labels are refused, including the trailing root dot: `example.com.`
/// resolves like `example.com`, so accepting it would let one party be
/// listed twice. The did:web method forbids IP addresses, so a name whose
/// last label URL parsing reads as a number is refused too. That is the
/// WHATWG "ends in a number" check, which the `url` crate under the resolver
/// applies: a last label of only digits (`127.0.0.1`, `example.123`), or of
/// `0x` or `0X` and nothing but hex digits, none included (`0x7f000001`,
/// `0x7f.0x1`, `0x`). Each such host is an IPv4 address to the resolver, or
/// one it refuses, so `did:web:0x7f000001` and `did:web:0x7f.0x1` would be
/// two more spellings of the IP address `127.0.0.1`. Only the last label
/// counts: `0xg.example` and `a.0x1b.example` are names.
pub fn is_dns_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && labels.last().is_some_and(|last| !is_ipv4_number(last))
}

/// Whether URL parsing reads `label`, the last label of a host, as an IPv4
/// number: ASCII digits only, or `0x`/`0X` followed by hex digits only (or by
/// nothing, which is 0). Assumes `label` is not empty.
fn is_ipv4_number(label: &str) -> bool {
    label.bytes().all(|c| c.is_ascii_digit())
        || label
            .strip_prefix("0x")
            .or_else(|| label.strip_prefix("0X"))
            .is_some_and(|hex| hex.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Whether `port` is a TCP port written one way only: decimal digits, no
/// leading zero, 1-65535. `08443` is the same port as `8443`, so accepting
/// it would give a did:web party a second spelling.
///
/// This is a general check, so 443 is a port. did:web has a rule of its own
/// on top of it, [`is_did_web_port`].
pub fn is_port(port: &str) -> bool {
    !port.is_empty()
        && !port.starts_with('0')
        && port.bytes().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

/// Whether `port` may follow the host of a did:web: an [`is_port`] that is
/// not 443. did:web always resolves over https, whose default port is 443, so
/// `host%3A443` fetches the same document as `host`. Accepting it would give
/// a did:web party a second spelling.
///
/// The registry applies it to the host of every did:web it stores, and the
/// binary applies it to `--did-host`.
pub fn is_did_web_port(port: &str) -> bool {
    is_port(port) && port != "443"
}

/// [`is_did`]'s method-independent part: the DID Core ABNF.
fn is_did_core(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("did:") else {
        return false;
    };
    let Some((method, id)) = rest.split_once(':') else {
        return false;
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return false;
    }
    // The grammar's last segment is non-empty: the id ends in an idchar.
    if id.is_empty() || id.ends_with(':') {
        return false;
    }
    let bytes = id.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if !(i + 2 < bytes.len()
                    && bytes[i + 1].is_ascii_hexdigit()
                    && bytes[i + 2].is_ascii_hexdigit())
                {
                    return false;
                }
                i += 3;
            }
            c if c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':') => i += 1,
            _ => return false,
        }
    }
    true
}

/// Serializes the DID-keyed map as a plain array of records (the DID is
/// already inside each record), which is the shape the API and the
/// snapshot expose.
mod records_as_list {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serializer};

    use crate::model::IssuerRecord;

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<String, IssuerRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(map.values())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, IssuerRecord>, D::Error> {
        let list = Vec::<IssuerRecord>::deserialize(deserializer)?;
        let mut map = BTreeMap::new();
        for record in list {
            if map.contains_key(&record.id) {
                return Err(serde::de::Error::custom(format!(
                    "'{}' is listed more than once",
                    record.id
                )));
            }
            map.insert(record.id.clone(), record);
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "did:web:authority.example";
    const TAO: &str = "did:web:tao.example";
    const TI: &str = "did:web:issuer.example";

    fn record(did: &str, role: Role, types: &[&str], by: Option<&str>) -> IssuerRecord {
        IssuerRecord {
            id: did.into(),
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

    fn three_tier() -> Registry {
        let mut r = Registry::default();
        r.upsert(record(ROOT, Role::RootTao, &["*"], None), 1)
            .unwrap();
        r.upsert(
            record(
                TAO,
                Role::Tao,
                &["MembershipCredential", "DataProcessorCredential"],
                Some(ROOT),
            ),
            1,
        )
        .unwrap();
        r.upsert(
            record(TI, Role::Ti, &["MembershipCredential"], Some(TAO)),
            1,
        )
        .unwrap();
        r
    }

    #[test]
    fn full_chain_is_trusted() {
        let r = three_tier();
        let d = r.check(TI, "MembershipCredential", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec![TI, TAO, ROOT]);
        assert_eq!(r.version, 3);
    }

    #[test]
    fn type_outside_issuer_scope_is_denied() {
        let d = three_tier().check(TI, "DataProcessorCredential", 10);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![TI]);
    }

    #[test]
    fn unknown_issuer_is_denied() {
        assert!(
            !three_tier()
                .check("did:web:nobody.example", "MembershipCredential", 10)
                .trusted
        );
    }

    #[test]
    fn suspending_an_accreditor_distrusts_its_issuers() {
        let mut r = three_tier();
        r.set_status(TAO, Status::Suspended, 5).unwrap();
        let d = r.check(TI, "MembershipCredential", 10);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![TI, TAO]);
        r.set_status(TAO, Status::Active, 6).unwrap();
        assert!(r.check(TI, "MembershipCredential", 10).trusted);
    }

    #[test]
    fn validity_window_is_enforced() {
        let mut r = three_tier();
        let mut ti = r.get(TI).unwrap().clone();
        ti.valid_from = Some(100);
        ti.valid_until = Some(200);
        r.upsert(ti, 2).unwrap();
        assert!(!r.check(TI, "MembershipCredential", 99).trusted);
        assert!(r.check(TI, "MembershipCredential", 100).trusted);
        assert!(!r.check(TI, "MembershipCredential", 200).trusted);
    }

    #[test]
    fn narrowing_an_accreditor_scope_is_rechecked_at_read_time() {
        let mut r = three_tier();
        r.upsert(
            record(TAO, Role::Tao, &["DataProcessorCredential"], Some(ROOT)),
            2,
        )
        .unwrap();
        let d = r.check(TI, "MembershipCredential", 10);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![TI, TAO]);
    }

    #[test]
    fn write_rules() {
        let mut r = three_tier();
        assert_eq!(
            r.upsert(record(ROOT, Role::RootTao, &["*"], Some(TAO)), 2),
            Err(RegistryError::RootWithAccreditor)
        );
        assert_eq!(
            r.upsert(record("did:web:x.example", Role::Ti, &["A"], None), 2),
            Err(RegistryError::MissingAccreditor(Role::Ti))
        );
        assert_eq!(
            r.upsert(record("did:web:x.example", Role::Ti, &["*"], Some(ROOT)), 2),
            Err(RegistryError::WildcardNotAllowed)
        );
        assert_eq!(
            r.upsert(record("did:web:x.example", Role::Ti, &["A"], Some(TI)), 2),
            Err(RegistryError::AccreditorCannotAccredit(TI.into()))
        );
        assert!(matches!(
            r.upsert(
                record("did:web:x.example", Role::Ti, &["Other"], Some(TAO)),
                2
            ),
            Err(RegistryError::AccreditorScope { .. })
        ));
        assert_eq!(
            r.upsert(record("not-a-did", Role::Ti, &["A"], Some(ROOT)), 2),
            Err(RegistryError::InvalidId("not-a-did".into()))
        );
        // Demoting a TAO that still accredits someone would orphan them.
        assert!(matches!(
            r.upsert(
                record(TAO, Role::Ti, &["MembershipCredential"], Some(ROOT)),
                2
            ),
            Err(RegistryError::HasDependents { .. })
        ));
        assert!(matches!(
            r.remove(TAO),
            Err(RegistryError::HasDependents { .. })
        ));
        assert_eq!(r.version, 3, "failed writes must not bump the version");
    }

    #[test]
    fn cycles_are_refused() {
        let mut r = three_tier();
        let sub = "did:web:sub-tao.example";
        r.upsert(
            record(sub, Role::Tao, &["MembershipCredential"], Some(TAO)),
            2,
        )
        .unwrap();
        assert_eq!(
            r.upsert(
                record(TAO, Role::Tao, &["MembershipCredential"], Some(sub)),
                3
            ),
            Err(RegistryError::Cycle(sub.into()))
        );
    }

    #[test]
    fn chains_longer_than_the_check_allows_are_refused_at_write() {
        let mut r = Registry::default();
        r.upsert(record("did:web:t0.example", Role::RootTao, &["*"], None), 1)
            .unwrap();
        for i in 1..MAX_CHAIN_DEPTH {
            r.upsert(
                record(
                    &format!("did:web:t{i}.example"),
                    Role::Tao,
                    &["A"],
                    Some(&format!("did:web:t{}.example", i - 1)),
                ),
                1,
            )
            .unwrap();
        }
        let last = format!("did:web:t{}.example", MAX_CHAIN_DEPTH - 1);
        assert!(r.check(&last, "A", 1).trusted);
        assert_eq!(
            r.upsert(
                record("did:web:too-deep.example", Role::Ti, &["A"], Some(&last)),
                1
            ),
            Err(RegistryError::ChainTooLong)
        );
        // Re-parenting a subtree deeper is caught too: t1 under a new TAO
        // at depth 2 would push the bottom of t1's subtree past the limit.
        r.upsert(
            record(
                "did:web:side.example",
                Role::Tao,
                &["A"],
                Some("did:web:t0.example"),
            ),
            1,
        )
        .unwrap();
        assert_eq!(
            r.upsert(
                record(
                    "did:web:t1.example",
                    Role::Tao,
                    &["A"],
                    Some("did:web:side.example")
                ),
                1
            ),
            Err(RegistryError::ChainTooLong)
        );
    }

    #[test]
    fn revalidation_rejects_files_that_break_the_rules() {
        let good = three_tier();
        assert_eq!(good.clone().revalidated().unwrap(), good);

        let mut wildcard = three_tier();
        wildcard.issuers.get_mut(TI).unwrap().credential_types = vec!["*".into()];
        assert_eq!(
            wildcard.revalidated(),
            Err(RegistryError::WildcardNotAllowed)
        );

        let mut orphan = three_tier();
        orphan.issuers.remove(TAO);
        assert_eq!(
            orphan.revalidated(),
            Err(RegistryError::UnknownAccreditor(TAO.into()))
        );

        let json = serde_json::json!({"version": 1, "issuers": [
            record(ROOT, Role::RootTao, &["*"], None),
            record(ROOT, Role::RootTao, &["*"], None),
        ]});
        assert!(serde_json::from_value::<Registry>(json).is_err());
    }

    #[test]
    fn canonical_did_normalizes_did_web_only() {
        for (input, want) in [
            ("did:web:issuer.example", "did:web:issuer.example"),
            ("did:web:Issuer.EXAMPLE", "did:web:issuer.example"),
            ("did:web:host.example%3a8443", "did:web:host.example%3A8443"),
            ("did:web:HOST.example%3a8443", "did:web:host.example%3A8443"),
            // Path segments are case-sensitive; only their escapes change.
            (
                "did:web:Example.com:Users:Alice%2fx",
                "did:web:example.com:Users:Alice%2Fx",
            ),
            // Other methods are returned unchanged.
            ("did:key:z6MkAbC%3a", "did:key:z6MkAbC%3a"),
            ("did:ebsi:zAbC", "did:ebsi:zAbC"),
            ("not-a-did", "not-a-did"),
        ] {
            assert_eq!(canonical_did(input), want, "{input}");
            assert_eq!(canonical_did(want), want, "idempotent: {want}");
        }
    }

    #[test]
    fn canonical_did_keeps_case_after_an_encoded_delimiter() {
        // `%2F`, `%40`, `%3F`, `%23` in the host segment decode to a path,
        // userinfo or query, which are case-sensitive. is_did refuses them
        // on write, so no lookup's result depends on the case after them.
        // It is kept so the DID echoed back is the canonical form of the one
        // asked for, and so the rule stays right if is_did ever admits such
        // an escape. Only canonical_did's own output (and the DID echoed in
        // an InvalidId) shows it, so this test pins it. That a lookup is
        // echoed in canonical form is pinned by
        // an_unlisted_lookup_is_echoed_in_canonical_form, and that escapes
        // are never decoded or dropped by
        // a_lookup_with_an_escaped_host_never_matches_a_stored_host.
        for (a, b) in [
            ("did:web:example.com%2FAlice", "did:web:example.com%2Falice"),
            ("did:web:example.com%40Bob", "did:web:example.com%40bob"),
            (
                "did:web:example.com%3FUser%3DBob",
                "did:web:example.com%3Fuser%3Dbob",
            ),
            ("did:web:example.com%23Frag", "did:web:example.com%23frag"),
        ] {
            assert_ne!(canonical_did(a), canonical_did(b), "{a} vs {b}");
            assert_eq!(canonical_did(a), a, "{a} is already canonical");
        }
        // The DNS host in front of the escape is still folded.
        assert_eq!(
            canonical_did("did:web:Example.COM%2fAlice"),
            "did:web:example.com%2FAlice"
        );
    }

    #[test]
    fn an_unlisted_lookup_is_echoed_in_canonical_form() {
        // The DID echoed back is the canonical form of what was asked, not
        // the text as written: host lowercased and escapes uppercased, but
        // the case after an escape kept.
        let mut r = three_tier();
        let asked = "did:web:Example.COM%2fAlice";
        let canonical = "did:web:example.com%2FAlice";
        let d = r.check(asked, "MembershipCredential", 10);
        assert!(!d.trusted);
        assert_eq!(d.chain, vec![canonical]);
        assert!(d.reason.is_some_and(|reason| reason.contains(canonical)));
        assert_eq!(
            r.set_status(asked, Status::Revoked, 5),
            Err(RegistryError::NotFound(canonical.into()))
        );
        assert_eq!(
            r.remove(asked),
            Err(RegistryError::NotFound(canonical.into()))
        );
    }

    #[test]
    fn a_lookup_with_an_escaped_host_never_matches_a_stored_host() {
        // Such DIDs can't be stored (is_did refuses them), but lookups take
        // any string. canonical_did never decodes, adds or drops an escape,
        // so none of them may land on a listed host, in any operation.
        let mut r = three_tier();
        let before = r.clone();
        for spelling in [
            "did:web:TAO.example%2F",
            "did:web:tao.example%2Fx",
            "did:web:tao.example%40",
            "did:web:tao.example%3F",
            "did:web:tao.example%23",
            // Escapes of unreserved characters decode to the listed host
            // under RFC 3986, but canonical_did leaves them alone.
            "did:web:tao%2Eexample",
            "did:web:%74ao.example",
            // The port separator without a port.
            "did:web:tao.example%3A",
            "did:web:tao.example%3Ax",
        ] {
            assert!(r.get(spelling).is_none(), "{spelling}");
            assert!(
                !r.check(spelling, "MembershipCredential", 10).trusted,
                "{spelling}"
            );
            assert!(r.dependents_of(spelling).is_empty(), "{spelling}");
            assert!(
                matches!(
                    r.set_status(spelling, Status::Revoked, 5),
                    Err(RegistryError::NotFound(_))
                ),
                "{spelling}"
            );
            assert!(
                matches!(r.remove(spelling), Err(RegistryError::NotFound(_))),
                "{spelling}"
            );
            assert_eq!(r, before, "{spelling} changed the registry");
        }
        assert!(r.get("did:web:TAO.example").is_some());
    }

    #[test]
    fn upsert_refuses_an_escaped_unreserved_character_in_the_did_web_host() {
        // `%2E` is `.` and `%74` is `t`, so these would be second spellings
        // of `new.example` and `tenant.example`. canonical_did can't merge
        // them (it never decodes), so is_did refuses them on write.
        let mut r = three_tier();
        for did in [
            "did:web:new%2Eexample",
            "did:web:%74enant.example",
            "did:web:tenant.example%3A",
            "did:web:tenant.example%3Ax",
            "did:web:tenant.example%23",
        ] {
            assert_eq!(
                r.upsert(
                    record(did, Role::Ti, &["MembershipCredential"], Some(TAO)),
                    2
                ),
                Err(RegistryError::InvalidId(did.into())),
                "{did}"
            );
        }
        assert_eq!(r.version, 3);
    }

    #[test]
    fn lookups_accept_non_canonical_dids() {
        let mut r = Registry::default();
        r.upsert(record(ROOT, Role::RootTao, &["*"], None), 1)
            .unwrap();
        r.upsert(
            record("did:web:host.example%3A8443", Role::Tao, &["A"], Some(ROOT)),
            1,
        )
        .unwrap();
        let mixed = "did:web:HOST.example%3a8443";
        assert!(r.get(mixed).is_some());
        let d = r.check(mixed, "A", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec!["did:web:host.example%3A8443", ROOT]);
        assert_eq!(r.dependents_of("did:web:AUTHORITY.example").len(), 1);
        r.set_status(mixed, Status::Suspended, 5).unwrap();
        assert!(!r.check(mixed, "A", 10).trusted);
        assert!(matches!(
            r.remove("did:web:AUTHORITY.example"),
            Err(RegistryError::HasDependents { .. })
        ));
        r.remove(mixed).unwrap();
        assert!(r.get("did:web:host.example%3A8443").is_none());
    }

    #[test]
    fn upsert_stores_the_canonical_form() {
        let mut r = three_tier();
        r.upsert(
            record(
                "did:web:New.Example%3a8443",
                Role::Ti,
                &["MembershipCredential"],
                Some("did:web:TAO.example"),
            ),
            2,
        )
        .unwrap();
        let stored = r.get("did:web:new.example%3A8443").unwrap();
        assert_eq!(stored.id, "did:web:new.example%3A8443");
        assert_eq!(stored.accredited_by.as_deref(), Some(TAO));
        // Writing the same DID in another spelling replaces, not duplicates.
        let before = r.issuers.len();
        r.upsert(
            record(
                "did:web:NEW.example%3A8443",
                Role::Ti,
                &["MembershipCredential"],
                Some(TAO),
            ),
            3,
        )
        .unwrap();
        assert_eq!(r.issuers.len(), before);
        assert!(r.issuers.keys().all(|k| k == &canonical_did(k)));
    }

    #[test]
    fn non_canonical_accredited_by_still_resolves() {
        let mut r = three_tier();
        r.upsert(
            record(
                "did:web:other.example",
                Role::Ti,
                &["MembershipCredential"],
                Some("did:web:Tao.Example"),
            ),
            2,
        )
        .unwrap();
        let d = r.check("did:web:other.example", "MembershipCredential", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec!["did:web:other.example", TAO, ROOT]);
    }

    #[test]
    fn revalidation_canonicalizes_and_rejects_collisions() {
        let mut loose = three_tier();
        let mut ti = loose.issuers.remove(TI).unwrap();
        ti.id = "did:web:Issuer.example".into();
        ti.accredited_by = Some("did:web:TAO.example".into());
        loose.issuers.insert(ti.id.clone(), ti);
        let fixed = loose.revalidated().unwrap();
        assert!(fixed.issuers.contains_key(TI));
        assert_eq!(fixed.get(TI).unwrap().accredited_by.as_deref(), Some(TAO));

        let mut dup = three_tier();
        let mut twin = dup.get(TI).unwrap().clone();
        twin.id = "did:web:ISSUER.example".into();
        dup.issuers.insert(twin.id.clone(), twin);
        assert_eq!(dup.revalidated(), Err(RegistryError::Duplicate(TI.into())));
    }

    #[test]
    fn is_did_follows_the_did_core_syntax() {
        for valid in [
            "did:web:issuer.example",
            "did:web:localhost%3A8443",
            "did:web:example.com:user:alice",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:ebsi:zabc",
            "did:x::a",
            "did:x:a_b-c.d",
        ] {
            assert!(is_did(valid), "{valid} should be valid");
        }
        for invalid in [
            "did:web:x.example#key-1",
            "did:web:x.example?versionId=1",
            "did:web:x.example/path",
            "did:web:x example",
            "did:web:x.example:",
            "did:web:",
            "did::x",
            "did:Web:x.example",
            "did:web",
            "did:web:x.example%3",
            "did:web:x.example%zz",
            "did:web:x.example%",
            "did:web:ex\u{e4}mple",
            "DID:web:x.example",
        ] {
            assert!(!is_did(invalid), "{invalid} should be invalid");
        }
    }

    #[test]
    fn did_web_host_is_a_dns_name_with_an_optional_port() {
        for valid in [
            "did:web:Issuer.Example",
            "did:web:localhost%3A8443",
            "did:web:localhost%3a8443",
            "did:web:localhost%3A1",
            "did:web:localhost%3A65535",
            // Only exactly 443 is the https default.
            "did:web:localhost%3A44",
            "did:web:localhost%3A80",
            "did:web:localhost%3A4430",
        ] {
            assert!(is_did(valid), "{valid} should be valid");
        }
        for invalid in [
            // Escapes other than the port separator decode to something
            // that is not part of a DNS host.
            "did:web:example.com%2FAlice",
            "did:web:user%40example.com",
            "did:web:%49ssuer.example",
            "did:web:issuer%2Eexample",
            // The port separator needs a port, and only one.
            "did:web:localhost%3A",
            "did:web:localhost%3Ahttp",
            "did:web:localhost%3A80%3A81",
            "did:web:%3A8443",
            // A port is 1-65535, as `--did-host` requires for the
            // registry's own DID.
            "did:web:localhost%3A0",
            "did:web:localhost%3A65536",
            "did:web:localhost%3A99999",
            "did:web:localhost%3A123456789012345678901234567890",
            // did:web always uses https, whose default port is 443, so
            // `host%3A443` fetches the same document as `host`: a second
            // spelling of the same party.
            "did:web:localhost%3A443",
            "did:web:localhost%3a443",
            "did:web:localhost%3A443:user:Alice",
            // Not DNS host characters.
            "did:web:a_b.example",
        ] {
            assert!(!is_did(invalid), "{invalid} should be invalid");
        }
    }

    #[test]
    fn is_port_is_a_general_canonical_port_check() {
        for valid in ["1", "80", "443", "8443", "65535"] {
            assert!(is_port(valid), "{valid} should be a port");
        }
        for invalid in [
            "", "0", "08443", "00", "65536", "99999", "+80", "-1", "8 0", "80a", "0x50", "８０",
        ] {
            assert!(!is_port(invalid), "{invalid} should not be a port");
        }
        // 443 is a port, but did:web has no second spelling of "no port".
        assert!(!is_did("did:web:localhost%3A443"));
    }

    #[test]
    fn did_web_path_segments_have_one_spelling() {
        for valid in [
            "did:web:example.com:user:Alice",
            "did:web:localhost%3A8443:user:Alice",
            // Escapes of reserved characters other than `/` and of `~`
            // (which DID Core's idchar can only write that way) are not
            // RFC 3986 aliases of a plain character.
            "did:web:example.com:user%7Ex",
            "did:web:example.com:a%3Ab",
            // Only a segment that is exactly `.` or `..` is a dot segment.
            "did:web:example.com:.a",
            "did:web:example.com:a..b",
            "did:web:example.com:...",
        ] {
            assert!(is_did(valid), "{valid} should be valid");
        }
        for invalid in [
            // The resolver joins path segments with `/` and the url crate
            // removes dot segments, so each of these fetches the same
            // document as the DID without it.
            "did:web:example.com:.",
            "did:web:example.com:..",
            "did:web:example.com:user:.",
            "did:web:example.com:.:alice",
            "did:web:example.com:bob:..:alice",
            "did:web:localhost%3A8443:.:alice",
            // Escaped dots are dot segments too, in either case.
            "did:web:example.com:%2E",
            "did:web:example.com:%2e",
            "did:web:example.com:bob:%2E%2E:alice",
            "did:web:example.com:bob:%2e%2e:alice",
            "did:web:example.com:bob:.%2E:alice",
            "did:web:example.com:bob:%2E.:alice",
            // An escaped ALPHA, DIGIT, `-`, `.` or `_` is RFC 3986-equivalent
            // to the plain character.
            "did:web:example.com:%61lice",
            "did:web:example.com:%41lice",
            "did:web:example.com:user%2Dx:Alice",
            "did:web:example.com:a%5Fb",
            "did:web:example.com:%30",
            // A server that decodes `%2F` before it removes dot segments
            // serves another path's document, so `%2F` is refused in either
            // case instead of proving what each server does.
            "did:web:example.com:a%2Fb",
            "did:web:example.com:a%2fb",
            "did:web:example.com:%2F",
            "did:web:example.com:bob%2F..%2Falice",
            "did:web:localhost%3A8443:bob%2f..%2fAlice",
        ] {
            assert!(!is_did(invalid), "{invalid} should be invalid");
        }
    }

    #[test]
    fn did_web_path_segments_are_not_empty() {
        // An empty segment makes `//` in the URL, which a server that merges
        // slashes serves as the path without it: `did:web:host::alice` would
        // alias `did:web:host:alice`.
        for invalid in [
            "did:web:example.com::alice",
            "did:web:example.com:user::alice",
            "did:web:example.com:user:::alice",
            "did:web:localhost%3A8443::alice",
        ] {
            assert!(!is_did(invalid), "{invalid} should be invalid");
        }
        // DID Core's grammar allows empty segments, and other methods keep
        // them.
        assert!(is_did("did:x::a"));
        assert!(is_did("did:web:example.com:user:alice"));
    }

    #[test]
    fn did_web_host_follows_dns_label_rules() {
        let label_63 = "a".repeat(63);
        let label_64 = "a".repeat(64);
        for valid in [
            "did:web:localhost".to_string(),
            "did:web:a-b.example".to_string(),
            "did:web:xn--bcher-kva.example".to_string(),
            "did:web:1password.example".to_string(),
            format!("did:web:{label_63}.example"),
        ] {
            assert!(is_did(&valid), "{valid} should be valid");
        }
        for invalid in [
            // Empty labels, including the trailing root dot that makes
            // `example.com.` a second spelling of `example.com`.
            "did:web:example.com.".to_string(),
            "did:web:.".to_string(),
            "did:web:.example.com".to_string(),
            "did:web:a..b".to_string(),
            // Hyphens may not start or end a label.
            "did:web:-".to_string(),
            "did:web:-a-.example".to_string(),
            "did:web:a.example-".to_string(),
            format!("did:web:{label_64}.example"),
            // The did:web method-specific id must not be an IP address.
            "did:web:127.0.0.1".to_string(),
            "did:web:127.0.0.1%3A8443".to_string(),
            // A leading zero is a second spelling of the same port.
            "did:web:localhost%3A08443".to_string(),
            "did:web:localhost%3A00".to_string(),
        ] {
            assert!(!is_did(&invalid), "{invalid} should be invalid");
        }
    }

    #[test]
    fn did_web_host_refuses_what_url_parsing_reads_as_ipv4() {
        // WHATWG URL parsing (the url crate under the resolver) reads a host
        // whose last label is all digits, or `0x` and hex digits (none
        // included), as an IPv4 address: every one of these is fetched from
        // 127.0.0.1 (or 0.0.0.0), which did:web forbids and which would give
        // that one address many spellings.
        for ip in [
            "0x7f000001",
            "0X7F000001",
            "0x7f.0x1",
            "0x7f.0.0.0x1",
            "0x7F.0.0.1",
            "0x",
            "0X",
            "0x0",
            // url refuses these ("invalid IPv4 address"), so nobody can
            // resolve them either.
            "a.0x",
            "example.0x10",
            "example.0X",
            "a.0x1b",
        ] {
            assert!(!is_dns_name(ip), "{ip} should not be a DNS name");
            for did in [
                format!("did:web:{ip}"),
                format!("did:web:{ip}%3A8443"),
                format!("did:web:{ip}:alice"),
            ] {
                assert!(!is_did(&did), "{did} should be invalid");
            }
        }
        // Only the last label decides, and only `0x` followed by nothing but
        // hex digits does: these stay names to url.
        for name in [
            "0xg.example",
            "a.0x1b.example",
            "0x.example",
            "0xff.example",
            "example.0xg",
            "example.0x1g",
            "0xg",
            "0x1g",
            "example.0b1",
            "x0.example",
            "a0x1",
        ] {
            assert!(is_dns_name(name), "{name} should be a DNS name");
            let did = format!("did:web:{name}");
            assert!(is_did(&did), "{did} should be valid");
        }
    }

    #[test]
    fn a_party_cannot_be_stored_under_a_second_host_spelling() {
        let mut r = three_tier();
        for (first, second) in [
            (
                "did:web:tenant.example%3A8443",
                "did:web:tenant.example%3A08443",
            ),
            ("did:web:other.example", "did:web:other.example."),
            ("did:web:default.example", "did:web:default.example%3A443"),
        ] {
            r.upsert(
                record(first, Role::Ti, &["MembershipCredential"], Some(TAO)),
                2,
            )
            .unwrap();
            assert_eq!(
                r.upsert(
                    record(second, Role::Ti, &["MembershipCredential"], Some(TAO)),
                    2
                ),
                Err(RegistryError::InvalidId(second.into()))
            );
        }
        assert_eq!(r.issuers.len(), 6);
    }

    #[test]
    fn a_hex_ipv4_host_cannot_be_stored_as_an_alias_of_an_address() {
        // Each of these is fetched from https://127.0.0.1/, as is
        // `did:web:127.0.0.1`, which is refused: storing two of them and
        // suspending one would leave the other trusted.
        let mut r = three_tier();
        let before = r.clone();
        for did in [
            "did:web:0x7f000001",
            "did:web:0X7F000001",
            "did:web:0x7f.0x1",
            "did:web:0x7f.0.0.0x1",
            "did:web:0x7f000001:alice",
            "did:web:0x7f.0.0.0x1:alice",
            "did:web:0x7f000001%3A8443",
        ] {
            assert_eq!(
                r.upsert(
                    record(did, Role::Ti, &["MembershipCredential"], Some(TAO)),
                    2
                ),
                Err(RegistryError::InvalidId(canonical_did(did))),
                "{did}"
            );
            assert_eq!(r, before, "{did} changed the registry");
        }
    }

    #[test]
    fn a_party_cannot_be_stored_under_a_second_path_spelling() {
        let mut r = three_tier();
        let by_tao = |did: &str| record(did, Role::Ti, &["MembershipCredential"], Some(TAO));
        r.upsert(by_tao("did:web:host.example:alice"), 2).unwrap();
        for alias in [
            "did:web:host.example:.:alice",
            "did:web:host.example:bob:..:alice",
            "did:web:host.example:bob:%2E%2E:alice",
            "did:web:host.example:%61lice",
            "did:web:host.example:alice:.",
            "did:web:host.example:bob%2F..%2Falice",
            "did:web:host.example:bob%2f..%2falice",
            "did:web:host.example::alice",
        ] {
            // The error names the DID in canonical form (`%2f` is `%2F`).
            assert_eq!(
                r.upsert(by_tao(alias), 2),
                Err(RegistryError::InvalidId(canonical_did(alias))),
                "{alias}"
            );
        }
        assert_eq!(r.issuers.len(), 4);
    }

    #[test]
    fn a_stored_path_alias_is_refused_on_load_too() {
        for alias in [
            "did:web:issuer.example:bob:%2E%2E:alice",
            "did:web:issuer.example:bob%2F..%2Falice",
            "did:web:issuer.example::alice",
        ] {
            let mut loose = three_tier();
            let mut ti = loose.issuers.remove(TI).unwrap();
            ti.id = alias.into();
            loose.issuers.insert(ti.id.clone(), ti);
            assert_eq!(
                loose.revalidated(),
                Err(RegistryError::InvalidId(alias.into())),
                "{alias}"
            );
        }
    }

    #[test]
    fn a_did_web_path_cannot_name_the_bare_host_document() {
        for valid in [
            // `.well-known` is only the bare host's document when it is the
            // whole path; anywhere else it is an ordinary directory name.
            "did:web:example.com:.well-known:alice",
            "did:web:example.com:alice:.well-known",
            "did:web:example.com:well-known",
            "did:web:example.com:.well-known2",
            // Path segments keep their case, so this is another directory.
            "did:web:example.com:.Well-Known",
        ] {
            assert!(is_did(valid), "{valid} should be valid");
        }
        for invalid in [
            // The resolver turns the bare host into
            // https://host/.well-known/did.json, and a sole `.well-known`
            // path segment into the very same URL.
            "did:web:example.com:.well-known",
            "did:web:localhost%3A8443:.well-known",
        ] {
            assert!(!is_did(invalid), "{invalid} should be invalid");
        }
    }

    #[test]
    fn a_party_cannot_be_stored_as_both_its_host_and_its_well_known_path() {
        let mut r = three_tier();
        let by_tao = |did: &str| record(did, Role::Ti, &["MembershipCredential"], Some(TAO));
        r.upsert(by_tao("did:web:host2.example"), 2).unwrap();
        let alias = "did:web:host2.example:.well-known";
        assert_eq!(
            r.upsert(by_tao(alias), 2),
            Err(RegistryError::InvalidId(alias.into()))
        );
        // Suspending the host's spelling must distrust the party, so the
        // other spelling can't exist to stay trusted.
        r.set_status("did:web:host2.example", Status::Suspended, 3)
            .unwrap();
        assert!(!r.check(alias, "MembershipCredential", 10).trusted);
        assert!(r.get(alias).is_none());
        assert_eq!(r.issuers.len(), 4);
    }

    #[test]
    fn a_stored_well_known_path_is_refused_on_load_too() {
        let mut loose = three_tier();
        let mut ti = loose.issuers.remove(TI).unwrap();
        ti.id = "did:web:issuer.example:.well-known".into();
        loose.issuers.insert(ti.id.clone(), ti);
        assert_eq!(
            loose.revalidated(),
            Err(RegistryError::InvalidId(
                "did:web:issuer.example:.well-known".into()
            ))
        );
    }

    #[test]
    fn a_stored_default_port_is_refused_on_load_too() {
        // Data written before `host%3A443` was refused must fail startup
        // instead of listing the same party under two spellings.
        let mut loose = three_tier();
        let mut ti = loose.issuers.remove(TI).unwrap();
        ti.id = "did:web:issuer.example%3A443".into();
        loose.issuers.insert(ti.id.clone(), ti);
        assert_eq!(
            loose.revalidated(),
            Err(RegistryError::InvalidId(
                "did:web:issuer.example%3A443".into()
            ))
        );
    }

    #[test]
    fn a_stored_hex_ipv4_host_is_refused_on_load_too() {
        // Data written while `did:web:0x7f000001` was accepted must fail
        // startup instead of listing one address under many spellings.
        for did in [
            "did:web:0x7f000001",
            "did:web:0x7f.0x1",
            "did:web:0x7f.0.0.0x1:alice",
            "did:web:example.0x10",
        ] {
            let mut loose = three_tier();
            let mut ti = loose.issuers.remove(TI).unwrap();
            ti.id = did.into();
            loose.issuers.insert(ti.id.clone(), ti);
            assert_eq!(
                loose.revalidated(),
                Err(RegistryError::InvalidId(did.into())),
                "{did}"
            );
        }
    }

    #[test]
    fn upsert_refuses_an_encoded_delimiter_in_the_did_web_host() {
        let mut r = three_tier();
        assert_eq!(
            r.upsert(
                record(
                    "did:web:tenant.example%2FAlice",
                    Role::Ti,
                    &["MembershipCredential"],
                    Some(TAO)
                ),
                2
            ),
            Err(RegistryError::InvalidId(
                "did:web:tenant.example%2FAlice".into()
            ))
        );
        assert_eq!(r.version, 3);
    }

    #[test]
    fn upsert_refuses_a_did_url() {
        let mut r = three_tier();
        let url = "did:web:x.example#key-1";
        assert_eq!(
            r.upsert(
                record(url, Role::Ti, &["MembershipCredential"], Some(TAO)),
                2
            ),
            Err(RegistryError::InvalidId(url.into()))
        );
        assert_eq!(r.version, 3);
    }

    #[test]
    fn serializes_as_a_list() {
        let r = three_tier();
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["issuers"].as_array().unwrap().len(), 3);
        let back: Registry = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn records_are_written_with_id_and_legacy_did_still_reads() {
        // A record names its party with `id`, which holds a DID (DCP) or an
        // OID4VCI credential issuer URL, so the key is not called `did`.
        let json = serde_json::to_value(three_tier()).unwrap();
        let first = &json["issuers"][0];
        assert_eq!(first["id"], ROOT, "{first}");
        assert!(first.get("did").is_none(), "{first}");

        // Data files and snapshots written before the rename still load.
        let legacy = serde_json::json!({"version": 1, "issuers": [
            {"did": ROOT, "role": "root_tao", "credentialTypes": ["*"], "status": "active"}
        ]});
        let r: Registry = serde_json::from_value(legacy).unwrap();
        assert!(r.get(ROOT).is_some());
    }

    // OID4VCI names a credential issuer by its Credential Issuer Identifier:
    // an https URL with a host, an optional port and path, and no query or
    // fragment. SD-JWT VCs carry it as `iss` and their type as `vct`.
    const OID4VCI_TI: &str = "https://issuer.example";
    const OID4VCI_TENANT: &str = "https://issuers.example:8443/tenants/acme";
    const PID_VCT: &str = "https://credentials.example/identity_credential";

    #[test]
    fn an_oid4vci_issuer_is_listed_and_checked_next_to_dcp_issuers() {
        let mut r = three_tier();
        r.upsert(
            record(OID4VCI_TI, Role::Ti, &["MembershipCredential"], Some(TAO)),
            2,
        )
        .unwrap();
        let d = r.check(OID4VCI_TI, "MembershipCredential", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec![OID4VCI_TI, TAO, ROOT]);
        // The DCP issuer under the same TAO is unaffected.
        assert!(r.check(TI, "MembershipCredential", 10).trusted);
        // Scope still applies.
        assert!(!r.check(OID4VCI_TI, "DataProcessorCredential", 10).trusted);
    }

    #[test]
    fn an_oid4vci_party_can_accredit_and_vct_types_are_scoped() {
        let mut r = three_tier();
        // A TAO named by URL, accredited by the did:web root, accrediting a
        // tenant issuer for an SD-JWT VC type.
        r.upsert(record(OID4VCI_TI, Role::Tao, &[PID_VCT], Some(ROOT)), 2)
            .unwrap();
        r.upsert(
            record(OID4VCI_TENANT, Role::Ti, &[PID_VCT], Some(OID4VCI_TI)),
            2,
        )
        .unwrap();
        let d = r.check(OID4VCI_TENANT, PID_VCT, 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec![OID4VCI_TENANT, OID4VCI_TI, ROOT]);
        assert_eq!(r.dependents_of(OID4VCI_TI), vec![OID4VCI_TENANT]);

        r.set_status(OID4VCI_TI, Status::Suspended, 3).unwrap();
        assert!(!r.check(OID4VCI_TENANT, PID_VCT, 10).trusted);
    }

    #[test]
    fn well_formed_credential_issuer_identifiers_are_accepted() {
        for id in [
            "https://issuer.example",
            "https://issuer.example:8443",
            "https://issuer.example/tenant",
            "https://issuer.example/realms/acme-1/issuer",
            "https://issuer.example/~alice/a_b.c-d",
            "https://issuer.example/caf%C3%A9",
            "https://issuer.example/a%3Ab",
        ] {
            let mut r = three_tier();
            assert_eq!(
                r.upsert(
                    record(id, Role::Ti, &["MembershipCredential"], Some(TAO)),
                    2
                ),
                Ok(()),
                "{id}"
            );
            assert!(r.check(id, "MembershipCredential", 10).trusted, "{id}");
        }
    }

    #[test]
    fn urls_that_are_not_credential_issuer_identifiers_are_refused() {
        for id in [
            // Not https.
            "http://issuer.example",
            "ftp://issuer.example",
            "issuer.example",
            "https:issuer.example",
            "https://",
            // OID4VCI: no query or fragment.
            "https://issuer.example?tenant=acme",
            "https://issuer.example/t?x=1",
            "https://issuer.example#frag",
            // No userinfo: who the party is must not hide before an `@`.
            "https://alice@issuer.example",
            "https://issuer.example@evil.example",
            // The host must be a DNS name, as for did:web.
            "https://127.0.0.1",
            "https://[::1]",
            "https://issuer_x.example",
            "https://-issuer.example",
            "https://issuer%2Eexample",
            // A port is 1-65535, no leading zero.
            "https://issuer.example:0",
            "https://issuer.example:65536",
            "https://issuer.example:",
            // Characters a URL parser rewrites or that are not URL syntax.
            "https://issuer.example/a b",
            "https://issuer.example/a\\b",
            "https://issuer.example/caf\u{e9}",
            "https://issuer.example/%zz",
            "https://issuer.example/a%2",
        ] {
            let mut r = three_tier();
            assert_eq!(
                r.upsert(
                    record(id, Role::Ti, &["MembershipCredential"], Some(TAO)),
                    2
                ),
                Err(RegistryError::InvalidId(id.into())),
                "{id}"
            );
            assert_eq!(r.version, 3, "{id}");
        }
    }

    #[test]
    fn credential_issuer_ids_are_stored_and_looked_up_in_canonical_form() {
        // Scheme and host are case-insensitive to every URL parser, and an
        // escape's hex digits are too; the path is case-sensitive.
        let mut r = three_tier();
        r.upsert(
            record(
                "HTTPS://Issuer.EXAMPLE:8443/Tenant/caf%c3%a9",
                Role::Tao,
                &["MembershipCredential"],
                Some(TAO),
            ),
            2,
        )
        .unwrap();
        let canonical = "https://issuer.example:8443/Tenant/caf%C3%A9";
        assert_eq!(r.get(canonical).map(|x| x.id.as_str()), Some(canonical));
        assert!(
            r.get("https://ISSUER.example:8443/Tenant/caf%c3%A9")
                .is_some()
        );
        assert!(
            r.get("https://issuer.example:8443/tenant/caf%C3%A9")
                .is_none()
        );

        // accreditedBy in another spelling resolves to the same party.
        r.upsert(
            record(
                OID4VCI_TI,
                Role::Ti,
                &["MembershipCredential"],
                Some("https://ISSUER.example:8443/Tenant/caf%C3%a9"),
            ),
            2,
        )
        .unwrap();
        assert_eq!(
            r.get(OID4VCI_TI).unwrap().accredited_by.as_deref(),
            Some(canonical)
        );
        let d = r.check("Https://Issuer.Example", "MembershipCredential", 10);
        assert!(d.trusted, "{d:?}");
        assert_eq!(d.chain, vec![OID4VCI_TI, canonical, TAO, ROOT]);

        // A rewrite in another spelling replaces instead of duplicating.
        let before = r.issuers.len();
        r.upsert(
            record(
                "https://Issuer.example",
                Role::Ti,
                &["MembershipCredential"],
                Some(TAO),
            ),
            3,
        )
        .unwrap();
        assert_eq!(r.issuers.len(), before);
        assert_eq!(
            canonical_id("HTTPS://X.Example/A%2f"),
            "https://x.example/A%2F"
        );
        assert_eq!(canonical_id("did:web:X.example"), "did:web:x.example");
        assert_eq!(canonical_id("did:key:zAbC"), "did:key:zAbC");
    }

    #[test]
    fn a_credential_issuer_cannot_be_stored_under_a_second_spelling() {
        // Each of these fetches the same issuer metadata as an identifier
        // without the alias (or as another listed one), so storing it would
        // list one party twice, or let a record read as another tenant.
        for alias in [
            // https's default port.
            "https://issuer.example:443",
            "https://issuer.example:443/tenant",
            // A port with a leading zero.
            "https://issuer.example:08443",
            // A trailing slash: OID4VCI removes it before building the
            // metadata URL, and URL parsers add one to a bare origin.
            "https://issuer.example/",
            "https://issuer.example/tenant/",
            // Empty segments, which servers that merge slashes drop.
            "https://issuer.example//tenant",
            "https://issuer.example/a//tenant",
            // Dot segments, which URL parsing removes.
            "https://issuer.example/.",
            "https://issuer.example/./tenant",
            "https://issuer.example/x/../tenant",
            "https://issuer.example/..",
            // Escaped unreserved characters, which servers decode.
            "https://issuer.example/%2E%2E/tenant",
            "https://issuer.example/%2e",
            "https://issuer.example/%61cme",
            "https://issuer.example/%7Ealice",
            "https://issuer.example/a%5Fb",
            // An encoded slash hides a path separator in one segment.
            "https://issuer.example/x%2F..%2Ftenant",
            "https://issuer.example/a%2fb",
            // Host spellings did:web refuses for the same reason.
            "https://issuer.example.",
            "https://0x7f000001",
            "https://example.0x10",
        ] {
            let mut r = three_tier();
            assert_eq!(
                r.upsert(
                    record(alias, Role::Ti, &["MembershipCredential"], Some(TAO)),
                    2
                ),
                Err(RegistryError::InvalidId(canonical_id(alias))),
                "{alias}"
            );
            assert_eq!(r.version, 3, "{alias}");
        }
    }

    #[test]
    fn a_stored_credential_issuer_alias_is_refused_on_load_too() {
        let mut r = three_tier();
        let alias = "https://issuer.example/tenant/";
        let mut rec = record(alias, Role::Ti, &["MembershipCredential"], Some(TAO));
        rec.updated_at = 1;
        r.issuers.insert(alias.into(), rec);
        assert_eq!(r.revalidated(), Err(RegistryError::InvalidId(alias.into())));

        // Two spellings of one party in a file collapse and are refused.
        let mut r = three_tier();
        for id in ["https://issuer.example", "https://ISSUER.example"] {
            r.issuers.insert(
                id.into(),
                record(id, Role::Ti, &["MembershipCredential"], Some(TAO)),
            );
        }
        assert_eq!(
            r.revalidated(),
            Err(RegistryError::Duplicate("https://issuer.example".into()))
        );
    }
}
