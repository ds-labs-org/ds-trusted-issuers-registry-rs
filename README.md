# Trusted Issuers Registry

*(repo/product: `ds-trusted-issuers-registry-rs`)*

The dataspace authority's list of **who may issue which credentials**. A
verifier that receives a Verifiable Credential (a DCP Credential Service
accepting a `CredentialMessage`, a connector checking a presentation, the
catalog broker, a wallet or verifier taking OID4VCI-issued credentials) asks
the registry whether the credential's issuer is trusted for that credential
type, instead of each service carrying its own static allow-list (today,
`ds-identity-hub-rs`'s `--trusted-issuer-did`).

It lists issuers from both issuance protocols the dataspace uses, side by
side and under one accreditation chain:

| Protocol | The issuer is named by | Example `id` | The credential type is |
|---|---|---|---|
| DCP (Decentralized Claims Protocol) | its DID, the VC's `issuer` | `did:web:issuer.example` | a VC `type` entry, e.g. `MembershipCredential` |
| OID4VCI (OpenID for Verifiable Credential Issuance) | its Credential Issuer Identifier, an https URL (an SD-JWT VC's `iss`) | `https://issuer.example/tenants/acme` | the format's type: `vct` for SD-JWT VC (often a URL), `type` for W3C VCs |

The rule of thumb: register a party under whatever its credentials put in
the issuer field, because that is what a verifier looks up. An OID4VCI
issuer that signs W3C VCs with a DID is registered under that DID. An
organisation that issues both ways gets two records, one per id; they may
share an accreditor.

## Model

The registry follows the EBSI Trusted Issuers Registry's three-tier
accreditation chain:

| Role | Meaning | `accreditedBy` |
|---|---|---|
| `root_tao` | Root Trusted Accreditation Organisation: the trust anchor, normally the dataspace authority itself | none |
| `tao` | Trusted Accreditation Organisation: may accredit others | a `root_tao` or `tao` |
| `ti` | Trusted Issuer: issues credentials, accredits no one | a `root_tao` or `tao` |

Each record lists the `credentialTypes` it may issue (and, for the two TAO
roles, accredit others for). A child can never be scoped wider than its
accreditor; only a `root_tao` may use the `*` wildcard. A record also has an
optional validity window (`validFrom`/`validUntil`, unix seconds) and a
`status` (`active`, `suspended`, `revoked`).

```json
{
  "id": "did:web:issuer.example",
  "role": "ti",
  "name": "Example Issuer",
  "credentialTypes": ["MembershipCredential"],
  "accreditedBy": "did:web:authority.example",
  "validUntil": 1830000000,
  "status": "active",
  "updatedAt": 1792017886
}
```

**Trust check.** An issuer is trusted for a type when it and every
accreditor up to a `root_tao` are listed, `active`, inside their validity
window and scoped for that type. The chain is re-walked on every check, so
suspending or narrowing a TAO immediately distrusts everything it
accredited.

**Write rules.** The accreditor must exist and be able to accredit, cover
the child's types, and not close a cycle or make a chain longer than 8
links. A record that still accredits
others can't be removed or demoted to `ti`. Failed writes change nothing.

An OID4VCI issuer looks the same with a URL `id` and, here, an SD-JWT VC
type, accredited by the same DID-named TAO a DCP issuer could be:

```json
{
  "id": "https://issuer.example/tenants/acme",
  "role": "ti",
  "name": "ACME PID issuer (OID4VCI)",
  "credentialTypes": ["https://credentials.example/identity_credential"],
  "accreditedBy": "did:web:pid-tao.example",
  "status": "active"
}
```

Records written before OID4VCI support used the key `did`. It is still read
everywhere (data files, snapshots, PUT bodies) and written back as `id`.

**DID canonicalization.** `did:web` DIDs are stored and looked up in one
canonical form: the DNS host is lowercased and the hex digits of
percent-escapes are uppercased (`did:web:Host.example%3a8443` is
`did:web:host.example%3A8443`; path segments keep their case). It applies
to `id` and `accreditedBy` on write and to the DID in every read, check
and status change, so a record matches however a credential spells its
issuer. Other DID methods are compared as given. Two records that collapse
to the same DID in a loaded data file or snapshot are refused as
duplicates.

A DID `id` must be a bare DID per DID Core syntax. DID URLs
(with a `#fragment`, `?query` or `/path`), spaces, a trailing `:` and
malformed `%` escapes are refused with 422. A `did:web` host must be a DNS
name with an optional `%3A` and port, so that each party has one spelling:
labels of `[A-Za-z0-9-]`, 1-63 characters, not starting or ending with
`-`, no empty label or trailing dot (`example.com.`), and no IP address,
which includes what URL parsing reads as one: a last label of only digits,
or of `0x` and hex digits (`did:web:0x7f000001` and `did:web:0x7f.0x1` are
fetched from 127.0.0.1, like `did:web:127.0.0.1`; `0xg.example` is a name);
the port is 1-65535 without leading zeros (`%3A08443`) and is not 443
(`did:web:host%3A443` fetches the same document as `did:web:host`, since
did:web always uses https). Any other escape in the host
(`did:web:example.com%2FAlice`) is refused too. One spelling covers path
segments as well: one may not be `.` or `..` or escape a letter, digit,
`-`, `.` or `_`. The resolver turns the DID into a URL and URL parsing
removes dot segments, so `did:web:host:bob:..:alice` and
`did:web:host:bob:%2E%2E:alice` fetch the document of `did:web:host:alice`;
servers treat an escaped letter, digit, `-`, `.` or `_` as the plain
character, so `did:web:host:%61lice` does too.
A path may not be just `.well-known` either
(`did:web:host:.well-known` fetches the document of `did:web:host`);
`.well-known` with other segments is fine. A path segment may not be empty
(`did:web:host::alice` aliases `did:web:host:alice` on servers that merge
slashes) or contain `%2F` (a server that decodes it before removing dot
segments serves another path's document for `did:web:host:bob%2F..%2Falice`).
Escapes of other characters (`%3A`, `%7E`, ...) stay legal. `--did-host`
applies the same rules to the registry's own DID.

**OID4VCI issuer ids.** A URL `id` (or `accreditedBy`) must be an OID4VCI
Credential Issuer Identifier: `https://`, a host, an optional port and
path, no query (`?`) or fragment (`#`). The same one-spelling idea applies
as for did:web, because a verifier fetches the issuer's metadata from
`https://<host>/.well-known/openid-credential-issuer<path>` and two
strings that fetch the same metadata must not be two parties:

- Stored and looked up with the scheme and host lowercased and escape hex
  digits uppercased (`HTTPS://Issuer.example/Tenant` is
  `https://issuer.example/Tenant`); the path keeps its case.
- The host follows the did:web host rules above: a DNS name, no IP address
  in any form, no trailing dot, no userinfo (`https://alice@host`).
- A port is 1-65535 without leading zeros, and not 443 (`https://host:443`
  is `https://host`).
- No trailing slash (`https://host/` and `https://host/tenant/` fetch the
  same metadata as without it; OID4VCI strips it).
- Path segments are letters, digits, `-`, `.`, `_`, `~` and
  percent-escapes of anything else; not empty (`//`), not `.` or `..`, and
  no escape of a letter, digit, `-`, `.`, `_`, `~` (`%61`, `%2E`) or of
  `/` (`%2F`). Other characters (spaces, `;`, `:`, `@`, non-ASCII) must be
  escaped (`%3B`, `%C3%A9`, ...).

Anything else is refused with 422.

This covers how an OID4VCI issuer is *named*. Credentials whose issuer is
proven only by an X.509 chain (ISO mdoc/mDL, SD-JWT VCs with only an `x5c`
header) aren't covered: the registry stores no certificates (see
[Not done yet](#not-done-yet)).

**Upgrading.** On startup, data files and snapshots are re-checked under
this DID syntax and canonical form. A record whose DID is now invalid or
that collapses into another record makes startup fail with an error naming
the DID; fix or remove it in the file before upgrading. Besides DID URLs
(`#fragment`, `?query`), that covers `did:web` hosts that earlier versions
accepted: escapes other than the port's `%3A` (`%2F`, `%40`, ...), `_`,
empty or hyphen-edged labels, a trailing dot, IP addresses (also those
written with a last label of `0x` and hex digits, such as `0x7f000001` or
`example.0x10`), and ports that are 0, above 65535, 443 or written with
leading zeros, path segments that are empty (`host::alice`), `.` or `..`, or
contain `%2F` or an escape of a letter, digit, `-`, `.` or `_` (`user%2Dx`),
and a path that is just `.well-known`. `--did-host` likewise refuses an IP
address (in either form), port 443 (leave it out: did:web already uses
https) or a port with leading zeros.

Records are now written with `id` instead of `did`. The registry reads
both, but a verifier embedding an older `trusted-issuers-core` can't parse
a new snapshot: upgrade verifiers' `trusted-issuers-core` before (or with)
the registry.

## API

Public reads, no authentication:

| Method and path | Returns |
|---|---|
| `GET /v1/issuers[?credentialType=T&role=R&status=S&idKind=K]` | `{version, total, items}`, optionally only records covering `T`, in role `R` (`root_tao`, `tao`, `ti`), with status `S` (`active`, `suspended`, `revoked`) and named by kind `K` (`did` for DID-named issuers such as DCP's, `url` for OID4VCI credential issuer URLs); an unknown role, status or kind is a 400. This is a listing, not an allow-list: it includes suspended and expired records, so use the trust check or the snapshot for decisions |
| `GET /v1/issuers/{id}` | one record, or 404 |
| `GET /v1/issuers/{id}/types/{type}` | `{trusted, chain, reason?}` for that issuer and type, now |
| `GET /v1/issuers/{id}/accreditations` | `{accreditations: [jwt, ...]}`: the issuer's chain as registry-signed accreditation VCs (see [Accreditations as VCs](#accreditations-as-vcs)); 404 for an unknown issuer, 422 when its chain is broken now |
| `POST /v1/x509/check` | `{x5c, credentialType, eku?}` → `{trusted, chain, reason?}`: whether a certificate chain proves a listed issuer (see [X.509 trust anchors](#x509-trust-anchors)); bodies are strict, at most 10 certificates |
| `GET /v1/snapshot` | the whole registry as a signed JWS (`application/trust-list+jwt`) |
| `GET /v1/lote` | the registry as an ETSI TS 119 602 List of Trusted Entities, JSON (see [ETSI LoTE export](#etsi-lote-export)) |
| `GET /v1/lote.jws` | the same list as a compact JWS signed by the registry key (`application/jose`) |
| `GET /.well-known/did.json` | the registry's `did:web` document, holding the snapshot key |
| `GET /health` | `ok` |

Authority writes, behind `Authorization: Bearer <admin token>`:

| Method and path | Effect |
|---|---|
| `GET /v1/admin` | 204 when the token would be accepted, else the same 401/403 a write gets; lets a console show itself read-only |
| `PUT /v1/issuers/{id}` | create (201) or replace (200) a record; a body `id` (or legacy `did`) is optional but must match the path |
| `PATCH /v1/issuers/{id}/status` | `{"status": "suspended"}` and so on |
| `DELETE /v1/issuers/{id}` | remove (204); 409 while it still accredits someone |
| `GET /v1/admin/audit[?after=N&limit=L&id=ID]` | `{entries, head}`: the audit log from `seq` N+1, at most L entries (default 100, 1-1000), only those about ID; `head` is the latest entry's `{seq, hash}` (see [Audit log](#audit-log)) |

Authorization is checked before the body is read, so an unauthenticated
caller only ever gets 401 (or 403 when the admin API is disabled). Bodies
with unknown fields (such as a misspelled `validUntil`) are refused with 400.
Rule violations return 422, removing or demoting a record that still
accredits others returns 409, and unknown ids return 404. An id goes in the path as one
percent-encoded segment, so `did:web:host%3A8443` is sent as
`did:web:host%253A8443` and `https://issuer.example/tenants/acme` as
`https:%2F%2Fissuer.example%2Ftenants%2Facme`. A credential type that is a
URL (an SD-JWT `vct`) is encoded the same way in `/types/{type}` and in
`credentialType=`. A gateway in front of the registry must forward `%2F`
and `%25` without decoding them (some proxies decode the path, such as nginx
when `proxy_pass` names a URI); the did:web `%253A` form already relies on
this.

The admin API is meant to sit behind the same OIDC gateway (apisix +
Zitadel) as `ds-authority-governance-ui`, whose "Trusted Issuers" view
drives it. The admin token is the service-to-service
credential behind that gateway. Without one, or with an empty one, the
admin API is disabled.

### Audit log

Every successful admin write appends one entry: `seq`, `at` (unix
seconds), `actor`, `action` (`put`, `status`, `delete`), the record `id`,
the record `before` and `after` (absent when created or deleted), the
registry `version` after the write, and the hash chain fields `prevHash`
and `hash` (hex SHA-256 of the entry without `hash`; the first entry's
`prevHash` is 64 zeros). Failed writes leave no entry, and a write is
stored together with its entry or not at all.

Editing, inserting or removing a past entry breaks every later link;
`trusted_issuers_core::verify_audit_chain` reports where, and the registry
refuses to start on a broken log rather than extending it. The chain makes
tampering detectable, not impossible: whoever can rewrite the whole log can
recompute it, so keep a copy of a recent `head` elsewhere if that matters.

The actor is `admin` (the holder of the admin token) unless
`--audit-actor-header` names a header the gateway sets to the
authenticated person (such as `X-Forwarded-User`). Only set it when nothing
but the gateway can reach the admin API.

### X.509 trust anchors

Some credentials prove their issuer with a certificate chain instead of a
DID or OID4VCI issuer metadata: an ISO mdoc/mDL's document signer
certificate chains to the issuing authority's IACA root, and an SD-JWT VC
may carry only an `x5c` header. A record lists such roots in
`x509Certificates` (base64 DER, as in a JOSE `x5c`):

```json
{
  "id": "https://mdl.example",
  "role": "ti",
  "credentialTypes": ["org.iso.18013.5.1.mDL"],
  "accreditedBy": "did:web:authority.example",
  "status": "active",
  "x509Certificates": ["MIIBVzCB/qADAgECAhR4..."]
}
```

On write each anchor must decode and parse as an X.509 CA certificate
(`basicConstraints` with `cA` set; at most 10 per record, 16 KiB each), and
no anchor may be listed under two parties,
so a chain never proves two issuers. `POST /v1/x509/check` (and
`Registry::check_x5c` / `TrustList::check_x5c` for verifiers holding a
snapshot) validates the presented chain, leaf first, with `rustls-webpki`
(signatures, validity, CA and path length constraints, name constraints)
against each record's anchors that are inside their own validity period
(webpki alone would accept an expired anchor), then runs the ordinary accreditation check
on the record whose anchor it reached: a valid chain to a suspended or
out-of-scope party is not trusted. With `eku` (a dotted OID such as the mDL
document signer's `1.0.18013.5.1.2`) the leaf must carry that extended key
usage, and any certificate in the path that lists EKUs must include it.
Revocation (CRLs, OCSP) is not checked; remove or suspend a party, or its
anchor, to stop trusting its chains.

### Accreditations as VCs

`GET /v1/issuers/{id}/accreditations` returns one JWT VC per link of the
issuer's chain (the issuer, its accreditor, ... up to the Root TAO), so the
issuer can hand them to a verifier with its credentials and the verifier
needs only the registry's key, as for the snapshot:

```rust
let chain = trusted_issuers_core::verify_accreditations(&tokens, registry_did, &key, now)?;
let decision = chain.check(issuer_id, "MembershipCredential", now);
```

They conform to EBSI's Verifiable Accreditation schema
(`@cef-ebsi/vcdm1.1-accreditation-schema` 2.0.0, checked by the
[conformance suite](#conformance)): VCDM 1.1 JWT encoding (`vc` claim,
`typ: JWT`), a `urn:uuid:` id, types `VerifiableAccreditationToAttest` (TI),
`VerifiableAccreditationToAccredit` (TAO) or
`VerifiableAuthorisationForTrustChain` (Root TAO), one
`credentialSubject.accreditedFor` entry per credential type in scope, the
accreditor in an `IssuanceCertificate` `termsOfUse` (the Root TAO's is a
`TrustFrameworkPolicy` naming the registry), `credentialSchema` pointing at
the schema's id in the EBSI pilot Trusted Schemas Registry, and any X.509
anchors in `credentialSubject.x509Certificates`. Differences from EBSI:

- There each accreditation is signed by the accreditor; here the registry
  signs every link, since it does not hold the accreditors' keys.
- `accreditedFor[].schemaId` must be a URI, and a credential type often
  has no registered schema: a type that is already an absolute URI (an
  SD-JWT VC `vct`) is its own `schemaId`, any other (`MembershipCredential`)
  gets `https://ds42.org/ontologies/ds-trusted-issuers-registry-rs/credential-types/`
  followed by the percent-encoded type.
- `reservedAttributeId` is the hex SHA-256 of the party's id, and there is
  no `credentialStatus`: every link expires at the earliest of now plus
  `--snapshot-ttl-secs` and each link's `validUntil`, so a suspension stops
  new accreditations at once and old ones expire within one TTL.

The registry refuses to issue them for a chain that is broken now.

### ETSI LoTE export

`GET /v1/lote` renders the registry as an ETSI TS 119 602 List of Trusted
Entities in the JSON binding (the `{"LoTE": {...}}` document, field names
from the standard's JSON schema), for EUDI wallets and verifiers that read
LoTEs:

- `ListAndSchemeInformation`: `LoTEVersionIdentifier` 1,
  `LoTESequenceNumber` = registry version + 1, `LoTEType` (a
  dataspace-defined URI by default, since none of the EU list types fits),
  the operator's name, postal and electronic address,
  `StatusDeterminationApproach` (the registry's accreditation chain check),
  `ListIssueDateTime`, `NextUpdate` (issue time + snapshot TTL) and the
  distribution point.
- One `TrustedEntity` per party whose accreditation chain is valid at issue
  time, with one service per credential type it is trusted for
  (`ServiceTypeIdentifier` `#CredentialIssuance` for a TI,
  `#Accreditation` for a TAO), its id in
  `ServiceDigitalIdentity.OtherIds` and its anchors in `X509Certificates`.
  The standard requires a postal address for every entity, so a party
  without a `postalAddress` is left out too. Suspended, revoked, expired and orphaned parties are left out: outside
  the Pub-EAA profile, presence in a LoTE means trusted, and there is no
  `ServiceStatus`.

`GET /v1/lote.jws` is the same document as a compact ES256 JWS (`typ:
lote+jwt`), verifiable against the registry's DID document. It is not a
JAdES baseline signature: the registry signs with its DID key and has no
X.509 certificate to put in `x5c`, so a consumer that requires JAdES needs
a signer in front. The list's addresses default to the https origin of the
registry's did:web (`--public-base-url` overrides); `--lote-operator-name`,
`--lote-type` and `--lote-territory` fill the rest.

The operator's postal address has no sensible default, so both endpoints
answer 503 until `--lote-operator-street`, `--lote-operator-locality` and
`--lote-operator-country` (plus, optionally, `--lote-operator-postal-code`
and `--lote-operator-region`) are given. A party's own address is set on
the record:

```json
"postalAddress": {
  "streetAddress": "Rue de la Loi 200", "locality": "Brussels",
  "postalCode": "1049", "country": "BE"
}
```

`streetAddress`, `locality` and `country` (ISO 3166-1 alpha-2) are
required; `postalCode` and `stateOrProvince` are optional. The graph store
keeps it as a `schema:PostalAddress`.

### Signed snapshot

`GET /v1/snapshot` signs the whole registry with the registry's ES256 key:

```json
{ "iss": "did:web:registry.example", "iat": 1792017886, "exp": 1792021486,
  "version": 42, "issuers": [ ... ] }
```

with header `{"alg": "ES256", "typ": "trust-list+jwt", "kid": "<registry DID>#registry-key"}`.
A verifier fetches it once, verifies it against the key in the registry's
DID document, and answers trust checks locally until `exp`, with no call to
the registry per credential. `version` increases on every write, so a
verifier can tell whether its copy is stale. `verify_snapshot` also
re-applies the write rules to the contents, refuses an expired snapshot, one
whose `iat` is not before `exp`, and one whose `iat` is more than
`SNAPSHOT_CLOCK_SKEW_SECS` (60) in the future. Responses carry
`Cache-Control: max-age` of a quarter of the TTL, so shared caches never
hand out a nearly expired snapshot. `trusted-issuers-core` has no
network code, so a verifier can embed it directly (sketch, error handling
elided):

```rust
use trusted_issuers_core::{snapshot_kid, verify_snapshot};

let key = dcp_core::find_verifying_key(&registry_did_doc, &snapshot_kid(&token)?)?;
let trust_list = verify_snapshot(&token, registry_did, &key, dcp_core::now_secs())?;
// Keep `trust_list` around; it refuses every check once the snapshot expires.
let decision = trust_list.check(issuer_did, "MembershipCredential", dcp_core::now_secs());
// The same check for an OID4VCI-issued SD-JWT VC: its `iss` and `vct`.
let decision = trust_list.check(&sd_jwt.iss, &sd_jwt.vct, dcp_core::now_secs());
```

## Crates

- `trusted-issuers-core`: records, write rules, the chain check, and
  snapshot signing and verification. Built on
  [`ds-dcp-core-rs`](https://github.com/ds-labs-org/ds-dcp-core-rs)'s JWS
  and `did:web` primitives, at the same pin as `ds-identity-hub-rs`.
- `trusted-issuers-graph`: the registry graph, an embedded Oxigraph RDF
  store (records and audit log as triples, RocksDB on disk).
- `trusted-issuers-contreforts`: Contreforts' `ContrefortsConnector` over
  that graph, with its `declaration.ttl`.
- `trusted-issuers-http`: the `axum` HTTP surface, the stores and the
  `trusted-issuers-registry` binary.
- `vendor/contreforts-core`: git submodule, the same commit
  `ds-identity-hub-rs` pins. Clone with `--recurse-submodules` (or run
  `git submodule update --init`).

## Storage

The registry and its audit log are kept together by one of three stores:

| Flag | Store | Audit log |
|---|---|---|
| none | memory: nothing survives a restart | in memory |
| `--data-file FILE` | the registry as one JSON file, rewritten atomically and durably after each write | JSON lines in `FILE.audit.jsonl`, fsynced before the registry file is replaced and truncated back if that fails |
| `--graph-dir DIR` | the registry graph: RDF in an on-disk Oxigraph (RocksDB) store, each write one transaction flushed to disk | `prov:Activity` nodes in the same transaction |

The graph store follows `ds-identity-hub-rs`'s Contreforts pattern (its
`identity-hub-graph` and `identity-hub-contreforts` crates), but is durable
where the hub's graph is in memory. Records live in the named graph
`tir:records`, each a node named by the party's own id (DIDs and https URLs
are IRIs) with `tir:accreditedBy` as a link to the accreditor's node, so the
accreditation tree can be walked in SPARQL; audit entries live in
`tir:audit` (`tir:` is
`https://ds42.org/ontologies/ds-trusted-issuers-registry-rs#`). Values are
typed literals, never spliced into query text. The graph is reachable
through Contreforts' connector interface (`RegistryGraphConnector`, entity
kinds `ds-trusted-issuers-registry-rs:issuer-record` and
`ds-trusted-issuers-registry-rs:audit-entry`, with `since` for incremental
pulls; `push` is refused, since writes must pass the registry's rules and
audit); the binary pulls the records through it once at startup, as the hub
does.

To move from a JSON data file to the graph, start once with
`--graph-dir DIR --import-data-file FILE`: the registry is imported into an
empty graph (a graph that already holds one is never overwritten); the JSON
store's audit log is not carried over. Every store re-checks what it loads
against the write rules and the audit chain.

## Building and testing

```bash
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Conformance

`crates/trusted-issuers-core/tests/conformance.rs` checks the registry's
outputs against third-party material that `conformance/fetch.sh` downloads,
each pinned to a version or commit and checked against its SHA-256, into
`target/conformance` (`$CONFORMANCE_DIR` overrides). Those tests are
`#[ignore]`d in the plain `cargo test`; CI runs them in their own job:

```bash
conformance/fetch.sh
cargo test -p trusted-issuers-core --test conformance -- --ignored
```

| Suite | What it checks | Source |
| --- | --- | --- |
| ETSI TS 119 602 JSON schema | `GET /v1/lote` validates against the standard's JSON binding (`1960201_json_schema.json`) | taken from the European Commission's EUDI library `eu.europa.ec.eudi:etsi-119602-data-model-jvm` 0.4.0-alpha.4 (Apache-2.0), since forge.etsi.org is often unreachable |
| EBSI Verifiable Accreditation schema | every link `GET /v1/issuers/{id}/accreditations` signs validates against the official schema, after EBSI's own examples pass the same validator | npm `@cef-ebsi/vcdm1.1-accreditation-schema` and `vcdm1.1-attestation-schema` 2.0.0 (EUPL-1.2) |
| C2SP x509-limbo | `check_x5c` agrees with 9,754 X.509 path validation cases (BetterTLS, RFC 5280, webpki, CVE and pathological chains), the name check being the harness's | [`limbo.json`](https://github.com/C2SP/x509-limbo) at a pinned commit (Apache-2.0) |

Nothing is vendored: the material is downloaded at test time. The x509-limbo
test skips the cases that do not apply (CRLs, ML-DSA, a caller-chosen chain
depth or key usage, and the ones limbo marks pedantic) and lists the 48 it
knowingly decides otherwise, each with its reason, in `LIMBO_DIVERGENCES`:
the leaf EKU rule above, rustls-webpki's known leniencies (AKI/SKI,
extension criticality, a trust anchor's own extensions), and Web PKI rules
on the subject CN. Any other disagreement fails it, and so does a listed
case that agrees again. Two cases it found are fixed: an anchor must be a CA
certificate, and an expired anchor proves nothing.

## Running it

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out registry-key.pem

TRUSTED_ISSUERS_ADMIN_TOKEN=change-me \
cargo run -p trusted-issuers-http --bin trusted-issuers-registry -- \
  --did-host localhost:8090 \
  --signing-key-file registry-key.pem \
  --data-file registry.json --create-data-file
```

| Flag | Default | Meaning |
|---|---|---|
| `--bind` | `0.0.0.0:8090` | listen address |
| `--did-host` | required | host the registry's `did:web` resolves to |
| `--signing-key-file` | ephemeral key | PKCS#8 PEM P-256 key that signs snapshots |
| `--data-file` | in memory | JSON file loaded at start (and re-checked against the write rules) and rewritten atomically and durably after each write; audit log in `<file>.audit.jsonl` |
| `--create-data-file` | off | start empty when `--data-file` doesn't exist yet; otherwise a missing file is a startup error |
| `--graph-dir` | off | keep the registry in the on-disk registry graph instead (see [Storage](#storage)); conflicts with `--data-file` |
| `--import-data-file` | off | with `--graph-dir`: import this JSON data file into the empty graph once |
| `--audit-actor-header` | off | header holding the authenticated person behind an admin write, recorded as the audit actor |
| `--public-base-url` | the did:web origin | public base URL used in the LoTE |
| `--lote-operator-name` | `Dataspace authority` | LoTE `SchemeOperatorName` |
| `--lote-type` | dataspace-defined URI | LoTE `LoTEType` |
| `--lote-territory` | none | LoTE `SchemeTerritory` |
| `--lote-operator-street`, `-locality`, `-country` | none | LoTE operator postal address; `GET /v1/lote` answers 503 without it |
| `--lote-operator-postal-code`, `-region` | none | optional parts of that address |
| `--admin-token` / `TRUSTED_ISSUERS_ADMIN_TOKEN` | disabled | bearer token for the admin API |
| `--snapshot-ttl-secs` | `3600` | snapshot lifetime, at least 1 |

## Not done yet

- A JAdES baseline signature on the LoTE (it needs an X.509 signing
  certificate), `ServiceHistory`, and the Pub-EAA profile's
  `ServiceStatus`.
- Revocation checking (CRL/OCSP) for X.509 chains.
- Accreditations signed by the accreditors themselves, as in EBSI, rather
  than by the registry.
- Storage shared by several registry instances: both durable stores are
  single-process.

## License

GNU Affero General Public License, version 3 only (`AGPL-3.0-only`, see
[LICENSE](LICENSE)). Beyond the GPL's terms, section 13 requires anyone who
runs a modified registry as a network service to offer its users the
modified source. The vendored `vendor/contreforts-core` keeps its own
licence (MIT), and the conformance material is downloaded at test time
under its own licences (see [Conformance](#conformance)).
