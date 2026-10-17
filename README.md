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
| `GET /v1/snapshot` | the whole registry as a signed JWS (`application/trust-list+jwt`) |
| `GET /.well-known/did.json` | the registry's `did:web` document, holding the snapshot key |
| `GET /health` | `ok` |

Authority writes, behind `Authorization: Bearer <admin token>`:

| Method and path | Effect |
|---|---|
| `GET /v1/admin` | 204 when the token would be accepted, else the same 401/403 a write gets; lets a console show itself read-only |
| `PUT /v1/issuers/{id}` | create (201) or replace (200) a record; a body `id` (or legacy `did`) is optional but must match the path |
| `PATCH /v1/issuers/{id}/status` | `{"status": "suspended"}` and so on |
| `DELETE /v1/issuers/{id}` | remove (204); 409 while it still accredits someone |

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
Zitadel) as `ds-authority-governance-ui`, which will get a "Trusted
Issuers" view on top of it. The admin token is the service-to-service
credential behind that gateway. Without one, or with an empty one, the
admin API is disabled.

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
- `trusted-issuers-http`: the `axum` HTTP surface and the
  `trusted-issuers-registry` binary.

## Building and testing

```bash
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

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
| `--data-file` | in memory | JSON file loaded at start (and re-checked against the write rules) and rewritten atomically and durably after each write |
| `--create-data-file` | off | start empty when `--data-file` doesn't exist yet; otherwise a missing file is a startup error |
| `--admin-token` / `TRUSTED_ISSUERS_ADMIN_TOKEN` | disabled | bearer token for the admin API |
| `--snapshot-ttl-secs` | `3600` | snapshot lifetime, at least 1 |

## Not done yet

- `ds-identity-hub-rs` still uses its static `--trusted-issuer-did` list;
  switching it to this registry (snapshot-backed, checking the credential
  type as well as the DID) is the next change. No OID4VCI wallet or
  verifier consumes the registry yet either.
- X.509 trust anchors, for credentials whose issuer is proven by a
  certificate chain rather than a DID or issuer metadata (ISO mdoc/mDL
  with its IACA roots, SD-JWT VCs signed with only `x5c`).
- Exporting the registry in a standard trust-list format (ETSI TS 119 612,
  or the ETSI TS 119 602 lists of trusted entities that EUDI wallets use,
  or OpenID Federation) next to the custom `trust-list+jwt` snapshot, so
  off-the-shelf OID4VCI wallets and verifiers can read it.
- The "Trusted Issuers" view in `ds-authority-governance-ui`.
- Publishing accreditations as Verifiable Credentials (EBSI's
  `VerifiableAccreditation`), so the chain can be proven without the
  registry.
- An audit log of writes, and storage beyond a single JSON file.
