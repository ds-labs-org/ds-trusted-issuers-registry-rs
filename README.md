# Trusted Issuers Registry

*(repo/product: `ds-trusted-issuers-registry-rs`)*

The dataspace authority's list of **who may issue which credentials**. A
verifier that receives a Verifiable Credential (a DCP Credential Service
accepting a `CredentialMessage`, a connector checking a presentation, the
catalog broker) asks the registry whether the credential's issuer DID is
trusted for that credential type, instead of each service carrying its own
static allow-list (today, `ds-identity-hub-rs`'s `--trusted-issuer-did`).

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
  "did": "did:web:issuer.example",
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

**DID canonicalization.** `did:web` DIDs are stored and looked up in one
canonical form: the host is lowercased and the hex digits of percent-escapes
are uppercased (`did:web:Host.example%3a8443` is `did:web:host.example%3A8443`;
path segments keep their case). It applies to `did` and `accreditedBy` on
write and to the DID in every read, check and status change, so a record
matches however a credential spells its issuer. Other DID methods are
compared as given. Two records that collapse to the same DID in a loaded
data file or snapshot are refused as duplicates.

A record's `did` must be a bare DID per DID Core syntax. DID URLs
(with a `#fragment`, `?query` or `/path`), spaces, a trailing `:` and
malformed `%` escapes are refused with 422.

## API

Public reads, no authentication:

| Method and path | Returns |
|---|---|
| `GET /v1/issuers[?credentialType=T&role=R&status=S]` | `{version, total, items}`, optionally only records covering `T`, in role `R` (`root_tao`, `tao`, `ti`) and with status `S` (`active`, `suspended`, `revoked`); an unknown role or status is a 400. This is a listing, not an allow-list: it includes suspended and expired records, so use the trust check or the snapshot for decisions |
| `GET /v1/issuers/{did}` | one record, or 404 |
| `GET /v1/issuers/{did}/types/{type}` | `{trusted, chain, reason?}` for that issuer and type, now |
| `GET /v1/snapshot` | the whole registry as a signed JWS (`application/trust-list+jwt`) |
| `GET /.well-known/did.json` | the registry's `did:web` document, holding the snapshot key |
| `GET /health` | `ok` |

Authority writes, behind `Authorization: Bearer <admin token>`:

| Method and path | Effect |
|---|---|
| `GET /v1/admin` | 204 when the token would be accepted, else the same 401/403 a write gets; lets a console show itself read-only |
| `PUT /v1/issuers/{did}` | create (201) or replace (200) a record; a body `did` is optional but must match the path |
| `PATCH /v1/issuers/{did}/status` | `{"status": "suspended"}` and so on |
| `DELETE /v1/issuers/{did}` | remove (204); 409 while it still accredits someone |

Authorization is checked before the body is read, so an unauthenticated
caller only ever gets 401 (or 403 when the admin API is disabled). Bodies
with unknown fields (such as a misspelled `validUntil`) are refused with 400.
Rule violations return 422, removing or demoting a record that still
accredits others returns 409, and unknown DIDs return 404. A DID goes in the path as one
percent-encoded segment, so `did:web:host%3A8443` is sent as
`did:web:host%253A8443`.

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
  type as well as the DID) is the next change.
- The "Trusted Issuers" view in `ds-authority-governance-ui`.
- Publishing accreditations as Verifiable Credentials (EBSI's
  `VerifiableAccreditation`), so the chain can be proven without the
  registry.
- An audit log of writes, and storage beyond a single JSON file.
