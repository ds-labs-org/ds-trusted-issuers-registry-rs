//! Registry records, modelled on the EBSI Trusted Issuers Registry's
//! three-tier accreditation chain: a Root Trusted Accreditation
//! Organisation (the dataspace authority itself) accredits Trusted
//! Accreditation Organisations, which accredit Trusted Issuers. Each tier
//! is scoped to the credential types it lists, and a child can never be
//! scoped wider than the party that accredited it.
//!
//! A party is named the way its credentials name their issuer: by a DID for
//! DCP (and any issuer that signs with a DID), or by its Credential Issuer
//! Identifier, an https URL, for OID4VCI. Both kinds share one chain, so a
//! DID-named TAO can accredit a URL-named issuer and the other way round.

use serde::{Deserialize, Serialize};

/// Wildcard credential type: only a [`Role::RootTao`] may hold it, meaning
/// "may accredit (or issue) any credential type".
pub const ANY_CREDENTIAL_TYPE: &str = "*";

/// A party's tier in the accreditation chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Root Trusted Accreditation Organisation: the trust anchor. Has no
    /// accreditor of its own.
    RootTao,
    /// Trusted Accreditation Organisation: accredited by a Root TAO or
    /// another TAO, and may accredit further parties.
    Tao,
    /// Trusted Issuer: issues credentials, never accredits anyone.
    Ti,
}

impl Role {
    /// Whether a party in this role may appear as another record's
    /// `accredited_by`.
    pub fn can_accredit(self) -> bool {
        matches!(self, Role::RootTao | Role::Tao)
    }
}

/// Lifecycle status. Only `Active` records are trusted; `Suspended` is
/// meant to be temporary, `Revoked` final (by convention - the registry
/// does not forbid reactivating, so a mistaken revocation can be undone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Suspended,
    Revoked,
}

/// How a party is named, which follows from the protocol its credentials
/// come through: DCP issuers (and anyone signing with a DID) by a DID, OID4VCI
/// issuers by their https Credential Issuer Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdKind {
    Did,
    Url,
}

impl IdKind {
    /// The kind of a stored id. Ids are validated on write, so anything that
    /// is not a DID is an https URL.
    pub fn of(id: &str) -> Self {
        if id.starts_with("did:") {
            IdKind::Did
        } else {
            IdKind::Url
        }
    }
}

/// A postal address, as the ETSI TS 119 602 LoTE carries it: street,
/// locality and country required (the standard's XML schema requires all
/// three, its JSON schema street and country), postal code and region
/// optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostalAddress {
    pub street_address: String,
    pub locality: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_or_province: Option<String>,
    /// ISO 3166-1 alpha-2 country code (`FR`, `DE`, ...).
    pub country: String,
}

impl PostalAddress {
    /// Why the address is unusable, if it is: an empty street or locality,
    /// an empty optional field, or a country that is not two upper-case
    /// letters.
    pub fn problem(&self) -> Option<&'static str> {
        let blank = |s: &str| s.trim().is_empty();
        if blank(&self.street_address) || blank(&self.locality) {
            Some("streetAddress and locality must not be empty")
        } else if self.postal_code.as_deref().is_some_and(blank)
            || self.state_or_province.as_deref().is_some_and(blank)
        {
            Some("postalCode and stateOrProvince must be omitted rather than empty")
        } else if self.country.len() != 2 || !self.country.bytes().all(|c| c.is_ascii_uppercase()) {
            Some("country must be an ISO 3166-1 alpha-2 code such as FR")
        } else {
            None
        }
    }
}

/// One party in the registry.
///
/// `credential_types` means "may issue these types" for every role, and
/// additionally "may accredit others for these types" for the two TAO
/// roles. Types are matched by exact string against the VC's `type` entries
/// (e.g. `MembershipCredential`), the same matching DCP scopes use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerRecord {
    /// The party: a DID (DCP issuers) or an OID4VCI Credential Issuer
    /// Identifier. Read as `did` too, the key used before OID4VCI issuers
    /// could be listed.
    #[serde(alias = "did")]
    pub id: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub credential_types: Vec<String>,
    /// DID of the accrediting party. `None` exactly when `role` is
    /// [`Role::RootTao`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accredited_by: Option<String>,
    /// Unix seconds; `None` means "from the beginning".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,
    /// Unix seconds, exclusive; `None` means "no expiry".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    pub status: Status,
    /// X.509 trust anchors of this party, base64 (standard, padded) DER as
    /// in a JOSE `x5c`: the certificates its credentials' certificate
    /// chains end at, for issuers proven by X.509 rather than by a DID or
    /// issuer metadata (an mdoc/mDL issuing authority's IACA root, the CA of
    /// an SD-JWT VC issuer signing with `x5c`). See
    /// [`crate::Registry::check_x5c`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x509_certificates: Vec<String>,
    /// The party's postal address. Optional in the registry, but the ETSI
    /// TS 119 602 LoTE requires one for every trusted entity, so a party
    /// without it is left out of `GET /v1/lote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_address: Option<PostalAddress>,
    /// Unix seconds of the last write, set by the registry.
    #[serde(default)]
    pub updated_at: u64,
}

impl IssuerRecord {
    /// Whether this record is `Active` and inside its validity window at
    /// `now` (unix seconds).
    pub fn is_usable_at(&self, now: u64) -> bool {
        self.status == Status::Active
            && self.valid_from.is_none_or(|from| now >= from)
            && self.valid_until.is_none_or(|until| now < until)
    }

    /// Whether this record's scope includes `credential_type`.
    pub fn covers(&self, credential_type: &str) -> bool {
        self.credential_types
            .iter()
            .any(|t| t == credential_type || t == ANY_CREDENTIAL_TYPE)
    }
}
