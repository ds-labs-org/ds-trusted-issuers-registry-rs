//! Registry records, modelled on the EBSI Trusted Issuers Registry's
//! three-tier accreditation chain: a Root Trusted Accreditation
//! Organisation (the dataspace authority itself) accredits Trusted
//! Accreditation Organisations, which accredit Trusted Issuers. Each tier
//! is scoped to the credential types it lists, and a child can never be
//! scoped wider than the party that accredited it.

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

/// One party in the registry.
///
/// `credential_types` means "may issue these types" for every role, and
/// additionally "may accredit others for these types" for the two TAO
/// roles. Types are matched by exact string against the VC's `type` entries
/// (e.g. `MembershipCredential`), the same matching DCP scopes use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerRecord {
    pub did: String,
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
