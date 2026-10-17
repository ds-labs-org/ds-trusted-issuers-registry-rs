//! HTTP surface of the trusted issuers registry.
//!
//! Public, unauthenticated reads (anyone verifying a credential needs them):
//!
//! - `GET /health`
//! - `GET /.well-known/did.json` - the registry's own `did:web` document,
//!   holding the key that signs snapshots
//! - `GET /v1/issuers[?credentialType=T&role=R&status=S&idKind=K]` - every record,
//!   optionally only those scoped for `T`, in role `R`, with status `S`, named
//!   by a DID or a URL (`idKind=did|url`) (a listing, not an allow-list: suspended or
//!   expired records are included - use the trust check for decisions)
//! - `GET /v1/issuers/{id}` - one record
//! - `GET /v1/issuers/{id}/types/{type}` - the accreditation-chain trust
//!   decision for `id` issuing `type`, right now
//! - `GET /v1/snapshot` - the whole registry as a signed compact JWS
//!   (`application/trust-list+jwt`)
//!
//! Authority-only writes, behind `Authorization: Bearer <admin token>`
//! (disabled entirely when no admin token is configured). Authorization
//! runs before the request body is read, so unauthenticated callers only
//! ever see 401/403:
//!
//! - `GET /v1/admin` - `204` when the presented token would be accepted, so
//!   a console can show itself read-only before offering writes
//! - `PUT /v1/issuers/{id}` - create or replace a record
//! - `PATCH /v1/issuers/{id}/status` - `{"status": "suspended"}` etc.
//! - `DELETE /v1/issuers/{id}`
//!
//! `{id}` is a DID (DCP issuers) or an OID4VCI credential issuer URL, sent
//! percent-encoded as one segment: a `did:web` with a port
//! (`did:web:host%3A8080`) is sent as `did:web:host%253A8080`, and
//! `https://issuer.example/tenant` as `https:%2F%2Fissuer.example%2Ftenant`.

pub mod store;

use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, put};
use axum::{Json, Router};
use dcp_core::{DcpKeyPair, now_secs};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;
use trusted_issuers_core::{
    AuditAction, AuditEntry, AuditRecord, IdKind, IssuerRecord, Registry, RegistryError, Role,
    Status, canonical_id, sign_snapshot,
};

pub use store::{JsonFileStore, MemoryStore, Store, load, persist};

pub const SNAPSHOT_CONTENT_TYPE: &str = "application/trust-list+jwt";

pub struct AppState {
    pub registry: RwLock<Registry>,
    pub key: DcpKeyPair,
    /// `None` disables the admin API (every write is refused). Never
    /// `Some("")`: [`AppState::new`] maps an empty token to `None`.
    admin_token: Option<String>,
    /// Where each write is made durable, together with its audit entry.
    pub store: Arc<dyn Store>,
    pub snapshot_ttl_secs: u64,
}

impl AppState {
    /// An empty or whitespace-only `admin_token` is treated as no token, so
    /// an unset secret (`TOKEN=`) disables the admin API instead of making
    /// the empty string the password.
    pub fn new(
        registry: Registry,
        key: DcpKeyPair,
        admin_token: Option<String>,
        store: Arc<dyn Store>,
        snapshot_ttl_secs: u64,
    ) -> Self {
        Self {
            registry: RwLock::new(registry),
            key,
            admin_token: admin_token.filter(|t| !t.trim().is_empty()),
            store,
            snapshot_ttl_secs,
        }
    }

    pub fn admin_enabled(&self) -> bool {
        self.admin_token.is_some()
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let admin = Router::new()
        .route("/v1/issuers/{id}", put(put_issuer).delete(delete_issuer))
        .route("/v1/issuers/{id}/status", patch(patch_status))
        .route("/v1/admin", get(|| async { StatusCode::NO_CONTENT }))
        .route_layer(from_fn_with_state(state.clone(), require_admin));
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/.well-known/did.json", get(did_document))
        .route("/v1/issuers", get(list_issuers))
        .route("/v1/issuers/{id}", get(get_issuer))
        .route("/v1/issuers/{id}/types/{credential_type}", get(check_trust))
        .route("/v1/snapshot", get(snapshot))
        .merge(admin)
        .with_state(state)
}

/// A JSON `{"error": ...}` response, kept small so `Result<_, ApiError>`
/// stays cheap to return.
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

fn error(status: StatusCode, message: impl Into<String>) -> ApiError {
    ApiError {
        status,
        message: message.into(),
    }
}

fn registry_error(err: RegistryError) -> ApiError {
    let status = match err {
        RegistryError::NotFound(_) => StatusCode::NOT_FOUND,
        RegistryError::HasDependents { .. } => StatusCode::CONFLICT,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    error(status, err.to_string())
}

/// Admin-route middleware: runs before any extractor, so the body is never
/// read for an unauthorized caller.
async fn require_admin(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.admin_token.as_deref() else {
        return error(
            StatusCode::FORBIDDEN,
            "the admin API is disabled: no admin token is configured",
        )
        .into_response();
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .unwrap_or_default();
    if !presented.is_empty() && constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        next.run(request).await
    } else {
        error(StatusCode::UNAUTHORIZED, "missing or wrong admin token").into_response()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Applies a write to a copy of the registry, commits the copy and its
/// audit entry to the store, and only then makes it live, so memory and the
/// store never disagree after a failed write. Writes are rare, so copying
/// the registry is cheap enough. Store I/O runs on the blocking pool; the
/// write lock is held across it, which serializes writes (readers wait for
/// at most one commit) and keeps the audit chain in order.
async fn apply(
    state: &AppState,
    actor: String,
    action: AuditAction,
    id: &str,
    write: impl FnOnce(&mut Registry) -> Result<(), RegistryError>,
) -> Result<Registry, ApiError> {
    let id = canonical_id(id);
    let mut registry = state.registry.write().await;
    let mut next = registry.clone();
    write(&mut next).map_err(registry_error)?;
    let entry = AuditEntry::next(
        state.store.audit_head().as_ref(),
        AuditRecord {
            at: now_secs(),
            actor,
            action,
            before: registry.get(&id).cloned(),
            after: next.get(&id).cloned(),
            id,
            version: next.version,
        },
    );
    let store = state.store.clone();
    let to_save = next.clone();
    let result = tokio::task::spawn_blocking(move || store.commit(&to_save, &entry))
        .await
        .map_err(std::io::Error::other)
        .and_then(|r| r);
    if let Err(e) = result {
        tracing::error!("failed to commit a registry write: {e}");
        return Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the registry could not be persisted; nothing was changed",
        ));
    }
    *registry = next.clone();
    Ok(next)
}

/// Who is making an admin write, for the audit log.
fn actor() -> String {
    "admin".to_string()
}

async fn did_document(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(state.key.did_document(&[]))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    credential_type: Option<String>,
    role: Option<Role>,
    status: Option<Status>,
    id_kind: Option<IdKind>,
}

async fn list_issuers(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let registry = state.registry.read().await;
    let items: Vec<&IssuerRecord> = registry
        .list()
        .filter(|r| query.credential_type.as_deref().is_none_or(|t| r.covers(t)))
        .filter(|r| query.role.is_none_or(|role| r.role == role))
        .filter(|r| query.status.is_none_or(|status| r.status == status))
        .filter(|r| query.id_kind.is_none_or(|kind| IdKind::of(&r.id) == kind))
        .collect();
    Json(json!({"version": registry.version, "total": items.len(), "items": items}))
}

async fn get_issuer(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match state.registry.read().await.get(&id) {
        Some(record) => Json(record).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            format!("'{id}' is not in the registry"),
        )
        .into_response(),
    }
}

async fn check_trust(
    State(state): State<Arc<AppState>>,
    Path((id, credential_type)): Path<(String, String)>,
) -> Response {
    let decision = state
        .registry
        .read()
        .await
        .check(&id, &credential_type, now_secs());
    Json(decision).into_response()
}

async fn snapshot(State(state): State<Arc<AppState>>) -> Response {
    let token = sign_snapshot(
        &*state.registry.read().await,
        &state.key,
        now_secs(),
        state.snapshot_ttl_secs,
    );
    // Shared caches may hold it for a quarter of its lifetime at most, so a
    // verifier never receives a nearly expired snapshot and a revocation
    // reaches verifiers within ~1.25 TTL.
    (
        [
            (header::CONTENT_TYPE, SNAPSHOT_CONTENT_TYPE.to_string()),
            (
                header::CACHE_CONTROL,
                format!("public, max-age={}", state.snapshot_ttl_secs / 4),
            ),
        ],
        token,
    )
        .into_response()
}

/// The PUT body. Unlike the core [`IssuerRecord`] (kept lenient so newer
/// snapshots still parse), it rejects unknown fields: a misspelled
/// `validUntil` must fail loudly, not silently create a record that never
/// expires.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutBody {
    /// Optional; must match the path when given.
    #[serde(alias = "did")]
    id: Option<String>,
    role: Role,
    name: Option<String>,
    credential_types: Vec<String>,
    accredited_by: Option<String>,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
    status: Status,
    /// Accepted so a GET response can be PUT back; always overwritten.
    #[serde(rename = "updatedAt")]
    _updated_at: Option<u64>,
}

async fn put_issuer(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Result<Json<PutBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    // Compare and store the canonical form, so the path and body may spell
    // the same id differently.
    let id = canonical_id(&id);
    let body = match body {
        Ok(Json(b)) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.body_text()).into_response(),
    };
    if body.id.as_deref().is_some_and(|d| canonical_id(d) != id) {
        return error(StatusCode::BAD_REQUEST, "body id does not match the path").into_response();
    }
    let record = IssuerRecord {
        id: id.clone(),
        role: body.role,
        name: body.name,
        credential_types: body.credential_types,
        accredited_by: body.accredited_by,
        valid_from: body.valid_from,
        valid_until: body.valid_until,
        status: body.status,
        updated_at: 0,
    };
    let mut created = false;
    let result = apply(&state, actor(), AuditAction::Put, &id, |registry| {
        created = registry.get(&id).is_none();
        registry.upsert(record, now_secs())
    })
    .await;
    match result {
        Ok(registry) => {
            let status = if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (status, Json(registry.get(&id))).into_response()
        }
        Err(r) => r.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusBody {
    status: Status,
}

async fn patch_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Result<Json<StatusBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(b)) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.body_text()).into_response(),
    };
    match apply(&state, actor(), AuditAction::Status, &id, |registry| {
        registry.set_status(&id, body.status, now_secs())
    })
    .await
    {
        Ok(registry) => Json(registry.get(&id)).into_response(),
        Err(r) => r.into_response(),
    }
}

async fn delete_issuer(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match apply(&state, actor(), AuditAction::Delete, &id, |registry| {
        registry.remove(&id).map(drop)
    })
    .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(r) => r.into_response(),
    }
}
