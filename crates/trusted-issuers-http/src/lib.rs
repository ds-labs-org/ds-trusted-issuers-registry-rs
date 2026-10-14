//! HTTP surface of the trusted issuers registry.
//!
//! Public, unauthenticated reads (anyone verifying a credential needs them):
//!
//! - `GET /health`
//! - `GET /.well-known/did.json` - the registry's own `did:web` document,
//!   holding the key that signs snapshots
//! - `GET /v1/issuers[?credentialType=T]` - every record, optionally only
//!   those scoped for `T`
//! - `GET /v1/issuers/{did}` - one record
//! - `GET /v1/issuers/{did}/types/{type}` - the accreditation-chain trust
//!   decision for `did` issuing `type`, right now
//! - `GET /v1/snapshot` - the whole registry as a signed compact JWS
//!   (`application/trust-list+jwt`)
//!
//! Authority-only writes, behind `Authorization: Bearer <admin token>`
//! (disabled entirely when no admin token is configured):
//!
//! - `PUT /v1/issuers/{did}` - create or replace a record
//! - `PATCH /v1/issuers/{did}/status` - `{"status": "suspended"}` etc.
//! - `DELETE /v1/issuers/{did}`
//!
//! DIDs go in the path percent-encoded as one segment, so a `did:web` with a
//! port (`did:web:host%3A8080`) is sent as `did:web:host%253A8080`.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::{Json, Router};
use dcp_core::{DcpKeyPair, now_secs};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;
use trusted_issuers_core::{IssuerRecord, Registry, RegistryError, Status, sign_snapshot};

pub const SNAPSHOT_CONTENT_TYPE: &str = "application/trust-list+jwt";

pub struct AppState {
    pub registry: RwLock<Registry>,
    pub key: DcpKeyPair,
    /// `None` disables the admin API (every write is refused).
    pub admin_token: Option<String>,
    /// Where the registry is persisted after each write; `None` keeps it in
    /// memory only.
    pub data_file: Option<PathBuf>,
    pub snapshot_ttl_secs: u64,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/.well-known/did.json", get(did_document))
        .route("/v1/issuers", get(list_issuers))
        .route(
            "/v1/issuers/{did}",
            get(get_issuer).put(put_issuer).delete(delete_issuer),
        )
        .route("/v1/issuers/{did}/status", patch(patch_status))
        .route(
            "/v1/issuers/{did}/types/{credential_type}",
            get(check_trust),
        )
        .route("/v1/snapshot", get(snapshot))
        .with_state(state)
}

/// Loads a registry persisted by [`persist`]; a missing file is an empty
/// registry.
pub fn load(path: &std::path::Path) -> Result<Registry, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Writes the registry to `path` via a temp file and rename, so a crash
/// mid-write never leaves a truncated file.
pub fn persist(path: &std::path::Path, registry: &Registry) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(registry)?)?;
    std::fs::rename(tmp, path)
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

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(expected) = state.admin_token.as_deref() else {
        return Err(error(
            StatusCode::FORBIDDEN,
            "the admin API is disabled: no admin token is configured",
        ));
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(error(
            StatusCode::UNAUTHORIZED,
            "missing or wrong admin token",
        ))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Applies a write to a copy of the registry, persists the copy, and only
/// then makes it live, so memory and disk never disagree after a failed
/// write. Writes are rare, so copying the registry is cheap enough.
async fn apply(
    state: &AppState,
    write: impl FnOnce(&mut Registry) -> Result<(), RegistryError>,
) -> Result<Registry, ApiError> {
    let mut registry = state.registry.write().await;
    let mut next = registry.clone();
    write(&mut next).map_err(registry_error)?;
    if let Some(path) = &state.data_file
        && let Err(e) = persist(path, &next)
    {
        tracing::error!("failed to persist registry to {}: {e}", path.display());
        return Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the registry could not be persisted; nothing was changed",
        ));
    }
    *registry = next.clone();
    Ok(next)
}

async fn did_document(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(state.key.did_document(&[]))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    credential_type: Option<String>,
}

async fn list_issuers(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let registry = state.registry.read().await;
    let items: Vec<&IssuerRecord> = registry
        .list()
        .filter(|r| query.credential_type.as_deref().is_none_or(|t| r.covers(t)))
        .collect();
    Json(json!({"version": registry.version, "total": items.len(), "items": items}))
}

async fn get_issuer(State(state): State<Arc<AppState>>, Path(did): Path<String>) -> Response {
    match state.registry.read().await.get(&did) {
        Some(record) => Json(record).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            format!("'{did}' is not in the registry"),
        )
        .into_response(),
    }
}

async fn check_trust(
    State(state): State<Arc<AppState>>,
    Path((did, credential_type)): Path<(String, String)>,
) -> Response {
    let decision = state
        .registry
        .read()
        .await
        .check(&did, &credential_type, now_secs());
    Json(decision).into_response()
}

async fn snapshot(State(state): State<Arc<AppState>>) -> Response {
    let token = sign_snapshot(
        &*state.registry.read().await,
        &state.key,
        now_secs(),
        state.snapshot_ttl_secs,
    );
    (
        [
            (header::CONTENT_TYPE, SNAPSHOT_CONTENT_TYPE.to_string()),
            (
                header::CACHE_CONTROL,
                format!("public, max-age={}", state.snapshot_ttl_secs),
            ),
        ],
        token,
    )
        .into_response()
}

async fn put_issuer(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    headers: HeaderMap,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r.into_response();
    }
    // The path names the record; a body `did` is optional but must agree.
    match body.get("did") {
        None => body["did"] = json!(did),
        Some(v) if v == &json!(did) => {}
        Some(_) => {
            return error(StatusCode::BAD_REQUEST, "body did does not match the path")
                .into_response();
        }
    }
    let record: IssuerRecord = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let mut created = false;
    let result = apply(&state, |registry| {
        created = registry.get(&did).is_none();
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
            (status, Json(registry.get(&did))).into_response()
        }
        Err(r) => r.into_response(),
    }
}

#[derive(Deserialize)]
struct StatusBody {
    status: Status,
}

async fn patch_status(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    headers: HeaderMap,
    Json(body): Json<StatusBody>,
) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r.into_response();
    }
    match apply(&state, |registry| {
        registry.set_status(&did, body.status, now_secs())
    })
    .await
    {
        Ok(registry) => Json(registry.get(&did)).into_response(),
        Err(r) => r.into_response(),
    }
}

async fn delete_issuer(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r.into_response();
    }
    match apply(&state, |registry| registry.remove(&did).map(drop)).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(r) => r.into_response(),
    }
}
