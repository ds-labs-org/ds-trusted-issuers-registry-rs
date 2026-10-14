//! End-to-end tests of the HTTP surface, in process (no socket): the
//! authority builds a three-tier chain through the admin API, and a
//! verifier reads it back both live and from a verified snapshot.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use dcp_core::{DcpKeyPair, find_verifying_key};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use trusted_issuers_core::{snapshot_kid, verify_snapshot};
use trusted_issuers_http::{AppState, SNAPSHOT_CONTENT_TYPE, load, router};

const REGISTRY_DID: &str = "did:web:registry.example";
const ROOT: &str = "did:web:authority.example";
const TAO: &str = "did:web:tao.example";
// A did:web with a port: its "%3A" must be sent as "%253A" in the path.
const TI: &str = "did:web:issuer.example%3A8443";
const TI_PATH: &str = "did:web:issuer.example%253A8443";
const TOKEN: &str = "s3cret";

fn state(admin_token: Option<&str>, data_file: Option<std::path::PathBuf>) -> Arc<AppState> {
    Arc::new(AppState::new(
        Default::default(),
        DcpKeyPair::generate(REGISTRY_DID.into()),
        admin_token.map(Into::into),
        data_file,
        600,
    ))
}

async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = router(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, value, content_type)
}

async fn seed(state: &Arc<AppState>) {
    for (path, body) in [
        (
            ROOT,
            json!({"role": "root_tao", "name": "Dataspace Authority", "credentialTypes": ["*"], "status": "active"}),
        ),
        (
            TAO,
            json!({"role": "tao", "credentialTypes": ["MembershipCredential"], "accreditedBy": ROOT, "status": "active"}),
        ),
        (
            TI_PATH,
            json!({"role": "ti", "credentialTypes": ["MembershipCredential"], "accreditedBy": TAO, "status": "active"}),
        ),
    ] {
        let (status, body, _) = call(
            state,
            "PUT",
            &format!("/v1/issuers/{path}"),
            Some(TOKEN),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
}

#[tokio::test]
async fn authority_builds_a_chain_and_verifiers_read_it() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;

    let (status, body, _) = call(&s, "GET", &format!("/v1/issuers/{TI_PATH}"), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["did"], TI);
    assert!(body["updatedAt"].as_u64().unwrap() > 0);

    let (_, body, _) = call(
        &s,
        "GET",
        "/v1/issuers?credentialType=MembershipCredential",
        None,
        None,
    )
    .await;
    assert_eq!(body["total"], 3);
    assert_eq!(body["version"], 3);
    let (_, body, _) = call(&s, "GET", "/v1/issuers?credentialType=Other", None, None).await;
    assert_eq!(body["total"], 1, "only the wildcard root covers Other");

    let (status, body, _) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{TI_PATH}/types/MembershipCredential"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["trusted"], true);
    assert_eq!(body["chain"], json!([TI, TAO, ROOT]));

    // Suspending the TAO cuts off the issuer it accredited.
    let (status, _, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{TAO}/status"),
        Some(TOKEN),
        Some(json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body, _) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{TI_PATH}/types/MembershipCredential"),
        None,
        None,
    )
    .await;
    assert_eq!(body["trusted"], false);
    assert!(body["reason"].as_str().unwrap().contains(TAO));
}

#[tokio::test]
async fn snapshot_verifies_against_the_registry_did_document() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;

    let (status, token, content_type) = call(&s, "GET", "/v1/snapshot", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some(SNAPSHOT_CONTENT_TYPE));
    let token = token.as_str().unwrap();

    // What a verifier does: resolve the registry's DID document, pick the
    // key the snapshot names, verify, then check locally.
    let (_, doc, _) = call(&s, "GET", "/.well-known/did.json", None, None).await;
    let doc = serde_json::from_value(doc).unwrap();
    let key = find_verifying_key(&doc, &snapshot_kid(token).unwrap()).unwrap();
    let list = verify_snapshot(token, REGISTRY_DID, &key, dcp_core::now_secs()).unwrap();
    assert_eq!(list.version, 3);
    assert!(
        list.check(TI, "MembershipCredential", dcp_core::now_secs())
            .trusted
    );
}

#[tokio::test]
async fn admin_api_is_guarded() {
    let body = json!({"role": "root_tao", "credentialTypes": ["*"], "status": "active"});
    let disabled = state(None, None);
    let (status, _, _) = call(
        &disabled,
        "PUT",
        &format!("/v1/issuers/{ROOT}"),
        Some(TOKEN),
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let s = state(Some(TOKEN), None);
    for token in [None, Some("wrong")] {
        let (status, _, _) = call(
            &s,
            "PUT",
            &format!("/v1/issuers/{ROOT}"),
            token,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = call(&s, "DELETE", &format!("/v1/issuers/{ROOT}"), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn write_errors_map_to_statuses() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;

    // Body DID disagreeing with the path.
    let (status, _, _) = call(
        &s,
        "PUT",
        &format!("/v1/issuers/{TAO}"),
        Some(TOKEN),
        Some(json!({"did": ROOT, "role": "tao", "credentialTypes": ["A"], "accreditedBy": ROOT, "status": "active"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Rule violation: issuer scoped wider than its accreditor.
    let (status, body, _) = call(
        &s,
        "PUT",
        "/v1/issuers/did:web:x.example",
        Some(TOKEN),
        Some(json!({"role": "ti", "credentialTypes": ["Other"], "accreditedBy": TAO, "status": "active"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Removing a TAO that still accredits someone.
    let (status, _, _) = call(
        &s,
        "DELETE",
        &format!("/v1/issuers/{TAO}"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _, _) = call(
        &s,
        "DELETE",
        &format!("/v1/issuers/{TI_PATH}"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = call(&s, "GET", &format!("/v1/issuers/{TI_PATH}"), None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{TI_PATH}/status"),
        Some(TOKEN),
        Some(json!({"status": "active"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn writes_are_persisted_and_reloaded() {
    let dir = std::env::temp_dir().join(format!("tir-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("registry.json");
    let _ = std::fs::remove_file(&file);

    let s = state(Some(TOKEN), Some(file.clone()));
    seed(&s).await;
    let reloaded = load(&file, false).unwrap();
    assert_eq!(reloaded, *s.registry.read().await);
    assert_eq!(reloaded.version, 3);

    // A write that can't be persisted changes nothing in memory either.
    let blocked = state(
        Some(TOKEN),
        Some(dir.join("missing-dir").join("registry.json")),
    );
    let (status, _, _) = call(
        &blocked,
        "PUT",
        &format!("/v1/issuers/{ROOT}"),
        Some(TOKEN),
        Some(json!({"role": "root_tao", "credentialTypes": ["*"], "status": "active"})),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(blocked.registry.read().await.version, 0);

    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn an_empty_admin_token_disables_the_admin_api() {
    let body = json!({"role": "root_tao", "credentialTypes": ["*"], "status": "active"});
    for empty in ["", "  "] {
        let s = state(Some(empty), None);
        for token in [None, Some(""), Some(empty)] {
            let (status, _, _) = call(
                &s,
                "PUT",
                &format!("/v1/issuers/{ROOT}"),
                token,
                Some(body.clone()),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}

#[tokio::test]
async fn auth_runs_before_the_body_is_read() {
    let s = state(Some(TOKEN), None);
    // No content type, and a body that isn't valid for the route: still 401.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/issuers/{ROOT}"))
        .body(Body::from("not json"))
        .unwrap();
    let resp = router(s.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let (status, _, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{ROOT}/status"),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The scheme is case-insensitive (RFC 7235).
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/issuers/{ROOT}"))
        .header(header::AUTHORIZATION, format!("bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"role": "root_tao", "credentialTypes": ["*"], "status": "active"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        router(s).oneshot(req).await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn put_bodies_are_strict() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;
    // A misspelled expiry must not silently create a never-expiring issuer.
    let (status, body, _) = call(
        &s,
        "PUT",
        "/v1/issuers/did:web:x.example",
        Some(TOKEN),
        Some(json!({"role": "ti", "credentialTypes": ["MembershipCredential"], "accreditedBy": TAO, "status": "active", "valid_until": 1000})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("valid_until"));
    for not_an_object in [json!([]), json!(1), json!("x")] {
        let (status, _, _) = call(
            &s,
            "PUT",
            "/v1/issuers/did:web:x.example",
            Some(TOKEN),
            Some(not_an_object),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    // A GET response (with updatedAt) can be PUT back unchanged.
    let (_, record, _) = call(&s, "GET", &format!("/v1/issuers/{TAO}"), None, None).await;
    let (status, _, _) = call(
        &s,
        "PUT",
        &format!("/v1/issuers/{TAO}"),
        Some(TOKEN),
        Some(record),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn load_refuses_missing_and_rule_breaking_files() {
    let dir = std::env::temp_dir().join(format!("tir-load-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("registry.json");
    let _ = std::fs::remove_file(&file);
    assert!(load(&file, false).is_err());
    assert_eq!(load(&file, true).unwrap().version, 0);

    std::fs::write(
        &file,
        json!({"version": 1, "issuers": [
            {"did": ROOT, "role": "root_tao", "credentialTypes": ["*"], "status": "active"},
            {"did": TI, "role": "ti", "credentialTypes": ["*"], "accreditedBy": ROOT, "status": "active"}
        ]})
        .to_string(),
    )
    .unwrap();
    assert!(load(&file, false).unwrap_err().contains("'*'"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_data_file_named_tmp_is_still_written_atomically() {
    let dir = std::env::temp_dir().join(format!("tir-tmp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("registry.tmp");
    let _ = std::fs::remove_file(&file);
    let s = state(Some(TOKEN), Some(file.clone()));
    seed(&s).await;
    assert_eq!(load(&file, false).unwrap().version, 3);
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n != "registry.tmp")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn list_filters_by_role_and_status() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;
    let (status, _, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{TI_PATH}/status"),
        Some(TOKEN),
        Some(json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let dids = |body: &Value| -> Vec<String> {
        let mut dids: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["did"].as_str().unwrap().to_string())
            .collect();
        dids.sort();
        dids
    };

    // What the console's "accredited by" picker asks for.
    let (_, body, _) = call(&s, "GET", "/v1/issuers?role=tao", None, None).await;
    assert_eq!(dids(&body), vec![TAO]);
    assert_eq!(body["total"], 1);
    let (_, body, _) = call(&s, "GET", "/v1/issuers?status=active", None, None).await;
    assert_eq!(dids(&body), vec![ROOT, TAO]);
    let (_, body, _) = call(
        &s,
        "GET",
        "/v1/issuers?role=ti&status=suspended&credentialType=MembershipCredential",
        None,
        None,
    )
    .await;
    assert_eq!(dids(&body), vec![TI]);
    let (_, body, _) = call(&s, "GET", "/v1/issuers?role=ti&status=active", None, None).await;
    assert_eq!(body["total"], 0);

    let (status, _, _) = call(&s, "GET", "/v1/issuers?role=bogus", None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_probe_reports_whether_writes_are_allowed() {
    let s = state(Some(TOKEN), None);
    let (status, _, _) = call(&s, "GET", "/v1/admin", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for token in [None, Some("wrong")] {
        let (status, body, _) = call(&s, "GET", "/v1/admin", token, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body["error"].is_string());
    }
    let disabled = state(None, None);
    let (status, _, _) = call(&disabled, "GET", "/v1/admin", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
