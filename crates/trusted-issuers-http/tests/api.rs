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
use trusted_issuers_http::{
    AppState, JsonFileStore, MemoryStore, SNAPSHOT_CONTENT_TYPE, Store, load, router,
};

const REGISTRY_DID: &str = "did:web:registry.example";
const ROOT: &str = "did:web:authority.example";
const TAO: &str = "did:web:tao.example";
// A did:web with a port: its "%3A" must be sent as "%253A" in the path.
const TI: &str = "did:web:issuer.example%3A8443";
const TI_PATH: &str = "did:web:issuer.example%253A8443";
const TOKEN: &str = "s3cret";

fn state(admin_token: Option<&str>, data_file: Option<std::path::PathBuf>) -> Arc<AppState> {
    let (store, registry): (Arc<dyn Store>, _) = match data_file {
        Some(path) => {
            let (store, registry) = JsonFileStore::open(&path, true).unwrap();
            (Arc::new(store), registry)
        }
        None => (Arc::new(MemoryStore::new()), Default::default()),
    };
    Arc::new(AppState::new(
        registry,
        DcpKeyPair::generate(REGISTRY_DID.into()),
        admin_token.map(Into::into),
        store,
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
    assert_eq!(body["id"], TI);
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
        // The audit log lives next to the data file by design.
        .filter(|n| n != "registry.tmp" && n != "registry.tmp.audit.jsonl")
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
            .map(|r| r["id"].as_str().unwrap().to_string())
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

#[tokio::test]
async fn dids_are_canonicalized_on_write_and_lookup() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;

    // The same DID as TI, spelled with an upper-case host and a lower-case
    // escape, replaces it instead of creating a second record.
    let (status, body, _) = call(
        &s,
        "PUT",
        "/v1/issuers/did:web:Issuer.example%253a8443",
        Some(TOKEN),
        Some(json!({
            "id": TI,
            "role": "ti", "credentialTypes": ["MembershipCredential"],
            "accreditedBy": "did:web:TAO.example", "status": "active"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], TI);
    assert_eq!(body["accreditedBy"], TAO);

    let (_, body, _) = call(&s, "GET", "/v1/issuers", None, None).await;
    assert_eq!(body["total"], 3);

    let (status, body, _) = call(
        &s,
        "GET",
        "/v1/issuers/did:web:ISSUER.example%253a8443",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], TI);

    let (_, body, _) = call(
        &s,
        "GET",
        "/v1/issuers/did:web:ISSUER.example%253a8443/types/MembershipCredential",
        None,
        None,
    )
    .await;
    assert_eq!(body["trusted"], true, "{body}");
    assert_eq!(body["chain"], json!([TI, TAO, ROOT]));

    // A body did that is the same DID in another spelling is not a mismatch.
    let (status, _, _) = call(
        &s,
        "PUT",
        "/v1/issuers/did:web:tao.example",
        Some(TOKEN),
        Some(json!({
            "did": "did:web:TAO.example",
            "role": "tao", "credentialTypes": ["MembershipCredential"],
            "accreditedBy": ROOT, "status": "active"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn did_urls_and_malformed_dids_are_refused_with_422() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;

    // The README promises 422 for these; pin it so a status-mapping change
    // for `InvalidDid` can't silently break the documented behaviour.
    for did in [
        "did:web:x.example%23key-1",
        "did:web:x.example%3Fq=1",
        "did:web:x.example:",
        "did:web:x.example%20y",
        "did:web:x.example%zz",
    ] {
        let (status, body, _) = call(
            &s,
            "PUT",
            &format!("/v1/issuers/{did}"),
            Some(TOKEN),
            Some(json!({
                "role": "ti", "credentialTypes": ["MembershipCredential"],
                "accreditedBy": TAO, "status": "active"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{did}: {body}");
    }

    let (_, body, _) = call(&s, "GET", "/v1/issuers", None, None).await;
    assert_eq!(body["total"], 3);
}

// An OID4VCI credential issuer is named by an https URL. In a path it is one
// percent-encoded segment: each "/" is sent as "%2F" (and a "%" as "%25").
const OID4VCI_TI: &str = "https://issuers.example/tenants/acme";
const OID4VCI_TI_PATH: &str = "https:%2F%2Fissuers.example%2Ftenants%2Facme";
// An SD-JWT VC type (vct) is often a URL too, and is encoded the same way.
const PID_VCT: &str = "https://credentials.example/identity_credential";
const PID_VCT_PATH: &str = "https:%2F%2Fcredentials.example%2Fidentity_credential";

/// The registry from [`seed`] plus an OID4VCI issuer accredited by the TAO
/// for `MembershipCredential` and by the root for the PID `vct`.
async fn seed_with_oid4vci(s: &Arc<AppState>) {
    seed(s).await;
    let (status, body, _) = call(
        s,
        "PUT",
        "/v1/issuers/did:web:pid-tao.example",
        Some(TOKEN),
        Some(json!({"role": "tao", "credentialTypes": [PID_VCT, "MembershipCredential"], "accreditedBy": ROOT, "status": "active"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body, _) = call(
        s,
        "PUT",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}"),
        Some(TOKEN),
        Some(json!({
            "role": "ti", "name": "ACME (OID4VCI)",
            "credentialTypes": [PID_VCT, "MembershipCredential"],
            "accreditedBy": "did:web:pid-tao.example", "status": "active"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["id"], OID4VCI_TI);
}

#[tokio::test]
async fn oid4vci_issuers_are_maintained_next_to_dcp_issuers() {
    let s = state(Some(TOKEN), None);
    seed_with_oid4vci(&s).await;

    let (status, body, _) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], OID4VCI_TI);

    // The trust check, with a URL issuer and a URL credential type.
    let (_, body, _) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}/types/{PID_VCT_PATH}"),
        None,
        None,
    )
    .await;
    assert_eq!(body["trusted"], true, "{body}");
    assert_eq!(
        body["chain"],
        json!([OID4VCI_TI, "did:web:pid-tao.example", ROOT])
    );
    let (_, body, _) = call(
        &s,
        "GET",
        &format!(
            "/v1/issuers?credentialType={}",
            PID_VCT.replace('/', "%2F").replace(':', "%3A")
        ),
        None,
        None,
    )
    .await;
    assert_eq!(
        body["total"], 3,
        "root, pid-tao and the OID4VCI issuer: {body}"
    );

    // Status changes and removal work on URL ids like on DIDs.
    let (status, body, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}/status"),
        Some(TOKEN),
        Some(json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body, _) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}/types/MembershipCredential"),
        None,
        None,
    )
    .await;
    assert_eq!(body["trusted"], false, "{body}");
    let (status, _, _) = call(
        &s,
        "DELETE",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn oid4vci_issuer_ids_are_canonicalized_on_write_and_lookup() {
    let s = state(Some(TOKEN), None);
    seed_with_oid4vci(&s).await;

    // Same issuer, upper-case scheme and host in the path, canonical in the
    // body: a replace (200), not a mismatch (400) or a second record.
    let (status, body, _) = call(
        &s,
        "PUT",
        "/v1/issuers/HTTPS:%2F%2FIssuers.Example%2Ftenants%2Facme",
        Some(TOKEN),
        Some(json!({
            "id": OID4VCI_TI,
            "role": "ti", "credentialTypes": ["MembershipCredential"],
            "accreditedBy": "did:web:pid-tao.example", "status": "active"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], OID4VCI_TI);
    let (_, body, _) = call(
        &s,
        "GET",
        "/v1/issuers/https:%2F%2FISSUERS.example%2Ftenants%2Facme/types/MembershipCredential",
        None,
        None,
    )
    .await;
    assert_eq!(body["trusted"], true, "{body}");
    // The path is case-sensitive.
    let (status, _, _) = call(
        &s,
        "GET",
        "/v1/issuers/https:%2F%2Fissuers.example%2Ftenants%2FACME",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_and_aliased_oid4vci_issuer_ids_are_refused_with_422() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;
    for path in [
        "http:%2F%2Fissuer.example",
        "https:%2F%2Fissuer.example%3Ftenant=acme",
        "https:%2F%2Fissuer.example%2F",
        "https:%2F%2Fissuer.example:443",
        "https:%2F%2F127.0.0.1",
        "https:%2F%2Falice@issuer.example",
        "https:%2F%2Fissuer.example%2F%252E%252E%2Facme",
    ] {
        let (status, body, _) = call(
            &s,
            "PUT",
            &format!("/v1/issuers/{path}"),
            Some(TOKEN),
            Some(json!({
                "role": "ti", "credentialTypes": ["MembershipCredential"],
                "accreditedBy": TAO, "status": "active"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path}: {body}");
    }
    let (_, body, _) = call(&s, "GET", "/v1/issuers", None, None).await;
    assert_eq!(body["total"], 3);
}

#[tokio::test]
async fn list_filters_by_id_kind() {
    let s = state(Some(TOKEN), None);
    seed_with_oid4vci(&s).await;
    let ids = |body: &Value| -> Vec<String> {
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect()
    };

    // A governance console's "OID4VCI issuers" and "DCP issuers" tabs.
    let (status, body, _) = call(&s, "GET", "/v1/issuers?idKind=url", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body), vec![OID4VCI_TI]);
    let (_, body, _) = call(&s, "GET", "/v1/issuers?idKind=did&role=ti", None, None).await;
    assert_eq!(ids(&body), vec![TI]);
    let (_, body, _) = call(&s, "GET", "/v1/issuers?idKind=did", None, None).await;
    assert_eq!(body["total"], 4);

    let (status, _, _) = call(&s, "GET", "/v1/issuers?idKind=https", None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oid4vci_issuers_survive_the_snapshot_and_the_data_file() {
    let dir = std::env::temp_dir().join(format!("tir-oid4vci-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("registry.json");
    let _ = std::fs::remove_file(&file);
    let s = state(Some(TOKEN), Some(file.clone()));
    seed_with_oid4vci(&s).await;

    let reloaded = load(&file, false).unwrap();
    assert_eq!(reloaded, *s.registry.read().await);
    assert!(reloaded.get(OID4VCI_TI).is_some());

    let (_, token, _) = call(&s, "GET", "/v1/snapshot", None, None).await;
    let token = token.as_str().unwrap();
    let (_, doc, _) = call(&s, "GET", "/.well-known/did.json", None, None).await;
    let doc = serde_json::from_value(doc).unwrap();
    let key = find_verifying_key(&doc, &snapshot_kid(token).unwrap()).unwrap();
    let list = verify_snapshot(token, REGISTRY_DID, &key, dcp_core::now_secs()).unwrap();
    let now = dcp_core::now_secs();
    assert!(list.check(OID4VCI_TI, PID_VCT, now).trusted);
    assert!(list.check(TI, "MembershipCredential", now).trusted);
    assert!(!list.check(TI, PID_VCT, now).trusted);

    std::fs::remove_dir_all(dir).unwrap();
}

fn audit_entries(body: &Value) -> Vec<trusted_issuers_core::AuditEntry> {
    serde_json::from_value(body["entries"].clone()).unwrap()
}

#[tokio::test]
async fn every_write_is_audited_in_a_verifiable_chain() {
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
    let (status, _, _) = call(
        &s,
        "DELETE",
        &format!("/v1/issuers/{TI_PATH}"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body, _) = call(&s, "GET", "/v1/admin/audit", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entries = audit_entries(&body);
    use trusted_issuers_core::AuditAction::*;
    assert_eq!(
        entries
            .iter()
            .map(|e| (e.seq, e.action, e.id.as_str(), e.version))
            .collect::<Vec<_>>(),
        vec![
            (1, Put, ROOT, 1),
            (2, Put, TAO, 2),
            (3, Put, TI, 3),
            (4, Status, TI, 4),
            (5, Delete, TI, 5),
        ]
    );
    assert!(entries.iter().all(|e| e.actor == "admin"));
    assert!(entries[0].before.is_none());
    assert_eq!(entries[0].after.as_ref().unwrap().id, ROOT);
    assert_eq!(
        entries[3].before.as_ref().unwrap().status,
        trusted_issuers_core::Status::Active
    );
    assert_eq!(
        entries[3].after.as_ref().unwrap().status,
        trusted_issuers_core::Status::Suspended
    );
    assert!(entries[4].after.is_none());
    assert_eq!(trusted_issuers_core::verify_audit_chain(&entries), Ok(()));
    assert_eq!(body["head"]["seq"], 5);
    assert_eq!(body["head"]["hash"], entries[4].hash.as_str());
}

#[tokio::test]
async fn failed_writes_leave_no_audit_entry() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;
    // A rule violation and an unknown record.
    let (status, _, _) = call(
        &s,
        "PUT",
        "/v1/issuers/did:web:x.example",
        Some(TOKEN),
        Some(json!({"role": "ti", "credentialTypes": ["Other"], "accreditedBy": TAO, "status": "active"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _, _) = call(
        &s,
        "DELETE",
        "/v1/issuers/did:web:nobody.example",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, body, _) = call(&s, "GET", "/v1/admin/audit", Some(TOKEN), None).await;
    assert_eq!(audit_entries(&body).len(), 3, "{body}");
}

#[tokio::test]
async fn the_audit_log_is_admin_only() {
    let s = state(Some(TOKEN), None);
    let (status, _, _) = call(&s, "GET", "/v1/admin/audit", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = call(&s, "GET", "/v1/admin/audit", Some("wrong"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_audit_log_pages_and_filters_by_issuer() {
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

    let (_, body, _) = call(
        &s,
        "GET",
        "/v1/admin/audit?after=1&limit=2",
        Some(TOKEN),
        None,
    )
    .await;
    let seqs: Vec<u64> = audit_entries(&body).iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![2, 3], "{body}");
    // The head is the whole log's, whatever the page.
    assert_eq!(body["head"]["seq"], 4);

    // `id` is a query value, so its own % is sent as %25; any spelling of
    // the DID matches.
    let (_, body, _) = call(
        &s,
        "GET",
        "/v1/admin/audit?id=did:web:ISSUER.example%253a8443",
        Some(TOKEN),
        None,
    )
    .await;
    let seqs: Vec<u64> = audit_entries(&body).iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![3, 4], "{body}");

    let (status, _, _) = call(&s, "GET", "/v1/admin/audit?limit=0", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = call(&s, "GET", "/v1/admin/audit?limit=1001", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_audit_actor_comes_from_the_configured_gateway_header() {
    let s = Arc::new(
        AppState::new(
            Default::default(),
            DcpKeyPair::generate(REGISTRY_DID.into()),
            Some(TOKEN.into()),
            Arc::new(MemoryStore::new()),
            600,
        )
        .with_audit_actor_header("x-forwarded-user"),
    );
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/issuers/{ROOT}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("X-Forwarded-User", "alice@authority.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"role": "root_tao", "credentialTypes": ["*"], "status": "active"}).to_string(),
        ))
        .unwrap();
    let resp = router(s.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    // Without the header the actor falls back to "admin".
    let (status, _, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{ROOT}/status"),
        Some(TOKEN),
        Some(json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body, _) = call(&s, "GET", "/v1/admin/audit", Some(TOKEN), None).await;
    let actors: Vec<String> = audit_entries(&body).into_iter().map(|e| e.actor).collect();
    assert_eq!(actors, vec!["alice@authority.example", "admin"]);
}

#[tokio::test]
async fn the_audit_log_survives_a_restart_and_tampering_is_refused() {
    let dir = std::env::temp_dir().join(format!("tir-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("registry.json");
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(trusted_issuers_http::audit_file(&file));

    let s = state(Some(TOKEN), Some(file.clone()));
    seed(&s).await;
    drop(s);

    // Restart: the log is back and the next write chains onto it.
    let s = state(Some(TOKEN), Some(file.clone()));
    let (status, _, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{TI_PATH}/status"),
        Some(TOKEN),
        Some(json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body, _) = call(&s, "GET", "/v1/admin/audit", Some(TOKEN), None).await;
    let entries = audit_entries(&body);
    assert_eq!(entries.len(), 4, "{body}");
    assert_eq!(trusted_issuers_core::verify_audit_chain(&entries), Ok(()));
    drop(s);

    // A crash after the audit entry was written but before the registry
    // file was replaced leaves one entry ahead of the registry: it is
    // dropped on open, since that write never happened.
    let audit = trusted_issuers_http::audit_file(&file);
    let ahead = trusted_issuers_core::AuditEntry::next(
        entries.last(),
        trusted_issuers_core::AuditRecord {
            at: 1,
            actor: "admin".into(),
            action: trusted_issuers_core::AuditAction::Delete,
            id: TI.into(),
            before: entries.last().unwrap().after.clone(),
            after: None,
            version: 5,
        },
    );
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&audit)
        .unwrap();
    use std::io::Write;
    writeln!(f, "{}", serde_json::to_string(&ahead).unwrap()).unwrap();
    drop(f);
    let (store, registry) = JsonFileStore::open(&file, false).unwrap();
    assert_eq!(registry.version, 4);
    assert_eq!(store.audit_head().unwrap().seq, 4);

    // Editing a past entry makes the store refuse to open.
    let text = std::fs::read_to_string(&audit).unwrap();
    std::fs::write(
        &audit,
        text.replacen("\"actor\":\"admin\"", "\"actor\":\"mallory\"", 1),
    )
    .unwrap();
    let err = JsonFileStore::open(&file, false)
        .err()
        .expect("tampered log");
    assert!(err.contains("audit"), "{err}");

    std::fs::remove_dir_all(dir).unwrap();
}

fn graph_state(dir: &std::path::Path, import: Option<&std::path::Path>) -> Arc<AppState> {
    let (store, registry) = trusted_issuers_http::GraphStore::open(dir, import).unwrap();
    Arc::new(AppState::new(
        registry,
        DcpKeyPair::generate(REGISTRY_DID.into()),
        Some(TOKEN.into()),
        Arc::new(store),
        600,
    ))
}

#[tokio::test]
async fn the_graph_store_keeps_the_registry_and_its_audit_log_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let s = graph_state(dir.path(), None);
    seed_with_oid4vci(&s).await;
    let (_, before, _) = call(&s, "GET", "/v1/issuers", None, None).await;
    drop(s);

    let s = graph_state(dir.path(), None);
    let (_, after, _) = call(&s, "GET", "/v1/issuers", None, None).await;
    assert_eq!(after, before);
    assert_eq!(after["total"], 5);
    let (_, body, _) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}/types/{PID_VCT_PATH}"),
        None,
        None,
    )
    .await;
    assert_eq!(body["trusted"], true, "{body}");

    let (status, _, _) = call(
        &s,
        "PATCH",
        &format!("/v1/issuers/{TI_PATH}/status"),
        Some(TOKEN),
        Some(json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body, _) = call(&s, "GET", "/v1/admin/audit", Some(TOKEN), None).await;
    let entries = audit_entries(&body);
    assert_eq!(entries.len(), 6, "{body}");
    assert_eq!(trusted_issuers_core::verify_audit_chain(&entries), Ok(()));
    assert_eq!(body["head"]["seq"], 6);
}

#[tokio::test]
async fn a_json_data_file_is_imported_into_an_empty_graph_once() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("registry.json");
    let s = state(Some(TOKEN), Some(file.clone()));
    seed(&s).await;
    drop(s);

    let graph_dir = dir.path().join("graph");
    let s = graph_state(&graph_dir, Some(&file));
    let (_, body, _) = call(&s, "GET", "/v1/issuers", None, None).await;
    assert_eq!(body["total"], 3);
    assert_eq!(body["version"], 3);
    drop(s);
    // A graph that already holds a registry is not overwritten.
    assert!(trusted_issuers_http::GraphStore::open(&graph_dir, Some(&file)).is_err());
    // Reopening without import keeps what was imported.
    let s = graph_state(&graph_dir, None);
    let (_, body, _) = call(&s, "GET", "/v1/issuers", None, None).await;
    assert_eq!(body["total"], 3);
}

mod pki {
    use base64::Engine;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    pub fn b64(der: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    pub fn iaca() -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Example IACA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }

    /// An mDL document signer certificate issued by `iaca`.
    pub fn document_signer(iaca: &CertifiedIssuer<'static, KeyPair>) -> String {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Document Signer");
        params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::Other(vec![1, 0, 18013, 5, 1, 2])];
        b64(params
            .signed_by(&KeyPair::generate().unwrap(), iaca)
            .unwrap()
            .der())
    }
}

const MDL_ISSUER_PATH: &str = "https:%2F%2Fmdl.example";
const MDL: &str = "org.iso.18013.5.1.mDL";

#[tokio::test]
async fn x5c_chains_are_checked_against_listed_trust_anchors() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;
    let iaca = pki::iaca();
    let (status, body, _) = call(
        &s,
        "PUT",
        &format!("/v1/issuers/{MDL_ISSUER_PATH}"),
        Some(TOKEN),
        Some(json!({
            "role": "ti", "name": "Example mDL issuing authority",
            "credentialTypes": [MDL], "accreditedBy": ROOT, "status": "active",
            "x509Certificates": [pki::b64(iaca.der())]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["x509Certificates"][0], pki::b64(iaca.der()));

    let ds = pki::document_signer(&iaca);
    let (status, body, _) = call(
        &s,
        "POST",
        "/v1/x509/check",
        None,
        Some(json!({"x5c": [ds], "credentialType": MDL, "eku": "1.0.18013.5.1.2"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["trusted"], true, "{body}");
    assert_eq!(body["chain"], json!(["https://mdl.example", ROOT]));

    // Someone else's CA.
    let other = pki::document_signer(&pki::iaca());
    let (_, body, _) = call(
        &s,
        "POST",
        "/v1/x509/check",
        None,
        Some(json!({"x5c": [other], "credentialType": MDL})),
    )
    .await;
    assert_eq!(body["trusted"], false, "{body}");

    // Bodies are strict.
    for bad in [
        json!({"credentialType": MDL}),
        json!({"x5c": [], "credentialType": MDL, "extra": 1}),
    ] {
        let (status, _, _) = call(&s, "POST", "/v1/x509/check", None, Some(bad.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn invalid_or_shared_anchors_are_refused_with_422() {
    let s = state(Some(TOKEN), None);
    seed(&s).await;
    let iaca = pki::b64(pki::iaca().der());
    for (path, anchors) in [
        ("https:%2F%2Fa.example", json!(["not base64!"])),
        ("https:%2F%2Fb.example", json!([iaca.clone()])),
        ("https:%2F%2Fc.example", json!([iaca.clone()])),
    ] {
        let (status, body, _) = call(
            &s,
            "PUT",
            &format!("/v1/issuers/{path}"),
            Some(TOKEN),
            Some(json!({
                "role": "ti", "credentialTypes": ["MembershipCredential"],
                "accreditedBy": TAO, "status": "active", "x509Certificates": anchors
            })),
        )
        .await;
        let want = if path.contains("b.example") {
            StatusCode::CREATED
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        };
        assert_eq!(status, want, "{path}: {body}");
    }
}

#[tokio::test]
async fn an_issuer_downloads_accreditations_that_verify_offline() {
    let s = state(Some(TOKEN), None);
    seed_with_oid4vci(&s).await;
    let (status, body, content_type) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}/accreditations"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(content_type.as_deref(), Some("application/json"));
    let tokens: Vec<String> = serde_json::from_value(body["accreditations"].clone()).unwrap();
    assert_eq!(tokens.len(), 3);

    // A verifier with only the registry's DID document.
    let (_, doc, _) = call(&s, "GET", "/.well-known/did.json", None, None).await;
    let doc = serde_json::from_value(doc).unwrap();
    let kid = dcp_core::decode_jws_unverified(&tokens[0]).unwrap().1["kid"]
        .as_str()
        .unwrap()
        .to_string();
    let key = find_verifying_key(&doc, &kid).unwrap();
    let now = dcp_core::now_secs();
    let chain =
        trusted_issuers_core::verify_accreditations(&tokens, REGISTRY_DID, &key, now).unwrap();
    assert!(chain.check(OID4VCI_TI, PID_VCT, now).trusted);

    // Unknown issuer: 404; broken chain: 422.
    let (status, _, _) = call(
        &s,
        "GET",
        "/v1/issuers/did:web:nobody.example/accreditations",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = call(
        &s,
        "PATCH",
        "/v1/issuers/did:web:pid-tao.example/status",
        Some(TOKEN),
        Some(json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body, _) = call(
        &s,
        "GET",
        &format!("/v1/issuers/{OID4VCI_TI_PATH}/accreditations"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}
