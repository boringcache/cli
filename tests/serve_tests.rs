use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use boring_cache_cli::api::client::ApiClient;
use boring_cache_cli::cas_oci;
use boring_cache_cli::git::GitContext;
use boring_cache_cli::serve::routes::build_router;
use boring_cache_cli::serve::state::{
    digest_tag, ref_tag, AppState, BlobLocatorCache, UploadSessionStore,
};
use boring_cache_cli::tag_utils::TagResolver;
use http_body_util::BodyExt;
use mockito::{Matcher, Server};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

static ENV_MUTEX: Mutex<()> = Mutex::const_new(());

async fn setup(
    server: &Server,
) -> (
    AppState,
    tempfile::TempDir,
    tokio::sync::MutexGuard<'static, ()>,
) {
    let guard = ENV_MUTEX.lock().await;
    let temp_home = tempfile::tempdir().expect("temp dir");
    unsafe {
        std::env::set_var("HOME", temp_home.path());
        std::env::set_var("BORINGCACHE_API_URL", server.url());
        std::env::set_var("BORINGCACHE_AUTH_TOKEN", "test-token");
        std::env::set_var("BORINGCACHE_TEST_MODE", "1");
    }

    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("API client");

    let state = AppState {
        api_client,
        workspace: "org/repo".to_string(),
        tag_resolver: TagResolver::new(None, GitContext::default(), false),
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
    };

    (state, temp_home, guard)
}

fn make_pointer(index_json: &[u8], blobs: &[(&str, u64)]) -> Vec<u8> {
    let pointer = cas_oci::OciPointer {
        format_version: 1,
        adapter: "oci-v1".to_string(),
        index_json_base64: STANDARD.encode(index_json),
        oci_layout_base64: STANDARD.encode(br#"{"imageLayoutVersion":"1.0.0"}"#),
        blobs: blobs
            .iter()
            .map(|(digest, size)| cas_oci::OciPointerBlob {
                digest: digest.to_string(),
                size_bytes: *size,
            })
            .collect(),
    };
    serde_json::to_vec(&pointer).unwrap()
}

#[tokio::test]
async fn test_v2_base_returns_200() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder().uri("/v2/").body(Body::empty()).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Docker-Distribution-API-Version")
            .unwrap(),
        "registry/2.0"
    );
}

#[tokio::test]
async fn test_nonexistent_route_returns_404() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_manifest_hit_returns_decoded_index_json() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let blob_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 5000)]);

    let tag = ref_tag("my-cache", "main");

    let restore_body = json!([{
        "tag": tag,
        "status": "hit",
        "cache_entry_id": "entry-123",
        "manifest_url": format!("{}/pointers/entry-123", server.url()),
        "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
        "storage_mode": "cas",
        "cas_layout": "oci-v1",
    }]);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(restore_body.to_string())
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-123")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/my-cache/manifests/main")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert!(response
        .headers()
        .get("Docker-Content-Digest")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("sha256:"));

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["schemaVersion"], 2);
}

#[tokio::test]
async fn test_manifest_miss_returns_404() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let tag = ref_tag("my-cache", "nonexistent");
    let restore_body = json!([{
        "tag": tag,
        "status": "miss",
    }]);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(restore_body.to_string())
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/my-cache/manifests/nonexistent")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
}

#[tokio::test]
async fn test_manifest_head_returns_headers_no_body() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":50},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[]);
    let tag = ref_tag("img", "latest");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-456",
                "manifest_url": format!("{}/pointers/entry-456", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-456")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri("/v2/img/manifests/latest")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("Docker-Content-Digest").is_some());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_blob_unknown_without_manifest_returns_404() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/my-cache/blobs/sha256:deadbeef")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
}

#[tokio::test]
async fn test_blob_get_after_manifest_resolution() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let blob_content = b"hello blob content";
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, blob_content.len() as u64)]);
    let tag = ref_tag("img", "v1");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-789",
                "manifest_url": format!("{}/pointers/entry-789", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-789")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": blob_digest,
                    "url": format!("{}/blobs/{}", server.url(), blob_digest),
                }],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(200)
        .with_body(blob_content)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/img/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        blob_digest
    );
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/octet-stream"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], blob_content);
}

#[tokio::test]
async fn test_index_manifest_detected_as_index_type() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json = br#"{"schemaVersion":2,"manifests":[{"digest":"sha256:aaa","size":100,"mediaType":"application/vnd.oci.image.manifest.v1+json","platform":{"architecture":"amd64","os":"linux"}}]}"#;
    let pointer_bytes = make_pointer(index_json, &[]);
    let tag = ref_tag("multi", "latest");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-idx",
                "manifest_url": format!("{}/pointers/entry-idx", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-idx")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/multi/manifests/latest")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/vnd.oci.image.index.v1+json"
    );
}

#[tokio::test]
async fn test_tag_mapping_deterministic() {
    let t1 = ref_tag("my-cache", "main");
    let t2 = ref_tag("my-cache", "main");
    assert_eq!(t1, t2);
    assert!(t1.starts_with("oci_ref_"));
    assert_eq!(t1.len(), 8 + 64);

    let t3 = ref_tag("my-cache", "dev");
    assert_ne!(t1, t3);

    let dt = digest_tag("sha256:abc123");
    assert_eq!(dt, "oci_digest_abc123");
}

#[tokio::test]
async fn test_oci_error_envelope_format() {
    use axum::response::IntoResponse;
    use boring_cache_cli::serve::error::OciError;
    let err = OciError::manifest_unknown("test detail");
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    assert_eq!(parsed["errors"][0]["message"], "test detail");
}

#[tokio::test]
async fn test_upload_start_and_finalize() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = response
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.contains(&uuid));

    let chunk_data = b"test blob data";
    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::from(chunk_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let range = response
        .headers()
        .get("Range")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(range, format!("0-{}", chunk_data.len() - 1));

    let digest = cas_oci::prefixed_sha256_digest(chunk_data);
    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );
}

#[tokio::test]
async fn test_upload_digest_mismatch_returns_error() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = resp
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let chunk_data = b"some data";
    let app = build_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::from(chunk_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/my-cache/blobs/uploads/{uuid}?digest={wrong_digest}"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");
}

#[tokio::test]
async fn test_delete_upload_returns_204() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = resp
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_monolithic_upload() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_data = b"monolithic blob payload";
    let digest = cas_oci::prefixed_sha256_digest(blob_data);

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v2/my-cache/blobs/uploads/?digest={digest}"))
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );
}

#[tokio::test]
async fn test_multi_segment_name_manifest() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":50},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[]);
    let tag = ref_tag("org/my-cache", "main");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-multi",
                "manifest_url": format!("{}/pointers/entry-multi", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-multi")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/org/my-cache/manifests/main")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("Docker-Content-Digest").is_some());
}

#[tokio::test]
async fn test_multi_segment_name_blob_upload() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/org/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with("/v2/org/my-cache/blobs/uploads/"));
}

#[tokio::test]
async fn test_blob_upload_start_without_trailing_slash() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/org/my-cache/blobs/uploads")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with("/v2/org/my-cache/blobs/uploads/"));
}

#[tokio::test]
async fn test_put_upload_accepts_empty_body_when_blob_already_exists_remote() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _check_mock = server
        .mock("POST", "/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": 0
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": blob_digest,
                    "exists": true
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let start_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(start_response.status(), StatusCode::ACCEPTED);
    let uuid = start_response
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/my-cache/blobs/uploads/{uuid}?digest={blob_digest}"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        blob_digest
    );
}

#[tokio::test]
async fn test_blob_proxy_returns_error_on_storage_failure() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 100)]);
    let tag = ref_tag("img", "v1");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-err",
                "manifest_url": format!("{}/pointers/entry-err", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-err")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": blob_digest,
                    "url": format!("{}/blobs/{}", server.url(), blob_digest),
                }],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(403)
        .with_body("Forbidden - signed URL expired")
        .create_async()
        .await;

    let app = build_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/img/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "INTERNAL_ERROR");
}
