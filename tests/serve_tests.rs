use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use boring_cache_cli::api::client::ApiClient;
use boring_cache_cli::cas_file;
use boring_cache_cli::cas_oci;
use boring_cache_cli::git::GitContext;
use boring_cache_cli::manifest::EntryType;
use boring_cache_cli::serve::routes::build_router;
use boring_cache_cli::serve::state::{
    digest_tag, ref_tag, AppState, BlobLocatorCache, BlobLocatorEntry, BlobReadCache,
    KvPendingStore, KvPublishedIndex, OciManifestCacheEntry, UploadSession, UploadSessionStore,
};
use boring_cache_cli::tag_utils::TagResolver;
use http_body_util::BodyExt;
use mockito::{Matcher, Server};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

static ENV_MUTEX: Mutex<()> = Mutex::const_new(());
static ORIGINAL_TMPDIR: std::sync::LazyLock<Option<String>> =
    std::sync::LazyLock::new(|| std::env::var("TMPDIR").ok());

struct ScopedEnvVar(&'static str);

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(self.0);
        }
    }
}

fn set_scoped_env_var(key: &'static str, value: &str) -> ScopedEnvVar {
    unsafe {
        std::env::set_var(key, value);
    }
    ScopedEnvVar(key)
}

async fn setup(
    server: &Server,
) -> (
    AppState,
    tempfile::TempDir,
    tokio::sync::MutexGuard<'static, ()>,
) {
    let guard = ENV_MUTEX.lock().await;
    let _ = *ORIGINAL_TMPDIR;
    unsafe {
        match ORIGINAL_TMPDIR.as_deref() {
            Some(orig) => std::env::set_var("TMPDIR", orig),
            None => std::env::remove_var("TMPDIR"),
        }
    }
    let temp_home = tempfile::tempdir().expect("temp dir");
    unsafe {
        std::env::set_var("HOME", temp_home.path());
        std::env::set_var("TMPDIR", temp_home.path());
        std::env::set_var("BORINGCACHE_API_URL", server.url());
        std::env::set_var("BORINGCACHE_AUTH_TOKEN", "test-token");
        std::env::set_var("BORINGCACHE_TEST_MODE", "1");
    }

    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("API client");
    let (kv_replication_work_tx, _kv_replication_work_rx) = tokio::sync::mpsc::channel(
        boring_cache_cli::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY,
    );

    let state = AppState {
        api_client,
        workspace: "org/repo".to_string(),
        read_only: false,
        tag_resolver: TagResolver::new(None, GitContext::default(), false),
        configured_human_tags: Vec::new(),
        registry_root_tag: "registry".to_string(),
        fail_on_cache_error: true,
        kv_manifest_warm_enabled: true,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(Mutex::new(())),
        kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        kv_last_put: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_backlog_rejects: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_enqueue_deferred: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_conflict: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_error: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_permanent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_queue_depth: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_work_tx,
        kv_next_flush_at: Arc::new(RwLock::new(None)),
        kv_flush_scheduled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_published_index: Arc::new(RwLock::new(KvPublishedIndex::default())),
        kv_flushing: Arc::new(RwLock::new(None)),
        shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_recent_misses: Arc::new(dashmap::DashMap::new()),
        kv_miss_generations: Arc::new(dashmap::DashMap::new()),
        blob_read_cache: Arc::new(
            BlobReadCache::new_at(
                temp_home.path().join("blob-read-cache"),
                2 * 1024 * 1024 * 1024,
            )
            .expect("blob read cache"),
        ),
        blob_download_max_concurrency: 16,
        blob_download_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        blob_prefetch_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
        cache_ops: Arc::new(boring_cache_cli::serve::cache_registry::cache_ops::Aggregator::new()),
        oci_manifest_cache: Arc::new(dashmap::DashMap::new()),
        backend_breaker: Arc::new(boring_cache_cli::serve::state::BackendCircuitBreaker::new()),
        prefetch_complete: Arc::new(std::sync::atomic::AtomicBool::new(true)),
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
            .enumerate()
            .map(|(sequence, (digest, size))| cas_oci::OciPointerBlob {
                digest: digest.to_string(),
                size_bytes: *size,
                sequence: Some(sequence as u64),
            })
            .collect(),
    };
    serde_json::to_vec(&pointer).unwrap()
}

fn make_file_pointer(blob_digest: &str, size_bytes: u64) -> Vec<u8> {
    let pointer = cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: Vec::new(),
        blobs: vec![cas_file::FilePointerBlob {
            digest: blob_digest.to_string(),
            size_bytes,
            sequence: None,
        }],
    };
    serde_json::to_vec(&pointer).unwrap()
}

fn make_kv_pointer(entries: &[(String, String, u64)]) -> Vec<u8> {
    let pointer = cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: entries
            .iter()
            .map(|(path, digest, size_bytes)| cas_file::FilePointerEntry {
                path: path.clone(),
                entry_type: EntryType::File,
                size_bytes: *size_bytes,
                executable: None,
                target: None,
                digest: Some(digest.clone()),
            })
            .collect(),
        blobs: entries
            .iter()
            .enumerate()
            .map(
                |(sequence, (_, digest, size_bytes))| cas_file::FilePointerBlob {
                    digest: digest.clone(),
                    size_bytes: *size_bytes,
                    sequence: Some(sequence as u64),
                },
            )
            .collect(),
    };
    serde_json::to_vec(&pointer).unwrap()
}

#[tokio::test]
async fn test_startup_manifest_warm_runs_by_default() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;

    let handle = boring_cache_cli::serve::start_server_background(
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("api client"),
        "org/repo".to_string(),
        "127.0.0.1".to_string(),
        0,
        TagResolver::new(None, GitContext::default(), false),
        vec!["main".to_string()],
        "registry".to_string(),
        BTreeMap::new(),
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let get = client
            .get(format!("{base_url}/v2/"))
            .send()
            .await
            .expect("get request");
        if get.status() == reqwest::StatusCode::OK {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "proxy did not become ready within 10s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    handle.shutdown_and_flush().await.expect("shutdown proxy");
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_v2_returns_503_before_prefetch_complete() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder().uri("/v2/").body(Body::empty()).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_startup_prefetch_warms_bounded_slice_and_leaves_tail_on_demand() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;
    let _max_blobs_env = set_scoped_env_var("BORINGCACHE_STARTUP_PREFETCH_MAX_BLOBS", "2");
    let _max_bytes_env = set_scoped_env_var("BORINGCACHE_STARTUP_PREFETCH_MAX_TOTAL_BYTES", "10");

    let warm_blob_a = b"aaaaa";
    let warm_blob_b = b"bbbbb";
    let cold_blob = b"cccccccccccc";
    let digest_a = cas_oci::prefixed_sha256_digest(warm_blob_a);
    let digest_b = cas_oci::prefixed_sha256_digest(warm_blob_b);
    let digest_c = cas_oci::prefixed_sha256_digest(cold_blob);

    let key_a = digest_a.strip_prefix("sha256:").unwrap();
    let key_b = digest_b.strip_prefix("sha256:").unwrap();
    let key_c = digest_c.strip_prefix("sha256:").unwrap();
    let pointer_entries = vec![
        (
            format!("bazel_cas/{key_a}"),
            digest_a.clone(),
            warm_blob_a.len() as u64,
        ),
        (
            format!("bazel_cas/{key_b}"),
            digest_b.clone(),
            warm_blob_b.len() as u64,
        ),
        (
            format!("bazel_cas/{key_c}"),
            digest_c.clone(),
            cold_blob.len() as u64,
        ),
    ];
    let pointer_bytes = make_kv_pointer(&pointer_entries);

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "registry",
                "status": "hit",
                "cache_entry_id": "entry-startup-slice",
                "manifest_url": format!("{}/pointers/entry-startup-slice", server.url()),
                "manifest_root_digest": cas_file::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-startup-slice")
        .expect_at_least(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(1)
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [
                    {
                        "digest": digest_a,
                        "url": format!("{}/blobs/{}", server.url(), digest_a),
                    },
                    {
                        "digest": digest_b,
                        "url": format!("{}/blobs/{}", server.url(), digest_b),
                    },
                    {
                        "digest": digest_c,
                        "url": format!("{}/blobs/{}", server.url(), digest_c),
                    }
                ],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let warm_blob_a_mock = server
        .mock("GET", format!("/blobs/{}", digest_a).as_str())
        .expect(1)
        .with_status(200)
        .with_body(warm_blob_a)
        .create_async()
        .await;
    let warm_blob_b_mock = server
        .mock("GET", format!("/blobs/{}", digest_b).as_str())
        .expect(1)
        .with_status(200)
        .with_body(warm_blob_b)
        .create_async()
        .await;
    let cold_blob_startup_mock = server
        .mock("GET", format!("/blobs/{}", digest_c).as_str())
        .expect(0)
        .with_status(200)
        .with_body(cold_blob)
        .create_async()
        .await;

    let handle = boring_cache_cli::serve::start_server_background(
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("api client"),
        "org/repo".to_string(),
        "127.0.0.1".to_string(),
        0,
        TagResolver::new(None, GitContext::default(), false),
        Vec::new(),
        "registry".to_string(),
        BTreeMap::new(),
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let get = client
            .get(format!("{base_url}/v2/"))
            .send()
            .await
            .expect("get request");
        if get.status() == reqwest::StatusCode::OK {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "proxy did not become ready within 10s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    warm_blob_a_mock.assert_async().await;
    warm_blob_b_mock.assert_async().await;
    assert!(
        cold_blob_startup_mock.matched_async().await,
        "third blob should not be prefetched during startup"
    );
    cold_blob_startup_mock.remove_async().await;

    let cold_blob_on_demand_mock = server
        .mock("GET", format!("/blobs/{}", digest_c).as_str())
        .expect(1)
        .with_status(200)
        .with_body(cold_blob)
        .create_async()
        .await;

    let blob_response = client
        .get(format!("{base_url}/cas/{key_c}"))
        .send()
        .await
        .expect("blob request");
    assert_eq!(blob_response.status(), reqwest::StatusCode::OK);
    assert_eq!(blob_response.bytes().await.unwrap().as_ref(), cold_blob);

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    cold_blob_on_demand_mock.assert_async().await;
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
async fn test_unknown_put_route_returns_created() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/unknown-protocol/path")
            .body(Body::from("payload"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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
async fn test_manifest_degrades_to_miss_when_pointer_blobs_missing_in_best_effort() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [
                    {
                        "digest": blob_digest,
                        "exists": false
                    }
                ]
            })
            .to_string(),
        )
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
}

#[tokio::test]
async fn test_manifest_degrades_to_miss_when_storage_blob_is_unreadable_in_best_effort() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 4096)]);
    let tag = ref_tag("my-cache", "main");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-storage-miss",
                "manifest_url": format!("{}/pointers/entry-storage-miss", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-storage-miss")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
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

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
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
        .expect(2)
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(404)
        .with_body("missing")
        .expect(2)
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
}

#[tokio::test]
async fn test_cached_manifest_hit_revalidates_blob_retrievability_in_best_effort() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#
            .to_vec();
    let tag = ref_tag("cached", "v1");
    let manifest_digest = cas_oci::prefixed_sha256_digest(&index_json);
    let cached = Arc::new(OciManifestCacheEntry {
        index_json,
        content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        manifest_digest: manifest_digest.clone(),
        cache_entry_id: "entry-cached-miss".to_string(),
        blobs: vec![boring_cache_cli::api::models::cache::BlobDescriptor {
            digest: blob_digest.to_string(),
            size_bytes: 2048,
        }],
        name: "cached".to_string(),
        inserted_at: Instant::now(),
        blob_retrievability_validated_at: std::sync::Mutex::new(None),
        blob_retrievability_validation_lock: Mutex::new(()),
    });
    state
        .oci_manifest_cache
        .insert(tag.clone(), Arc::clone(&cached));
    state
        .oci_manifest_cache
        .insert(digest_tag(&manifest_digest), cached);

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
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

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
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
        .expect(2)
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(404)
        .with_body("missing")
        .expect(2)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/cached/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(state.oci_manifest_cache.get(&tag).is_none());
    assert!(state
        .oci_manifest_cache
        .get(&digest_tag(&manifest_digest))
        .is_none());
}

#[tokio::test]
async fn test_recently_validated_cached_manifest_skips_revalidation_and_keeps_locator_urls() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:abababababababababababababababababababababababababababababababab";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#
            .to_vec();
    let tag = ref_tag("cached-fast", "v2");
    let manifest_digest = cas_oci::prefixed_sha256_digest(&index_json);
    let cached = Arc::new(OciManifestCacheEntry {
        index_json,
        content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        manifest_digest: manifest_digest.clone(),
        cache_entry_id: "entry-cached-fast".to_string(),
        blobs: vec![boring_cache_cli::api::models::cache::BlobDescriptor {
            digest: blob_digest.to_string(),
            size_bytes: 2048,
        }],
        name: "cached-fast".to_string(),
        inserted_at: Instant::now(),
        blob_retrievability_validated_at: std::sync::Mutex::new(Some(Instant::now())),
        blob_retrievability_validation_lock: Mutex::new(()),
    });
    state
        .oci_manifest_cache
        .insert(tag.clone(), Arc::clone(&cached));
    state
        .oci_manifest_cache
        .insert(digest_tag(&manifest_digest), cached);

    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "cached-fast",
            blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-cached-fast".to_string(),
                size_bytes: 2048,
                download_url: Some(format!("{}/blobs/{}", server.url(), blob_digest)),
                download_url_cached_at: Some(Instant::now()),
            },
        );
    }

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(200)
        .with_body("cached-fast-blob")
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let manifest_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/cached-fast/manifests/v2")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(manifest_response.status(), StatusCode::OK);

    let app = build_router(state);
    let blob_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/cached-fast/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(blob_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_manifest_refreshes_stale_blob_urls_before_returning_manifest() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_a = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let blob_b = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_a, 1024), (blob_b, 2048)]);
    let tag = ref_tag("img", "latest");
    let batch_request = json!({
        "cache_entry_id": "entry-refresh",
        "blobs": [
            {"digest": blob_a, "size_bytes": 1024},
            {"digest": blob_b, "size_bytes": 2048}
        ]
    });
    let single_request = json!({
        "cache_entry_id": "entry-refresh",
        "blobs": [
            {"digest": blob_a, "size_bytes": 1024}
        ]
    });

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-refresh",
                "manifest_url": format!("{}/pointers/entry-refresh", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-refresh")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [
                    {"digest": blob_a, "exists": true},
                    {"digest": blob_b, "exists": true}
                ]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _download_urls_batch_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(batch_request))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [
                    {
                        "digest": blob_a,
                        "url": format!("{}/blobs/stale/{}", server.url(), blob_a),
                    },
                    {
                        "digest": blob_b,
                        "url": format!("{}/blobs/good/{}", server.url(), blob_b),
                    }
                ],
                "missing": [],
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let _download_urls_retry_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(single_request))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": blob_a,
                    "url": format!("{}/blobs/fresh/{}", server.url(), blob_a),
                }],
                "missing": [],
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let _stale_blob_mock = server
        .mock("GET", format!("/blobs/stale/{}", blob_a).as_str())
        .with_status(403)
        .with_body("Forbidden - signed URL expired")
        .expect(1)
        .create_async()
        .await;

    let _fresh_blob_mock = server
        .mock("GET", format!("/blobs/fresh/{}", blob_a).as_str())
        .with_status(200)
        .with_body("fresh-a")
        .expect(2)
        .create_async()
        .await;

    let _good_blob_mock = server
        .mock("GET", format!("/blobs/good/{}", blob_b).as_str())
        .with_status(200)
        .with_body("good-b")
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let manifest_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/img/manifests/latest")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(manifest_response.status(), StatusCode::OK);

    let app = build_router(state);
    let blob_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_a}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(blob_response.status(), StatusCode::OK);
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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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
async fn test_blob_head_and_get_return_local_finalized_upload_session() {
    let server = Server::new_async().await;
    let (state, temp_home, _guard) = setup(&server).await;

    let blob_content = b"local-uploaded-blob";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let temp_path = temp_home.path().join("uploaded-blob");
    tokio::fs::write(&temp_path, blob_content).await.unwrap();

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "upload-local".to_string(),
            name: "my-cache".to_string(),
            temp_path,
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: blob_content.len() as u64,
            finalized_digest: Some(blob_digest.clone()),
            finalized_size: Some(blob_content.len() as u64),
            created_at: Instant::now(),
        });
    }

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(head_response.status(), StatusCode::OK);
    assert_eq!(
        head_response
            .headers()
            .get("Content-Length")
            .and_then(|value| value.to_str().ok()),
        Some(blob_content.len().to_string().as_str())
    );

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(get_response.status(), StatusCode::OK);
    let body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], blob_content);
}

#[tokio::test]
async fn test_blob_head_after_manifest_resolution_uses_remote_existence_check() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let blob_size = 23u64;
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, blob_size)]);
    let tag = ref_tag("img", "v1");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-head-check",
                "manifest_url": format!("{}/pointers/entry-head-check", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-head-check")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
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
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let manifest_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri("/v2/img/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(manifest_response.status(), StatusCode::OK);

    let app = build_router(state);
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(head_response.status(), StatusCode::OK);
    assert_eq!(
        head_response
            .headers()
            .get("Content-Length")
            .and_then(|value| value.to_str().ok()),
        Some(blob_size.to_string().as_str())
    );
}

#[tokio::test]
async fn test_blob_head_degrades_remote_check_failures_to_404() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "img",
            blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-head-failure".to_string(),
                size_bytes: 42,
                download_url: None,
                download_url_cached_at: None,
            },
        );
    }

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend failure"}"#)
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
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
        .expect(1)
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

    let app = build_router(state.clone());
    let first_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(
        first_response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        blob_digest
    );
    assert_eq!(
        first_response.headers().get("Content-Type").unwrap(),
        "application/octet-stream"
    );

    let first_body = first_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&first_body[..], blob_content);

    let app = build_router(state.clone());
    let second_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = second_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&second_body[..], blob_content);
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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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
async fn test_manifest_put_confirms_alias_when_alias_save_exists() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = ref_tag("my-cache", "main");
    let alias_tag = digest_tag(&manifest_digest);

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": primary_tag,
                "cache_entry_id": "entry-primary",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "manifest_upload_url": format!("{}/uploads/entry-primary-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_mock = server
        .mock("GET", primary_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "cache_entry_id": "entry-primary",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_confirm_mock = server
        .mock("PUT", primary_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "3")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let alias_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": alias_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": alias_tag,
                "cache_entry_id": "entry-alias",
                "exists": true,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&alias_tag)
    );
    let alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&alias_tag)
    );
    let alias_pointer_mock = server
        .mock("GET", alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "5",
                "cache_entry_id": "entry-alias",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let alias_confirm_mock = server
        .mock("PUT", alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "5")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "5",
                "status": "ok",
                "cache_entry_id": "entry-alias"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    alias_save_mock.assert_async().await;
    alias_pointer_mock.assert_async().await;
    alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_by_digest_binds_latest_alias() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = digest_tag(&manifest_digest);
    let latest_alias_tag = ref_tag("my-cache", "latest");

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": primary_tag,
                "cache_entry_id": "entry-primary",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "manifest_upload_url": format!("{}/uploads/entry-primary-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_mock = server
        .mock("GET", primary_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "cache_entry_id": "entry-primary",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_confirm_mock = server
        .mock("PUT", primary_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "3")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let latest_alias_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": latest_alias_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": latest_alias_tag,
                "cache_entry_id": "entry-latest",
                "exists": true,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let latest_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&latest_alias_tag)
    );
    let latest_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&latest_alias_tag)
    );
    let latest_alias_pointer_mock = server
        .mock("GET", latest_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "4",
                "cache_entry_id": "entry-latest",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let latest_alias_confirm_mock = server
        .mock("PUT", latest_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "4")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "4",
                "status": "ok",
                "cache_entry_id": "entry-latest"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/manifests/{manifest_digest}"))
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    latest_alias_save_mock.assert_async().await;
    latest_alias_pointer_mock.assert_async().await;
    latest_alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_fails_on_alias_error_in_strict_mode() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.configured_human_tags = vec!["human-alias".to_string()];
    state.fail_on_cache_error = true;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = ref_tag("my-cache", "main");
    let digest_alias_tag = digest_tag(&manifest_digest);

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": primary_tag,
                "cache_entry_id": "entry-primary",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "manifest_upload_url": format!("{}/uploads/entry-primary-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_mock = server
        .mock("GET", primary_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "cache_entry_id": "entry-primary",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_confirm_mock = server
        .mock("PUT", primary_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "3")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let digest_alias_save_error_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": digest_alias_tag
            }
        })))
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "INTERNAL_ERROR");

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    digest_alias_save_error_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_best_effort_skips_alias_error() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.configured_human_tags = vec!["human-alias".to_string()];
    state.fail_on_cache_error = false;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = ref_tag("my-cache", "main");
    let digest_alias_tag = digest_tag(&manifest_digest);

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": primary_tag,
                "cache_entry_id": "entry-primary",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "manifest_upload_url": format!("{}/uploads/entry-primary-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_mock = server
        .mock("GET", primary_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "cache_entry_id": "entry-primary",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_confirm_mock = server
        .mock("PUT", primary_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "3")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let digest_alias_save_error_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": digest_alias_tag
            }
        })))
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .expect(1)
        .create_async()
        .await;

    let human_alias_tag = "human-alias";
    let human_alias_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": human_alias_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": human_alias_tag,
                "cache_entry_id": "entry-human-alias",
                "exists": true,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let human_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(human_alias_tag)
    );
    let human_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(human_alias_tag)
    );
    let human_alias_pointer_mock = server
        .mock("GET", human_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "5",
                "cache_entry_id": "entry-human-alias",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let human_alias_confirm_mock = server
        .mock("PUT", human_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "5")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "5",
                "status": "ok",
                "cache_entry_id": "entry-human-alias"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    digest_alias_save_error_mock.assert_async().await;
    human_alias_save_mock.assert_async().await;
    human_alias_pointer_mock.assert_async().await;
    human_alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_rejects_invalid_blob_digest() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let manifest_body = br#"{
        "schemaVersion": 2,
        "config": {
            "digest": "sha256:not-a-valid-digest",
            "size": 123
        },
        "layers": []
    }"#;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body.to_vec()))
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

    let app = build_router(state.clone());
    let status_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(status_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        status_response
            .headers()
            .get("Docker-Upload-UUID")
            .and_then(|value| value.to_str().ok()),
        Some(uuid.as_str())
    );
    assert_eq!(
        status_response
            .headers()
            .get("Range")
            .and_then(|value| value.to_str().ok()),
        Some("0-0")
    );

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
async fn test_put_upload_body_stream_error_returns_internal_error() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let start = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = start
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let digest = cas_oci::prefixed_sha256_digest(b"stream-error");
    let stream = futures_util::stream::once(async {
        let err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
        Err::<axum::body::Bytes, std::io::Error>(err)
    });

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .body(Body::from_stream(stream))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "INTERNAL_ERROR");
    assert!(parsed["errors"][0]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("body stream error"));
}

#[tokio::test]
async fn test_patch_retry_with_same_content_range_is_idempotent() {
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

    let blob_data = b"retry-safe-blob";
    let range = format!("0-{}", blob_data.len() - 1);
    let app = build_router(state.clone());
    let first_patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", range.clone())
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(first_patch.status(), StatusCode::ACCEPTED);

    let app = build_router(state.clone());
    let retry_patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", range)
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(retry_patch.status(), StatusCode::ACCEPTED);

    let digest = cas_oci::prefixed_sha256_digest(blob_data);
    let app = build_router(state.clone());
    let finalize = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finalize.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_put_upload_uses_content_range_offset() {
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

    let prefix = b"hello ";
    let suffix = b"world";
    let app = build_router(state.clone());
    let patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", "0-5")
            .body(Body::from(prefix.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(patch.status(), StatusCode::ACCEPTED);

    let full_blob = b"hello world";
    let digest = cas_oci::prefixed_sha256_digest(full_blob);
    let app = build_router(state.clone());
    let finalize = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .header("Content-Range", "6-10")
            .body(Body::from(suffix.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finalize.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_put_upload_rewrites_when_put_body_digest_matches() {
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

    let stale_blob = b"this-is-an-older-and-longer-blob";
    let app = build_router(state.clone());
    let patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", format!("0-{}", stale_blob.len() - 1))
            .body(Body::from(stale_blob.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(patch.status(), StatusCode::ACCEPTED);

    let final_blob = b"final-v1";
    let digest = cas_oci::prefixed_sha256_digest(final_blob);
    let app = build_router(state.clone());
    let finalize = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .header("Content-Range", format!("0-{}", final_blob.len() - 1))
            .body(Body::from(final_blob.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finalize.status(), StatusCode::CREATED);
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
    assert_eq!(
        response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok()),
        Some(format!("/v2/my-cache/blobs/{digest}").as_str())
    );
}

#[tokio::test]
async fn test_large_monolithic_upload_over_two_megabytes() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_data = vec![b'x'; 3 * 1024 * 1024];
    let digest = cas_oci::prefixed_sha256_digest(&blob_data);

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v2/my-cache/blobs/uploads/?digest={digest}"))
            .body(Body::from(blob_data))
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
    assert_eq!(
        response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok()),
        Some(format!("/v2/my-cache/blobs/{digest}").as_str())
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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
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
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
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

#[tokio::test]
async fn test_blob_proxy_best_effort_returns_404_on_storage_failure() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 100)]);
    let tag = ref_tag("img", "v1");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
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

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
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

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
}

#[tokio::test]
async fn test_cache_registry_best_effort_returns_miss_on_backend_error() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/cache/cache-key-1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_bazel_cas_put_head_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let payload = b"bazel-cas-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let bazel_key = payload_digest
        .strip_prefix("sha256:")
        .expect("sha256 prefix present");
    let pointer_bytes = make_file_pointer(&payload_digest, payload.len() as u64);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "unused",
                "cache_entry_id": "entry-bazel-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "manifest_upload_url": format!("{}/manifest-upload", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-upload", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload")
        .match_body(Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    let _pointer_mock = server
        .mock(
            "GET",
            "/v2/workspaces/org/repo/caches/tags/registry/pointer",
        )
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "9",
                "cache_entry_id": "entry-bazel-kv",
                "status": "ready"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .match_header("if-match", "9")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "9",
                "status": "confirmed",
                "cache_entry_id": "entry-bazel-kv"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/cas/{bazel_key}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let _restore_head_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-bazel-kv",
                "manifest_url": format!("{}/pointer-download", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_head_mock = server
        .mock("GET", "/pointer-download")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/cas/{bazel_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let expected_content_length = payload.len().to_string();
    assert_eq!(
        head_response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_content_length.as_str())
    );
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

    let _restore_get_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-bazel-kv",
                "manifest_url": format!("{}/pointer-download-get", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-get")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{bazel_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_sccache_mkcol_is_noop_success() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::from_bytes(b"MKCOL").unwrap())
            .uri("/prefix/0/1/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_sccache_put_head_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload = b"sccache-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_bytes = make_file_pointer(&payload_digest, payload.len() as u64);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "unused",
                "cache_entry_id": "entry-sccache-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "manifest_upload_url": format!("{}/manifest-upload-sccache", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-upload-sccache", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-sccache")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-sccache")
        .match_body(Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    let _pointer_mock = server
        .mock(
            "GET",
            "/v2/workspaces/org/repo/caches/tags/registry/pointer",
        )
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "11",
                "cache_entry_id": "entry-sccache-kv",
                "status": "ready"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .match_header("if-match", "11")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "11",
                "status": "confirmed",
                "cache_entry_id": "entry-sccache-kv"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/{key_path}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::CREATED);

    let _restore_head_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-sccache-kv",
                "manifest_url": format!("{}/pointer-download-sccache", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_head_mock = server
        .mock("GET", "/pointer-download-sccache")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let expected_content_length = payload.len().to_string();
    assert_eq!(
        head_response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_content_length.as_str())
    );
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

    let _restore_get_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-sccache-kv",
                "manifest_url": format!("{}/pointer-download-sccache-get", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-sccache-get")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-sccache", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-sccache")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_sccache_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let key_path =
        "cache-prefix/0/1/2/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_sccache_miss_is_temporarily_cached_to_reduce_backend_lookups() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload_digest = cas_file::prefixed_sha256_digest(b"unrelated");
    let pointer = cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: vec![cas_file::FilePointerEntry {
            path: "sccache/other-key".to_string(),
            entry_type: EntryType::File,
            size_bytes: 9,
            executable: None,
            target: None,
            digest: Some(payload_digest.clone()),
        }],
        blobs: vec![cas_file::FilePointerBlob {
            digest: payload_digest,
            size_bytes: 9,
            sequence: None,
        }],
    };
    let pointer_bytes = serde_json::to_vec(&pointer).expect("pointer");

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-sccache-kv",
                "manifest_url": format!("{}/pointer-miss-sccache", server.url()),
                "manifest_root_digest": cas_file::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointer-miss-sccache")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let first_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(first_response.status(), StatusCode::NOT_FOUND);

    let app = build_router(state);
    let second_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(second_response.status(), StatusCode::NOT_FOUND);

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
}

#[tokio::test]
async fn test_bazel_route_rejects_invalid_digest() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/ac/not-a-sha256")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_bazel_put_rejects_digest_key_mismatch() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/cas/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .body(Body::from("mismatched-bazel-payload"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_bazel_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/ac/{digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_gradle_put_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let cache_key = "1234abcd";
    let payload = b"gradle-cache-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_bytes = make_file_pointer(&payload_digest, payload.len() as u64);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "unused",
                "cache_entry_id": "entry-gradle-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "manifest_upload_url": format!("{}/manifest-upload-gradle", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-upload-gradle", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-gradle")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-gradle")
        .match_body(Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    let _pointer_mock = server
        .mock(
            "GET",
            "/v2/workspaces/org/repo/caches/tags/registry/pointer",
        )
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "13",
                "cache_entry_id": "entry-gradle-kv",
                "status": "ready"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .match_header("if-match", "13")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "13",
                "status": "confirmed",
                "cache_entry_id": "entry-gradle-kv"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/cache/{cache_key}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let _restore_get_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-gradle-kv",
                "manifest_url": format!("{}/pointer-download-gradle", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-gradle")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-gradle", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-gradle")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cache/{cache_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_gradle_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/cache/test-key")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_maven_put_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let cache_key = "v1.1/com.example/app/abcdef1234567890/buildinfo.xml";
    let payload = b"maven-cache-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_bytes = make_file_pointer(&payload_digest, payload.len() as u64);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "unused",
                "cache_entry_id": "entry-maven-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "manifest_upload_url": format!("{}/manifest-upload-maven", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-upload-maven", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-maven")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-maven")
        .match_body(Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    let _pointer_mock = server
        .mock(
            "GET",
            "/v2/workspaces/org/repo/caches/tags/registry/pointer",
        )
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "13",
                "cache_entry_id": "entry-maven-kv",
                "status": "ready"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .match_header("if-match", "13")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "13",
                "status": "confirmed",
                "cache_entry_id": "entry-maven-kv"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/{cache_key}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let _restore_get_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-maven-kv",
                "manifest_url": format!("{}/pointer-download-maven", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-maven")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-maven", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-maven")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/{cache_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

    let _restore_get_mock_second = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-maven-kv",
                "manifest_url": format!("{}/pointer-download-maven-2", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock_second = server
        .mock("GET", "/pointer-download-maven-2")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let _download_urls_mock_second = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-maven-2", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock_second = server
        .mock("GET", "/blob-download-maven-2")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{cache_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_maven_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/v1.1/com.example/app/abcdef1234567890/buildinfo.xml")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_nx_requires_bearer_auth() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v1/cache/hash1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_nx_put_head_get_round_trip() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxhash123";
    let payload = b"nx-cache-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let expected_content_length = payload.len().to_string();
    assert_eq!(
        head_response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_content_length.as_str())
    );

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_nx_query_returns_misses() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxtaskhash1";
    let payload = b"nx-query-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);
    {
        let mut published = state.kv_published_index.write().await;
        published.set_empty();
    }

    let app = build_router(state);
    let query_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v1/cache")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "hashes": [hash, "deadbeef"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(query_response.status(), StatusCode::OK);
    let body = query_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["misses"], json!(["deadbeef"]));
}

#[tokio::test]
async fn test_go_cache_put_head_get_round_trip() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let action = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let payload = b"go-cache-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/gocache/{action}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::CREATED);

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/gocache/{action}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let expected_content_length = payload.len().to_string();
    assert_eq!(
        head_response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_content_length.as_str())
    );

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/gocache/{action}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_go_cache_rejects_invalid_action_id() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/gocache/not-hex")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_turborepo_status_requires_bearer_auth() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let unauth = tower::ServiceExt::oneshot(
        app.clone(),
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    let auth = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/status")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(auth.status(), StatusCode::OK);
    let body = auth.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["status"], "enabled");
}

#[tokio::test]
async fn test_turborepo_status_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts/status")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_turborepo_status_rejects_invalid_bearer_header() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/status")
            .header("authorization", "token only")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_turborepo_query_requires_bearer_auth() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "hashes": ["a1b2"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_turborepo_query_rejects_invalid_payload() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from("not-json"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_turborepo_put_head_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "aabbcc1234";
    let payload = b"turbo-cache-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_bytes = make_file_pointer(&payload_digest, payload.len() as u64);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "unused",
                "cache_entry_id": "entry-turbo-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "manifest_upload_url": format!("{}/manifest-upload-turbo", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-upload-turbo", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-turbo")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-turbo")
        .match_body(Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    let _pointer_mock = server
        .mock(
            "GET",
            "/v2/workspaces/org/repo/caches/tags/registry/pointer",
        )
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "15",
                "cache_entry_id": "entry-turbo-kv",
                "status": "ready"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .match_header("if-match", "15")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "15",
                "status": "confirmed",
                "cache_entry_id": "entry-turbo-kv"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v8/artifacts/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::ACCEPTED);
    let put_body = put_response.into_body().collect().await.unwrap().to_bytes();
    let put_json: serde_json::Value = serde_json::from_slice(&put_body).unwrap();
    assert_eq!(put_json["urls"], json!([]));

    let _restore_head_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-turbo-kv",
                "manifest_url": format!("{}/pointer-download-turbo", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_head_mock = server
        .mock("GET", "/pointer-download-turbo")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v8/artifacts/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);

    let _restore_get_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-turbo-kv",
                "manifest_url": format!("{}/pointer-download-turbo-get", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-turbo-get")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-turbo", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-turbo")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v8/artifacts/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_turborepo_artifact_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/v8/artifacts/aabbcc")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_turborepo_query_artifacts_returns_metadata_map() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let digest_a = format!("sha256:{}", "a".repeat(64));
    let digest_b = format!("sha256:{}", "b".repeat(64));
    let pointer = cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: vec![
            cas_file::FilePointerEntry {
                path: "turbo/a1b2".to_string(),
                entry_type: EntryType::File,
                size_bytes: 11,
                executable: None,
                target: None,
                digest: Some(digest_a.clone()),
            },
            cas_file::FilePointerEntry {
                path: "turbo/c3d4".to_string(),
                entry_type: EntryType::File,
                size_bytes: 17,
                executable: None,
                target: None,
                digest: Some(digest_b.clone()),
            },
        ],
        blobs: vec![
            cas_file::FilePointerBlob {
                digest: digest_a,
                size_bytes: 11,
                sequence: None,
            },
            cas_file::FilePointerBlob {
                digest: digest_b,
                size_bytes: 17,
                sequence: None,
            },
        ],
    };
    let pointer_bytes = serde_json::to_vec(&pointer).unwrap();
    let manifest_url = format!("{}/pointer/registry", server.url());

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": "registry",
                    "status": "hit",
                    "cache_entry_id": "entry-turbo-index",
                    "manifest_url": manifest_url,
                    "storage_mode": "cas",
                    "cas_layout": "file-v1",
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointer/registry")
        .with_status(200)
        .with_header("content-type", "application/cbor")
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "hashes": ["a1b2", "c3d4"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["a1b2"]["size"], 11);
    assert_eq!(parsed["c3d4"]["size"], 17);
    assert_eq!(parsed["a1b2"]["taskDurationMs"], 0);
}

#[tokio::test]
async fn test_turborepo_events_accepts_post_with_bearer() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts/events")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!([
                    {
                        "sessionId": "abc",
                        "source": "REMOTE",
                        "event": "HIT",
                        "hash": "hash-a",
                        "duration": 12
                    }
                ])
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_turborepo_events_rejects_get() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/events")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_tag_pointer_returns_cache_entry_id() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_header("etag", "\"42\"")
        .with_body(
            serde_json::to_string(&json!({
                "tag": "registry",
                "cache_entry_id": "entry-abc-123",
                "manifest_root_digest": "sha256:aaa",
                "version": "42"
            }))
            .unwrap(),
        )
        .create_async()
        .await;

    use boring_cache_cli::api::client::TagPointerPollResult;
    let result = _state
        .api_client
        .tag_pointer(&_state.workspace, "registry", None)
        .await
        .expect("tag_pointer should succeed");

    match result {
        TagPointerPollResult::Changed { pointer, etag } => {
            assert_eq!(pointer.cache_entry_id.as_deref(), Some("entry-abc-123"));
            assert_eq!(pointer.manifest_root_digest.as_deref(), Some("sha256:aaa"));
            assert_eq!(etag.as_deref(), Some("\"42\""));
        }
        other => panic!("Expected Changed, got {:?}", other),
    }

    pointer_mock.assert_async().await;
}

#[tokio::test]
async fn test_tag_pointer_returns_not_modified_on_304() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .match_header("If-None-Match", "\"42\"")
        .with_status(304)
        .create_async()
        .await;

    use boring_cache_cli::api::client::TagPointerPollResult;
    let result = _state
        .api_client
        .tag_pointer(&_state.workspace, "registry", Some("\"42\""))
        .await
        .expect("tag_pointer should succeed");

    assert!(matches!(result, TagPointerPollResult::NotModified));
    pointer_mock.assert_async().await;
}

#[tokio::test]
async fn test_tag_pointer_returns_not_found_on_404() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .with_status(404)
        .with_body("{\"error\": \"not found\"}")
        .create_async()
        .await;

    use boring_cache_cli::api::client::TagPointerPollResult;
    let result = _state
        .api_client
        .tag_pointer(&_state.workspace, "registry", None)
        .await
        .expect("tag_pointer should succeed");

    assert!(matches!(result, TagPointerPollResult::NotFound));
    pointer_mock.assert_async().await;
}
