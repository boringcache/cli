use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use boring_cache_cli::api::client::ApiClient;
use boring_cache_cli::api::models::cache::BlobDescriptor;
use boring_cache_cli::cas_file;
use boring_cache_cli::cas_oci;
use boring_cache_cli::git::GitContext;
use boring_cache_cli::manifest::EntryType;
use boring_cache_cli::serve::routes::build_router;
use boring_cache_cli::serve::state::{
    AppState, BlobLocatorCache, BlobLocatorEntry, BlobReadCache, BlobReadMetrics, KvPendingStore,
    KvPublishedIndex, OciManifestCacheEntry, UploadSession, UploadSessionStore, digest_tag,
    ref_tag,
};
use boring_cache_cli::tag_utils::TagResolver;
use boring_cache_cli::test_env;
use http_body_util::BodyExt;
use mockito::{Matcher, Server};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

static ORIGINAL_TMPDIR: std::sync::LazyLock<Option<String>> =
    std::sync::LazyLock::new(|| std::env::var("TMPDIR").ok());

async fn wait_for_prefetch_state(client: &reqwest::Client, base_url: &str, expected: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let response = client
            .get(format!("{base_url}/v2/"))
            .send()
            .await
            .expect("get request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        if response
            .headers()
            .get("X-BoringCache-Prefetch-State")
            .and_then(|value| value.to_str().ok())
            == Some(expected)
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "proxy did not reach prefetch state {expected} within 10s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn assert_json_error(response: &serde_json::Value, code: &str) {
    assert_eq!(response["code"], code);
    assert_eq!(response["error"]["code"], code);
    assert!(response["message"].is_string());
    assert!(response["error"]["message"].is_string());
}

fn assert_digest_etag(headers: &HeaderMap, digest: &str) {
    let etag = headers
        .get("ETag")
        .and_then(|value| value.to_str().ok())
        .expect("ETag header");
    assert_eq!(etag, format!("\"{digest}\""));
}

async fn setup(server: &Server) -> (AppState, tempfile::TempDir, test_env::Guard) {
    let guard = test_env::lock();
    let _ = *ORIGINAL_TMPDIR;
    match ORIGINAL_TMPDIR.as_deref() {
        Some(orig) => test_env::set_var("TMPDIR", orig),
        None => test_env::remove_var("TMPDIR"),
    }
    let temp_home = tempfile::tempdir().expect("temp dir");
    test_env::set_var("HOME", temp_home.path());
    test_env::set_var("TMPDIR", temp_home.path());
    test_env::set_var("BORINGCACHE_API_URL", server.url());
    test_env::set_var("BORINGCACHE_AUTH_TOKEN", "test-token");
    test_env::set_var("BORINGCACHE_TEST_MODE", "1");
    test_env::remove_var("BORINGCACHE_MAX_SPOOL_BYTES");

    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("API client");
    let (kv_replication_work_tx, _kv_replication_work_rx) = tokio::sync::mpsc::channel(
        boring_cache_cli::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY,
    );

    let state = AppState {
        api_client,
        workspace: "org/repo".to_string(),
        runtime_temp_dir: temp_home.path().join("proxy-runtime"),
        kv_blob_temp_dir: temp_home.path().join("proxy-runtime/kv-blobs"),
        oci_upload_temp_dir: temp_home.path().join("proxy-runtime/oci-uploads"),
        read_only: false,
        tag_resolver: TagResolver::new(None, GitContext::default(), false),
        configured_human_tags: Vec::new(),
        registry_root_tag: "registry".to_string(),
        fail_on_cache_error: true,
        oci_hydration_policy: boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(Mutex::new(())),
        kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        oci_lookup_inflight: Arc::new(dashmap::DashMap::new()),
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
        blob_read_metrics: Arc::new(BlobReadMetrics::new()),
        oci_body_metrics: Arc::new(boring_cache_cli::serve::state::OciBodyMetrics::new()),
        oci_engine_diagnostics: Arc::new(
            boring_cache_cli::serve::state::OciEngineDiagnostics::new(),
        ),
        prefetch_metrics: Arc::new(boring_cache_cli::serve::state::PrefetchMetrics::new()),
        blob_download_max_concurrency: 16,
        blob_download_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        blob_prefetch_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
        cache_ops: Arc::new(boring_cache_cli::serve::cache_registry::cache_ops::Aggregator::new()),
        oci_manifest_cache: Arc::new(dashmap::DashMap::new()),
        backend_breaker: Arc::new(boring_cache_cli::serve::state::BackendCircuitBreaker::new()),
        prefetch_complete: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        prefetch_complete_notify: Arc::new(tokio::sync::Notify::new()),
        prefetch_error: Arc::new(RwLock::new(None)),
    };

    (state, temp_home, guard)
}

fn scoped_ref_tag(name: &str, reference: &str) -> String {
    ref_tag("registry", &format!("{name}:{reference}"))
}

fn make_pointer(index_json: &[u8], blobs: &[(&str, u64)]) -> Vec<u8> {
    let pointer = cas_oci::OciPointer {
        format_version: 1,
        adapter: "oci-v1".to_string(),
        manifest_content_type: None,
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
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();

    wait_for_prefetch_state(&client, &base_url, "ready").await;

    handle.shutdown_and_flush().await.expect("shutdown proxy");
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_command_proxy_start_continues_when_warmup_fails() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_SAVE_TOKEN", "test-token");

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect_at_least(1)
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"boom"}"#)
        .create_async()
        .await;

    let handle = boring_cache_cli::commands::cache_registry::start_proxy_background(
        "org/repo".to_string(),
        "main".to_string(),
        "127.0.0.1".to_string(),
        0,
        false,
        false,
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        None,
        BTreeMap::new(),
        true,
        true,
        false,
    )
    .await
    .expect("start proxy");

    handle.shutdown_and_flush().await.expect("shutdown proxy");
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_v2_returns_200_with_warming_header_before_prefetch_complete() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);
    let app = build_router(state.clone());

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
            .get("X-BoringCache-Prefetch-State")
            .unwrap(),
        "warming"
    );
}

#[tokio::test]
async fn test_kv_reads_wait_for_startup_prefetch_completion() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);

    let payload = b"warm-local-payload";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("blob cache insert");
    {
        let mut published = state.kv_published_index.write().await;
        published.update(
            std::collections::HashMap::from([(
                "gradle/cache-key-1".to_string(),
                BlobDescriptor {
                    digest: digest.clone(),
                    size_bytes: payload.len() as u64,
                },
            )]),
            vec![BlobDescriptor {
                digest: digest.clone(),
                size_bytes: payload.len() as u64,
            }],
            "entry-prefetched".to_string(),
        );
    }

    let app = build_router(state.clone());
    let request_task = tokio::spawn(async move {
        tower::ServiceExt::oneshot(
            app,
            Request::builder()
                .uri("/foo/cache/cache-key-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request")
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !request_task.is_finished(),
        "KV GET should wait while startup prefetch is still warming"
    );

    state
        .prefetch_complete
        .store(true, std::sync::atomic::Ordering::Release);
    state.prefetch_complete_notify.notify_waiters();

    let response = request_task.await.expect("join");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_startup_prefetch_hydrates_full_tag_before_ready() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

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
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

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
                "cache_entry_id": "entry-full-hydration",
                "manifest_url": format!("{}/pointers/entry-full-hydration", server.url()),
                "manifest_root_digest": cas_file::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-full-hydration")
        .expect_at_least(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect_at_least(1)
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
    let cold_blob_mock = server
        .mock("GET", format!("/blobs/{}", digest_c).as_str())
        .expect(1)
        .with_status(200)
        .with_body(cold_blob)
        .create_async()
        .await;
    let pointer_visibility_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            serde_json::to_string(&json!({
                "tag": "registry",
                "cache_entry_id": "entry-full-hydration",
                "manifest_root_digest": pointer_digest,
                "version": "1"
            }))
            .unwrap(),
        )
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
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();

    wait_for_prefetch_state(&client, &base_url, "ready").await;

    warm_blob_a_mock.assert_async().await;
    warm_blob_b_mock.assert_async().await;
    cold_blob_mock.assert_async().await;

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
    pointer_visibility_mock.assert_async().await;
}

#[tokio::test]
async fn test_startup_prefetch_partial_blob_failure_does_not_block_readiness() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let warm_blob = b"warm";
    let cold_blob = b"cold";
    let warm_digest = cas_oci::prefixed_sha256_digest(warm_blob);
    let cold_digest = cas_oci::prefixed_sha256_digest(cold_blob);
    let warm_key = warm_digest.strip_prefix("sha256:").unwrap();
    let cold_key = cold_digest.strip_prefix("sha256:").unwrap();
    let pointer_entries = vec![
        (
            format!("bazel_cas/{warm_key}"),
            warm_digest.clone(),
            warm_blob.len() as u64,
        ),
        (
            format!("bazel_cas/{cold_key}"),
            cold_digest.clone(),
            cold_blob.len() as u64,
        ),
    ];
    let pointer_bytes = make_kv_pointer(&pointer_entries);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

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
                "cache_entry_id": "entry-partial-hydration",
                "manifest_url": format!("{}/pointers/entry-partial-hydration", server.url()),
                "manifest_root_digest": cas_file::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-partial-hydration")
        .expect_at_least(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect_at_least(1)
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [
                    {
                        "digest": warm_digest,
                        "url": format!("{}/blobs/{}", server.url(), warm_digest),
                    },
                    {
                        "digest": cold_digest,
                        "url": format!("{}/blobs/{}", server.url(), cold_digest),
                    }
                ],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let warm_blob_mock = server
        .mock("GET", format!("/blobs/{}", warm_digest).as_str())
        .expect_at_least(1)
        .with_status(200)
        .with_body(warm_blob)
        .create_async()
        .await;
    let cold_blob_mock = server
        .mock("GET", format!("/blobs/{}", cold_digest).as_str())
        .expect_at_least(1)
        .with_status(500)
        .with_body("temporary backend failure")
        .create_async()
        .await;
    let pointer_visibility_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            serde_json::to_string(&json!({
                "tag": "registry",
                "cache_entry_id": "entry-partial-hydration",
                "manifest_root_digest": pointer_digest,
                "version": "1"
            }))
            .unwrap(),
        )
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
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        false,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();
    wait_for_prefetch_state(&client, &base_url, "ready").await;

    let response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let status: serde_json::Value = response.json().await.expect("status json");
    assert_eq!(status["phase"], "ready");
    assert_eq!(status["prefetch_complete"], true);
    assert!(status["prefetch_error"].is_null());
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_total_unique_blobs"],
        "2"
    );
    assert_eq!(status["startup_prefetch"]["startup_prefetch_inserted"], "1");
    assert_eq!(status["startup_prefetch"]["startup_prefetch_failures"], "1");
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_cold_blobs"],
        "1"
    );

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    warm_blob_mock.assert_async().await;
    cold_blob_mock.assert_async().await;
    pointer_visibility_mock.assert_async().await;
}

#[tokio::test]
async fn test_oci_prefetch_ref_indexes_manifest_before_ready() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let blob_payload = b"oci-prefetched-blob";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_payload);
    let index_json = br#"{"schemaVersion":2,"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[(blob_digest.as_str(), blob_payload.len() as u64)],
    );
    let oci_tag = scoped_ref_tag("img", "v1");
    let legacy_oci_tag = ref_tag("img", "v1");
    let oci_entries_input = format!("{oci_tag},{legacy_oci_tag}");
    let oci_entries = urlencoding::encode(&oci_entries_input);

    let oci_restore_mock = server
        .mock(
            "GET",
            format!("/v2/workspaces/org/repo/caches?entries={oci_entries}").as_str(),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": oci_tag,
                "status": "hit",
                "cache_entry_id": "entry-oci-prefetch",
                "manifest_url": format!("{}/pointers/entry-oci-prefetch", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let kv_restore_mock = server
        .mock("GET", "/v2/workspaces/org/repo/caches?entries=registry")
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-oci-prefetch")
        .expect(1)
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

    let blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .expect(1)
        .with_status(200)
        .with_body(blob_payload)
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
        vec![("img".to_string(), "v1".to_string())],
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();
    wait_for_prefetch_state(&client, &base_url, "ready").await;

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request");
    assert_eq!(status_response.status(), reqwest::StatusCode::OK);
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(status["startup_prefetch"]["startup_prefetch_oci_refs"], "1");
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_total_unique_blobs"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_hydration"],
        "metadata-only"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_inserted"],
        "0"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_cold_blobs"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_body_cold_blobs"],
        "1"
    );

    let response = client
        .get(format!("{base_url}/v2/img/blobs/{blob_digest}"))
        .send()
        .await
        .expect("blob request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), blob_payload);

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request after blob read");
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(status["oci_body"]["oci_body_remote_fetches"], "1");
    assert_eq!(status["oci_body"]["oci_body_local_hits"], "0");

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    oci_restore_mock.assert_async().await;
    kv_restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_oci_prefetch_ref_can_hydrate_bodies_before_ready() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let blob_payload = b"oci-prefetched-blob-ready";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_payload);
    let index_json = br#"{"schemaVersion":2,"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[(blob_digest.as_str(), blob_payload.len() as u64)],
    );
    let oci_tag = scoped_ref_tag("img", "v1");
    let legacy_oci_tag = ref_tag("img", "v1");
    let oci_entries_input = format!("{oci_tag},{legacy_oci_tag}");
    let oci_entries = urlencoding::encode(&oci_entries_input);

    let oci_restore_mock = server
        .mock(
            "GET",
            format!("/v2/workspaces/org/repo/caches?entries={oci_entries}").as_str(),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": oci_tag,
                "status": "hit",
                "cache_entry_id": "entry-oci-prefetch-ready",
                "manifest_url": format!("{}/pointers/entry-oci-prefetch-ready", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let kv_restore_mock = server
        .mock("GET", "/v2/workspaces/org/repo/caches?entries=registry")
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-oci-prefetch-ready")
        .expect(1)
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

    let blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .expect(1)
        .with_status(200)
        .with_body(blob_payload)
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
        vec![("img".to_string(), "v1".to_string())],
        boring_cache_cli::serve::OciHydrationPolicy::BodiesBeforeReady,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();
    wait_for_prefetch_state(&client, &base_url, "ready").await;

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request");
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_hydration"],
        "bodies-before-ready"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_inserted"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_cold_blobs"],
        "0"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_body_inserted"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_body_cold_blobs"],
        "0"
    );

    let response = client
        .get(format!("{base_url}/v2/img/blobs/{blob_digest}"))
        .send()
        .await
        .expect("blob request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), blob_payload);

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request after blob read");
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(status["oci_body"]["oci_body_local_hits"], "1");
    assert_eq!(status["oci_body"]["oci_body_remote_fetches"], "0");

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    oci_restore_mock.assert_async().await;
    kv_restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_v2_base_returns_200() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state.clone());

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
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Prefetch-State")
            .unwrap(),
        "ready"
    );
}

#[tokio::test]
async fn test_proxy_status_reports_warming_phase() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("warming")
    );
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Publish-State")
            .and_then(|value| value.to_str().ok()),
        Some("settled")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "warming");
    assert_eq!(status["publish_state"], "settled");
    assert_eq!(status["publish_settled"], true);
    assert_eq!(status["pending_entries"], 0);
    assert_eq!(status["flush_in_progress"], false);
}

#[tokio::test]
async fn test_proxy_status_reports_error_phase() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);
    {
        let mut prefetch_error = state.prefetch_error.write().await;
        *prefetch_error = Some("cache index load failed".to_string());
    }
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("error")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "error");
    assert_eq!(status["prefetch_error"], "cache index load failed");
    assert_eq!(status["prefetch_complete"], false);
}

#[tokio::test]
async fn test_proxy_status_reports_pending_when_entries_buffered() {
    let server = Server::new_async().await;
    let (state, home, _guard) = setup(&server).await;
    let temp_path = home.path().join("pending-blob.bin");
    tokio::fs::write(&temp_path, b"pending-bytes")
        .await
        .expect("write pending blob");
    {
        let mut pending = state.kv_pending.write().await;
        pending.insert(
            "cas/example".to_string(),
            BlobDescriptor {
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size_bytes: 13,
            },
            temp_path,
        );
    }
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("ready")
    );
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Publish-State")
            .and_then(|value| value.to_str().ok()),
        Some("pending")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "ready");
    assert_eq!(status["publish_settled"], false);
    assert_eq!(status["pending_entries"], 1);
    assert_eq!(status["pending_blobs"], 1);
}

#[tokio::test]
async fn test_proxy_status_reports_draining_until_tags_are_visible() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .shutdown_requested
        .store(true, std::sync::atomic::Ordering::Release);
    {
        let mut published = state.kv_published_index.write().await;
        published.update(
            std::collections::HashMap::new(),
            Vec::new(),
            "entry-123".to_string(),
        );
    }

    let _pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .with_status(404)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("draining")
    );
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Publish-State")
            .and_then(|value| value.to_str().ok()),
        Some("pending")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "draining");
    assert_eq!(status["cache_entry_id"], "entry-123");
    assert_eq!(status["tags_visible"], false);
    assert_eq!(status["publish_settled"], false);
}

#[tokio::test]
async fn test_nonexistent_route_returns_404() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state.clone());

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
async fn test_unknown_protocol_put_route_returns_not_found() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state.clone());

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

    let download_urls_request = json!({
        "cache_entry_id": "entry-123",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_digest, "size_bytes": 5000}
        ]
    });
    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(download_urls_request))
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
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
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
    assert!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["schemaVersion"], 2);
}

#[tokio::test]
async fn test_manifest_misses_when_prefetch_batch_reports_missing_blobs() {
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

    let batch_request = json!({
        "cache_entry_id": "entry-123",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_digest, "size_bytes": 5000}
        ]
    });
    let _download_urls_batch_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(batch_request))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [],
                "missing": [blob_digest]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
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

    let locator = state.blob_locator.read().await;
    assert!(locator.get("my-cache", blob_digest).is_none());
}

#[tokio::test]
async fn test_manifest_serves_after_verified_blob_storage_preflight_in_best_effort() {
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

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
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

    let locator = state.blob_locator.read().await;
    let cached = locator.get("my-cache", blob_digest).expect("locator entry");
    let expected_url = format!("{}/blobs/{}", server.url(), blob_digest);
    assert_eq!(cached.cache_entry_id, "entry-storage-miss");
    assert_eq!(cached.download_url.as_deref(), Some(expected_url.as_str()));
}

#[tokio::test]
async fn test_cached_manifest_hit_returns_without_revalidation_in_best_effort() {
    let server = Server::new_async().await;
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
    });
    state
        .oci_manifest_cache
        .insert(tag.clone(), Arc::clone(&cached));
    state
        .oci_manifest_cache
        .insert(digest_tag(&manifest_digest), cached);

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

    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.oci_manifest_cache.get(&tag).is_some());
    assert!(
        state
            .oci_manifest_cache
            .get(&digest_tag(&manifest_digest))
            .is_some()
    );
}

#[tokio::test]
async fn test_cached_manifest_hit_keeps_locator_urls() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_content = b"cached-fast-blob";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let blob_size = blob_content.len() as u64;
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
            digest: blob_digest.clone(),
            size_bytes: blob_size,
        }],
        name: "cached-fast".to_string(),
        inserted_at: Instant::now(),
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
            &blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-cached-fast".to_string(),
                size_bytes: blob_size,
                download_url: Some(format!("{}/blobs/{}", server.url(), blob_digest)),
                download_url_cached_at: Some(Instant::now()),
            },
        );
    }

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(200)
        .with_body(blob_content)
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
async fn test_blob_get_refreshes_stale_locator_url_after_manifest_return() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_a_content = b"fresh-a";
    let blob_a = cas_oci::prefixed_sha256_digest(blob_a_content);
    let blob_b = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[
            (blob_a.as_str(), blob_a_content.len() as u64),
            (blob_b, 2048),
        ],
    );
    let tag = ref_tag("img", "latest");
    let batch_request = json!({
        "cache_entry_id": "entry-refresh",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_a, "size_bytes": blob_a_content.len() as u64},
            {"digest": blob_b, "size_bytes": 2048}
        ]
    });
    let single_request = json!({
        "cache_entry_id": "entry-refresh",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_a, "size_bytes": blob_a_content.len() as u64}
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
        .with_body(blob_a_content)
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
    let manifest_digest = response
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|value| value.to_str().ok())
        .expect("Docker-Content-Digest header")
        .to_string();
    assert_digest_etag(response.headers(), &manifest_digest);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_referrers_route_returns_empty_index_when_missing() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let subject_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let referrers_tag = ref_tag(
        "my-cache",
        "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": referrers_tag,
                "status": "miss",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/my-cache/referrers/{subject_digest}"))
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
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["schemaVersion"], 2);
    assert_eq!(
        parsed["mediaType"],
        "application/vnd.oci.image.index.v1+json"
    );
    assert_eq!(parsed["manifests"], json!([]));
}

#[tokio::test]
async fn test_referrers_route_filters_artifact_type() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let subject_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let reference = "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let index_json = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 123,
                "artifactType": "application/vnd.example.sbom.v1",
                "annotations": {
                    "org.example.kind": "sbom"
                }
            },
            {
                "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
                "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "size": 456,
                "artifactType": "application/vnd.example.signature.v1",
                "annotations": {
                    "org.example.kind": "signature"
                }
            }
        ]
    }))
    .unwrap();
    state.oci_manifest_cache.insert(
        ref_tag("my-cache", reference),
        Arc::new(OciManifestCacheEntry {
            index_json: index_json.clone(),
            content_type: "application/vnd.oci.image.index.v1+json".to_string(),
            manifest_digest: cas_oci::prefixed_sha256_digest(&index_json),
            cache_entry_id: "entry-referrers".to_string(),
            blobs: Vec::new(),
            name: "my-cache".to_string(),
            inserted_at: Instant::now(),
        }),
    );

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!(
                "/v2/my-cache/referrers/{subject_digest}?artifactType=application/vnd.example.signature.v1"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("OCI-Filters-Applied").unwrap(),
        "artifactType"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["manifests"][0]["artifactType"],
        "application/vnd.example.signature.v1"
    );
}

#[tokio::test]
async fn test_referrers_route_rejects_invalid_digest() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri("/v2/my-cache/referrers/not-a-digest")
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
async fn test_blob_unknown_without_manifest_returns_404() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let missing_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{missing_digest}"))
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
    assert_digest_etag(head_response.headers(), &blob_digest);
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
    assert_digest_etag(get_response.headers(), &blob_digest);
    let body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], blob_content);
}

#[tokio::test]
async fn test_blob_get_range_returns_partial_content_from_local_upload_session() {
    let server = Server::new_async().await;
    let (state, temp_home, _guard) = setup(&server).await;

    let blob_content = b"0123456789abcdef";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let temp_path = temp_home.path().join("uploaded-range-blob");
    tokio::fs::write(&temp_path, blob_content).await.unwrap();

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "upload-range-local".to_string(),
            name: "my-cache".to_string(),
            temp_path,
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: blob_content.len() as u64,
            finalized_digest: Some(blob_digest.clone()),
            finalized_size: Some(blob_content.len() as u64),
            created_at: Instant::now(),
        });
    }

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=2-6")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_digest_etag(response.headers(), &blob_digest);
    assert_eq!(response.headers().get("Accept-Ranges").unwrap(), "bytes");
    assert_eq!(
        response.headers().get("Content-Range").unwrap(),
        &format!("bytes 2-6/{}", blob_content.len())
    );
    assert_eq!(response.headers().get("Content-Length").unwrap(), "5");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], &blob_content[2..=6]);
}

#[tokio::test]
async fn test_blob_get_suffix_range_returns_partial_content_from_body_cache() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_content = b"suffix-range-body";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    state
        .blob_read_cache
        .insert(&blob_digest, blob_content)
        .await
        .expect("insert blob body");

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=-4")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers().get("Content-Range").unwrap(),
        &format!(
            "bytes {}-{}/{}",
            blob_content.len() - 4,
            blob_content.len() - 1,
            blob_content.len()
        )
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], &blob_content[blob_content.len() - 4..]);
}

#[tokio::test]
async fn test_blob_get_invalid_range_returns_416() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_content = b"range-error";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    state
        .blob_read_cache
        .insert(&blob_digest, blob_content)
        .await
        .expect("insert blob body");

    let response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=99-100")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers().get("Content-Range").unwrap(),
        &format!("bytes */{}", blob_content.len())
    );

    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics.get("oci_engine_range_invalid_responses"),
        Some(&"1".to_string())
    );

    let status_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(status_response.status(), StatusCode::OK);
    let body = status_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        status["oci_engine"]["oci_engine_range_invalid_responses"],
        "1"
    );
    assert_eq!(
        status["oci_engine"]["oci_engine_hydration_policy"],
        "metadata-only"
    );
}

#[tokio::test]
async fn test_blob_get_if_range_mismatch_ignores_range() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_content = b"if-range-body";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let other_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    state
        .blob_read_cache
        .insert(&blob_digest, blob_content)
        .await
        .expect("insert blob body");

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=0-3")
            .header("If-Range", format!("\"{other_digest}\""))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("Content-Range").is_none());
    assert_eq!(
        response.headers().get("Content-Length").unwrap(),
        &blob_content.len().to_string()
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
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

    let download_urls_request = json!({
        "cache_entry_id": "entry-head-check",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_digest, "size_bytes": blob_size}
        ]
    });
    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(download_urls_request))
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
        .expect(1)
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

    let blob_content = b"hello blob content";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[(blob_digest.as_str(), blob_content.len() as u64)],
    );
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
    assert_digest_etag(first_response.headers(), &blob_digest);
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
    assert_digest_etag(second_response.headers(), &blob_digest);
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
    let primary_tag = scoped_ref_tag("my-cache", "main");
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
    let manifest_digest = response
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|value| value.to_str().ok())
        .expect("Docker-Content-Digest header")
        .to_string();
    assert_digest_etag(response.headers(), &manifest_digest);
    assert_eq!(
        response
            .headers()
            .get("Docker-Distribution-API-Version")
            .unwrap(),
        "registry/2.0"
    );

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    alias_save_mock.assert_async().await;
    alias_pointer_mock.assert_async().await;
    alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_degrades_when_primary_confirm_is_locked() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let primary_tag = scoped_ref_tag("my-cache", "main");

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
        .with_status(423)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "tag is locked",
                "message": "tag is locked",
                "code": "tag_locked"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let manifest_digest = response
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|value| value.to_str().ok())
        .expect("Docker-Content-Digest header")
        .to_string();
    assert_digest_etag(response.headers(), &manifest_digest);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Cache-Degraded")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_skips_alias_when_confirm_is_locked() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = scoped_ref_tag("my-cache", "main");
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
                "exists": false,
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
        .with_status(423)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "tag is locked",
                "message": "tag is locked",
                "code": "tag_locked"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        response
            .headers()
            .get("X-BoringCache-Cache-Degraded")
            .is_none()
    );

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    alias_save_mock.assert_async().await;
    alias_pointer_mock.assert_async().await;
    alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_with_subject_emits_oci_subject_and_serves_referrers() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let subject_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let manifest_body = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
        "artifactType": "application/vnd.example.sbom.v1",
        "blobs": [],
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": subject_digest,
            "size": 123
        },
        "annotations": {
            "org.example.kind": "sbom"
        }
    }))
    .unwrap();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = scoped_ref_tag("my-cache", "main");

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
                "cache_entry_id": "entry-primary-subject",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "manifest_upload_url": format!("{}/uploads/entry-primary-subject-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-subject-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
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
                "cache_entry_id": "entry-primary-subject",
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
                "cache_entry_id": "entry-primary-subject"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let referrers_reference =
        "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let referrers_tag = scoped_ref_tag("my-cache", referrers_reference);
    let referrers_restore_miss_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": referrers_tag,
                "status": "miss"
            }])
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let referrers_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": referrers_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": referrers_tag,
                "cache_entry_id": "entry-referrers",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "manifest_upload_url": format!("{}/uploads/entry-referrers-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let referrers_pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-referrers-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let referrers_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&referrers_tag)
    );
    let referrers_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&referrers_tag)
    );
    let referrers_pointer_mock = server
        .mock("GET", referrers_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "7",
                "cache_entry_id": "entry-referrers",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let referrers_confirm_mock = server
        .mock("PUT", referrers_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "7")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "7",
                "status": "ok",
                "cache_entry_id": "entry-referrers"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header(
                "Content-Type",
                "application/vnd.oci.artifact.manifest.v1+json",
            )
            .body(Body::from(manifest_body.clone()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get("OCI-Subject").unwrap(),
        subject_digest
    );
    assert!(
        response
            .headers()
            .get("X-BoringCache-Cache-Degraded")
            .is_none()
    );

    let referrers_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/my-cache/referrers/{subject_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(referrers_response.status(), StatusCode::OK);
    let body = referrers_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["manifests"][0]["digest"],
        serde_json::Value::String(manifest_digest)
    );
    assert_eq!(
        parsed["manifests"][0]["artifactType"],
        "application/vnd.example.sbom.v1"
    );
    assert_eq!(
        parsed["manifests"][0]["annotations"]["org.example.kind"],
        "sbom"
    );

    primary_save_mock.assert_async().await;
    primary_pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    referrers_restore_miss_mock.assert_async().await;
    referrers_save_mock.assert_async().await;
    referrers_pointer_upload_mock.assert_async().await;
    referrers_pointer_mock.assert_async().await;
    referrers_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_by_digest_binds_latest_alias() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = digest_tag(&manifest_digest);
    let latest_alias_tag = scoped_ref_tag("my-cache", "latest");

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
async fn test_manifest_put_by_digest_rejects_mismatched_digest_reference() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri(
                "/v2/my-cache/manifests/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .body(Body::from(br#"{"schemaVersion":2}"#.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("\"DIGEST_INVALID\""));
}

#[tokio::test]
async fn test_manifest_put_rejects_invalid_json_body() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from("{not-json"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("\"MANIFEST_INVALID\""));
}

#[tokio::test]
async fn test_manifest_put_rejects_missing_blob_with_blob_unknown_even_in_best_effort_mode() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let missing_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let manifest_body = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": missing_digest,
            "size": 10
        },
        "layers": []
    })
    .to_string();

    let check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": missing_digest,
                "size_bytes": 10
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": missing_digest,
                    "exists": false
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .expect(0)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("X-BoringCache-Degraded").is_none());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
    assert_eq!(parsed["errors"][0]["detail"]["digest"], missing_digest);

    check_mock.assert_async().await;
    save_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_rejects_missing_artifact_blob_with_blob_unknown() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let missing_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let manifest_body = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
        "artifactType": "application/vnd.example.sbom.v1",
        "blobs": [{
            "mediaType": "application/vnd.example.sbom.v1+json",
            "digest": missing_digest,
            "size": 10
        }]
    })
    .to_string();

    let check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": missing_digest,
                "size_bytes": 10
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": missing_digest,
                    "exists": false
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .expect(0)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header(
                "Content-Type",
                "application/vnd.oci.artifact.manifest.v1+json",
            )
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
    assert_eq!(parsed["errors"][0]["detail"]["digest"], missing_digest);

    check_mock.assert_async().await;
    save_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_fails_on_alias_error_in_strict_mode() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.configured_human_tags = vec!["human-alias".to_string()];
    state.fail_on_cache_error = true;
    let capabilities_mock = server
        .mock("GET", "/v2/capabilities")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "features": {
                    "tag_publish_v2": true
                }
            })
            .to_string(),
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = scoped_ref_tag("my-cache", "main");
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
        .expect_at_least(1)
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
    capabilities_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_best_effort_skips_alias_error() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.configured_human_tags = vec!["human-alias".to_string()];
    state.fail_on_cache_error = false;
    let capabilities_mock = server
        .mock("GET", "/v2/capabilities")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "features": {
                    "tag_publish_v2": true
                }
            })
            .to_string(),
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = scoped_ref_tag("my-cache", "main");
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
        .expect_at_least(1)
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
    capabilities_mock.assert_async().await;
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
    assert!(
        parsed["errors"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("body stream error")
    );
}

#[tokio::test]
async fn test_patch_retry_with_stale_content_range_returns_416() {
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
            .header("Content-Range", &range)
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(retry_patch.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(retry_patch.headers().get("Range").unwrap(), range.as_str());

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
async fn test_put_upload_with_stale_content_range_returns_416() {
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
    assert_eq!(finalize.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        finalize.headers().get("Range").unwrap(),
        format!("0-{}", stale_blob.len() - 1).as_str()
    );
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
            "verify_storage": true,
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
async fn test_manifest_put_uses_remote_proof_after_empty_finalize_reuse() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _empty_finalize_check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
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
        .expect(1)
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

    let app = build_router(state.clone());
    let finalize_response = tower::ServiceExt::oneshot(
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
    assert_eq!(finalize_response.status(), StatusCode::CREATED);

    let descriptor_size = 10u64;
    let _descriptor_check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": descriptor_size
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
        .expect(1)
        .create_async()
        .await;

    let primary_tag = scoped_ref_tag("my-cache", "main");
    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag,
                "blob_count": 1,
                "blob_total_size_bytes": descriptor_size
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
                "blob_count": 1,
                "blob_total_size_bytes": descriptor_size,
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

    let blob_stage_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": descriptor_size
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [],
                "already_present": [blob_digest]
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

    let manifest_body = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": blob_digest,
            "size": descriptor_size
        },
        "layers": []
    })
    .to_string();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    primary_save_mock.assert_async().await;
    blob_stage_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
async fn test_sccache_prefixed_probe_is_noop_success() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/rust/ci/.sccache_check")
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
async fn test_sccache_get_reads_internal_root_tag_only() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.registry_root_tag = "bc_registry_root_v2_root-only".to_string();
    state.configured_human_tags = vec!["human-alias".to_string()];

    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload = b"sccache-root-only";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_bytes = make_kv_pointer(&[(
        format!("sccache/{key_path}"),
        payload_digest.clone(),
        payload.len() as u64,
    )]);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);
    let root_tag = state.registry_root_tag.clone();
    let root_entries = urlencoding::encode(&root_tag).into_owned();
    let alias_entries = urlencoding::encode("human-alias").into_owned();

    let root_restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(format!(
                "^/v2/workspaces/org/repo/caches\\?entries={root_entries}(&.*)?$"
            )),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": root_tag,
                "status": "hit",
                "cache_entry_id": "entry-sccache-root-only",
                "manifest_url": format!("{}/pointer-download-sccache-root-only", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let alias_restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(format!(
                "^/v2/workspaces/org/repo/caches\\?entries={alias_entries}(&.*)?$"
            )),
        )
        .expect(0)
        .with_status(500)
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointer-download-sccache-root-only")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-sccache-root-only", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let blob_download_mock = server
        .mock("GET", "/blob-download-sccache-root-only")
        .expect(1)
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), payload);

    root_restore_mock.assert_async().await;
    alias_restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_download_mock.assert_async().await;
}

#[tokio::test]
async fn test_sccache_concurrent_get_coalesces_blob_download() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload = vec![b'x'; 2 * 1024 * 1024];
    let payload_digest = cas_file::prefixed_sha256_digest(&payload);
    let pointer_bytes = make_kv_pointer(&[(
        format!("sccache/{key_path}"),
        payload_digest.clone(),
        payload.len() as u64,
    )]);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

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
                "cache_entry_id": "entry-sccache-coalesced",
                "manifest_url": format!("{}/pointer-download-sccache-coalesced", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointer-download-sccache-coalesced")
        .expect_at_least(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-sccache-coalesced", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let blob_download_mock = server
        .mock("GET", "/blob-download-sccache-coalesced")
        .expect(1)
        .with_status(200)
        .with_body(payload.clone())
        .create_async()
        .await;

    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap()
    };

    let (first, second) = tokio::join!(
        tower::ServiceExt::oneshot(build_router(state.clone()), request()),
        tower::ServiceExt::oneshot(build_router(state), request())
    );

    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);

    let first_body = first.into_body().collect().await.unwrap().to_bytes();
    let second_body = second.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(first_body.as_ref(), payload.as_slice());
    assert_eq!(second_body.as_ref(), payload.as_slice());

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_download_mock.assert_async().await;
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
async fn test_bazel_ac_put_keeps_action_result_payload_opaque() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/ac/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .body(Body::from("action-result-metadata-is-not-cas-bytes"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_bazel_cas_get_ignores_pending_digest_mismatch() {
    let server = Server::new_async().await;
    let (state, home, _guard) = setup(&server).await;

    let key = cas_file::prefixed_sha256_digest(b"expected-bazel-cas-payload")
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    let mismatched_payload = b"mismatched-pending-bazel-cas-payload";
    let mismatched_digest = cas_file::prefixed_sha256_digest(mismatched_payload);
    let temp_path = home.path().join("mismatched-pending-bazel-cas.bin");
    tokio::fs::write(&temp_path, mismatched_payload)
        .await
        .expect("write pending blob");
    {
        let mut pending = state.kv_pending.write().await;
        pending.insert(
            format!("bazel_cas/{key}"),
            BlobDescriptor {
                digest: mismatched_digest,
                size_bytes: mismatched_payload.len() as u64,
            },
            temp_path,
        );
    }
    {
        let mut published = state.kv_published_index.write().await;
        published.set_empty();
    }

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_bazel_cas_get_ignores_published_digest_mismatch() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = cas_file::prefixed_sha256_digest(b"expected-published-bazel-cas-payload")
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    let mismatched_payload = b"mismatched-published-bazel-cas-payload";
    let mismatched_digest = cas_file::prefixed_sha256_digest(mismatched_payload);
    let blob_mock = server
        .mock("GET", "/mismatched-published-bazel-cas")
        .expect(0)
        .with_status(200)
        .with_body(mismatched_payload)
        .create_async()
        .await;

    {
        let mut published = state.kv_published_index.write().await;
        published.update(
            std::collections::HashMap::from([(
                format!("bazel_cas/{key}"),
                BlobDescriptor {
                    digest: mismatched_digest.clone(),
                    size_bytes: mismatched_payload.len() as u64,
                },
            )]),
            vec![BlobDescriptor {
                digest: mismatched_digest.clone(),
                size_bytes: mismatched_payload.len() as u64,
            }],
            "entry-bazel-mismatched-published".to_string(),
        );
        published.set_download_url(
            mismatched_digest,
            format!("{}/mismatched-published-bazel-cas", server.url()),
        );
    }

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_bazel_cas_get_ignores_backend_index_digest_mismatch() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = cas_file::prefixed_sha256_digest(b"expected-backend-bazel-cas-payload")
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    let mismatched_payload = b"mismatched-backend-bazel-cas-payload";
    let mismatched_digest = cas_file::prefixed_sha256_digest(mismatched_payload);
    let pointer_bytes = make_kv_pointer(&[(
        format!("bazel_cas/{key}"),
        mismatched_digest.clone(),
        mismatched_payload.len() as u64,
    )]);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

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
                "tag": "registry",
                "status": "hit",
                "cache_entry_id": "entry-bazel-mismatched-backend",
                "manifest_url": format!("{}/pointer-bazel-mismatched-backend", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;
    let pointer_mock = server
        .mock("GET", "/pointer-bazel-mismatched-backend")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;
    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(0)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": mismatched_digest,
                    "url": format!("{}/mismatched-backend-bazel-cas", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
async fn test_gradle_put_returns_413_when_spool_budget_exceeded() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_MAX_SPOOL_BYTES", "1");
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/cache/oversized-entry")
            .body(Body::from("too-large"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
async fn test_maven_put_keeps_generic_spool_rejection_status() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_MAX_SPOOL_BYTES", "1");
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v1.1/com.example/app/abcdef1234567890/buildinfo.xml")
            .body(Body::from("too-large"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_json_error(&parsed, "bad_request");
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
            .header("x-artifact-duration", "123")
            .header("x-artifact-tag", "signed-tag")
            .header("x-artifact-sha", "abc123def456")
            .header("x-artifact-dirty-hash", "dirty789")
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
    assert_eq!(
        head_response.headers().get("x-artifact-duration").unwrap(),
        "123"
    );
    assert_eq!(
        head_response.headers().get("x-artifact-sha").unwrap(),
        "abc123def456"
    );
    assert_eq!(
        head_response
            .headers()
            .get("x-artifact-dirty-hash")
            .unwrap(),
        "dirty789"
    );
    assert!(head_response.headers().get("x-artifact-tag").is_none());

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
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
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
    assert_eq!(
        get_response.headers().get("x-artifact-duration").unwrap(),
        "123"
    );
    assert_eq!(
        get_response.headers().get("x-artifact-tag").unwrap(),
        "signed-tag"
    );
    assert_eq!(
        get_response.headers().get("x-artifact-sha").unwrap(),
        "abc123def456"
    );
    assert_eq!(
        get_response.headers().get("x-artifact-dirty-hash").unwrap(),
        "dirty789"
    );
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
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let payload_a = b"hello-world";
    let payload_b = b"second-artifact-data";

    let app = build_router(state.clone());
    let put_a = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v8/artifacts/a1b2")
            .header("authorization", "Bearer token")
            .header("x-artifact-duration", "55")
            .header("x-artifact-tag", "tag-a1")
            .body(Body::from(payload_a.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_a.status(), StatusCode::ACCEPTED);

    let app = build_router(state.clone());
    let put_b = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v8/artifacts/c3d4")
            .header("authorization", "Bearer token")
            .header("x-artifact-duration", "99")
            .header("x-artifact-tag", "tag-c3")
            .body(Body::from(payload_b.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_b.status(), StatusCode::ACCEPTED);

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
    assert_eq!(parsed["a1b2"]["size"], payload_a.len() as u64);
    assert_eq!(parsed["c3d4"]["size"], payload_b.len() as u64);
    assert_eq!(parsed["a1b2"]["taskDurationMs"], 55);
    assert_eq!(parsed["c3d4"]["taskDurationMs"], 99);
    assert_eq!(parsed["a1b2"]["tag"], "tag-a1");
    assert_eq!(parsed["c3d4"]["tag"], "tag-c3");
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
async fn test_turborepo_events_rejects_invalid_payload() {
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
            .body(Body::from(r#"{"not":"an-array"}"#))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_json_error(&parsed, "bad_request");
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
async fn test_turborepo_invalid_put_path_returns_not_found() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v8/artifacts/not-a-hex-hash")
            .body(Body::from("payload"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
