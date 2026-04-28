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
    KvPublishedIndex, OciManifestCacheEntry, UploadSession, UploadSessionBody, UploadSessionStore,
    digest_tag, legacy_ref_tag_for_input, ref_tag,
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
    test_env::remove_var("BORINGCACHE_OCI_STREAM_THROUGH_MIN_BYTES");

    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("API client");
    let (kv_replication_work_tx, _kv_replication_work_rx) = tokio::sync::mpsc::channel(
        boring_cache_cli::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY,
    );

    let state = AppState {
        api_client,
        workspace: "org/repo".to_string(),
        started_at: Instant::now(),
        cache_session_summary_id: "proxy-summary-test".to_string(),
        runtime_temp_dir: temp_home.path().join("proxy-runtime"),
        kv_blob_temp_dir: temp_home.path().join("proxy-runtime/kv-blobs"),
        oci_upload_temp_dir: temp_home.path().join("proxy-runtime/oci-uploads"),
        read_only: false,
        tag_resolver: TagResolver::new(None, GitContext::default(), false),
        configured_human_tags: Vec::new(),
        registry_root_tag: "registry".to_string(),
        oci_alias_promotion_refs: Vec::new(),
        proxy_metadata_hints: std::collections::BTreeMap::new(),
        proxy_ci_run_context: None,
        fail_on_cache_error: true,
        oci_hydration_policy: boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(Mutex::new(())),
        kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        oci_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        oci_negative_cache: Arc::new(boring_cache_cli::serve::state::OciNegativeCache::new()),
        singleflight_metrics: Arc::new(boring_cache_cli::serve::state::SingleflightMetrics::new()),
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
        kv_blob_upload_metrics: Arc::new(boring_cache_cli::serve::state::KvBlobUploadMetrics::new()),
        blob_download_max_concurrency: 16,
        blob_prefetch_max_concurrency: 2,
        blob_prefetch_concurrency_from_env: false,
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

fn namespaced_scoped_ref_tag(namespace: &str, name: &str, reference: &str) -> String {
    ref_tag(namespace, &format!("{name}:{reference}"))
}

fn scoped_ref_tag(name: &str, reference: &str) -> String {
    namespaced_scoped_ref_tag("registry", name, reference)
}

fn namespaced_legacy_scoped_ref_tag(namespace: &str, name: &str, reference: &str) -> String {
    legacy_ref_tag_for_input(&format!("{namespace}:{name}:{reference}"))
}

fn legacy_scoped_ref_tag(name: &str, reference: &str) -> String {
    namespaced_legacy_scoped_ref_tag("registry", name, reference)
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

fn make_oci_publish_pointer(manifest_body: &[u8]) -> Vec<u8> {
    let pointer = cas_oci::OciPointer {
        format_version: 1,
        adapter: "oci-v1".to_string(),
        manifest_content_type: Some("application/vnd.oci.image.manifest.v1+json".to_string()),
        index_json_base64: STANDARD.encode(manifest_body),
        oci_layout_base64: STANDARD.encode(br#"{"imageLayoutVersion":"1.0.0"}"#),
        blobs: Vec::new(),
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

async fn mock_empty_cache_restore(server: &mut Server, expected_calls: usize) -> mockito::Mock {
    server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect(expected_calls)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await
}

#[path = "serve_tests/oci_publish.rs"]
mod oci_publish;
#[path = "serve_tests/oci_read.rs"]
mod oci_read;
#[path = "serve_tests/oci_uploads.rs"]
mod oci_uploads;
#[path = "serve_tests/startup.rs"]
mod startup;
#[path = "serve_tests/tag_pointer.rs"]
mod tag_pointer;
#[path = "serve_tests/tool_routes.rs"]
mod tool_routes;
