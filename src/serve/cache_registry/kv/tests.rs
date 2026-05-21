use super::*;
use crate::api::client::ApiClient;
use crate::git::GitContext;
use crate::serve::state::{
    AppState, BackendCircuitBreaker, BlobLocatorCache, BlobReadCache, BlobReadMetrics,
    KvPendingStore, KvPublishedIndex, UploadSessionStore,
};
use crate::tag_utils::TagResolver;
use crate::test_env;
use mockito::{Matcher, Server};
use serde_json::json;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex as TokioMutex, RwLock};

struct EnvVarGuard {
    key: &'static str,
    original: Option<OsString>,
}

impl EnvVarGuard {
    fn new(key: &'static str) -> Self {
        Self {
            key,
            original: std::env::var_os(key),
        }
    }

    fn set<V>(&self, value: V)
    where
        V: AsRef<OsStr>,
    {
        test_env::set_var(self.key, value);
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(ref value) = self.original {
            test_env::set_var(self.key, value);
        } else {
            test_env::remove_var(self.key);
        }
    }
}

fn kv_flush_test_state(api_client: ApiClient, temp_home: &Path, read_only: bool) -> AppState {
    let (kv_replication_work_tx, _kv_replication_work_rx) =
        tokio::sync::mpsc::channel(crate::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY);
    let runtime_temp_dir = temp_home.join("serve-runtime");
    std::fs::create_dir_all(runtime_temp_dir.join("kv-blobs")).expect("kv blob temp dir");
    std::fs::create_dir_all(runtime_temp_dir.join("oci-uploads")).expect("oci upload temp dir");

    AppState {
        api_client,
        workspace: "org/repo".to_string(),
        started_at: Instant::now(),
        cache_session_summary_id: "proxy-summary-test".to_string(),
        runtime_temp_dir: runtime_temp_dir.clone(),
        kv_blob_temp_dir: runtime_temp_dir.join("kv-blobs"),
        oci_upload_temp_dir: runtime_temp_dir.join("oci-uploads"),
        read_only,
        tag_resolver: TagResolver::new(None, GitContext::default(), false),
        configured_human_tags: Vec::new(),
        primary_cache_tag: "registry".to_string(),
        restore_cache_tags: vec!["registry".to_string()],
        oci_alias_promotion_refs: Vec::new(),
        proxy_metadata_hints: std::collections::BTreeMap::new(),
        proxy_skip_rules: std::sync::Arc::new(Vec::new()),
        proxy_ci_run_context: None,
        fail_on_cache_error: true,
        oci_hydration_policy: crate::serve::OciHydrationPolicy::MetadataOnly,
        http_transport: crate::serve::state::HttpTransportConfig::h1_h2c_auto(
            2 * 1024 * 1024,
            32 * 1024 * 1024,
            1024,
        ),
        blob_locator: std::sync::Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: std::sync::Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: std::sync::Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: std::sync::Arc::new(TokioMutex::new(())),
        kv_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
        oci_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
        oci_negative_cache: std::sync::Arc::new(crate::serve::state::OciNegativeCache::new()),
        singleflight_metrics: std::sync::Arc::new(crate::serve::state::SingleflightMetrics::new()),
        kv_key_lookup_metrics: std::sync::Arc::new(crate::serve::state::KvKeyLookupMetrics::new()),
        kv_last_put: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_backlog_rejects: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_enqueue_deferred: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_ok: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_conflict: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_error: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_permanent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_queue_depth: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_work_tx,
        kv_next_flush_at: std::sync::Arc::new(RwLock::new(None)),
        kv_flush_scheduled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_published_index: std::sync::Arc::new(RwLock::new(KvPublishedIndex::default())),
        kv_flushing: std::sync::Arc::new(RwLock::new(None)),
        shutdown_requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_recent_misses: std::sync::Arc::new(dashmap::DashMap::new()),
        kv_miss_generations: std::sync::Arc::new(dashmap::DashMap::new()),
        blob_read_cache: std::sync::Arc::new(
            BlobReadCache::new_at(temp_home.join("blob-read-cache"), 2 * 1024 * 1024 * 1024)
                .expect("blob read cache"),
        ),
        blob_read_metrics: std::sync::Arc::new(BlobReadMetrics::new()),
        oci_body_metrics: std::sync::Arc::new(crate::serve::state::OciBodyMetrics::new()),
        oci_engine_diagnostics: std::sync::Arc::new(
            crate::serve::state::OciEngineDiagnostics::new(),
        ),
        prefetch_metrics: std::sync::Arc::new(crate::serve::state::PrefetchMetrics::new()),
        kv_blob_upload_metrics: std::sync::Arc::new(crate::serve::state::KvBlobUploadMetrics::new()),
        skip_rule_metrics: std::sync::Arc::new(crate::serve::state::ProxySkipRuleMetrics::new()),
        blob_download_max_concurrency: 16,
        blob_prefetch_max_concurrency: 2,
        blob_prefetch_concurrency_from_env: false,
        blob_download_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
        blob_prefetch_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
        cache_ops: std::sync::Arc::new(crate::serve::cache_registry::cache_ops::Aggregator::new()),
        oci_manifest_cache: std::sync::Arc::new(dashmap::DashMap::new()),
        backend_breaker: std::sync::Arc::new(BackendCircuitBreaker::new()),
        prefetch_complete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        prefetch_complete_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
        prefetch_error: std::sync::Arc::new(RwLock::new(None)),
    }
}

async fn insert_pending_test_blob(
    state: &AppState,
    key: &str,
    file_name: &str,
    payload: &[u8],
) -> String {
    let blob_digest = crate::cas_file::prefixed_sha256_digest(payload);
    let blob_path = state.kv_blob_temp_dir.join(file_name);
    tokio::fs::write(&blob_path, payload)
        .await
        .expect("write pending blob");
    {
        let mut pending = state.kv_pending.write().await;
        pending.insert(
            key.to_string(),
            BlobDescriptor {
                digest: blob_digest.clone(),
                size_bytes: payload.len() as u64,
            },
            blob_path,
        );
    }
    blob_digest
}

#[tokio::test]
async fn serve_blob_read_handle_can_return_memory_body() {
    let _guard = test_env::lock();
    let memory_env = EnvVarGuard::new("BORINGCACHE_BLOB_READ_MEMORY_CACHE_BYTES");
    memory_env.set("1m");
    let temp_home = tempfile::tempdir().expect("temp dir");
    let cache = BlobReadCache::new_at(temp_home.path().join("blob-read-cache"), 1024 * 1024)
        .expect("blob read cache");
    let digest = format!("sha256:{}", "a".repeat(64));
    let payload = b"memory-body-response";

    assert!(cache.insert(&digest, payload).await.expect("insert blob"));
    let handle = cache.get_handle(&digest).await.expect("cache hit");

    let body = serve_blob_read_handle(&handle).await.expect("memory body");
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .expect("collect body")
        .to_bytes();
    assert_eq!(bytes.as_ref(), payload);
}

#[tokio::test]
async fn normal_flush_uploads_blobs_and_upserts_kv_rows_without_manifest_publish() {
    let mut server = Server::new_async().await;
    let _guard = test_env::lock();
    let temp_home = tempfile::tempdir().expect("temp dir");
    let home_env = EnvVarGuard::new("HOME");
    let api_url_env = EnvVarGuard::new("BORINGCACHE_API_URL");
    let auth_token_env = EnvVarGuard::new("BORINGCACHE_AUTH_TOKEN");
    let test_mode_env = EnvVarGuard::new("BORINGCACHE_TEST_MODE");
    home_env.set(temp_home.path());
    api_url_env.set(server.url());
    auth_token_env.set("test-token");
    test_mode_env.set("1");

    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("client");
    let mut state = kv_flush_test_state(api_client, temp_home.path(), false);
    state.configured_human_tags = vec!["human-tag".to_string()];

    let payload = b"direct-kv-payload";
    let digest = insert_pending_test_blob(&state, "bazel_cas/key", "direct-kv", payload).await;

    let blob_stage_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "blobs": [{ "digest": digest, "size_bytes": payload.len() }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": digest,
                    "url": format!("{}/blob-upload", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;
    let blob_upload_mock = server
        .mock("PUT", "/blob-upload")
        .expect(1)
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .with_header("etag", "kv-etag")
        .create_async()
        .await;
    let capabilities_mock = server
        .mock("GET", "/v2/capabilities")
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "api_version": "v2",
                "features": {
                    "cache_kv_entries_v1": true,
                    "cache_kv_entries_multi_tag_upsert_v1": true
                }
            })
            .to_string(),
        )
        .create_async()
        .await;
    let kv_upsert_mock = server
        .mock("POST", "/v2/workspaces/org/repo/cache-kv-entries")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "tags": ["registry", "human-tag"],
            "entries": [{
                "namespace": "bazel_cas",
                "scoped_key": "bazel_cas/key",
                "blob_digest": digest,
                "size_bytes": payload.len()
            }],
            "blob_receipts": [{ "digest": digest, "etag": "kv-etag" }]
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "entries": [{
                    "namespace": "bazel_cas",
                    "scoped_key": "bazel_cas/key",
                    "blob": { "digest": digest, "size_bytes": payload.len() }
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;
    let save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .expect(0)
        .create_async()
        .await;
    let publish_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .expect(0)
        .create_async()
        .await;

    let result = flush_kv_index(&state).await;
    assert!(matches!(result, FlushResult::Ok));
    {
        let published = state.kv_published_index.read().await;
        assert_eq!(published.entry_count(), 1);
        assert_eq!(published.cache_entry_id(), Some("kv-direct:registry"));
        assert!(published.is_stable());
    }

    blob_stage_mock.assert_async().await;
    blob_upload_mock.assert_async().await;
    capabilities_mock.assert_async().await;
    kv_upsert_mock.assert_async().await;
    save_mock.assert_async().await;
    publish_mock.assert_async().await;
}

#[tokio::test]
async fn shutdown_flush_upserts_only_new_kv_rows_without_manifest_publish() {
    let mut server = Server::new_async().await;
    let _guard = test_env::lock();
    let temp_home = tempfile::tempdir().expect("temp dir");
    let home_env = EnvVarGuard::new("HOME");
    let api_url_env = EnvVarGuard::new("BORINGCACHE_API_URL");
    let auth_token_env = EnvVarGuard::new("BORINGCACHE_AUTH_TOKEN");
    let test_mode_env = EnvVarGuard::new("BORINGCACHE_TEST_MODE");
    home_env.set(temp_home.path());
    api_url_env.set(server.url());
    auth_token_env.set("test-token");
    test_mode_env.set("1");

    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("client");
    let state = kv_flush_test_state(api_client, temp_home.path(), false);

    let first_payload = b"first direct kv payload";
    let first_digest =
        insert_pending_test_blob(&state, "bazel_cas/key-one", "direct-one", first_payload).await;
    let first_stage_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "blobs": [{ "digest": first_digest, "size_bytes": first_payload.len() }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": first_digest,
                    "url": format!("{}/blob-upload-one", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;
    let first_upload_mock = server
        .mock("PUT", "/blob-upload-one")
        .expect(1)
        .match_body(Matcher::Exact(
            String::from_utf8(first_payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .with_header("etag", "kv-etag-one")
        .create_async()
        .await;
    let first_upsert_mock = server
        .mock("POST", "/v2/workspaces/org/repo/cache-kv-entries")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "tags": ["registry"],
            "entries": [{
                "namespace": "bazel_cas",
                "scoped_key": "bazel_cas/key-one",
                "blob_digest": first_digest,
                "size_bytes": first_payload.len()
            }],
            "blob_receipts": [{ "digest": first_digest, "etag": "kv-etag-one" }]
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "entries": [{
                    "namespace": "bazel_cas",
                    "scoped_key": "bazel_cas/key-one",
                    "blob": { "digest": first_digest, "size_bytes": first_payload.len() }
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .expect(0)
        .create_async()
        .await;
    let publish_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .expect(0)
        .create_async()
        .await;

    assert!(matches!(flush_kv_index(&state).await, FlushResult::Ok));

    let second_payload = b"second direct kv payload";
    let second_digest =
        insert_pending_test_blob(&state, "bazel_cas/key-two", "direct-two", second_payload).await;
    let second_stage_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "blobs": [{ "digest": second_digest, "size_bytes": second_payload.len() }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": second_digest,
                    "url": format!("{}/blob-upload-two", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;
    let second_upload_mock = server
        .mock("PUT", "/blob-upload-two")
        .expect(1)
        .match_body(Matcher::Exact(
            String::from_utf8(second_payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .with_header("etag", "kv-etag-two")
        .create_async()
        .await;
    let second_upsert_mock = server
        .mock("POST", "/v2/workspaces/org/repo/cache-kv-entries")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "tags": ["registry"],
            "entries": [{
                "namespace": "bazel_cas",
                "scoped_key": "bazel_cas/key-two",
                "blob_digest": second_digest,
                "size_bytes": second_payload.len()
            }],
            "blob_receipts": [{ "digest": second_digest, "etag": "kv-etag-two" }]
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "entries": [{
                    "namespace": "bazel_cas",
                    "scoped_key": "bazel_cas/key-two",
                    "blob": { "digest": second_digest, "size_bytes": second_payload.len() }
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    assert!(matches!(
        flush_kv_index_on_shutdown(&state).await,
        FlushResult::Ok
    ));
    {
        let published = state.kv_published_index.read().await;
        assert_eq!(published.entry_count(), 2);
        assert_eq!(published.cache_entry_id(), Some("kv-direct:registry"));
        assert!(published.is_stable());
    }

    first_stage_mock.assert_async().await;
    first_upload_mock.assert_async().await;
    first_upsert_mock.assert_async().await;
    second_stage_mock.assert_async().await;
    second_upload_mock.assert_async().await;
    second_upsert_mock.assert_async().await;
    save_mock.assert_async().await;
    publish_mock.assert_async().await;
}

#[tokio::test]
async fn load_existing_index_prioritizes_metadata_and_recent_blobs_for_startup_warm() {
    let mut server = Server::new_async().await;
    let _guard = test_env::lock();
    let temp_home = tempfile::tempdir().expect("temp dir");
    let home_env = EnvVarGuard::new("HOME");
    let api_url_env = EnvVarGuard::new("BORINGCACHE_API_URL");
    let auth_token_env = EnvVarGuard::new("BORINGCACHE_AUTH_TOKEN");
    let test_mode_env = EnvVarGuard::new("BORINGCACHE_TEST_MODE");
    home_env.set(temp_home.path());
    api_url_env.set(server.url());
    auth_token_env.set("test-token");
    test_mode_env.set("1");

    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("client");
    let state = kv_flush_test_state(api_client, temp_home.path(), false);

    let older_cas = "sha256:111";
    let older_ac = "sha256:222";
    let recent_sccache = "sha256:333";
    let stream_mock = server
        .mock(
            "GET",
            Matcher::Regex(
                r"^/v2/workspaces/org/repo/cache-kv-entries\?tag=registry&limit=5000$".to_string(),
            ),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "entries": [
                    {
                        "namespace": "bazel_cas",
                        "scoped_key": "bazel_cas/old-output",
                        "blob": { "digest": older_cas, "size_bytes": 3 },
                        "last_written_at": "2026-05-01T00:00:00Z",
                        "updated_at": "2026-05-01T00:00:00Z"
                    },
                    {
                        "namespace": "sccache",
                        "scoped_key": "sccache/recent-object",
                        "blob": { "digest": recent_sccache, "size_bytes": 5 },
                        "last_read_at": "2026-05-18T00:00:00Z",
                        "last_written_at": "2026-05-03T00:00:00Z",
                        "updated_at": "2026-05-18T00:00:00Z"
                    },
                    {
                        "namespace": "bazel_ac",
                        "scoped_key": "bazel_ac/action-result",
                        "blob": { "digest": older_ac, "size_bytes": 2 },
                        "last_written_at": "2026-05-02T00:00:00Z",
                        "updated_at": "2026-05-02T00:00:00Z"
                    }
                ],
                "next_cursor": null
            })
            .to_string(),
        )
        .create_async()
        .await;

    let (entries, blob_order, cache_entry_id, manifest_root_digest) =
        load_existing_index(&state, "registry")
            .await
            .expect("load index");

    assert_eq!(entries.len(), 3);
    assert_eq!(cache_entry_id.as_deref(), Some("kv-direct:registry"));
    assert_eq!(manifest_root_digest, None);
    assert_eq!(
        blob_order
            .iter()
            .map(|blob| blob.digest.as_str())
            .collect::<Vec<_>>(),
        vec![older_ac, recent_sccache, older_cas]
    );

    stream_mock.assert_async().await;
}

#[tokio::test]
async fn put_kv_object_is_noop_in_read_only_mode() {
    let temp_home = tempfile::tempdir().expect("temp dir");
    let api_client =
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("client");
    let (kv_replication_work_tx, _kv_replication_work_rx) =
        tokio::sync::mpsc::channel(crate::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY);
    let runtime_temp_dir = temp_home.path().join("serve-runtime");
    std::fs::create_dir_all(runtime_temp_dir.join("kv-blobs")).expect("kv blob temp dir");
    std::fs::create_dir_all(runtime_temp_dir.join("oci-uploads")).expect("oci upload temp dir");

    let state = AppState {
        api_client,
        workspace: "org/repo".to_string(),
        started_at: Instant::now(),
        cache_session_summary_id: "proxy-summary-test".to_string(),
        runtime_temp_dir: runtime_temp_dir.clone(),
        kv_blob_temp_dir: runtime_temp_dir.join("kv-blobs"),
        oci_upload_temp_dir: runtime_temp_dir.join("oci-uploads"),
        read_only: true,
        tag_resolver: TagResolver::new(None, GitContext::default(), false),
        configured_human_tags: Vec::new(),
        primary_cache_tag: "registry".to_string(),
        restore_cache_tags: vec!["registry".to_string()],
        oci_alias_promotion_refs: Vec::new(),
        proxy_metadata_hints: std::collections::BTreeMap::new(),
        proxy_skip_rules: std::sync::Arc::new(Vec::new()),
        proxy_ci_run_context: None,
        fail_on_cache_error: true,
        oci_hydration_policy: crate::serve::OciHydrationPolicy::MetadataOnly,
        http_transport: crate::serve::state::HttpTransportConfig::h1_h2c_auto(
            2 * 1024 * 1024,
            32 * 1024 * 1024,
            1024,
        ),
        blob_locator: std::sync::Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: std::sync::Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: std::sync::Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: std::sync::Arc::new(TokioMutex::new(())),
        kv_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
        oci_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
        oci_negative_cache: std::sync::Arc::new(crate::serve::state::OciNegativeCache::new()),
        singleflight_metrics: std::sync::Arc::new(crate::serve::state::SingleflightMetrics::new()),
        kv_key_lookup_metrics: std::sync::Arc::new(crate::serve::state::KvKeyLookupMetrics::new()),
        kv_last_put: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_backlog_rejects: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_enqueue_deferred: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_ok: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_conflict: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_error: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_permanent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_queue_depth: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_work_tx,
        kv_next_flush_at: std::sync::Arc::new(RwLock::new(None)),
        kv_flush_scheduled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_published_index: std::sync::Arc::new(RwLock::new(KvPublishedIndex::default())),
        kv_flushing: std::sync::Arc::new(RwLock::new(None)),
        shutdown_requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_recent_misses: std::sync::Arc::new(dashmap::DashMap::new()),
        kv_miss_generations: std::sync::Arc::new(dashmap::DashMap::new()),
        blob_read_cache: std::sync::Arc::new(
            BlobReadCache::new_at(
                temp_home.path().join("blob-read-cache"),
                2 * 1024 * 1024 * 1024,
            )
            .expect("blob read cache"),
        ),
        blob_read_metrics: std::sync::Arc::new(BlobReadMetrics::new()),
        oci_body_metrics: std::sync::Arc::new(crate::serve::state::OciBodyMetrics::new()),
        oci_engine_diagnostics: std::sync::Arc::new(
            crate::serve::state::OciEngineDiagnostics::new(),
        ),
        prefetch_metrics: std::sync::Arc::new(crate::serve::state::PrefetchMetrics::new()),
        kv_blob_upload_metrics: std::sync::Arc::new(crate::serve::state::KvBlobUploadMetrics::new()),
        skip_rule_metrics: std::sync::Arc::new(crate::serve::state::ProxySkipRuleMetrics::new()),
        blob_download_max_concurrency: 16,
        blob_prefetch_max_concurrency: 2,
        blob_prefetch_concurrency_from_env: false,
        blob_download_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
        blob_prefetch_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
        cache_ops: std::sync::Arc::new(crate::serve::cache_registry::cache_ops::Aggregator::new()),
        oci_manifest_cache: std::sync::Arc::new(dashmap::DashMap::new()),
        backend_breaker: std::sync::Arc::new(BackendCircuitBreaker::new()),
        prefetch_complete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        prefetch_complete_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
        prefetch_error: std::sync::Arc::new(RwLock::new(None)),
    };

    let response = put_kv_object(
        &state,
        KvNamespace::Gradle,
        "cache-key",
        Body::from("payload"),
        StatusCode::OK,
    )
    .await
    .expect("read-only puts should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let pending = state.kv_pending.read().await;
    assert_eq!(pending.blob_count(), 0);
}

#[test]
fn classify_flush_error_treats_precondition_failed_as_conflict() {
    let error = anyhow::anyhow!("HTTP 412 from backend: precondition failed");
    let classified = classify_flush_error(&error, "confirm failed");
    assert!(matches!(classified, FlushError::Conflict(_)));
}

#[test]
fn classify_flush_error_treats_cache_pending_as_conflict() {
    let error: anyhow::Error = BoringCacheError::cache_pending().into();
    let classified = classify_flush_error(&error, "confirm failed");
    assert!(matches!(classified, FlushError::Transient(_)));
}

#[test]
fn classify_flush_error_treats_server_error_message_as_transient() {
    let error = anyhow::anyhow!("Server error (500). Please try again later.");
    let classified = classify_flush_error(&error, "confirm failed");
    assert!(matches!(classified, FlushError::Transient(_)));
}

#[test]
fn classify_flush_error_treats_tls_unexpected_eof_as_transient() {
    let error = anyhow::anyhow!(
        "blob upload failed: client error (SendRequest): connection error: peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
    );
    let classified = classify_flush_error(&error, "blob upload failed");
    assert!(matches!(classified, FlushError::Transient(_)));
}

#[test]
fn conflict_backoff_window_is_longer_for_in_progress_conflicts() {
    let (base, jitter) =
        conflict_backoff_window("save_entry failed: another cache upload is in progress");
    assert_eq!(base, KV_CONFLICT_IN_PROGRESS_BACKOFF_MS);
    assert_eq!(jitter, KV_CONFLICT_IN_PROGRESS_JITTER_MS);
}

#[test]
fn upload_in_progress_conflict_detector_is_narrow() {
    assert!(is_upload_in_progress_conflict(
        "save_entry failed: another cache upload is in progress"
    ));
    assert!(is_upload_in_progress_conflict(
        "cache upload in progress for this tag"
    ));
    assert!(!is_upload_in_progress_conflict(
        "tag already points to a different digest"
    ));
    assert!(!is_upload_in_progress_conflict(
        "confirm failed: blob not yet verified"
    ));
}

#[test]
fn transient_backoff_window_is_longer_for_write_path_failures() {
    let (base, jitter) = transient_backoff_window("confirm failed: Server error (500)");
    assert_eq!(base, KV_TRANSIENT_WRITE_PATH_BACKOFF_MS);
    assert_eq!(jitter, KV_TRANSIENT_WRITE_PATH_JITTER_MS);
}

#[test]
fn classify_flush_error_treats_bad_request_as_permanent() {
    let error = anyhow::anyhow!("HTTP 400 from backend: invalid payload");
    let classified = classify_flush_error(&error, "save failed");
    assert!(matches!(classified, FlushError::Permanent(_)));
}

#[test]
fn classify_flush_error_treats_server_returned_bad_request_as_permanent() {
    let error = anyhow::anyhow!(
        "Server returned 400 Bad Request for https://api.example.test: cache_entry must be pending or ready"
    );
    let classified = classify_flush_error(&error, "stable publish failed");
    assert!(matches!(classified, FlushError::Permanent(_)));
}

#[test]
fn classify_flush_error_treats_edge_blob_stage_bad_request_as_transient() {
    let error = anyhow::anyhow!(
        "HTTP 400 Bad Request from https://api.boringcache.com/v2/workspaces/ns/ws/caches/blobs/stage: <html><head><title>400 Bad Request</title></head><body><center>nginx</center></body></html>"
    );
    let classified = classify_flush_error(&error, "blob upload failed");
    assert!(matches!(classified, FlushError::Transient(_)));
}

#[test]
fn classify_flush_error_treats_edge_blob_download_urls_bad_request_as_transient() {
    let error = anyhow::anyhow!(
        "HTTP 400 Bad Request from https://api.boringcache.com/v2/workspaces/ns/ws/caches/blobs/download-urls: <html><head><title>400 Bad Request</title></head><body><center>nginx</center></body></html>"
    );
    let classified = classify_flush_error(&error, "blob URL planning failed");
    assert!(matches!(classified, FlushError::Transient(_)));
}

#[test]
fn classify_flush_error_treats_blob_verification_pending_as_permanent() {
    let error = anyhow::anyhow!(
        "Server returned 400 Bad Request: 714 blob(s) not yet verified in storage — retry after upload completes"
    );
    let classified = classify_flush_error(&error, "confirm failed");
    assert!(matches!(classified, FlushError::Permanent(_)));
}

#[test]
fn classify_flush_error_treats_receipt_incomplete_publish_as_transient() {
    let error = anyhow::anyhow!(
        "Server returned 422 Unprocessable Entity: CAS publish requires complete upload receipts (upload_session_receipts_incomplete)"
    );
    let classified = classify_flush_error(&error, "confirm failed");
    assert!(matches!(classified, FlushError::Transient(_)));
}

#[test]
fn should_clear_flushing_after_flush_skips_ok_path() {
    assert!(!should_clear_flushing_after_flush(&FlushResult::Ok));
    assert!(should_clear_flushing_after_flush(&FlushResult::Conflict));
    assert!(should_clear_flushing_after_flush(&FlushResult::Error));
    assert!(should_clear_flushing_after_flush(&FlushResult::Permanent));
}

#[test]
fn server_cache_tag_name_matches_web_tag_constraints() {
    assert!(crate::tag_utils::server_cache_tag_name(
        "build-main_amd64.1"
    ));
    assert!(!crate::tag_utils::server_cache_tag_name("build/main"));
    assert!(!crate::tag_utils::server_cache_tag_name("build:main"));
    assert!(!crate::tag_utils::server_cache_tag_name(".build-main"));
    assert!(!crate::tag_utils::server_cache_tag_name("build-main-"));
    assert!(!crate::tag_utils::server_cache_tag_name("build..main"));
}

#[test]
fn pending_refresh_suppression_applies_for_recent_local_puts() {
    let now_ms: u64 = 100_000;
    let last_put_ms = now_ms.saturating_sub(5_000);
    assert!(should_suppress_lookup_refresh_due_to_pending_values(
        true,
        last_put_ms,
        now_ms
    ));
}

#[test]
fn pending_refresh_suppression_expires_after_window() {
    let now_ms: u64 = 100_000;
    let last_put_ms =
        now_ms.saturating_sub(KV_PENDING_REFRESH_SUPPRESSION_WINDOW.as_millis() as u64 + 1);
    assert!(!should_suppress_lookup_refresh_due_to_pending_values(
        true,
        last_put_ms,
        now_ms
    ));
}

#[test]
fn pending_refresh_suppression_requires_pending_entries() {
    let now_ms: u64 = 100_000;
    let last_put_ms = now_ms.saturating_sub(1_000);
    assert!(!should_suppress_lookup_refresh_due_to_pending_values(
        false,
        last_put_ms,
        now_ms
    ));
}

#[test]
fn pending_or_flushing_refresh_suppression_applies_when_flushing() {
    let now_ms: u64 = 100_000;
    assert!(
        should_suppress_lookup_refresh_due_to_pending_or_flushing_values(false, true, 0, now_ms)
    );
}

#[test]
fn count_published_gaps_in_backend_reports_subset_gap() {
    let mut backend = BTreeMap::new();
    backend.insert(
        "k1".to_string(),
        BlobDescriptor {
            digest: "sha256:111".to_string(),
            size_bytes: 10,
        },
    );

    let mut published = HashMap::new();
    published.insert(
        "k1".to_string(),
        BlobDescriptor {
            digest: "sha256:111".to_string(),
            size_bytes: 10,
        },
    );
    published.insert(
        "k2".to_string(),
        BlobDescriptor {
            digest: "sha256:222".to_string(),
            size_bytes: 20,
        },
    );

    assert_eq!(
        count_published_gaps_in_backend(&backend, &published),
        PublishedGapCounts {
            missing_keys: 1,
            mismatched_keys: 0
        }
    );
}

#[test]
fn count_published_gaps_in_backend_reports_digest_mismatch() {
    let mut backend = BTreeMap::new();
    backend.insert(
        "k1".to_string(),
        BlobDescriptor {
            digest: "sha256:111".to_string(),
            size_bytes: 10,
        },
    );
    backend.insert(
        "k2".to_string(),
        BlobDescriptor {
            digest: "sha256:222".to_string(),
            size_bytes: 20,
        },
    );

    let mut published = HashMap::new();
    published.insert(
        "k1".to_string(),
        BlobDescriptor {
            digest: "sha256:999".to_string(),
            size_bytes: 99,
        },
    );

    assert_eq!(
        count_published_gaps_in_backend(&backend, &published),
        PublishedGapCounts {
            missing_keys: 0,
            mismatched_keys: 1
        }
    );
}

#[test]
fn replication_enqueue_marks_deferred_when_channel_is_full() {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let queue_depth = AtomicU64::new(0);
    let enqueue_deferred = AtomicU64::new(0);

    assert!(try_enqueue_replication_work(
        &tx,
        &queue_depth,
        &enqueue_deferred,
        false,
        true
    ));
    assert!(!try_enqueue_replication_work(
        &tx,
        &queue_depth,
        &enqueue_deferred,
        false,
        true
    ));

    assert_eq!(queue_depth.load(Ordering::Acquire), 1);
    assert_eq!(enqueue_deferred.load(Ordering::Acquire), 1);
}

#[test]
fn replication_enqueue_does_not_increment_deferred_when_not_counted() {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let queue_depth = AtomicU64::new(0);
    let enqueue_deferred = AtomicU64::new(0);

    assert!(try_enqueue_replication_work(
        &tx,
        &queue_depth,
        &enqueue_deferred,
        false,
        true
    ));
    assert!(!try_enqueue_replication_work(
        &tx,
        &queue_depth,
        &enqueue_deferred,
        false,
        false
    ));

    assert_eq!(queue_depth.load(Ordering::Acquire), 1);
    assert_eq!(enqueue_deferred.load(Ordering::Acquire), 0);
}

#[test]
fn should_skip_blob_preload_when_cache_is_near_capacity() {
    assert!(should_skip_blob_preload(95, 100));
    assert!(should_skip_blob_preload(190, 200));
    assert!(!should_skip_blob_preload(94, 100));
}

#[test]
fn should_skip_blob_preload_when_cache_capacity_is_invalid() {
    assert!(should_skip_blob_preload(0, 0));
    assert!(should_skip_blob_preload(10, 0));
}

#[test]
fn kv_startup_prefetch_limits_allow_env_overrides() {
    let _guard = test_env::lock();

    test_env::set_var(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV, "48");
    test_env::set_var(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV, "2097152");
    assert_eq!(kv_startup_prefetch_max_blobs(), 48);
    assert_eq!(
        kv_startup_prefetch_max_total_bytes(1024 * 1024 * 1024),
        2_097_152
    );
    test_env::remove_var(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV);
    test_env::remove_var(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV);
}

#[test]
fn startup_prefetch_slice_respects_order_and_total_budget() {
    let blobs = vec![
        BlobDescriptor {
            digest: "sha256:1".to_string(),
            size_bytes: 10,
        },
        BlobDescriptor {
            digest: "sha256:2".to_string(),
            size_bytes: 15,
        },
        BlobDescriptor {
            digest: "sha256:3".to_string(),
            size_bytes: 20,
        },
    ];

    let selected = select_startup_prefetch_slice(&blobs, 3, 25);
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].digest, "sha256:1");
    assert_eq!(selected[1].digest, "sha256:2");
}

#[test]
fn startup_prefetch_slice_skips_oversized_blobs_instead_of_stopping() {
    let blobs = vec![
        BlobDescriptor {
            digest: "sha256:1".to_string(),
            size_bytes: 10,
        },
        BlobDescriptor {
            digest: "sha256:oversized".to_string(),
            size_bytes: 1_000,
        },
        BlobDescriptor {
            digest: "sha256:2".to_string(),
            size_bytes: 15,
        },
    ];

    let selected = select_startup_prefetch_slice(&blobs, 3, 25);
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].digest, "sha256:1");
    assert_eq!(selected[1].digest, "sha256:2");
}

#[test]
fn kv_blob_prefetch_max_inflight_bytes_uses_env_override() {
    let _guard = test_env::lock();

    test_env::set_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV, "12345");
    assert_eq!(kv_blob_prefetch_max_inflight_bytes(1024 * 1024), 12_345);
    test_env::remove_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV);
}

#[test]
fn startup_prefetch_defaults_cover_full_tag_by_default() {
    let _guard = test_env::lock();
    test_env::remove_var(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV);
    test_env::remove_var(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV);
    test_env::remove_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV);
    let cache_max = 4 * 1024 * 1024 * 1024;
    assert_eq!(kv_startup_prefetch_max_blobs(), usize::MAX);
    assert_eq!(kv_startup_prefetch_max_total_bytes(cache_max), cache_max);
    assert_eq!(
        kv_blob_prefetch_max_inflight_bytes(cache_max),
        512 * 1024 * 1024
    );
}

#[test]
fn startup_prefetch_concurrency_uses_rtt_bound_cap_for_many_small_blobs() {
    let plan = adaptive_startup_prefetch_concurrency(100, false, 5_000, 5_000 * 4_096);

    assert_eq!(plan.max_concurrency, 100);
    assert_eq!(plan.effective_concurrency, 100);
    assert_eq!(plan.initial_concurrency, 100);
    assert!(plan.adaptive);
    assert_eq!(plan.source, "auto");
    assert_eq!(plan.reason, "many_small_blobs_rtt_bound");
}

#[test]
fn startup_prefetch_concurrency_uses_high_ci_ceiling_for_many_small_blobs() {
    let plan = adaptive_startup_prefetch_concurrency(2_000, false, 25_000, 25_000 * 40_000);

    assert_eq!(plan.max_concurrency, 2_000);
    assert_eq!(plan.effective_concurrency, 2_000);
    assert_eq!(plan.initial_concurrency, 2_000);
    assert!(plan.adaptive);
    assert_eq!(plan.source, "auto");
    assert_eq!(plan.reason, "many_small_blobs_rtt_bound");
}

#[test]
fn startup_prefetch_concurrency_uses_inflight_budget_for_many_small_io_bound_blobs() {
    let plan = adaptive_startup_prefetch_concurrency(1_000, false, 2_500, 2_500 * 512 * 1024);

    assert_eq!(plan.max_concurrency, 1_000);
    assert_eq!(plan.effective_concurrency, 128);
    assert_eq!(plan.initial_concurrency, 20);
    assert!(plan.adaptive);
    assert_eq!(plan.source, "auto");
    assert_eq!(plan.reason, "many_small_blobs_io_bound");
}

#[test]
fn startup_prefetch_concurrency_respects_smaller_machine_ceiling_for_many_small_blobs() {
    let plan = adaptive_startup_prefetch_concurrency(16, false, 5_000, 5_000 * 4_096);

    assert_eq!(plan.max_concurrency, 16);
    assert_eq!(plan.effective_concurrency, 16);
    assert_eq!(plan.initial_concurrency, 16);
    assert!(plan.adaptive);
    assert_eq!(plan.source, "auto");
    assert_eq!(plan.reason, "many_small_blobs_rtt_bound");
}

#[test]
fn startup_prefetch_concurrency_keeps_explicit_override_for_benchmarks() {
    let plan = adaptive_startup_prefetch_concurrency(20, true, 5_000, 5_000 * 4_096);

    assert_eq!(plan.max_concurrency, 20);
    assert_eq!(plan.effective_concurrency, 20);
    assert_eq!(plan.initial_concurrency, 20);
    assert!(!plan.adaptive);
    assert_eq!(plan.source, "env");
    assert_eq!(plan.reason, "explicit_override");
}

fn startup_prefetch_window(
    completed: usize,
    bytes: u64,
    failures: usize,
    rate_limited: bool,
    p95_ms: u64,
) -> StartupPrefetchWindowSample {
    startup_prefetch_window_with_retries(completed, bytes, failures, 0, rate_limited, p95_ms)
}

fn startup_prefetch_window_with_retries(
    completed: usize,
    bytes: u64,
    failures: usize,
    retries: usize,
    rate_limited: bool,
    p95_ms: u64,
) -> StartupPrefetchWindowSample {
    StartupPrefetchWindowSample {
        elapsed: std::time::Duration::from_secs(1),
        completed,
        bytes,
        failures,
        retries,
        rate_limited,
        retry_after: None,
        p95_ms,
    }
}

#[test]
fn startup_prefetch_tuner_increases_when_goodput_improves() {
    let mut state = StartupPrefetchTuningState::new();

    let (next, decision) = tune_startup_prefetch_concurrency(
        20,
        100,
        true,
        &mut state,
        startup_prefetch_window(20, 2_000_000, 0, false, 50),
        false,
    );

    assert_eq!(next, 25);
    assert_eq!(decision, StartupPrefetchAdjustment::Increase);
}

#[test]
fn startup_prefetch_tuner_ramps_faster_when_rtt_bound() {
    let mut state = StartupPrefetchTuningState::new();

    let (next, decision) = tune_startup_prefetch_concurrency(
        20,
        100,
        true,
        &mut state,
        startup_prefetch_window(20, 2_000_000, 0, false, 250),
        false,
    );

    assert_eq!(next, 30);
    assert_eq!(decision, StartupPrefetchAdjustment::Increase);
}

#[test]
fn startup_prefetch_tuner_halves_on_failures() {
    let mut state = StartupPrefetchTuningState::new();

    let (next, decision) = tune_startup_prefetch_concurrency(
        80,
        100,
        true,
        &mut state,
        startup_prefetch_window(80, 2_000_000, 1, false, 50),
        false,
    );

    assert_eq!(next, 40);
    assert_eq!(decision, StartupPrefetchAdjustment::DropFast);
}

#[test]
fn startup_prefetch_tuner_drops_slow_on_latency_spike() {
    let mut state = StartupPrefetchTuningState::new();
    let _ = tune_startup_prefetch_concurrency(
        40,
        100,
        true,
        &mut state,
        startup_prefetch_window(40, 2_000_000, 0, false, 50),
        false,
    );

    let (next, decision) = tune_startup_prefetch_concurrency(
        45,
        100,
        true,
        &mut state,
        startup_prefetch_window(45, 1_000_000, 0, false, 200),
        false,
    );

    assert_eq!(next, 38);
    assert_eq!(decision, StartupPrefetchAdjustment::DropSlow);
}

#[test]
fn startup_prefetch_tuner_holds_when_latency_spikes_without_goodput_regression() {
    let mut state = StartupPrefetchTuningState::new();
    let _ = tune_startup_prefetch_concurrency(
        40,
        100,
        true,
        &mut state,
        startup_prefetch_window(40, 2_000_000, 0, false, 50),
        false,
    );

    let (next, decision) = tune_startup_prefetch_concurrency(
        45,
        100,
        true,
        &mut state,
        startup_prefetch_window(45, 2_100_000, 0, false, 200),
        false,
    );

    assert_eq!(next, 45);
    assert_eq!(decision, StartupPrefetchAdjustment::Hold);
}

#[test]
fn startup_prefetch_tuner_holds_without_enough_gain() {
    let mut state = StartupPrefetchTuningState::new();
    let _ = tune_startup_prefetch_concurrency(
        20,
        100,
        true,
        &mut state,
        startup_prefetch_window(20, 2_000_000, 0, false, 50),
        false,
    );

    let (next, decision) = tune_startup_prefetch_concurrency(
        25,
        100,
        true,
        &mut state,
        startup_prefetch_window(25, 2_100_000, 0, false, 55),
        false,
    );

    assert_eq!(next, 25);
    assert_eq!(decision, StartupPrefetchAdjustment::Hold);
}

#[test]
fn startup_prefetch_tuner_holds_under_resource_pressure() {
    let mut state = StartupPrefetchTuningState::new();

    let (next, decision) = tune_startup_prefetch_concurrency(
        20,
        100,
        true,
        &mut state,
        startup_prefetch_window(20, 2_000_000, 0, false, 50),
        true,
    );

    assert_eq!(next, 20);
    assert_eq!(decision, StartupPrefetchAdjustment::Hold);
}

#[test]
fn startup_prefetch_tuner_rate_limit_halves_with_specific_reason() {
    let mut state = StartupPrefetchTuningState::new();

    let (next, decision) = tune_startup_prefetch_concurrency(
        80,
        100,
        true,
        &mut state,
        startup_prefetch_window(80, 2_000_000, 1, true, 50),
        false,
    );

    assert_eq!(next, 40);
    assert_eq!(decision, StartupPrefetchAdjustment::RateLimited);
}

#[test]
fn startup_prefetch_tuner_treats_retry_pressure_as_backoff_signal() {
    let mut state = StartupPrefetchTuningState::new();

    let (next, decision) = tune_startup_prefetch_concurrency(
        250,
        1_000,
        true,
        &mut state,
        startup_prefetch_window_with_retries(250, 8_000_000, 0, 3, false, 80),
        false,
    );

    assert_eq!(next, 125);
    assert_eq!(decision, StartupPrefetchAdjustment::DropFast);
}

#[test]
fn startup_prefetch_rate_limit_hold_pauses_new_spawns() {
    let plan = StartupPrefetchConcurrencyPlan {
        max_concurrency: 100,
        effective_concurrency: 100,
        initial_concurrency: 20,
        adaptive: true,
        source: "auto",
        reason: "many_small_blobs_rtt_bound",
    };
    let mut controller = AdaptiveStartupPrefetch::new(plan);
    controller.record(&StartupPrefetchTaskReport {
        inserted: false,
        size_bytes: 1,
        retry_count: 0,
        duration_ms: 50,
        status: Some(StatusCode::TOO_MANY_REQUESTS),
        retry_after: Some(std::time::Duration::from_secs(60)),
        error: Some("HTTP 429".to_string()),
    });
    controller.force_window_elapsed_for_test();

    let (decision, previous, next) = controller.maybe_adjust().expect("adjustment");

    assert_eq!(decision, StartupPrefetchAdjustment::RateLimited);
    assert_eq!(previous, 20);
    assert_eq!(next, 10);
    assert_eq!(controller.current(), 10);
    assert_eq!(controller.target_in_flight(), 0);
    assert!(
        controller.pause_remaining().expect("retry-after hold")
            > std::time::Duration::from_secs(50)
    );
}

#[test]
fn startup_prefetch_metrics_keep_ceiling_separate_from_initial() {
    let metrics = crate::serve::state::PrefetchMetrics::new();

    metrics.record_startup_plan(crate::serve::state::StartupPrefetchPlan {
        mode: "full_tag",
        total_unique_blobs: 5_000,
        target_blobs: 5_000,
        target_bytes: 5_000 * 4_096,
        max_concurrency: 100,
        effective_concurrency: 100,
        initial_concurrency: 20,
        concurrency_source: "auto",
        concurrency_reason: "many_small_blobs_rtt_bound",
    });

    let hints = metrics.metadata_hints();

    assert_eq!(
        hints
            .get("startup_prefetch_concurrency")
            .map(String::as_str),
        Some("100")
    );
    assert_eq!(
        hints
            .get("startup_prefetch_initial_concurrency")
            .map(String::as_str),
        Some("20")
    );
}

#[test]
fn startup_prefetch_tuner_disabled_when_not_adaptive() {
    let mut state = StartupPrefetchTuningState::new();

    let (next, decision) = tune_startup_prefetch_concurrency(
        16,
        16,
        false,
        &mut state,
        startup_prefetch_window(16, 2_000_000, 1, true, 50),
        true,
    );

    assert_eq!(next, 16);
    assert_eq!(decision, StartupPrefetchAdjustment::Disabled);
}

#[test]
fn startup_prefetch_tuner_can_recover_after_drop_fast() {
    let mut state = StartupPrefetchTuningState::new();
    let (dropped, decision) = tune_startup_prefetch_concurrency(
        80,
        100,
        true,
        &mut state,
        startup_prefetch_window(80, 2_000_000, 1, false, 50),
        false,
    );
    assert_eq!(dropped, 40);
    assert_eq!(decision, StartupPrefetchAdjustment::DropFast);

    let (next, decision) = tune_startup_prefetch_concurrency(
        dropped,
        100,
        true,
        &mut state,
        startup_prefetch_window(40, 2_200_000, 0, false, 60),
        false,
    );

    assert!(next > dropped);
    assert_eq!(decision, StartupPrefetchAdjustment::Increase);
}

#[test]
fn startup_prefetch_tuner_settles_after_initial_climb() {
    let mut state = StartupPrefetchTuningState::new();
    let mut current = 20;
    let windows = [
        (2_000_000, StartupPrefetchAdjustment::Increase),
        (2_500_000, StartupPrefetchAdjustment::Increase),
        (2_600_000, StartupPrefetchAdjustment::Increase),
        (2_620_000, StartupPrefetchAdjustment::Hold),
    ];

    for (bytes, expected) in windows {
        let (next, decision) = tune_startup_prefetch_concurrency(
            current,
            100,
            true,
            &mut state,
            startup_prefetch_window(current, bytes, 0, false, 50),
            false,
        );
        assert_eq!(decision, expected);
        current = next;
    }

    assert_eq!(current, 35);
}

#[test]
fn startup_prefetch_concurrency_caps_large_blobs() {
    let plan = adaptive_startup_prefetch_concurrency(1_000, false, 128, 128 * 16 * 1024 * 1024);

    assert_eq!(plan.effective_concurrency, 4);
    assert_eq!(plan.reason, "large_blobs");
}

#[test]
fn startup_prefetch_concurrency_caps_medium_blobs() {
    let plan = adaptive_startup_prefetch_concurrency(1_000, false, 128, 128 * 2 * 1024 * 1024);

    assert_eq!(plan.effective_concurrency, 32);
    assert_eq!(plan.initial_concurrency, 32);
    assert!(!plan.adaptive);
    assert_eq!(plan.reason, "medium_blobs");
}

#[test]
fn startup_prefetch_concurrency_uses_larger_budget_for_many_medium_blobs() {
    let plan = adaptive_startup_prefetch_concurrency(1_000, false, 1_024, 1_024 * 2 * 1024 * 1024);

    assert_eq!(plan.effective_concurrency, 96);
    assert_eq!(plan.initial_concurrency, 96);
    assert!(plan.adaptive);
    assert_eq!(plan.reason, "many_medium_blobs_io_bound");
}

#[test]
fn startup_prefetch_candidates_preserve_blob_order() {
    let blob_order = vec![
        BlobDescriptor {
            digest: "sha256:large-cas".to_string(),
            size_bytes: 4_096,
        },
        BlobDescriptor {
            digest: "sha256:ac".to_string(),
            size_bytes: 128,
        },
        BlobDescriptor {
            digest: "sha256:small-cas".to_string(),
            size_bytes: 1024,
        },
    ];
    let candidates = startup_prefetch_candidates(&blob_order);

    assert_eq!(candidates.ordered_blobs.len(), 3);
    assert_eq!(candidates.ordered_blobs[0].digest, "sha256:large-cas");
    assert_eq!(candidates.ordered_blobs[1].digest, "sha256:ac");
    assert_eq!(candidates.ordered_blobs[2].digest, "sha256:small-cas");
}

#[test]
fn background_blob_preload_candidates_fill_budget_without_count_or_blob_size_knobs() {
    let blobs = vec![
        BlobDescriptor {
            digest: "sha256:1".to_string(),
            size_bytes: 5,
        },
        BlobDescriptor {
            digest: "sha256:2".to_string(),
            size_bytes: 9,
        },
        BlobDescriptor {
            digest: "sha256:3".to_string(),
            size_bytes: 3,
        },
    ];
    let urls = HashMap::from([
        ("sha256:1".to_string(), "https://example.com/1".to_string()),
        ("sha256:2".to_string(), "https://example.com/2".to_string()),
        ("sha256:3".to_string(), "https://example.com/3".to_string()),
    ]);

    let selected = select_blob_preload_candidates(&blobs, 8, |digest| urls.get(digest).cloned());

    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].0.digest, "sha256:1");
    assert_eq!(selected[1].0.digest, "sha256:3");
}

#[test]
fn startup_prefetch_blobs_uses_whole_tag_when_it_fits() {
    let blobs = vec![
        BlobDescriptor {
            digest: "sha256:1".to_string(),
            size_bytes: 64,
        },
        BlobDescriptor {
            digest: "sha256:2".to_string(),
            size_bytes: 64,
        },
    ];

    let selected = startup_prefetch_blobs(&blobs, 1, 64, true);

    assert_eq!(selected.len(), blobs.len());
    assert_eq!(selected[0].digest, blobs[0].digest);
    assert_eq!(selected[1].digest, blobs[1].digest);
}

#[test]
fn startup_prefetch_targets_keep_blobs_without_preloaded_urls() {
    let blobs = vec![
        BlobDescriptor {
            digest: "sha256:1".to_string(),
            size_bytes: 64,
        },
        BlobDescriptor {
            digest: "sha256:2".to_string(),
            size_bytes: 64,
        },
    ];
    let cached_urls = HashMap::from([(
        "sha256:1".to_string(),
        "https://example.com/blob-1".to_string(),
    )]);

    let (targets, summary) =
        build_startup_prefetch_targets(&blobs, |digest| cached_urls.get(digest).cloned());

    assert_eq!(targets.len(), 2);
    assert_eq!(summary.cached_url_count, 1);
    assert_eq!(summary.unresolved_url_count, 1);
    assert_eq!(
        targets[0].cached_url.as_deref(),
        Some("https://example.com/blob-1")
    );
    assert!(targets[1].cached_url.is_none());
}

#[test]
fn startup_download_url_preload_stays_on_startup_slice() {
    let startup_blobs = vec![
        BlobDescriptor {
            digest: "sha256:1".to_string(),
            size_bytes: 128,
        },
        BlobDescriptor {
            digest: "sha256:2".to_string(),
            size_bytes: 256,
        },
    ];

    let selected = startup_download_url_preload_blobs(&startup_blobs);

    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].digest, "sha256:1");
    assert_eq!(selected[1].digest, "sha256:2");
}

#[test]
fn version_poll_interval_active_includes_jitter() {
    let base_ms = KV_VERSION_POLL_ACTIVE_SECS * 1000;
    let min = base_ms.saturating_sub(KV_VERSION_POLL_JITTER_MS);
    let max = base_ms + KV_VERSION_POLL_JITTER_MS;
    assert!(min < max);
    assert!(min >= 2000, "active poll min should be >= 2s");
    assert!(max <= 4000, "active poll max should be <= 4s");
}

#[test]
fn version_poll_interval_idle_includes_jitter() {
    let base_ms = KV_VERSION_POLL_IDLE_SECS * 1000;
    let min = base_ms.saturating_sub(KV_VERSION_POLL_JITTER_MS);
    let max = base_ms + KV_VERSION_POLL_JITTER_MS;
    assert!(min < max);
    assert!(min >= 29000, "idle poll min should be >= 29s");
    assert!(max <= 31000, "idle poll max should be <= 31s");
}

#[test]
fn version_change_detection_detects_new_id() {
    let last: Option<String> = Some("old-id".to_string());
    let new: Option<&str> = Some("new-id");
    let changed = match (&last, new) {
        (Some(old), Some(new_val)) => old != new_val,
        (None, Some(_)) => true,
        _ => false,
    };
    assert!(changed);
}

#[test]
fn version_change_detection_ignores_same_id() {
    let last: Option<String> = Some("same-id".to_string());
    let new: Option<&str> = Some("same-id");
    let changed = match (&last, new) {
        (Some(old), Some(new_val)) => old != new_val,
        (None, Some(_)) => true,
        _ => false,
    };
    assert!(!changed);
}

#[test]
fn version_change_detection_triggers_on_first_id() {
    let last: Option<String> = None;
    let new: Option<&str> = Some("first-id");
    let changed = match (&last, new) {
        (Some(old), Some(new_val)) => old != new_val,
        (None, Some(_)) => true,
        _ => false,
    };
    assert!(changed);
}

#[test]
fn version_refresh_cooldown_prevents_rapid_refreshes() {
    let cooldown_ms = KV_VERSION_REFRESH_COOLDOWN.as_millis() as u64;
    assert!(
        cooldown_ms >= 10_000,
        "refresh cooldown should be >= 10s to prevent storms"
    );
    assert!(
        cooldown_ms > KV_VERSION_POLL_ACTIVE_SECS * 1000,
        "cooldown must exceed active poll interval"
    );
}

#[test]
fn version_change_detection_ignores_none_to_none() {
    let last: Option<String> = None;
    let new: Option<&str> = None;
    let changed = match (&last, new) {
        (Some(old), Some(new_val)) => old != new_val,
        (None, Some(_)) => true,
        _ => false,
    };
    assert!(!changed);
}
