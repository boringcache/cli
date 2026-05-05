use super::*;
use crate::api::client::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::git::GitContext;
use crate::platform::Platform;
use crate::serve::engines::oci::{PresentBlob, PresentBlobSource, ensure_manifest_blobs_present};
use crate::serve::state::{
    BlobLocatorCache, BlobReadCache, BlobReadMetrics, KvPendingStore, KvPublishedIndex,
    UploadSession, UploadSessionBody, UploadSessionStore, legacy_ref_tag_for_input,
    ref_tag_for_input,
};
use crate::tag_utils::TagResolver;
use axum::body::Bytes;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

fn test_state() -> AppState {
    let (kv_replication_work_tx, _kv_replication_work_rx) =
        tokio::sync::mpsc::channel(crate::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY);
    let runtime_temp_dir = std::env::temp_dir().join(format!(
        "boringcache-handler-runtime-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(runtime_temp_dir.join("kv-blobs")).expect("kv blob temp dir");
    std::fs::create_dir_all(runtime_temp_dir.join("oci-uploads")).expect("oci upload temp dir");
    AppState {
        api_client: ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("api client"),
        workspace: "boringcache/benchmarks".to_string(),
        started_at: Instant::now(),
        cache_session_summary_id: "proxy-summary-test".to_string(),
        runtime_temp_dir: runtime_temp_dir.clone(),
        kv_blob_temp_dir: runtime_temp_dir.join("kv-blobs"),
        oci_upload_temp_dir: runtime_temp_dir.join("oci-uploads"),
        read_only: false,
        tag_resolver: TagResolver::new(None, GitContext::default(), false),
        configured_human_tags: Vec::new(),
        registry_root_tag: "registry".to_string(),
        registry_restore_root_tags: vec!["registry".to_string()],
        oci_alias_promotion_refs: Vec::new(),
        proxy_metadata_hints: std::collections::BTreeMap::new(),
        proxy_skip_rules: Arc::new(Vec::new()),
        proxy_ci_run_context: None,
        fail_on_cache_error: true,
        oci_hydration_policy: crate::serve::OciHydrationPolicy::MetadataOnly,
        http_transport: crate::serve::state::HttpTransportConfig::h1_h2c_auto(
            2 * 1024 * 1024,
            32 * 1024 * 1024,
            1024,
        ),
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(tokio::sync::Mutex::new(())),
        kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        oci_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        oci_negative_cache: Arc::new(crate::serve::state::OciNegativeCache::new()),
        singleflight_metrics: Arc::new(crate::serve::state::SingleflightMetrics::new()),
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
                std::env::temp_dir().join(format!(
                    "boringcache-handler-blob-cache-{}",
                    uuid::Uuid::new_v4()
                )),
                2 * 1024 * 1024 * 1024,
            )
            .expect("blob read cache"),
        ),
        blob_read_metrics: Arc::new(BlobReadMetrics::new()),
        oci_body_metrics: Arc::new(crate::serve::state::OciBodyMetrics::new()),
        oci_engine_diagnostics: Arc::new(crate::serve::state::OciEngineDiagnostics::new()),
        prefetch_metrics: Arc::new(crate::serve::state::PrefetchMetrics::new()),
        kv_blob_upload_metrics: Arc::new(crate::serve::state::KvBlobUploadMetrics::new()),
        skip_rule_metrics: Arc::new(crate::serve::state::ProxySkipRuleMetrics::new()),
        blob_download_max_concurrency: 16,
        blob_prefetch_max_concurrency: 2,
        blob_prefetch_concurrency_from_env: false,
        blob_download_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        blob_prefetch_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
        cache_ops: Arc::new(crate::serve::cache_registry::cache_ops::Aggregator::new()),
        oci_manifest_cache: Arc::new(dashmap::DashMap::new()),
        backend_breaker: Arc::new(crate::serve::state::BackendCircuitBreaker::new()),
        prefetch_complete: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        prefetch_complete_notify: Arc::new(tokio::sync::Notify::new()),
        prefetch_error: Arc::new(RwLock::new(None)),
    }
}

async fn write_temp_upload_file(contents: &[u8]) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("boringcache-upload-test-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.expect("temp dir");
    let path = dir.join("blob.bin");
    tokio::fs::write(&path, contents).await.expect("temp file");
    path
}

async fn read_upload_session_body(session: &UploadSession) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let mut file = tokio::fs::File::open(session.body_path())
        .await
        .expect("open upload session body");
    if session.body_offset() > 0 {
        file.seek(std::io::SeekFrom::Start(session.body_offset()))
            .await
            .expect("seek upload session body");
    }
    let mut bytes = vec![0u8; session.body_size() as usize];
    file.read_exact(&mut bytes)
        .await
        .expect("read upload session body");
    bytes
}

mod dispatch;
mod manifest;
mod routes;
mod tags;
mod uploads;
