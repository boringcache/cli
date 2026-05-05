use crate::api::client::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci::sha256_hex;
use crate::ci_detection::{CiRunContext, CiSourceRefType};
use crate::tag_utils::TagResolver;
use dashmap::DashMap;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::sync::{Mutex, Notify, RwLock, mpsc};

mod blob_locator;
mod blob_read_cache;
mod kv_pending;
mod kv_published_index;
mod metrics;
mod oci_negative_cache;
mod session_summary;
mod skip_rules;
mod upload_sessions;

pub use blob_locator::*;
pub use blob_read_cache::*;
pub use kv_pending::*;
pub use kv_published_index::*;
pub use metrics::*;
pub use oci_negative_cache::*;
pub use session_summary::*;
pub use skip_rules::*;
pub use upload_sessions::*;

pub use crate::serve::engines::oci::manifest_cache::OciManifestCacheEntry;

const PROXY_DEBUG_ENV: &str = "BORINGCACHE_PROXY_DEBUG";
static PROXY_DIAGNOSTICS_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HttpTransportConfig {
    pub mode: &'static str,
    pub http2_enabled: bool,
    pub h2_initial_stream_window_bytes: Option<u32>,
    pub h2_initial_connection_window_bytes: Option<u32>,
    pub h2_max_concurrent_streams: Option<u32>,
}

impl HttpTransportConfig {
    pub fn h1_only() -> Self {
        Self {
            mode: "h1",
            http2_enabled: false,
            h2_initial_stream_window_bytes: None,
            h2_initial_connection_window_bytes: None,
            h2_max_concurrent_streams: None,
        }
    }

    pub fn h1_h2c_auto(
        h2_initial_stream_window_bytes: u32,
        h2_initial_connection_window_bytes: u32,
        h2_max_concurrent_streams: u32,
    ) -> Self {
        Self {
            mode: "h1+h2c-auto",
            http2_enabled: true,
            h2_initial_stream_window_bytes: Some(h2_initial_stream_window_bytes),
            h2_initial_connection_window_bytes: Some(h2_initial_connection_window_bytes),
            h2_max_concurrent_streams: Some(h2_max_concurrent_streams),
        }
    }
}

pub fn set_diagnostics_enabled(enabled: bool) {
    PROXY_DIAGNOSTICS_ENABLED.store(enabled, Ordering::Release);
}

pub fn diagnostics_enabled() -> bool {
    PROXY_DIAGNOSTICS_ENABLED.load(Ordering::Acquire)
        || log::log_enabled!(log::Level::Debug)
        || crate::config::env_bool(PROXY_DEBUG_ENV)
}

#[derive(Clone)]
pub struct AppState {
    pub api_client: ApiClient,
    pub workspace: String,
    pub started_at: Instant,
    pub cache_session_summary_id: String,
    pub runtime_temp_dir: PathBuf,
    pub kv_blob_temp_dir: PathBuf,
    pub oci_upload_temp_dir: PathBuf,
    pub read_only: bool,
    pub tag_resolver: TagResolver,
    pub configured_human_tags: Vec<String>,
    pub registry_root_tag: String,
    pub registry_restore_root_tags: Vec<String>,
    pub oci_alias_promotion_refs: Vec<String>,
    pub proxy_metadata_hints: BTreeMap<String, String>,
    pub proxy_skip_rules: Arc<Vec<ProxySkipRule>>,
    pub proxy_ci_run_context: Option<CiRunContext>,
    pub fail_on_cache_error: bool,
    pub oci_hydration_policy: crate::serve::OciHydrationPolicy,
    pub http_transport: HttpTransportConfig,
    pub blob_locator: Arc<RwLock<BlobLocatorCache>>,
    pub upload_sessions: Arc<RwLock<UploadSessionStore>>,
    pub kv_pending: Arc<RwLock<KvPendingStore>>,
    pub kv_flush_lock: Arc<Mutex<()>>,
    pub kv_lookup_inflight: Arc<DashMap<String, Arc<Notify>>>,
    pub oci_lookup_inflight: Arc<DashMap<String, Arc<Notify>>>,
    pub oci_negative_cache: Arc<OciNegativeCache>,
    pub singleflight_metrics: Arc<SingleflightMetrics>,
    pub kv_last_put: Arc<AtomicU64>,
    pub kv_backlog_rejects: Arc<AtomicU64>,
    pub kv_replication_enqueue_deferred: Arc<AtomicU64>,
    pub kv_replication_flush_ok: Arc<AtomicU64>,
    pub kv_replication_flush_conflict: Arc<AtomicU64>,
    pub kv_replication_flush_error: Arc<AtomicU64>,
    pub kv_replication_flush_permanent: Arc<AtomicU64>,
    pub kv_replication_queue_depth: Arc<AtomicU64>,
    pub kv_replication_work_tx: mpsc::Sender<KvReplicationWork>,
    pub kv_next_flush_at: Arc<RwLock<Option<Instant>>>,
    pub kv_flush_scheduled: Arc<AtomicBool>,
    pub kv_published_index: Arc<RwLock<KvPublishedIndex>>,
    pub kv_flushing: Arc<RwLock<Option<KvFlushingSnapshot>>>,
    pub shutdown_requested: Arc<AtomicBool>,
    pub kv_recent_misses: Arc<DashMap<String, Instant>>,
    pub kv_miss_generations: Arc<DashMap<String, u64>>,
    pub blob_read_cache: Arc<BlobReadCache>,
    pub blob_read_metrics: Arc<BlobReadMetrics>,
    pub oci_body_metrics: Arc<OciBodyMetrics>,
    pub oci_engine_diagnostics: Arc<OciEngineDiagnostics>,
    pub prefetch_metrics: Arc<PrefetchMetrics>,
    pub kv_blob_upload_metrics: Arc<KvBlobUploadMetrics>,
    pub skip_rule_metrics: Arc<ProxySkipRuleMetrics>,
    pub blob_download_max_concurrency: usize,
    pub blob_prefetch_max_concurrency: usize,
    pub blob_prefetch_concurrency_from_env: bool,
    pub blob_download_semaphore: Arc<tokio::sync::Semaphore>,
    pub blob_prefetch_semaphore: Arc<tokio::sync::Semaphore>,
    pub cache_ops: Arc<super::cache_registry::cache_ops::Aggregator>,
    pub oci_manifest_cache: Arc<DashMap<String, Arc<OciManifestCacheEntry>>>,
    pub backend_breaker: Arc<BackendCircuitBreaker>,
    pub prefetch_complete: Arc<AtomicBool>,
    pub prefetch_complete_notify: Arc<Notify>,
    pub prefetch_error: Arc<RwLock<Option<String>>>,
}

impl AppState {
    pub fn proxy_metadata_hint(&self, key: &str) -> Option<String> {
        self.proxy_metadata_hints
            .get(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub fn ci_provider(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .map(|context| context.provider.clone())
    }

    pub fn ci_run_uid(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .map(|context| context.run_uid.clone())
    }

    pub fn ci_run_attempt(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .and_then(|context| context.run_attempt.clone())
    }

    pub fn ci_ref_type(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .map(|context| match context.source_ref_type {
                CiSourceRefType::Branch => "branch".to_string(),
                CiSourceRefType::Tag => "tag".to_string(),
                CiSourceRefType::PullRequest => "pull-request".to_string(),
                CiSourceRefType::Other => "other".to_string(),
            })
    }

    pub fn ci_ref_name(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .and_then(|context| context.source_ref_name.clone())
    }

    pub fn ci_default_branch(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .and_then(|context| context.default_branch.clone())
    }

    pub fn ci_pr_number(&self) -> Option<u32> {
        self.proxy_ci_run_context
            .as_ref()
            .and_then(|context| context.pull_request_number)
    }

    pub fn ci_commit_sha(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .and_then(|context| context.commit_sha.clone())
    }

    pub fn ci_run_started_at(&self) -> Option<String> {
        self.proxy_ci_run_context
            .as_ref()
            .and_then(|context| context.run_started_at.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_flag_and_env_enable_proxy_diagnostics() {
        let _guard = crate::test_env::lock();
        crate::test_env::remove_var(PROXY_DEBUG_ENV);
        set_diagnostics_enabled(false);

        assert_eq!(diagnostics_enabled(), log::log_enabled!(log::Level::Debug));

        set_diagnostics_enabled(true);
        assert!(diagnostics_enabled());

        set_diagnostics_enabled(false);
        crate::test_env::set_var(PROXY_DEBUG_ENV, "1");
        assert!(diagnostics_enabled());

        crate::test_env::remove_var(PROXY_DEBUG_ENV);
        set_diagnostics_enabled(false);
    }

    #[test]
    fn ref_tag_is_deterministic() {
        let tag1 = ref_tag("my-cache", "main");
        let tag2 = ref_tag("my-cache", "main");
        assert_eq!(tag1, tag2);
        assert_eq!(
            tag1,
            format!(
                "oci_ref_my-cache__main__{}",
                &sha256_hex(b"my-cache:main")[..16]
            )
        );
    }

    #[test]
    fn ref_tag_differs_for_different_inputs() {
        let tag1 = ref_tag("my-cache", "main");
        let tag2 = ref_tag("my-cache", "dev");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn legacy_ref_tag_keeps_hash_only_shape() {
        let tag = legacy_ref_tag_for_input("my-cache:main");
        assert_eq!(tag, format!("oci_ref_{}", sha256_hex(b"my-cache:main")));
    }

    #[test]
    fn digest_tag_strips_prefix() {
        let tag = digest_tag("sha256:abc123def456");
        assert_eq!(tag, "oci_digest_abc123def456");
    }

    #[test]
    fn digest_tag_handles_bare_hex() {
        let tag = digest_tag("abc123def456");
        assert_eq!(tag, "oci_digest_abc123def456");
    }

    #[test]
    fn blob_locator_cache_insert_and_get() {
        let mut cache = BlobLocatorCache::default();
        cache.insert(
            "myimg",
            "sha256:abc",
            BlobLocatorEntry {
                cache_entry_id: "entry1".into(),
                size_bytes: 100,
                download_url: None,
                download_url_cached_at: None,
            },
        );
        let entry = cache.get("myimg", "sha256:abc").unwrap();
        assert_eq!(entry.cache_entry_id, "entry1");
        assert_eq!(entry.size_bytes, 100);
        assert!(cache.get("myimg", "sha256:xyz").is_none());
        assert!(cache.get("other", "sha256:abc").is_none());
    }

    #[test]
    fn find_by_digest_prefers_non_empty_finalized_session() {
        let now = Instant::now();
        let mut store = UploadSessionStore::default();

        store.create(UploadSession {
            id: "empty".to_string(),
            name: "img".to_string(),
            temp_path: PathBuf::from("/tmp/empty"),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: 0,
            finalized_digest: Some("sha256:abc".to_string()),
            finalized_size: Some(0),
            created_at: now,
        });

        store.create(UploadSession {
            id: "filled".to_string(),
            name: "img".to_string(),
            temp_path: PathBuf::from("/tmp/filled"),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: 0,
            finalized_digest: Some("sha256:abc".to_string()),
            finalized_size: Some(128),
            created_at: now,
        });

        let selected = store.find_by_digest("sha256:abc").expect("digest session");
        assert_eq!(selected.id, "filled");
        assert_eq!(selected.finalized_size, Some(128));
    }

    #[tokio::test]
    async fn blob_read_cache_insert_and_get_round_trip() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        let digest = format!("sha256:{}", "a".repeat(64));

        let inserted = cache.insert(&digest, b"hello-world").await.expect("insert");
        assert!(inserted);

        let handle = cache.get_handle(&digest).await.expect("cache hit");
        let mut file = tokio::fs::File::open(handle.path())
            .await
            .expect("open cached bytes");
        if handle.offset() > 0 {
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(handle.offset()))
                .await
                .expect("seek cached bytes");
        }
        use tokio::io::AsyncReadExt;
        let mut bytes = vec![0u8; handle.size_bytes() as usize];
        file.read_exact(&mut bytes)
            .await
            .expect("read cached bytes");
        assert_eq!(bytes, b"hello-world");
    }

    #[tokio::test]
    async fn blob_read_cache_insert_and_promote_zero_byte_round_trip() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        let insert_digest = format!("sha256:{}", "d".repeat(64));
        let promote_digest = format!("sha256:{}", "e".repeat(64));

        let inserted = cache.insert(&insert_digest, b"").await.expect("insert");
        assert!(inserted);

        let insert_handle = cache
            .get_handle(&insert_digest)
            .await
            .expect("zero-byte insert cache hit");
        assert_eq!(insert_handle.size_bytes(), 0);

        let source_path = temp_dir.path().join("zero-byte-source");
        tokio::fs::write(&source_path, b"")
            .await
            .expect("zero-byte source");
        let promoted = cache
            .promote(&promote_digest, &source_path, 0)
            .await
            .expect("promote");
        assert!(promoted);
        assert!(!source_path.exists());

        let promote_handle = cache
            .get_handle(&promote_digest)
            .await
            .expect("zero-byte promote cache hit");
        assert_eq!(promote_handle.size_bytes(), 0);

        let reloaded = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("reloaded blob cache");
        let reloaded_insert = reloaded
            .get_handle(&insert_digest)
            .await
            .expect("reloaded zero-byte insert");
        let reloaded_promote = reloaded
            .get_handle(&promote_digest)
            .await
            .expect("reloaded zero-byte promote");
        assert_eq!(reloaded_insert.size_bytes(), 0);
        assert_eq!(reloaded_promote.size_bytes(), 0);
    }

    #[tokio::test]
    async fn blob_read_cache_concurrent_insert_round_trip_integrity() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = Arc::new(
            BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 16 * 1024 * 1024)
                .expect("blob cache"),
        );

        let mut tasks = Vec::new();
        for idx in 0..64u64 {
            let cache = Arc::clone(&cache);
            tasks.push(tokio::spawn(async move {
                let digest = format!("sha256:{:064x}", idx + 1);
                let payload = format!("blob-{idx}-{}", "x".repeat(1024)).into_bytes();
                let inserted = cache.insert(&digest, &payload).await.expect("insert");
                assert!(inserted);
                (digest, payload)
            }));
        }

        let mut expected = Vec::new();
        for task in tasks {
            expected.push(task.await.expect("task"));
        }

        for (digest, payload) in expected {
            let handle = cache.get_handle(&digest).await.expect("cache hit");
            let mut file = tokio::fs::File::open(handle.path())
                .await
                .expect("open cached bytes");
            if handle.offset() > 0 {
                use tokio::io::AsyncSeekExt;
                file.seek(std::io::SeekFrom::Start(handle.offset()))
                    .await
                    .expect("seek cached bytes");
            }
            use tokio::io::AsyncReadExt;
            let mut bytes = vec![0u8; handle.size_bytes() as usize];
            file.read_exact(&mut bytes)
                .await
                .expect("read cached bytes");
            assert_eq!(bytes, payload);
        }
    }

    #[tokio::test]
    async fn blob_read_cache_concurrent_promote_round_trip_integrity() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = Arc::new(
            BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 16 * 1024 * 1024)
                .expect("blob cache"),
        );

        let mut tasks = Vec::new();
        for idx in 0..64u64 {
            let cache = Arc::clone(&cache);
            let source_path = temp_dir.path().join(format!("source-{idx}"));
            let payload = format!("promote-{idx}-{}", "y".repeat(1024)).into_bytes();
            tokio::fs::write(&source_path, &payload)
                .await
                .expect("source write");
            tasks.push(tokio::spawn(async move {
                let digest = format!("sha256:{:064x}", idx + 1000);
                let promoted = cache
                    .promote(&digest, &source_path, payload.len() as u64)
                    .await
                    .expect("promote");
                assert!(promoted);
                (digest, payload)
            }));
        }

        let mut expected = Vec::new();
        for task in tasks {
            expected.push(task.await.expect("task"));
        }

        for (digest, payload) in expected {
            let handle = cache.get_handle(&digest).await.expect("cache hit");
            let mut file = tokio::fs::File::open(handle.path())
                .await
                .expect("open cached bytes");
            if handle.offset() > 0 {
                use tokio::io::AsyncSeekExt;
                file.seek(std::io::SeekFrom::Start(handle.offset()))
                    .await
                    .expect("seek cached bytes");
            }
            use tokio::io::AsyncReadExt;
            let mut bytes = vec![0u8; handle.size_bytes() as usize];
            file.read_exact(&mut bytes)
                .await
                .expect("read cached bytes");
            assert_eq!(bytes, payload);
        }
    }

    #[tokio::test]
    async fn blob_read_cache_promote_moves_source_file() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        let digest = format!("sha256:{}", "b".repeat(64));
        let source_path = temp_dir.path().join("source-blob");
        tokio::fs::write(&source_path, b"promoted")
            .await
            .expect("source");

        let promoted = cache
            .promote(&digest, &source_path, 8)
            .await
            .expect("promote");
        assert!(promoted);
        assert!(!source_path.exists());
        let handle = cache.get_handle(&digest).await.expect("cache hit");
        let expected_path = temp_dir.path().join("blob-cache").join("b".repeat(64));
        assert_eq!(handle.offset(), 0);
        assert_eq!(handle.path(), expected_path.as_path());
    }

    #[tokio::test]
    async fn blob_read_cache_rejects_invalid_digest() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");

        let inserted = cache
            .insert("not-a-digest", b"invalid")
            .await
            .expect("insert call");
        assert!(!inserted);
        assert!(cache.get_handle("not-a-digest").await.is_none());
    }

    #[tokio::test]
    async fn blob_read_cache_lease_prevents_segment_eviction() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache =
            BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 90).expect("blob cache");
        let digest_a = format!("sha256:{}", "1".repeat(64));
        let digest_b = format!("sha256:{}", "2".repeat(64));
        let digest_c = format!("sha256:{}", "3".repeat(64));

        assert!(
            cache
                .insert(&digest_a, b"aaaaaaaa")
                .await
                .expect("insert a")
        );
        let lease = cache.lease_handle(&digest_a).await.expect("lease a");
        assert!(lease.offset() > 0);

        assert!(
            cache
                .insert(&digest_b, b"bbbbbbbb")
                .await
                .expect("insert b")
        );
        assert!(
            cache.get_handle(&digest_a).await.is_some(),
            "leased segment entry should survive eviction"
        );

        drop(lease);
        assert!(
            cache
                .insert(&digest_c, b"cccccccc")
                .await
                .expect("insert c")
        );
        assert!(
            cache.get_handle(&digest_a).await.is_none(),
            "released segment entry should become evictable"
        );
        assert!(cache.get_handle(&digest_c).await.is_some());
    }

    #[test]
    fn kv_published_index_set_empty_incomplete_forces_refresh() {
        let mut index = KvPublishedIndex::default();
        let mut entries = HashMap::new();
        entries.insert(
            "ac/key".to_string(),
            BlobDescriptor {
                digest: format!("sha256:{}", "a".repeat(64)),
                size_bytes: 1,
            },
        );
        index.update(
            entries.clone(),
            entries.into_values().collect(),
            "cache-entry".to_string(),
        );
        assert!(index.is_complete());
        assert!(index.last_refresh_at().is_some());

        index.set_empty_incomplete();
        assert_eq!(index.entry_count(), 0);
        assert!(index.cache_entry_id().is_none());
        assert!(!index.is_complete());
        assert!(index.last_refresh_at().is_none());
    }

    #[test]
    fn kv_published_index_restores_download_urls_with_remaining_ttl() {
        let mut entries = HashMap::new();
        let digest = format!("sha256:{}", "a".repeat(64));
        entries.insert(
            "ac/key".to_string(),
            BlobDescriptor {
                digest: digest.clone(),
                size_bytes: 1,
            },
        );

        let mut index = KvPublishedIndex::default();
        index.update(
            entries.clone(),
            entries.values().cloned().collect(),
            "cache-entry".to_string(),
        );
        index.set_download_url(digest.clone(), "https://example.com/blob".to_string());
        let snapshot = index.snapshot_download_urls();
        assert_eq!(
            snapshot.get(&digest).map(String::as_str),
            Some("https://example.com/blob")
        );

        let mut restored = KvPublishedIndex::default();
        restored.update(
            entries.clone(),
            entries.values().cloned().collect(),
            "cache-entry".to_string(),
        );
        restored.restore_download_urls(snapshot.clone(), std::time::Duration::from_secs(30));
        assert_eq!(
            restored.download_url(&digest),
            Some("https://example.com/blob")
        );

        let mut expired = KvPublishedIndex::default();
        expired.update(
            entries.clone(),
            entries.values().cloned().collect(),
            "cache-entry".to_string(),
        );
        expired.restore_download_urls(snapshot, DOWNLOAD_URL_TTL);
        assert!(expired.download_url(&digest).is_none());
    }

    #[tokio::test]
    async fn blob_read_cache_follower_timeout_clears_stale_inflight_entry() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        let digest = format!("sha256:{}", "c".repeat(64));
        let key = BlobReadCache::normalize_digest_hex(&digest).expect("normalized digest");

        {
            cache.inflight.insert(key.clone(), Arc::new(Notify::new()));
        }

        let inserted = cache
            .insert(&digest, b"stale-flight")
            .await
            .expect("insert");
        assert!(!inserted);
        assert!(!cache.inflight.contains_key(&key));

        let inserted_after_cleanup = cache
            .insert(&digest, b"stale-flight")
            .await
            .expect("insert after cleanup");
        assert!(inserted_after_cleanup);
    }
}
