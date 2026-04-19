use crate::api::client::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci::sha256_hex;
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
mod upload_sessions;

pub use blob_locator::*;
pub use blob_read_cache::*;
pub use kv_pending::*;
pub use kv_published_index::*;
pub use metrics::*;
pub use upload_sessions::*;

pub fn diagnostics_enabled() -> bool {
    log::log_enabled!(log::Level::Debug)
}

#[derive(Clone)]
pub struct AppState {
    pub api_client: ApiClient,
    pub workspace: String,
    pub runtime_temp_dir: PathBuf,
    pub kv_blob_temp_dir: PathBuf,
    pub oci_upload_temp_dir: PathBuf,
    pub read_only: bool,
    pub tag_resolver: TagResolver,
    pub configured_human_tags: Vec<String>,
    pub registry_root_tag: String,
    pub fail_on_cache_error: bool,
    pub oci_hydration_policy: crate::serve::OciHydrationPolicy,
    pub blob_locator: Arc<RwLock<BlobLocatorCache>>,
    pub upload_sessions: Arc<RwLock<UploadSessionStore>>,
    pub kv_pending: Arc<RwLock<KvPendingStore>>,
    pub kv_flush_lock: Arc<Mutex<()>>,
    pub kv_lookup_inflight: Arc<DashMap<String, Arc<Notify>>>,
    pub oci_lookup_inflight: Arc<DashMap<String, Arc<Notify>>>,
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
    pub prefetch_metrics: Arc<PrefetchMetrics>,
    pub blob_download_max_concurrency: usize,
    pub blob_download_semaphore: Arc<tokio::sync::Semaphore>,
    pub blob_prefetch_semaphore: Arc<tokio::sync::Semaphore>,
    pub cache_ops: Arc<super::cache_registry::cache_ops::Aggregator>,
    pub oci_manifest_cache: Arc<DashMap<String, Arc<OciManifestCacheEntry>>>,
    pub backend_breaker: Arc<BackendCircuitBreaker>,
    pub prefetch_complete: Arc<AtomicBool>,
    pub prefetch_complete_notify: Arc<Notify>,
    pub prefetch_error: Arc<RwLock<Option<String>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_tag_is_deterministic() {
        let tag1 = ref_tag("my-cache", "main");
        let tag2 = ref_tag("my-cache", "main");
        assert_eq!(tag1, tag2);
        assert!(tag1.starts_with("oci_ref_"));
        assert_eq!(tag1.len(), 8 + 64);
    }

    #[test]
    fn ref_tag_differs_for_different_inputs() {
        let tag1 = ref_tag("my-cache", "main");
        let tag2 = ref_tag("my-cache", "dev");
        assert_ne!(tag1, tag2);
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
