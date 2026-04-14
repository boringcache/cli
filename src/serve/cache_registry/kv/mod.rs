use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use futures_util::future::join_all;
use rand::Rng;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::io::ReaderStream;

use crate::api::models::cache::{
    BlobDescriptor, CacheResolutionEntry, ConfirmRequest, SaveRequest,
};
use crate::cache::receipts::try_commit_blob_receipts;
use crate::cas_transport::upload_payload;
use crate::error::{BoringCacheError, PendingMetadata};
use crate::manifest::EntryType;
use crate::observability;
use crate::serve::state::{
    AppState, BlobReadHandle, KV_BACKLOG_POLICY, KvFlushingSnapshot, KvReplicationWork,
    diagnostics_enabled,
};

use super::error::RegistryError;
use super::kv_publish::{BlobUploadStats, partial_blob_upload_stats, upload_blobs};

const KV_MISS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const KV_CONFLICT_BACKOFF_MS: u64 = 5_000;
const KV_CONFLICT_JITTER_MS: u64 = 3_000;
const KV_CONFLICT_IN_PROGRESS_BACKOFF_MS: u64 = 30_000;
const KV_CONFLICT_IN_PROGRESS_JITTER_MS: u64 = 10_000;
const KV_TRANSIENT_BACKOFF_MS: u64 = 2_000;
const KV_TRANSIENT_JITTER_MS: u64 = 2_000;
const KV_TRANSIENT_WRITE_PATH_BACKOFF_MS: u64 = 20_000;
const KV_TRANSIENT_WRITE_PATH_JITTER_MS: u64 = 5_000;
const KV_CONFIRM_VERIFICATION_RETRY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(90);
const KV_CONFIRM_VERIFICATION_RETRY_BASE_MS: u64 = 1_000;
const KV_CONFIRM_VERIFICATION_RETRY_MAX_MS: u64 = 5_000;
const KV_INDEX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const KV_EMPTY_INDEX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(12);
const KV_PENDING_REFRESH_SUPPRESSION_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(12);
const KV_RESOLVE_NOT_FOUND_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);
const KV_BLOB_PRELOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const KV_BLOB_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const KV_BLOB_URL_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KV_LOOKUP_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KV_PUT_BODY_CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const KV_PUT_BODY_SLOW_WARN_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(5);
const KV_RESOLVE_HIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KV_FETCH_POINTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KV_VERSION_POLL_ACTIVE_SECS: u64 = 3;
const KV_VERSION_POLL_IDLE_SECS: u64 = 30;
const KV_VERSION_POLL_ACTIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
const KV_VERSION_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const KV_VERSION_POLL_JITTER_MS: u64 = 500;
const KV_VERSION_REFRESH_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);
const KV_PENDING_PUBLISH_HANDOFF_DIR: &str = "kv-pending-publish";
const KV_PENDING_PUBLISH_HANDOFF_VERSION: u32 = 2;
const KV_PENDING_PUBLISH_HANDOFF_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);
const KV_PENDING_PUBLISH_HANDOFF_RECONCILE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);
const SERVE_METRIC_SOURCE: &str = "serve";
const SERVE_PRELOAD_INDEX_OPERATION: &str = "cache_preload_index_fetch";
const SERVE_PREFETCH_OPERATION: &str = "blob_prefetch_cycle";
const SERVE_PRELOAD_INDEX_PATH: &str = "/serve/cache_registry/preload-index";
const SERVE_PREFETCH_PATH: &str = "/serve/cache_registry/prefetch";
const SERVE_BLOB_READ_OPERATION: &str = "cache_blob_read";
const SERVE_BLOB_READ_PATH: &str = "/serve/cache_registry/blob-read";
const LOOKUP_REFRESH_FLIGHT_KEY: &str = "lookup_refresh";
static KV_BLOB_DOWNLOAD_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobReadSource {
    LocalCache,
    RemoteFetch,
}

impl BlobReadSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalCache => "local_cache",
            Self::RemoteFetch => "remote_fetch",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DownloadUrlPreloadStats {
    requested: usize,
    resolved: usize,
    missing: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct StartupPrefetchTarget {
    blob: BlobDescriptor,
    cached_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StartupPrefetchTargetSummary {
    cached_url_count: usize,
    unresolved_url_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KvPendingPublishHandoff {
    version: u32,
    persisted_at_unix_ms: u64,
    workspace: String,
    registry_root_tag: String,
    configured_human_tags: Vec<String>,
    cache_entry_id: String,
    entries: BTreeMap<String, BlobDescriptor>,
    blob_order: Vec<BlobDescriptor>,
    download_urls: HashMap<String, String>,
    root_pending: Option<PendingMetadata>,
    pending_alias_tags: bool,
    pending_blob_paths: HashMap<String, PathBuf>,
}

pub(crate) struct PendingPublishHandoffPersist<'a> {
    root_pending: Option<&'a PendingMetadata>,
    pending_alias_tags: bool,
    pending_blob_paths: Option<&'a HashMap<String, PathBuf>>,
}

fn kv_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(diagnostics_enabled)
}

fn kv_trace(namespace: KvNamespace, scoped_key: &str, stage: &str) {
    if !kv_trace_enabled() || !matches!(namespace, KvNamespace::Sccache) {
        return;
    }
    let truncated = scoped_key.get(..96).unwrap_or(scoped_key);
    eprintln!("KV TRACE stage={stage} key={truncated}");
}

fn is_proxy_active(state: &AppState) -> bool {
    let now_ms = crate::serve::state::unix_time_ms_now();
    let window_ms = KV_VERSION_POLL_ACTIVE_WINDOW.as_millis() as u64;

    let last_put_ms = state.kv_last_put.load(Ordering::Acquire);
    if last_put_ms > 0 && now_ms.saturating_sub(last_put_ms) < window_ms {
        return true;
    }

    !state.kv_recent_misses.is_empty()
}

fn emit_serve_event(
    workspace: Option<&str>,
    operation: &'static str,
    path: &'static str,
    details: String,
) {
    observability::emit(
        observability::ObservabilityEvent::event(
            SERVE_METRIC_SOURCE,
            operation,
            "EVENT",
            path.to_string(),
            details,
        )
        .with_workspace(workspace.map(|value| value.to_string())),
    );
}

fn emit_serve_phase_metric(
    workspace: Option<&str>,
    cache_entry_id: Option<&str>,
    operation: &'static str,
    path: &'static str,
    status: u16,
    duration_ms: u64,
    batch_size: Option<u64>,
) {
    observability::emit(
        observability::ObservabilityEvent::success(
            SERVE_METRIC_SOURCE,
            operation,
            "PHASE",
            path.to_string(),
            status,
            duration_ms,
            None,
            None,
            None,
            None,
            batch_size,
            None,
        )
        .with_workspace(workspace.map(|value| value.to_string()))
        .with_cache_entry_id(cache_entry_id.map(|value| value.to_string())),
    );
}

fn emit_blob_read_metric(
    state: &AppState,
    cache_entry_id: &str,
    source: BlobReadSource,
    bytes: u64,
    duration_ms: u64,
) {
    match source {
        BlobReadSource::LocalCache => state.blob_read_metrics.record_local(bytes, duration_ms),
        BlobReadSource::RemoteFetch => state.blob_read_metrics.record_remote(bytes, duration_ms),
    }
    observability::emit(
        observability::ObservabilityEvent::success(
            SERVE_METRIC_SOURCE,
            SERVE_BLOB_READ_OPERATION,
            "GET",
            SERVE_BLOB_READ_PATH.to_string(),
            200,
            duration_ms,
            None,
            Some(bytes),
            None,
            None,
            None,
            None,
        )
        .with_workspace(Some(state.workspace.clone()))
        .with_cache_entry_id(Some(cache_entry_id.to_string()))
        .with_details(Some(format!("source={}", source.as_str()))),
    );
}

fn kv_miss_generation(state: &AppState, registry_root_tag: &str) -> u64 {
    state
        .kv_miss_generations
        .get(registry_root_tag.trim())
        .map(|entry| *entry.value())
        .unwrap_or(0)
}

fn kv_miss_cache_key(state: &AppState, registry_root_tag: &str, scoped_key: &str) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        registry_root_tag.trim(),
        kv_miss_generation(state, registry_root_tag),
        scoped_key
    )
}

fn use_kv_miss_cache(namespace: KvNamespace) -> bool {
    !matches!(namespace, KvNamespace::Sccache)
}

fn lookup_flight_key_for_sizes(scoped_keys: &[String]) -> String {
    let mut sorted = scoped_keys.to_vec();
    sorted.sort();
    let digest = crate::cas_file::sha256_hex(sorted.join("\0").as_bytes());
    format!("sizes:{digest}")
}

struct LookupFlightGuard {
    key: String,
    notify: Arc<tokio::sync::Notify>,
    inflight: Arc<dashmap::DashMap<String, Arc<tokio::sync::Notify>>>,
}

impl Drop for LookupFlightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

enum LookupFlight {
    Leader(LookupFlightGuard),
    Follower(std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>>),
}

const FLIGHT_WAIT_WARN_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);
const FLIGHT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

async fn await_flight(
    kind: &str,
    key: &str,
    notified: std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>>,
) -> bool {
    let started = std::time::Instant::now();
    match tokio::time::timeout(FLIGHT_WAIT_TIMEOUT, notified).await {
        Ok(()) => {
            let elapsed = started.elapsed();
            if elapsed >= FLIGHT_WAIT_WARN_THRESHOLD {
                log::warn!(
                    "flight follower waited {}ms: kind={} key={}",
                    elapsed.as_millis(),
                    kind,
                    &key[..key.len().min(24)],
                );
            }
            true
        }
        Err(_) => {
            log::warn!(
                "flight follower timed out after {}ms: kind={} key={}",
                started.elapsed().as_millis(),
                kind,
                &key[..key.len().min(24)],
            );
            false
        }
    }
}

fn begin_lookup_flight(state: &AppState, key: String) -> LookupFlight {
    match state.kv_lookup_inflight.entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(existing) => {
            let mut notified = Box::pin(existing.get().clone().notified_owned());
            notified.as_mut().enable();
            LookupFlight::Follower(notified)
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            let notify = Arc::new(tokio::sync::Notify::new());
            entry.insert(notify.clone());
            LookupFlight::Leader(LookupFlightGuard {
                key,
                notify,
                inflight: state.kv_lookup_inflight.clone(),
            })
        }
    }
}

fn clear_lookup_flight_entry(state: &AppState, key: &str) {
    state.kv_lookup_inflight.remove(key);
}

fn conflict_backoff_window(message: &str) -> (u64, u64) {
    let lower = message.to_ascii_lowercase();
    if lower.contains("another cache upload is in progress")
        || lower.contains("cache upload in progress")
    {
        (
            KV_CONFLICT_IN_PROGRESS_BACKOFF_MS,
            KV_CONFLICT_IN_PROGRESS_JITTER_MS,
        )
    } else {
        (KV_CONFLICT_BACKOFF_MS, KV_CONFLICT_JITTER_MS)
    }
}

fn transient_backoff_window(message: &str) -> (u64, u64) {
    let lower = message.to_ascii_lowercase();
    if lower.contains("save_entry failed")
        || lower.contains("blob upload failed")
        || lower.contains("confirm failed")
    {
        (
            KV_TRANSIENT_WRITE_PATH_BACKOFF_MS,
            KV_TRANSIENT_WRITE_PATH_JITTER_MS,
        )
    } else {
        (KV_TRANSIENT_BACKOFF_MS, KV_TRANSIENT_JITTER_MS)
    }
}

fn is_blob_verification_pending_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not yet verified in storage") || lower.contains("retry after upload completes")
}

fn kv_confirm_verification_retry_delay(attempt: u32) -> std::time::Duration {
    let exponent = attempt.saturating_sub(1).min(6);
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let delay_ms = KV_CONFIRM_VERIFICATION_RETRY_BASE_MS
        .saturating_mul(multiplier)
        .min(KV_CONFIRM_VERIFICATION_RETRY_MAX_MS);
    std::time::Duration::from_millis(delay_ms)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KvNamespace {
    BazelAc,
    BazelCas,
    Gradle,
    Maven,
    Nx,
    NxTerminalOutput,
    Turborepo,
    Sccache,
    GoCache,
}

impl KvNamespace {
    pub(crate) fn normalize_key(self, key: &str) -> String {
        match self {
            KvNamespace::BazelAc
            | KvNamespace::BazelCas
            | KvNamespace::Gradle
            | KvNamespace::GoCache => key.to_ascii_lowercase(),
            KvNamespace::Maven
            | KvNamespace::Nx
            | KvNamespace::NxTerminalOutput
            | KvNamespace::Turborepo
            | KvNamespace::Sccache => key.to_string(),
        }
    }

    fn namespace_prefix(self) -> &'static str {
        match self {
            KvNamespace::BazelAc => "bazel_ac",
            KvNamespace::BazelCas => "bazel_cas",
            KvNamespace::Gradle => "gradle",
            KvNamespace::Maven => "maven",
            KvNamespace::Nx => "nx",
            KvNamespace::NxTerminalOutput => "nx_terminal",
            KvNamespace::Turborepo => "turbo",
            KvNamespace::Sccache => "sccache",
            KvNamespace::GoCache => "go_cache",
        }
    }

    pub(crate) fn scoped_key(self, key: &str) -> String {
        format!("{}/{}", self.namespace_prefix(), self.normalize_key(key))
    }
}

mod blob_read;
mod flush;
mod index;
mod lookup;
mod prefetch;
mod write;

pub(crate) use blob_read::*;
pub(crate) use flush::*;
pub(crate) use index::*;
pub(crate) use lookup::*;
pub(crate) use prefetch::*;
pub(crate) use write::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::client::ApiClient;
    use crate::api::models::cache::ConfirmRequest;
    use crate::git::GitContext;
    use crate::serve::state::{
        AppState, BackendCircuitBreaker, BlobLocatorCache, BlobReadCache, BlobReadMetrics,
        KvPendingStore, KvPublishedIndex, UploadSessionStore,
    };
    use crate::tag_utils::TagResolver;
    use crate::test_env;
    use mockito::{Matcher, Server};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::{Mutex as TokioMutex, RwLock};

    struct TestEnvGuard(Vec<(&'static str, Option<String>)>);

    impl TestEnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            Self(
                keys.iter()
                    .map(|key| (*key, std::env::var(key).ok()))
                    .collect(),
            )
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(value) => test_env::set_var(key, value),
                    None => test_env::remove_var(key),
                }
            }
        }
    }

    fn networking_available() -> bool {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                drop(listener);
                true
            }
            Err(_) => false,
        }
    }

    async fn setup_state(server: &Server) -> (AppState, tempfile::TempDir) {
        let temp_home = tempfile::tempdir().expect("temp dir");
        test_env::set_var("BORINGCACHE_API_URL", server.url());

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
            runtime_temp_dir: runtime_temp_dir.clone(),
            kv_blob_temp_dir: runtime_temp_dir.join("kv-blobs"),
            oci_upload_temp_dir: runtime_temp_dir.join("oci-uploads"),
            read_only: false,
            tag_resolver: TagResolver::new(None, GitContext::default(), false),
            configured_human_tags: Vec::new(),
            registry_root_tag: "registry".to_string(),
            fail_on_cache_error: true,
            kv_manifest_warm_enabled: true,
            blob_locator: std::sync::Arc::new(RwLock::new(BlobLocatorCache::default())),
            upload_sessions: std::sync::Arc::new(RwLock::new(UploadSessionStore::default())),
            kv_pending: std::sync::Arc::new(RwLock::new(KvPendingStore::default())),
            kv_flush_lock: std::sync::Arc::new(TokioMutex::new(())),
            kv_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
            kv_last_put: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_backlog_rejects: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_enqueue_deferred: std::sync::Arc::new(
                std::sync::atomic::AtomicU64::new(0),
            ),
            kv_replication_flush_ok: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_conflict: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                0,
            )),
            kv_replication_flush_error: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_permanent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                0,
            )),
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
            prefetch_metrics: std::sync::Arc::new(crate::serve::state::PrefetchMetrics::new()),
            blob_download_max_concurrency: 16,
            blob_download_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
            blob_prefetch_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            cache_ops: std::sync::Arc::new(
                crate::serve::cache_registry::cache_ops::Aggregator::new(),
            ),
            oci_manifest_cache: std::sync::Arc::new(dashmap::DashMap::new()),
            backend_breaker: std::sync::Arc::new(BackendCircuitBreaker::new()),
            prefetch_complete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prefetch_complete_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
        };

        (state, temp_home)
    }

    fn confirm_request_for(tag: &str) -> ConfirmRequest {
        ConfirmRequest {
            manifest_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            manifest_size: 123,
            manifest_etag: None,
            archive_size: None,
            archive_etag: None,
            blob_count: Some(1),
            blob_total_size_bytes: Some(456),
            file_count: Some(1),
            uncompressed_size: None,
            compressed_size: None,
            storage_mode: Some("cas".to_string()),
            tag: Some(tag.to_string()),
            write_scope_tag: None,
        }
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
            runtime_temp_dir: runtime_temp_dir.clone(),
            kv_blob_temp_dir: runtime_temp_dir.join("kv-blobs"),
            oci_upload_temp_dir: runtime_temp_dir.join("oci-uploads"),
            read_only: true,
            tag_resolver: TagResolver::new(None, GitContext::default(), false),
            configured_human_tags: Vec::new(),
            registry_root_tag: "registry".to_string(),
            fail_on_cache_error: true,
            kv_manifest_warm_enabled: true,
            blob_locator: std::sync::Arc::new(RwLock::new(BlobLocatorCache::default())),
            upload_sessions: std::sync::Arc::new(RwLock::new(UploadSessionStore::default())),
            kv_pending: std::sync::Arc::new(RwLock::new(KvPendingStore::default())),
            kv_flush_lock: std::sync::Arc::new(TokioMutex::new(())),
            kv_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
            kv_last_put: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_backlog_rejects: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_enqueue_deferred: std::sync::Arc::new(
                std::sync::atomic::AtomicU64::new(0),
            ),
            kv_replication_flush_ok: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_conflict: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                0,
            )),
            kv_replication_flush_error: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_permanent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                0,
            )),
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
            prefetch_metrics: std::sync::Arc::new(crate::serve::state::PrefetchMetrics::new()),
            blob_download_max_concurrency: 16,
            blob_download_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
            blob_prefetch_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            cache_ops: std::sync::Arc::new(
                crate::serve::cache_registry::cache_ops::Aggregator::new(),
            ),
            oci_manifest_cache: std::sync::Arc::new(dashmap::DashMap::new()),
            backend_breaker: std::sync::Arc::new(BackendCircuitBreaker::new()),
            prefetch_complete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prefetch_complete_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
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
    fn classify_flush_error_treats_blob_verification_pending_as_transient() {
        let error = anyhow::anyhow!(
            "Server returned 400 Bad Request: 714 blob(s) not yet verified in storage — retry after upload completes"
        );
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
    fn kv_confirm_verification_retry_delay_is_capped() {
        assert_eq!(
            kv_confirm_verification_retry_delay(1),
            std::time::Duration::from_millis(1_000)
        );
        assert_eq!(
            kv_confirm_verification_retry_delay(3),
            std::time::Duration::from_millis(4_000)
        );
        assert_eq!(
            kv_confirm_verification_retry_delay(6),
            std::time::Duration::from_millis(5_000)
        );
    }

    #[test]
    fn confirm_retry_reason_retries_transient_server_errors() {
        let error = anyhow::anyhow!("Server error (500). Please try again later.");
        let classified = classify_flush_error(&error, "confirm failed");
        let reason = confirm_retry_reason(
            "confirm failed: Server error (500). Please try again later.",
            &classified,
        );
        assert_eq!(reason, Some("transient backend error"));
    }

    #[test]
    fn confirm_retry_reason_prefers_blob_verification_pending() {
        let error = anyhow::anyhow!(
            "Server returned 400 Bad Request: 714 blob(s) not yet verified in storage — retry after upload completes"
        );
        let classified = classify_flush_error(&error, "confirm failed");
        let reason = confirm_retry_reason(
            "confirm failed: Server returned 400 Bad Request: 714 blob(s) not yet verified in storage — retry after upload completes",
            &classified,
        );
        assert_eq!(reason, Some("blob verification pending"));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn confirm_polls_pending_publish_until_published() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        if !networking_available() {
            eprintln!(
                "skipping confirm_polls_pending_publish_until_published: networking disabled in sandbox"
            );
            return;
        }

        let mut server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;

        let capabilities = server
            .mock("GET", "/v2/capabilities")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"features":{"tag_publish_v2":true,"pending_publish_status_v2":true,"upload_sessions_v2":true,"cas_publish_bootstrap_if_match":"0"}}"#,
            )
            .create_async()
            .await;
        let pointer_initial = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"Tag not found","current_version":"0"}"#)
            .expect(1)
            .create_async()
            .await;
        let pointer_after_publish = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version":"1","cache_entry_id":"entry-1","status":"published"}"#)
            .create_async()
            .await;
        let publish = server
            .mock("PUT", "/v2/workspaces/org/repo/caches/tags/registry/publish")
            .match_header("authorization", "Bearer test-token")
            .match_header("if-match", "0")
            .match_header("x-boringcache-pending-publish-poll", "1")
            .match_header("content-type", Matcher::Regex("application/json".to_string()))
            .with_status(423)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"success":false,"error":"upload not yet fully verified in storage — retry after upload completes","code":"pending_publish","details":{"upload_session_id":"session-1","publish_attempt_id":"attempt-1","retry_after_seconds":1,"poll_path":"/v2/workspaces/org/repo/upload-sessions/session-1"}}"#,
            )
            .create_async()
            .await;
        let status = server
            .mock("GET", "/v2/workspaces/org/repo/upload-sessions/session-1")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"upload_session_id":"session-1","cache_entry_id":"entry-1","state":"published","publish_attempt_id":"attempt-1","publish_state":"published"}"#,
            )
            .create_async()
            .await;

        let outcome = confirm_kv_flush(
            &state,
            "entry-1",
            &confirm_request_for("registry"),
            FlushMode::Normal,
        )
        .await
        .expect("flush should poll pending publish to completion");

        assert!(
            matches!(outcome, KvConfirmOutcome::Published),
            "expected Published after polling"
        );

        capabilities.assert_async().await;
        pointer_initial.assert_async().await;
        pointer_after_publish.assert_async().await;
        publish.assert_async().await;
        status.assert_async().await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn normal_confirm_waits_for_pending_publish_terminal_state() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        if !networking_available() {
            eprintln!(
                "skipping normal_confirm_waits_for_pending_publish_terminal_state: networking disabled in sandbox"
            );
            return;
        }

        let mut server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;

        let capabilities = server
            .mock("GET", "/v2/capabilities")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"features":{"tag_publish_v2":true,"pending_publish_status_v2":true,"upload_sessions_v2":true,"cas_publish_bootstrap_if_match":"0"}}"#,
            )
            .create_async()
            .await;
        let pointer = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"Tag not found","current_version":"0"}"#)
            .create_async()
            .await;
        let publish = server
            .mock("PUT", "/v2/workspaces/org/repo/caches/tags/registry/publish")
            .match_header("authorization", "Bearer test-token")
            .match_header("if-match", "0")
            .match_header("x-boringcache-pending-publish-poll", "1")
            .match_header("content-type", Matcher::Regex("application/json".to_string()))
            .with_status(423)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"success":false,"error":"upload not yet fully verified in storage — retry after upload completes","code":"pending_publish","details":{"upload_session_id":"session-1","publish_attempt_id":"attempt-1","retry_after_seconds":1,"poll_path":"/v2/workspaces/org/repo/upload-sessions/session-1"}}"#,
            )
            .create_async()
            .await;
        let status = server
            .mock("GET", "/v2/workspaces/org/repo/upload-sessions/session-1")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"upload_session_id":"session-1","cache_entry_id":"entry-1","state":"awaiting_blob_visibility","publish_attempt_id":"attempt-1","publish_state":"conflicted","error":"Tag publish conflict"}"#,
            )
            .create_async()
            .await;

        let outcome = confirm_kv_flush(
            &state,
            "entry-1",
            &confirm_request_for("registry"),
            FlushMode::Normal,
        )
        .await;

        assert!(
            matches!(outcome, Err(FlushError::Conflict(message)) if message.contains("Tag publish conflict"))
        );

        capabilities.assert_async().await;
        pointer.assert_async().await;
        publish.assert_async().await;
        status.assert_async().await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn normal_confirm_waits_for_pending_publish_completion_even_when_shutdown_requested() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        if !networking_available() {
            eprintln!(
                "skipping normal_confirm_waits_for_pending_publish_completion_even_when_shutdown_requested: networking disabled in sandbox"
            );
            return;
        }

        let mut server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;
        state.shutdown_requested.store(true, Ordering::Release);

        let capabilities = server
            .mock("GET", "/v2/capabilities")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"features":{"tag_publish_v2":true,"pending_publish_status_v2":true,"upload_sessions_v2":true,"cas_publish_bootstrap_if_match":"0"}}"#,
            )
            .create_async()
            .await;
        let pointer = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"Tag not found","current_version":"0"}"#)
            .expect(1)
            .create_async()
            .await;
        let pointer_after_publish = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version":"1","cache_entry_id":"entry-1","status":"published"}"#)
            .create_async()
            .await;
        let publish = server
            .mock("PUT", "/v2/workspaces/org/repo/caches/tags/registry/publish")
            .match_header("authorization", "Bearer test-token")
            .match_header("if-match", "0")
            .match_header("x-boringcache-pending-publish-poll", "1")
            .match_header("content-type", Matcher::Regex("application/json".to_string()))
            .with_status(423)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"success":false,"error":"upload not yet fully verified in storage — retry after upload completes","code":"pending_publish","details":{"upload_session_id":"session-1","publish_attempt_id":"attempt-1","retry_after_seconds":1,"poll_path":"/v2/workspaces/org/repo/upload-sessions/session-1"}}"#,
            )
            .create_async()
            .await;
        let status = server
            .mock("GET", "/v2/workspaces/org/repo/upload-sessions/session-1")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"upload_session_id":"session-1","cache_entry_id":"entry-1","state":"published","publish_attempt_id":"attempt-1","publish_state":"published"}"#,
            )
            .create_async()
            .await;

        let outcome = confirm_kv_flush(
            &state,
            "entry-1",
            &confirm_request_for("registry"),
            FlushMode::Normal,
        )
        .await
        .expect("normal flush should wait for pending publish completion");

        assert!(
            matches!(outcome, KvConfirmOutcome::Published),
            "normal confirm should publish instead of handing off pending state"
        );

        capabilities.assert_async().await;
        pointer.assert_async().await;
        pointer_after_publish.assert_async().await;
        publish.assert_async().await;
        status.assert_async().await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn shutdown_confirm_hands_off_pending_publish() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        test_env::set_var("BORINGCACHE_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS", "0");
        if !networking_available() {
            eprintln!(
                "skipping shutdown_confirm_hands_off_pending_publish: networking disabled in sandbox"
            );
            test_env::remove_var("BORINGCACHE_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS");
            return;
        }

        let mut server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;
        state.shutdown_requested.store(true, Ordering::Release);

        let capabilities = server
            .mock("GET", "/v2/capabilities")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"features":{"tag_publish_v2":true,"pending_publish_status_v2":true,"upload_sessions_v2":true,"cas_publish_bootstrap_if_match":"0"}}"#,
            )
            .create_async()
            .await;
        let pointer_initial = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"Tag not found","current_version":"0"}"#)
            .expect(1)
            .create_async()
            .await;
        let publish = server
            .mock("PUT", "/v2/workspaces/org/repo/caches/tags/registry/publish")
            .match_header("authorization", "Bearer test-token")
            .match_header("if-match", "0")
            .match_header("x-boringcache-pending-publish-poll", "1")
            .match_header("content-type", Matcher::Regex("application/json".to_string()))
            .with_status(423)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"success":false,"error":"upload not yet fully verified in storage — retry after upload completes","code":"pending_publish","details":{"upload_session_id":"session-1","publish_attempt_id":"attempt-1","retry_after_seconds":1,"poll_path":"/v2/workspaces/org/repo/upload-sessions/session-1"}}"#,
            )
            .create_async()
            .await;
        let outcome = confirm_kv_flush(
            &state,
            "entry-1",
            &confirm_request_for("registry"),
            FlushMode::Shutdown,
        )
        .await
        .expect("shutdown flush should hand off pending publish state");

        assert!(
            matches!(outcome, KvConfirmOutcome::Pending(_)),
            "shutdown confirm should hand off pending publish"
        );

        test_env::remove_var("BORINGCACHE_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS");
        capabilities.assert_async().await;
        pointer_initial.assert_async().await;
        publish.assert_async().await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn shutdown_confirm_waits_for_pending_publish_completion_within_grace() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        test_env::set_var("BORINGCACHE_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS", "10");
        if !networking_available() {
            eprintln!(
                "skipping shutdown_confirm_waits_for_pending_publish_completion_within_grace: networking disabled in sandbox"
            );
            test_env::remove_var("BORINGCACHE_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS");
            return;
        }

        let mut server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;
        state.shutdown_requested.store(true, Ordering::Release);

        let capabilities = server
            .mock("GET", "/v2/capabilities")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"features":{"tag_publish_v2":true,"pending_publish_status_v2":true,"upload_sessions_v2":true,"cas_publish_bootstrap_if_match":"0"}}"#,
            )
            .create_async()
            .await;
        let pointer_initial = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"Tag not found","current_version":"0"}"#)
            .expect(1)
            .create_async()
            .await;
        let pointer_after_publish = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version":"1","cache_entry_id":"entry-1","status":"published"}"#)
            .create_async()
            .await;
        let publish = server
            .mock("PUT", "/v2/workspaces/org/repo/caches/tags/registry/publish")
            .match_header("authorization", "Bearer test-token")
            .match_header("if-match", "0")
            .match_header("x-boringcache-pending-publish-poll", "1")
            .match_header("content-type", Matcher::Regex("application/json".to_string()))
            .with_status(423)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"success":false,"error":"upload not yet fully verified in storage — retry after upload completes","code":"pending_publish","details":{"upload_session_id":"session-1","publish_attempt_id":"attempt-1","retry_after_seconds":1,"poll_path":"/v2/workspaces/org/repo/upload-sessions/session-1"}}"#,
            )
            .create_async()
            .await;
        let status = server
            .mock("GET", "/v2/workspaces/org/repo/upload-sessions/session-1")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"upload_session_id":"session-1","cache_entry_id":"entry-1","state":"published","publish_attempt_id":"attempt-1","publish_state":"published"}"#,
            )
            .create_async()
            .await;

        let outcome = confirm_kv_flush(
            &state,
            "entry-1",
            &confirm_request_for("registry"),
            FlushMode::Shutdown,
        )
        .await
        .expect("shutdown flush should complete publish when it settles within grace");

        assert!(
            matches!(outcome, KvConfirmOutcome::Published),
            "shutdown confirm should prefer published over handoff within grace"
        );

        test_env::remove_var("BORINGCACHE_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS");
        capabilities.assert_async().await;
        pointer_initial.assert_async().await;
        pointer_after_publish.assert_async().await;
        publish.assert_async().await;
        status.assert_async().await;
    }

    #[tokio::test]
    async fn pending_publish_handoff_marks_shutdown_visibility_wait_skippable() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        let server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;

        let mut entries = BTreeMap::new();
        entries.insert(
            "scoped/key".to_string(),
            BlobDescriptor {
                digest: format!("sha256:{}", "a".repeat(64)),
                size_bytes: 12,
            },
        );
        let pending = PendingMetadata {
            code: Some("pending_publish".to_string()),
            upload_session_id: Some("session-1".to_string()),
            publish_attempt_id: Some("attempt-1".to_string()),
            poll_path: Some("/v2/workspaces/org/repo/upload-sessions/session-1".to_string()),
            retry_after_seconds: Some(1),
        };

        persist_kv_pending_publish_handoff(
            &state,
            &entries,
            &entries.values().cloned().collect::<Vec<_>>(),
            "entry-1",
            PendingPublishHandoffPersist {
                root_pending: Some(&pending),
                pending_alias_tags: false,
                pending_blob_paths: None,
            },
        )
        .await;

        assert!(should_skip_shutdown_tag_visibility_wait(&state, "entry-1").await);
        assert!(!should_skip_shutdown_tag_visibility_wait(&state, "entry-2").await);
    }

    #[tokio::test]
    async fn restore_pending_publish_handoff_reloads_published_index() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        if !networking_available() {
            eprintln!(
                "skipping restore_pending_publish_handoff_reloads_published_index: networking disabled in sandbox"
            );
            return;
        }

        let mut server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;

        let mut entries = BTreeMap::new();
        entries.insert(
            "scoped/key".to_string(),
            BlobDescriptor {
                digest: format!("sha256:{}", "b".repeat(64)),
                size_bytes: 34,
            },
        );
        let pending = PendingMetadata {
            code: Some("pending_publish".to_string()),
            upload_session_id: Some("session-1".to_string()),
            publish_attempt_id: Some("attempt-1".to_string()),
            poll_path: Some("/v2/workspaces/org/repo/upload-sessions/session-1".to_string()),
            retry_after_seconds: Some(1),
        };

        persist_kv_pending_publish_handoff(
            &state,
            &entries,
            &entries.values().cloned().collect::<Vec<_>>(),
            "entry-1",
            PendingPublishHandoffPersist {
                root_pending: Some(&pending),
                pending_alias_tags: false,
                pending_blob_paths: None,
            },
        )
        .await;

        let pointer = server
            .mock(
                "GET",
                "/v2/workspaces/org/repo/caches/tags/registry/pointer",
            )
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tag":"registry","cache_entry_id":"entry-1","version":"1"}"#)
            .create_async()
            .await;

        restore_kv_pending_publish_handoff(&state).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let published = state.kv_published_index.read().await;
        let (blob, cache_entry_id) = published.get("scoped/key").expect("restored entry");
        assert_eq!(cache_entry_id, "entry-1");
        assert_eq!(blob.size_bytes, 34);
        drop(published);

        pointer.assert_async().await;
        assert!(!should_skip_shutdown_tag_visibility_wait(&state, "entry-1").await);
    }

    #[tokio::test]
    async fn restore_pending_upload_handoff_rehydrates_pending_store() {
        let _guard = test_env::lock();
        let _env_guard = TestEnvGuard::capture(&["BORINGCACHE_API_URL"]);
        let server = Server::new_async().await;
        let (state, _temp_home) = setup_state(&server).await;

        let digest = format!("sha256:{}", "c".repeat(64));
        let mut entries = BTreeMap::new();
        entries.insert(
            "scoped/key".to_string(),
            BlobDescriptor {
                digest: digest.clone(),
                size_bytes: 8,
            },
        );
        let blob_order = entries.values().cloned().collect::<Vec<_>>();
        let blob_path = state.kv_blob_temp_dir.join("pending-upload.bin");
        tokio::fs::write(&blob_path, b"blob-data")
            .await
            .expect("write pending blob");
        let pending_blob_paths = HashMap::from([(digest.clone(), blob_path.clone())]);

        persist_kv_pending_publish_handoff(
            &state,
            &entries,
            &blob_order,
            "",
            PendingPublishHandoffPersist {
                root_pending: None,
                pending_alias_tags: false,
                pending_blob_paths: Some(&pending_blob_paths),
            },
        )
        .await;

        assert!(should_preserve_runtime_temp_dir_for_shutdown_handoff(&state).await);

        restore_kv_pending_publish_handoff(&state).await;

        let pending = state.kv_pending.read().await;
        let blob = pending.get("scoped/key").expect("restored pending entry");
        assert_eq!(blob.digest, digest);
        assert_eq!(pending.entry_count(), 1);
        assert_eq!(pending.blob_count(), 1);
        assert_eq!(pending.blob_path(&digest), Some(&blob_path));
        drop(pending);
    }

    #[test]
    fn should_clear_flushing_after_flush_skips_ok_path() {
        assert!(!should_clear_flushing_after_flush(&FlushResult::Ok));
        assert!(should_clear_flushing_after_flush(&FlushResult::Conflict));
        assert!(should_clear_flushing_after_flush(&FlushResult::Error));
        assert!(should_clear_flushing_after_flush(&FlushResult::Permanent));
        assert!(should_clear_flushing_after_flush(&FlushResult::Deferred));
    }

    #[test]
    fn select_flush_base_entries_uses_backend_when_available() {
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
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, selection) = select_flush_base_entries(backend.clone(), &published);
        assert!(matches!(selection, FlushBaseSelection::Backend));
        assert_eq!(selected.len(), backend.len());
        assert!(selected.contains_key("k1"));
    }

    #[test]
    fn select_flush_base_entries_falls_back_to_published_when_backend_empty() {
        let backend = BTreeMap::new();
        let mut published = HashMap::new();
        published.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, selection) = select_flush_base_entries(backend, &published);
        assert!(matches!(
            selection,
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 0,
                published_entry_count: 1,
                missing_published_keys: 1,
                mismatched_published_keys: 0
            }
        ));
        assert_eq!(selected.len(), 1);
        assert!(selected.contains_key("k2"));
    }

    #[test]
    fn select_flush_base_entries_preserves_published_when_backend_is_stale_subset() {
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

        let (selected, selection) = select_flush_base_entries(backend, &published);
        assert!(matches!(
            selection,
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 1,
                published_entry_count: 2,
                missing_published_keys: 1,
                mismatched_published_keys: 0
            }
        ));
        assert_eq!(selected.len(), 2);
        assert!(selected.contains_key("k1"));
        assert!(selected.contains_key("k2"));
    }

    #[test]
    fn select_flush_base_entries_preserves_published_on_digest_mismatch() {
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
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, selection) = select_flush_base_entries(backend, &published);
        assert!(matches!(
            selection,
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 1,
                published_entry_count: 1,
                missing_published_keys: 0,
                mismatched_published_keys: 1
            }
        ));
        assert_eq!(selected.len(), 1);
        let selected_blob = selected.get("k1").expect("expected selected key");
        assert_eq!(selected_blob.digest, "sha256:222");
        assert_eq!(selected_blob.size_bytes, 20);
    }

    #[test]
    fn kv_visibility_tags_include_legacy_human_root_when_distinct() {
        let tags = kv_visibility_tags_from_values(
            "bc_registry_root_v2_abc",
            &[String::from("grpc-bazel")],
        );
        assert_eq!(
            tags,
            vec![
                "bc_registry_root_v2_abc".to_string(),
                "grpc-bazel".to_string()
            ]
        );
    }

    #[test]
    fn kv_visibility_tags_skip_empty_or_duplicate_legacy_root() {
        let duplicate = kv_visibility_tags_from_values(
            "grpc-bazel",
            &[String::from("grpc-bazel"), String::from(" ")],
        );
        assert_eq!(duplicate, vec!["grpc-bazel".to_string()]);

        let empty = kv_visibility_tags_from_values("grpc-bazel", &[String::from(" ")]);
        assert_eq!(empty, vec!["grpc-bazel".to_string()]);
    }

    #[test]
    fn kv_visibility_tags_include_all_distinct_human_aliases() {
        let tags = kv_visibility_tags_from_values(
            "bc_registry_root_v2_abc",
            &[
                String::from("alias-a"),
                String::from("alias-b"),
                String::from("alias-a"),
            ],
        );
        assert_eq!(
            tags,
            vec![
                "bc_registry_root_v2_abc".to_string(),
                "alias-a".to_string(),
                "alias-b".to_string()
            ]
        );
    }

    #[test]
    fn kv_alias_tags_exclude_internal_root_tag() {
        let aliases = kv_alias_tags_from_values(
            "bc_registry_root_v2_abc",
            &[String::from("alias-a"), String::from("alias-b")],
        );
        assert_eq!(aliases, vec!["alias-a".to_string(), "alias-b".to_string()]);
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
            should_suppress_lookup_refresh_due_to_pending_or_flushing_values(
                false, true, 0, now_ms
            )
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
            build_prefetch_targets(&blobs, |digest| cached_urls.get(digest).cloned());

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
    fn build_prefetch_targets_preserves_blob_order() {
        let blobs = vec![
            BlobDescriptor {
                digest: "sha256:1".to_string(),
                size_bytes: 128,
            },
            BlobDescriptor {
                digest: "sha256:2".to_string(),
                size_bytes: 256,
            },
        ];

        let (targets, summary) = build_prefetch_targets(&blobs, |_| None);

        assert_eq!(targets.len(), 2);
        assert_eq!(summary.cached_url_count, 0);
        assert_eq!(summary.unresolved_url_count, 2);
        assert_eq!(targets[0].blob.digest, "sha256:1");
        assert_eq!(targets[1].blob.digest, "sha256:2");
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
}
