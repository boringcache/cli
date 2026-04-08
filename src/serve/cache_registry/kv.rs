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
use crate::cas_transport::upload_payload;
use crate::error::{BoringCacheError, PendingMetadata};
use crate::manifest::EntryType;
use crate::observability;
use crate::serve::state::{
    AppState, BlobReadHandle, KV_BACKLOG_POLICY, KvFlushingSnapshot, KvReplicationWork,
    diagnostics_enabled,
};
use crate::upload_receipts::try_commit_blob_receipts;

use super::error::RegistryError;
use super::kv_publish::{BlobUploadStats, upload_blobs};

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
const KV_BLOB_PRELOAD_MAX_BLOBS: usize = 2_000;
const KV_BLOB_PRELOAD_MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024;
const KV_BLOB_PRELOAD_MAX_BLOBS_ENV: &str = "BORINGCACHE_CACHE_PREFETCH_BATCH_MAX";
const KV_BLOB_PRELOAD_MAX_BLOB_BYTES_ENV: &str = "BORINGCACHE_CACHE_PREFETCH_MAX_BLOB_BYTES";
const KV_STARTUP_PREFETCH_MAX_BLOBS: usize = 2_048;
const KV_STARTUP_PREFETCH_MIN_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const KV_STARTUP_PREFETCH_MAX_BLOBS_ENV: &str = "BORINGCACHE_STARTUP_PREFETCH_MAX_BLOBS";
const KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV: &str =
    "BORINGCACHE_STARTUP_PREFETCH_MAX_TOTAL_BYTES";
const KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV: &str =
    "BORINGCACHE_BLOB_PREFETCH_MAX_INFLIGHT_BYTES";
const KV_BLOB_PRELOAD_SKIP_USED_PCT: u64 = 95;
const KV_VERSION_POLL_ACTIVE_SECS: u64 = 3;
const KV_VERSION_POLL_IDLE_SECS: u64 = 30;
const KV_VERSION_POLL_ACTIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
const KV_VERSION_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const KV_VERSION_POLL_JITTER_MS: u64 = 500;
const KV_VERSION_REFRESH_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);
const KV_PENDING_PUBLISH_HANDOFF_DIR: &str = "kv-pending-publish";
const KV_PENDING_PUBLISH_HANDOFF_VERSION: u32 = 1;
const KV_PENDING_PUBLISH_HANDOFF_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);
const KV_PENDING_PUBLISH_HANDOFF_RECONCILE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);
const SERVE_METRIC_SOURCE: &str = "serve";
const SERVE_PRELOAD_INDEX_OPERATION: &str = "cache_preload_index_fetch";
const SERVE_PREFETCH_OPERATION: &str = "blob_prefetch_cycle";
const SERVE_PRELOAD_INDEX_PATH: &str = "/serve/cache_registry/preload-index";
const SERVE_PREFETCH_PATH: &str = "/serve/cache_registry/prefetch";
const LOOKUP_REFRESH_FLIGHT_KEY: &str = "lookup_refresh";
static KV_BLOB_DOWNLOAD_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KvPendingPublishHandoff {
    version: u32,
    persisted_at_unix_ms: u64,
    workspace: String,
    registry_root_tag: String,
    configured_human_tags: Vec<String>,
    cache_entry_id: String,
    entries: BTreeMap<String, BlobDescriptor>,
    blob_order: Vec<BlobDescriptor>,
    root_pending: Option<PendingMetadata>,
    pending_alias_tags: bool,
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

fn parse_positive_usize_env(name: &str) -> Option<usize> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<usize>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
}

fn parse_positive_u64_env(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u64>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
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

pub(crate) async fn put_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    body: Body,
    put_status: StatusCode,
) -> Result<Response, RegistryError> {
    let put_start = std::time::Instant::now();
    let scoped_key = namespace.scoped_key(key);
    if state.read_only {
        state.cache_ops.record(
            namespace.into(),
            super::cache_ops::Op::Put,
            super::cache_ops::OpResult::Hit,
            false,
            0,
            put_start.elapsed().as_millis() as u64,
        );
        log::debug!("KV PUT {scoped_key}: ignored in read-only mode");
        return Ok((put_status, Body::empty()).into_response());
    }

    let use_miss_cache = use_kv_miss_cache(namespace);
    let put_probe = super::PutProbeGuard::start(&scoped_key);
    put_probe.stage("precheck_spool");
    let spool_limit = crate::serve::state::max_spool_bytes();
    {
        let pending = state.kv_pending.read().await;
        if pending.total_spool_bytes() >= spool_limit {
            state.kv_backlog_rejects.fetch_add(1, Ordering::AcqRel);
            state.cache_ops.record(
                namespace.into(),
                super::cache_ops::Op::Put,
                super::cache_ops::OpResult::Error,
                false,
                0,
                put_start.elapsed().as_millis() as u64,
            );
            return Err(RegistryError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("KV spool budget exceeded ({KV_BACKLOG_POLICY}), try again after flush"),
            ));
        }
    }

    put_probe.stage("read_body");
    let (path, blob_size, blob_digest) = write_body_to_temp_file(state, body, &put_probe).await?;

    if let Some(expected_digest) = expected_bazel_cas_blob_digest(namespace, key)
        && !blob_digest.eq_ignore_ascii_case(&expected_digest)
    {
        cleanup_temp_file(&path).await;
        return Err(RegistryError::new(
            StatusCode::BAD_REQUEST,
            format!("Bazel CAS digest mismatch: expected {expected_digest}, got {blob_digest}"),
        ));
    }

    let miss_key = kv_miss_cache_key(state, &state.registry_root_tag, &scoped_key);

    put_probe.stage("pending_lock");
    let (redundant, should_flush) = {
        let mut pending = state.kv_pending.write().await;
        let digest_exists = pending.blob_path(&blob_digest).is_some();
        let projected_spool = pending
            .total_spool_bytes()
            .saturating_add(if digest_exists { 0 } else { blob_size });
        if projected_spool > spool_limit {
            drop(pending);
            let _ = tokio::fs::remove_file(&path).await;
            state.kv_backlog_rejects.fetch_add(1, Ordering::AcqRel);
            state.cache_ops.record(
                namespace.into(),
                super::cache_ops::Op::Put,
                super::cache_ops::OpResult::Error,
                false,
                0,
                put_start.elapsed().as_millis() as u64,
            );
            return Err(RegistryError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("KV spool budget exceeded ({KV_BACKLOG_POLICY}), try again after flush"),
            ));
        }

        let redundant = pending.insert(
            scoped_key.clone(),
            BlobDescriptor {
                digest: blob_digest.clone(),
                size_bytes: blob_size,
            },
            path,
        );
        let should_flush = pending.blob_count() >= crate::serve::state::flush_blob_threshold()
            || pending.total_spool_bytes() >= crate::serve::state::FLUSH_SIZE_THRESHOLD;
        (redundant, should_flush)
    };
    put_probe.stage("pending_updated");
    if use_miss_cache {
        put_probe.stage("recent_miss_remove_wait");
        state.kv_recent_misses.remove(&miss_key);
        put_probe.stage("recent_miss_removed");
    }
    if let Some(redundant_path) = redundant {
        put_probe.stage("cleanup_redundant_wait");
        let _ = tokio::fs::remove_file(&redundant_path).await;
        put_probe.stage("cleanup_redundant_done");
    }

    state
        .kv_last_put
        .store(crate::serve::state::unix_time_ms_now(), Ordering::Release);

    put_probe.stage("replication_enqueue");
    if !enqueue_replication_flush_hint(state, should_flush, true) {
        put_probe.stage("replication_deferred");
    }

    state.cache_ops.record(
        namespace.into(),
        super::cache_ops::Op::Put,
        super::cache_ops::OpResult::Hit,
        false,
        blob_size,
        put_start.elapsed().as_millis() as u64,
    );

    put_probe.stage("respond");
    log::debug!("KV PUT {scoped_key}: queued ({blob_size} bytes, digest={blob_digest})");
    Ok((put_status, Body::empty()).into_response())
}

pub(crate) fn enqueue_replication_flush_hint(
    state: &AppState,
    urgent: bool,
    count_deferred: bool,
) -> bool {
    try_enqueue_replication_work(
        &state.kv_replication_work_tx,
        &state.kv_replication_queue_depth,
        &state.kv_replication_enqueue_deferred,
        urgent,
        count_deferred,
    )
}

fn try_enqueue_replication_work(
    replication_work_tx: &tokio::sync::mpsc::Sender<KvReplicationWork>,
    replication_queue_depth: &AtomicU64,
    replication_enqueue_deferred: &AtomicU64,
    urgent: bool,
    count_deferred: bool,
) -> bool {
    match replication_work_tx.try_send(KvReplicationWork::FlushHint { urgent }) {
        Ok(()) => {
            replication_queue_depth.fetch_add(1, Ordering::AcqRel);
            true
        }
        Err(TrySendError::Full(_)) => {
            if count_deferred {
                replication_enqueue_deferred.fetch_add(1, Ordering::AcqRel);
            }
            false
        }
        Err(TrySendError::Closed(_)) => {
            if count_deferred {
                replication_enqueue_deferred.fetch_add(1, Ordering::AcqRel);
            }
            false
        }
    }
}

async fn resolve_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
) -> Result<String, RegistryError> {
    let download_urls = match state
        .api_client
        .blob_download_urls_verified(&state.workspace, cache_entry_id, std::slice::from_ref(blob))
        .await
    {
        Ok(urls) => {
            state.backend_breaker.record_success();
            urls
        }
        Err(e) => {
            state.backend_breaker.record_failure();
            return Err(RegistryError::internal(format!(
                "Failed to resolve blob download URL: {e}"
            )));
        }
    };

    if download_urls
        .missing
        .iter()
        .any(|digest| digest == &blob.digest)
    {
        return Err(RegistryError::not_found(
            "Cache object is missing blob data",
        ));
    }

    download_urls
        .download_urls
        .iter()
        .find(|item| item.digest == blob.digest)
        .map(|item| item.url.clone())
        .ok_or_else(|| RegistryError::internal("Missing blob download URL in API response"))
}

async fn serve_backend_blob(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    cached_url: Option<&str>,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        CONTENT_TYPE,
        "application/octet-stream"
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-type header: {e}")))?,
    );
    response_headers.insert(
        CONTENT_LENGTH,
        blob.size_bytes
            .to_string()
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-length header: {e}")))?,
    );

    if is_head {
        return Ok((StatusCode::OK, response_headers, Body::empty()).into_response());
    }

    let cache_handle = download_blob_to_cache(state, cache_entry_id, blob, cached_url).await?;
    let mut file = tokio::fs::File::open(cache_handle.path())
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to open cached blob: {e}")))?;
    if cache_handle.offset() > 0 {
        file.seek(std::io::SeekFrom::Start(cache_handle.offset()))
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to seek cached blob: {e}")))?;
    }
    let stream = ReaderStream::new(file.take(cache_handle.size_bytes()));

    Ok((StatusCode::OK, response_headers, Body::from_stream(stream)).into_response())
}

fn is_recent_kv_miss(state: &AppState, scoped_key: &str) -> bool {
    let now = std::time::Instant::now();
    match state.kv_recent_misses.get(scoped_key) {
        Some(entry) if *entry.value() > now => true,
        Some(_) => {
            state.kv_recent_misses.remove(scoped_key);
            false
        }
        None => false,
    }
}

fn mark_kv_miss(state: &AppState, scoped_key: &str) {
    state.kv_recent_misses.insert(
        scoped_key.to_string(),
        std::time::Instant::now() + KV_MISS_CACHE_TTL,
    );
}

fn clear_kv_miss(state: &AppState, scoped_key: &str) {
    state.kv_recent_misses.remove(scoped_key);
}

fn clear_tag_misses(state: &AppState, registry_root_tag: &str) {
    let tag = registry_root_tag.trim().to_string();
    match state.kv_miss_generations.entry(tag) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            let next = entry.get().wrapping_add(1);
            entry.insert(next);
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(1);
        }
    }
}

pub(crate) fn cleanup_expired_kv_misses(state: &AppState) {
    let now = std::time::Instant::now();
    state
        .kv_recent_misses
        .retain(|_, expires_at| *expires_at > now);
}

fn kv_root_tags_from_values(
    registry_root_tag: &str,
    configured_human_tags: &[String],
) -> Vec<String> {
    let mut tags = vec![registry_root_tag.trim().to_string()];
    for human_tag in configured_human_tags {
        let human_tag = human_tag.trim();
        if !human_tag.is_empty() && !tags.iter().any(|tag| tag == human_tag) {
            tags.push(human_tag.to_string());
        }
    }
    tags
}

fn kv_root_tags(state: &AppState) -> Vec<String> {
    kv_root_tags_from_values(&state.registry_root_tag, &state.configured_human_tags)
}

fn kv_alias_tags_from_values(
    registry_root_tag: &str,
    configured_human_tags: &[String],
) -> Vec<String> {
    kv_root_tags_from_values(registry_root_tag, configured_human_tags)
        .into_iter()
        .skip(1)
        .collect()
}

fn kv_alias_tags(state: &AppState) -> Vec<String> {
    kv_alias_tags_from_values(&state.registry_root_tag, &state.configured_human_tags)
}

fn kv_primary_write_scope_tag(state: &AppState) -> Option<String> {
    state
        .configured_human_tags
        .first()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
}

fn clear_root_tag_misses(state: &AppState) {
    for tag in kv_root_tags(state) {
        clear_tag_misses(state, &tag);
    }
}

fn kv_pending_publish_handoff_path(state: &AppState) -> PathBuf {
    let human_tags = state
        .configured_human_tags
        .iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    let scope = format!(
        "{}|{}|{}",
        state.workspace,
        state.registry_root_tag.trim(),
        human_tags
    );
    let digest = crate::cas_oci::sha256_hex(scope.as_bytes());
    state
        .blob_read_cache
        .cache_dir()
        .join(KV_PENDING_PUBLISH_HANDOFF_DIR)
        .join(format!("{digest}.json"))
}

fn kv_pending_publish_handoff_is_expired(handoff: &KvPendingPublishHandoff) -> bool {
    let now_ms = crate::serve::state::unix_time_ms_now();
    now_ms.saturating_sub(handoff.persisted_at_unix_ms)
        > KV_PENDING_PUBLISH_HANDOFF_MAX_AGE.as_millis() as u64
}

fn kv_pending_publish_handoff_matches_state(
    handoff: &KvPendingPublishHandoff,
    state: &AppState,
) -> bool {
    handoff.version == KV_PENDING_PUBLISH_HANDOFF_VERSION
        && handoff.workspace == state.workspace
        && handoff.registry_root_tag == state.registry_root_tag
        && handoff.configured_human_tags == state.configured_human_tags
}

async fn read_kv_pending_publish_handoff(state: &AppState) -> Option<KvPendingPublishHandoff> {
    let path = kv_pending_publish_handoff_path(state);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            log::warn!(
                "KV pending publish handoff: failed to read {}: {error}",
                path.display()
            );
            return None;
        }
    };

    let handoff = match serde_json::from_slice::<KvPendingPublishHandoff>(&bytes) {
        Ok(handoff) => handoff,
        Err(error) => {
            log::warn!(
                "KV pending publish handoff: failed to parse {}: {error}",
                path.display()
            );
            let _ = tokio::fs::remove_file(&path).await;
            return None;
        }
    };

    if !kv_pending_publish_handoff_matches_state(&handoff, state)
        || kv_pending_publish_handoff_is_expired(&handoff)
    {
        let _ = tokio::fs::remove_file(&path).await;
        return None;
    }

    Some(handoff)
}

async fn clear_kv_pending_publish_handoff(state: &AppState) {
    let path = kv_pending_publish_handoff_path(state);
    if let Err(error) = tokio::fs::remove_file(&path).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!(
            "KV pending publish handoff: failed to remove {}: {error}",
            path.display()
        );
    }
}

async fn persist_kv_pending_publish_handoff(
    state: &AppState,
    entries: &BTreeMap<String, BlobDescriptor>,
    blob_order: &[BlobDescriptor],
    cache_entry_id: &str,
    root_pending: Option<&PendingMetadata>,
    pending_alias_tags: bool,
) {
    if root_pending.is_none() && !pending_alias_tags {
        clear_kv_pending_publish_handoff(state).await;
        return;
    }

    let handoff = KvPendingPublishHandoff {
        version: KV_PENDING_PUBLISH_HANDOFF_VERSION,
        persisted_at_unix_ms: crate::serve::state::unix_time_ms_now(),
        workspace: state.workspace.clone(),
        registry_root_tag: state.registry_root_tag.clone(),
        configured_human_tags: state.configured_human_tags.clone(),
        cache_entry_id: cache_entry_id.to_string(),
        entries: entries.clone(),
        blob_order: blob_order.to_vec(),
        root_pending: root_pending.cloned(),
        pending_alias_tags,
    };

    let path = kv_pending_publish_handoff_path(state);
    let Some(parent) = path.parent() else {
        log::warn!(
            "KV pending publish handoff: invalid path {}",
            path.display()
        );
        return;
    };

    if let Err(error) = tokio::fs::create_dir_all(parent).await {
        log::warn!(
            "KV pending publish handoff: failed to create {}: {error}",
            parent.display()
        );
        return;
    }

    let payload = match serde_json::to_vec(&handoff) {
        Ok(payload) => payload,
        Err(error) => {
            log::warn!("KV pending publish handoff: failed to encode snapshot: {error}");
            return;
        }
    };

    let temp_path = path.with_extension("json.tmp");
    if let Err(error) = tokio::fs::write(&temp_path, payload).await {
        log::warn!(
            "KV pending publish handoff: failed to write {}: {error}",
            temp_path.display()
        );
        return;
    }
    if let Err(error) = tokio::fs::rename(&temp_path, &path).await {
        log::warn!(
            "KV pending publish handoff: failed to rename {} -> {}: {error}",
            temp_path.display(),
            path.display()
        );
        let _ = tokio::fs::remove_file(&temp_path).await;
        return;
    }

    eprintln!(
        "KV pending publish handoff persisted: cache_entry_id={} root_pending={} alias_pending={}",
        cache_entry_id,
        root_pending.is_some(),
        pending_alias_tags
    );
}

async fn kv_publish_tags_visible(state: &AppState, expected_cache_entry_id: &str) -> bool {
    for tag in kv_root_tags(state) {
        let visible = match state
            .api_client
            .tag_pointer(&state.workspace, &tag, None)
            .await
        {
            Ok(crate::api::client::TagPointerPollResult::Changed { pointer, .. }) => {
                pointer.cache_entry_id.as_deref() == Some(expected_cache_entry_id)
            }
            Ok(crate::api::client::TagPointerPollResult::NotModified)
            | Ok(crate::api::client::TagPointerPollResult::NotFound) => false,
            Err(error) => {
                log::warn!(
                    "KV pending publish handoff: tag visibility poll failed for {} tag={}: {}",
                    expected_cache_entry_id,
                    tag,
                    error
                );
                false
            }
        };
        if !visible {
            return false;
        }
    }
    true
}

async fn reconcile_kv_pending_publish_handoff(state: AppState, handoff: KvPendingPublishHandoff) {
    let deadline = std::time::Instant::now() + KV_PENDING_PUBLISH_HANDOFF_RECONCILE_TIMEOUT;

    loop {
        if kv_publish_tags_visible(&state, &handoff.cache_entry_id).await {
            clear_kv_pending_publish_handoff(&state).await;
            eprintln!(
                "KV pending publish handoff settled: cache_entry_id={} tags now visible",
                handoff.cache_entry_id
            );
            return;
        }

        let Some(metadata) = handoff.root_pending.as_ref() else {
            if std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        };

        match state
            .api_client
            .pending_publish_status(&state.workspace, metadata)
            .await
        {
            Ok(status) => {
                let publish_state = status
                    .publish_state
                    .as_deref()
                    .unwrap_or(status.state.as_str());
                match publish_state {
                    "published" => {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    "failed" | "conflicted" => {
                        {
                            let mut published = state.kv_published_index.write().await;
                            if published.cache_entry_id() == Some(handoff.cache_entry_id.as_str()) {
                                published.set_empty_incomplete();
                            }
                        }
                        clear_kv_pending_publish_handoff(&state).await;
                        refresh_kv_index_keys_only(&state).await;
                        eprintln!(
                            "KV pending publish handoff invalidated: cache_entry_id={} state={publish_state}",
                            handoff.cache_entry_id
                        );
                        return;
                    }
                    _ => {
                        let delay = std::time::Duration::from_secs(
                            metadata.retry_after_seconds.unwrap_or(1).max(1),
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
            Err(error) => {
                log::warn!(
                    "KV pending publish handoff: status poll failed for cache_entry_id={}: {error}",
                    handoff.cache_entry_id
                );
                if std::time::Instant::now() >= deadline {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

pub(crate) async fn restore_kv_pending_publish_handoff(state: &AppState) {
    let Some(handoff) = read_kv_pending_publish_handoff(state).await else {
        return;
    };

    if let Some(_pending) = handoff.root_pending.as_ref() {
        {
            let mut published = state.kv_published_index.write().await;
            published.update(
                handoff
                    .entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                handoff.blob_order.clone(),
                handoff.cache_entry_id.clone(),
            );
        }
        clear_root_tag_misses(state);
        eprintln!(
            "KV startup: restored pending publish handoff cache_entry_id={} entries={}",
            handoff.cache_entry_id,
            handoff.entries.len()
        );
    } else {
        eprintln!(
            "KV startup: restored alias visibility handoff cache_entry_id={}",
            handoff.cache_entry_id
        );
    }

    let reconcile_state = state.clone();
    tokio::spawn(async move {
        reconcile_kv_pending_publish_handoff(reconcile_state, handoff).await;
    });
}

pub(crate) async fn should_skip_shutdown_tag_visibility_wait(
    state: &AppState,
    expected_cache_entry_id: &str,
) -> bool {
    read_kv_pending_publish_handoff(state)
        .await
        .is_some_and(|handoff| handoff.cache_entry_id == expected_cache_entry_id)
}

async fn lookup_published_blob(
    state: &AppState,
    scoped_key: &str,
) -> Option<(BlobDescriptor, String, Option<String>)> {
    let published = state.kv_published_index.read().await;
    let (blob, cache_entry_id) = published.get(scoped_key)?;
    let blob = blob.clone();
    let cache_entry_id = cache_entry_id.to_string();
    let cached_url = published.download_url(&blob.digest).map(str::to_string);
    Some((blob, cache_entry_id, cached_url))
}

async fn populate_sizes_from_published(
    state: &AppState,
    scoped_keys: &[String],
    sizes: &mut HashMap<String, u64>,
) {
    let published = state.kv_published_index.read().await;
    for scoped in scoped_keys {
        if sizes.contains_key(scoped) {
            continue;
        }
        if let Some((blob, _)) = published.get(scoped) {
            sizes.insert(scoped.clone(), blob.size_bytes);
        }
    }
}

async fn should_refresh_published_index_for_lookup(state: &AppState) -> bool {
    if should_suppress_lookup_refresh_due_to_pending(state).await {
        return false;
    }

    let now = std::time::Instant::now();
    let published = state.kv_published_index.read().await;
    if !published.is_complete() {
        return true;
    }
    let Some(last_refresh_at) = published.last_refresh_at() else {
        return true;
    };
    let refresh_interval = if published.entry_count() == 0 {
        KV_EMPTY_INDEX_REFRESH_INTERVAL
    } else {
        KV_INDEX_REFRESH_INTERVAL
    };
    now.duration_since(last_refresh_at) >= refresh_interval
}

async fn should_suppress_lookup_refresh_due_to_pending(state: &AppState) -> bool {
    let has_pending_entries = {
        let pending = state.kv_pending.read().await;
        !pending.is_empty()
    };
    let has_flushing_entries = {
        let flushing = state.kv_flushing.read().await;
        flushing.is_some()
    };
    if !has_pending_entries && !has_flushing_entries {
        return false;
    }

    let last_put_ms = state.kv_last_put.load(Ordering::Acquire);
    if last_put_ms == 0 && !has_flushing_entries {
        return false;
    }

    let now_ms = crate::serve::state::unix_time_ms_now();
    should_suppress_lookup_refresh_due_to_pending_or_flushing_values(
        has_pending_entries,
        has_flushing_entries,
        last_put_ms,
        now_ms,
    )
}

fn should_suppress_lookup_refresh_due_to_pending_values(
    has_pending_entries: bool,
    last_put_ms: u64,
    now_ms: u64,
) -> bool {
    if !has_pending_entries || last_put_ms == 0 {
        return false;
    }

    let elapsed_ms = now_ms.saturating_sub(last_put_ms);
    elapsed_ms < KV_PENDING_REFRESH_SUPPRESSION_WINDOW.as_millis() as u64
}

fn should_suppress_lookup_refresh_due_to_pending_or_flushing_values(
    has_pending_entries: bool,
    has_flushing_entries: bool,
    last_put_ms: u64,
    now_ms: u64,
) -> bool {
    if has_flushing_entries {
        return true;
    }
    should_suppress_lookup_refresh_due_to_pending_values(has_pending_entries, last_put_ms, now_ms)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PublishedGapCounts {
    missing_keys: usize,
    mismatched_keys: usize,
}

fn count_published_gaps_in_backend(
    backend_entries: &BTreeMap<String, BlobDescriptor>,
    published_entries: &HashMap<String, BlobDescriptor>,
) -> PublishedGapCounts {
    let mut counts = PublishedGapCounts::default();
    for (key, published_blob) in published_entries {
        match backend_entries.get(key) {
            Some(backend_blob)
                if backend_blob.digest == published_blob.digest
                    && backend_blob.size_bytes == published_blob.size_bytes => {}
            Some(_) => {
                counts.mismatched_keys = counts.mismatched_keys.saturating_add(1);
            }
            None => {
                counts.missing_keys = counts.missing_keys.saturating_add(1);
            }
        }
    }
    counts
}

async fn refresh_published_index_for_lookup(state: &AppState) -> Result<(), RegistryError> {
    let (entries, blob_order, cache_entry_id, _) =
        match load_existing_index_with_fallback(state, true).await {
            Ok(result) => {
                state.backend_breaker.record_success();
                result
            }
            Err(e) => {
                state.backend_breaker.record_failure();
                return Err(e);
            }
        };

    let backend_entry_count = entries.len();
    {
        let mut published = state.kv_published_index.write().await;
        let published_entries = published.entries_snapshot();
        let published_entry_count = published_entries.len();
        let gap_counts = count_published_gaps_in_backend(&entries, published_entries.as_ref());

        if published_entry_count > 0
            && (gap_counts.missing_keys > 0 || gap_counts.mismatched_keys > 0)
        {
            log::warn!(
                "KV lookup refresh: preserving in-memory index (backend={} published={} missing_keys={} mismatched_keys={})",
                backend_entry_count,
                published_entry_count,
                gap_counts.missing_keys,
                gap_counts.mismatched_keys
            );
            published.touch_refresh();
        } else if entries.is_empty() {
            published.set_empty();
        } else if let Some(cache_entry_id) = cache_entry_id {
            published.update(entries.into_iter().collect(), blob_order, cache_entry_id);
        } else if published_entry_count > 0 {
            log::warn!(
                "KV lookup refresh: backend returned entries without cache_entry_id; preserving in-memory index"
            );
            published.touch_refresh();
        } else {
            published.set_empty();
        }
    }
    clear_root_tag_misses(state);

    Ok(())
}

async fn refresh_published_index_for_lookup_with_timeout(
    state: &AppState,
) -> Result<(), RegistryError> {
    match tokio::time::timeout(
        KV_LOOKUP_REFRESH_TIMEOUT,
        refresh_published_index_for_lookup(state),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            log::warn!(
                "KV index refresh for lookup timed out after {}s",
                KV_LOOKUP_REFRESH_TIMEOUT.as_secs()
            );
            Ok(())
        }
    }
}

async fn maybe_refresh_published_index_for_lookup(state: &AppState) -> Result<(), RegistryError> {
    if state.backend_breaker.is_open() {
        return Ok(());
    }
    if !should_refresh_published_index_for_lookup(state).await {
        return Ok(());
    }

    let flight_key = LOOKUP_REFRESH_FLIGHT_KEY.to_string();
    match begin_lookup_flight(state, flight_key.clone()) {
        LookupFlight::Follower(notified) => {
            if !await_flight("refresh", &flight_key, notified).await {
                clear_lookup_flight_entry(state, &flight_key);
                if should_refresh_published_index_for_lookup(state).await {
                    refresh_published_index_for_lookup_with_timeout(state).await?;
                }
            }
            Ok(())
        }
        LookupFlight::Leader(_refresh_guard) => {
            if should_refresh_published_index_for_lookup(state).await {
                refresh_published_index_for_lookup_with_timeout(state).await?;
            }
            Ok(())
        }
    }
}

fn content_length_bytes(response: &Response) -> u64 {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn expected_bazel_cas_blob_digest(namespace: KvNamespace, key: &str) -> Option<String> {
    if !matches!(namespace, KvNamespace::BazelCas) {
        return None;
    }
    Some(format!("sha256:{}", namespace.normalize_key(key)))
}

fn bazel_cas_blob_matches(namespace: KvNamespace, key: &str, blob: &BlobDescriptor) -> bool {
    match expected_bazel_cas_blob_digest(namespace, key) {
        Some(expected) => blob.digest.eq_ignore_ascii_case(&expected),
        None => true,
    }
}

pub(crate) async fn get_or_head_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let get_start = std::time::Instant::now();
    let result = get_or_head_kv_object_inner(state, namespace, key, is_head).await;
    let elapsed_ms = get_start.elapsed().as_millis() as u64;
    let tool = namespace.into();

    match &result {
        Ok(response) => {
            state.cache_ops.record(
                tool,
                super::cache_ops::Op::Get,
                super::cache_ops::OpResult::Hit,
                false,
                content_length_bytes(response),
                elapsed_ms,
            );
        }
        Err(e) if e.status == StatusCode::NOT_FOUND => {
            state.cache_ops.record(
                tool,
                super::cache_ops::Op::Get,
                super::cache_ops::OpResult::Miss,
                false,
                0,
                elapsed_ms,
            );
            state.cache_ops.record_miss(tool, key);
        }
        Err(error) => {
            let degraded = !state.fail_on_cache_error && error.status.is_server_error();
            state.cache_ops.record(
                tool,
                super::cache_ops::Op::Get,
                super::cache_ops::OpResult::Error,
                degraded,
                0,
                elapsed_ms,
            );
        }
    }

    result
}

async fn get_or_head_kv_object_inner(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let scoped_key = namespace.scoped_key(key);
    kv_trace(namespace, &scoped_key, "start");
    let use_miss_cache = use_kv_miss_cache(namespace);
    let miss_key = kv_miss_cache_key(state, &state.registry_root_tag, &scoped_key);

    let local = {
        let pending = state.kv_pending.read().await;
        pending.get(&scoped_key).and_then(|blob| {
            pending
                .blob_path(&blob.digest)
                .map(|path| (blob.clone(), path.clone()))
        })
    };
    kv_trace(namespace, &scoped_key, "after-pending");

    if let Some((blob, path)) = local {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-local");
            match serve_local_blob(&blob, &path, is_head).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("KV local blob read failed, falling back to backend: {e:?}");
                }
            }
        } else {
            log::warn!(
                "Bazel CAS local blob digest mismatch: key={} digest={}",
                key,
                blob.digest
            );
        }
    }

    let flushing_local = {
        let flushing = state.kv_flushing.read().await;
        flushing.as_ref().and_then(|snapshot| {
            snapshot.get(&scoped_key).and_then(|blob| {
                snapshot
                    .blob_path(&blob.digest)
                    .map(|path| (blob.clone(), path.clone()))
            })
        })
    };
    kv_trace(namespace, &scoped_key, "after-flushing");

    if let Some((blob, path)) = flushing_local {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-flushing");
            match serve_local_blob(&blob, &path, is_head).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("KV flushing blob read failed, falling through: {e:?}");
                }
            }
        } else {
            log::warn!(
                "Bazel CAS flushing blob digest mismatch: key={} digest={}",
                key,
                blob.digest
            );
        }
    }

    if let Some((blob, cache_entry_id, cached_url)) =
        lookup_published_blob(state, &scoped_key).await
    {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-published-fast");
            if use_miss_cache {
                clear_kv_miss(state, &miss_key);
            }
            return serve_backend_blob(
                state,
                &cache_entry_id,
                &blob,
                cached_url.as_deref(),
                is_head,
            )
            .await;
        }
        log::warn!(
            "Bazel CAS published blob digest mismatch: key={} digest={}",
            key,
            blob.digest
        );
    }

    if use_miss_cache && is_recent_kv_miss(state, &miss_key) {
        kv_trace(namespace, &scoped_key, "recent-miss");
        return Err(RegistryError::not_found("Cache key not found"));
    }

    kv_trace(namespace, &scoped_key, "lookup-flight-begin");
    let lookup_result = match begin_lookup_flight(state, miss_key.clone()) {
        LookupFlight::Follower(notified) => {
            kv_trace(namespace, &scoped_key, "lookup-flight-follower-wait");
            if !await_flight("kv", &miss_key, notified).await {
                clear_lookup_flight_entry(state, &miss_key);
            }
            kv_trace(namespace, &scoped_key, "lookup-flight-follower-after-wait");
            lookup_published_blob(state, &scoped_key).await
        }
        LookupFlight::Leader(_lookup_guard) => {
            if use_miss_cache && is_recent_kv_miss(state, &miss_key) {
                kv_trace(namespace, &scoped_key, "leader-recent-miss");
                return Err(RegistryError::not_found("Cache key not found"));
            }

            if let Some(found) = lookup_published_blob(state, &scoped_key).await {
                kv_trace(namespace, &scoped_key, "leader-published-hit");
                Some(found)
            } else {
                kv_trace(namespace, &scoped_key, "leader-before-refresh");
                maybe_refresh_published_index_for_lookup(state).await?;
                kv_trace(namespace, &scoped_key, "leader-after-refresh");
                let result = lookup_published_blob(state, &scoped_key).await;
                if use_miss_cache && result.is_none() {
                    mark_kv_miss(state, &miss_key);
                    kv_trace(namespace, &scoped_key, "leader-mark-miss");
                }
                result
            }
            // _lookup_guard drops here — BEFORE the download
        }
    };
    kv_trace(namespace, &scoped_key, "lookup-flight-end");

    if let Some((blob, cache_entry_id, cached_url)) = lookup_result {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-published-after-lookup");
            if use_miss_cache {
                clear_kv_miss(state, &miss_key);
            }
            return serve_backend_blob(
                state,
                &cache_entry_id,
                &blob,
                cached_url.as_deref(),
                is_head,
            )
            .await;
        }
        log::warn!(
            "Bazel CAS lookup blob digest mismatch: key={} digest={}",
            key,
            blob.digest
        );
    }

    kv_trace(namespace, &scoped_key, "not-found");
    Err(RegistryError::not_found("Cache key not found"))
}

async fn serve_local_blob(
    blob: &BlobDescriptor,
    path: &PathBuf,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        "application/octet-stream"
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-type header: {e}")))?,
    );
    headers.insert(
        CONTENT_LENGTH,
        blob.size_bytes
            .to_string()
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-length header: {e}")))?,
    );

    if is_head {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to open local blob: {e}")))?;
    let stream = ReaderStream::new(file);

    Ok((StatusCode::OK, headers, Body::from_stream(stream)).into_response())
}

async fn resolve_blob_url(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    cached_url: Option<&str>,
) -> Result<(String, bool), RegistryError> {
    if let Some(url) = cached_url {
        return Ok((url.to_string(), true));
    }

    let flight_key = format!("url:{}", blob.digest);
    match begin_lookup_flight(state, flight_key.clone()) {
        LookupFlight::Follower(notified) => {
            if !await_flight("url", &flight_key, notified).await {
                clear_lookup_flight_entry(state, &flight_key);
            }
            let published = state.kv_published_index.read().await;
            if let Some(url) = published.download_url(&blob.digest) {
                return Ok((url.to_string(), true));
            }
            drop(published);
            let resolved = resolve_download_url(state, cache_entry_id, blob).await?;
            {
                let mut published = state.kv_published_index.write().await;
                published.set_download_url(blob.digest.clone(), resolved.clone());
            }
            Ok((resolved, false))
        }
        LookupFlight::Leader(_url_flight) => {
            let resolved = resolve_download_url(state, cache_entry_id, blob).await?;
            {
                let mut published = state.kv_published_index.write().await;
                published.set_download_url(blob.digest.clone(), resolved.clone());
            }
            Ok((resolved, false))
        }
    }
}

async fn do_download_blob_to_cache(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    cached_url: Option<&str>,
) -> Result<BlobReadHandle, RegistryError> {
    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
        return Ok(cache_handle);
    }

    if cached_url.is_none() && state.backend_breaker.is_open() {
        return Err(RegistryError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Backend temporarily unavailable",
        ));
    }

    let (url, from_cache) = match tokio::time::timeout(
        KV_BLOB_URL_RESOLVE_TIMEOUT,
        resolve_blob_url(state, cache_entry_id, blob, cached_url),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(RegistryError::internal(format!(
                "Blob URL resolution timed out after {}s",
                KV_BLOB_URL_RESOLVE_TIMEOUT.as_secs()
            )));
        }
    };

    let _permit = state
        .blob_download_semaphore
        .acquire()
        .await
        .map_err(|_| RegistryError::internal("Download semaphore closed"))?;

    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
        return Ok(cache_handle);
    }

    let digest_hex = crate::cas_file::sha256_hex(blob.digest.as_bytes());
    let temp_suffix = KV_BLOB_DOWNLOAD_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_dir = state.runtime_temp_dir.join("kv-downloads");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to create temp dir: {e}")))?;
    let temp_path = temp_dir.join(format!(
        "blob-{}-{}-{temp_suffix:016x}",
        &digest_hex[..16],
        std::process::id(),
    ));
    let written = match tokio::time::timeout(
        KV_BLOB_DOWNLOAD_TIMEOUT,
        stream_blob_to_file(state, cache_entry_id, blob, &url, from_cache, &temp_path),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(RegistryError::internal(format!(
                "Blob download timed out after {}s",
                KV_BLOB_DOWNLOAD_TIMEOUT.as_secs()
            )));
        }
    };

    if written == 0 {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(RegistryError::internal("Downloaded blob was empty"));
    }

    match state
        .blob_read_cache
        .promote(&blob.digest, &temp_path, written)
        .await
    {
        Ok(_) => {}
        Err(error) => {
            log::warn!("Blob cache promote failed for {}: {error}", blob.digest);
        }
    }

    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
        return Ok(cache_handle);
    }

    if tokio::fs::metadata(&temp_path).await.is_ok() {
        return Ok(BlobReadHandle::from_file(temp_path, written));
    }

    Err(RegistryError::internal(
        "Blob not found after download (promote may have moved it)",
    ))
}

async fn stream_blob_to_file(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    url: &str,
    from_cache: bool,
    dest: &std::path::Path,
) -> Result<u64, RegistryError> {
    let mut active_url = url.to_string();
    let mut may_refresh = from_cache;
    let expected_digest = blob.digest.to_ascii_lowercase();

    for attempt in 0..=1 {
        let response = state
            .api_client
            .transfer_client()
            .get(&active_url)
            .send()
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to download blob: {e}")))?;

        let response = if may_refresh
            && (response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::NOT_FOUND)
        {
            let fresh_url = resolve_download_url(state, cache_entry_id, blob).await?;
            {
                let mut published = state.kv_published_index.write().await;
                published.set_download_url(blob.digest.clone(), fresh_url.clone());
            }
            may_refresh = false;
            state
                .api_client
                .transfer_client()
                .get(&fresh_url)
                .send()
                .await
                .map_err(|e| RegistryError::internal(format!("Failed to download blob: {e}")))?
                .error_for_status()
                .map_err(|e| {
                    RegistryError::internal(format!("Blob storage returned an error: {e}"))
                })?
        } else {
            response.error_for_status().map_err(|e| {
                RegistryError::internal(format!("Blob storage returned an error: {e}"))
            })?
        };

        let mut stream = response.bytes_stream();
        let mut file = tokio::fs::File::create(dest)
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to create temp file: {e}")))?;
        let mut written = 0u64;
        let mut hasher = Sha256::new();
        loop {
            let next_chunk = stream.next().await;
            let Some(chunk) = next_chunk else {
                break;
            };
            let chunk = chunk
                .map_err(|e| RegistryError::internal(format!("Failed to read blob stream: {e}")))?;
            file.write_all(&chunk).await.map_err(|e| {
                RegistryError::internal(format!("Failed to write blob to temp file: {e}"))
            })?;
            hasher.update(&chunk);
            written += chunk.len() as u64;
        }
        file.flush()
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to flush temp file: {e}")))?;
        drop(file);

        let actual_digest = format!("sha256:{:x}", hasher.finalize());
        if actual_digest.eq_ignore_ascii_case(&expected_digest) {
            return Ok(written);
        }

        let _ = tokio::fs::remove_file(dest).await;
        if may_refresh && attempt == 0 {
            let fresh_url = resolve_download_url(state, cache_entry_id, blob).await?;
            {
                let mut published = state.kv_published_index.write().await;
                published.set_download_url(blob.digest.clone(), fresh_url.clone());
            }
            active_url = fresh_url;
            may_refresh = false;
            continue;
        }

        return Err(RegistryError::internal(format!(
            "Downloaded blob digest mismatch: expected {}, got {}",
            expected_digest, actual_digest
        )));
    }

    Err(RegistryError::internal(
        "Blob download failed after digest validation retries",
    ))
}

fn short_digest(digest: &str) -> &str {
    if digest.len() > 16 {
        &digest[..16]
    } else {
        digest
    }
}

async fn download_blob_to_cache(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    cached_url: Option<&str>,
) -> Result<BlobReadHandle, RegistryError> {
    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
        log::debug!("dl cache hit: {}", short_digest(&blob.digest));
        return Ok(cache_handle);
    }

    let flight_key = format!("dl:{}", blob.digest);
    match begin_lookup_flight(state, flight_key.clone()) {
        LookupFlight::Leader(_dl_guard) => {
            if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                return Ok(cache_handle);
            }

            do_download_blob_to_cache(state, cache_entry_id, blob, cached_url).await
        }
        LookupFlight::Follower(notified) => {
            if !await_flight("dl", &flight_key, notified).await {
                clear_lookup_flight_entry(state, &flight_key);
            }
            if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                return Ok(cache_handle);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                return Ok(cache_handle);
            }
            let retry_key = format!("dlretry:{}", blob.digest);
            match begin_lookup_flight(state, retry_key.clone()) {
                LookupFlight::Leader(_retry_guard) => {
                    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await
                    {
                        return Ok(cache_handle);
                    }
                    do_download_blob_to_cache(state, cache_entry_id, blob, cached_url).await
                }
                LookupFlight::Follower(retry_notified) => {
                    if !await_flight("dlretry", &retry_key, retry_notified).await {
                        clear_lookup_flight_entry(state, &retry_key);
                    }
                    state
                        .blob_read_cache
                        .get_handle(&blob.digest)
                        .await
                        .ok_or_else(|| {
                            RegistryError::internal(format!(
                                "Blob download failed after retry: {}",
                                short_digest(&blob.digest)
                            ))
                        })
                }
            }
        }
    }
}

pub(crate) async fn resolve_kv_entries(
    state: &AppState,
    namespace: KvNamespace,
    keys: &[&str],
) -> Result<HashMap<String, u64>, RegistryError> {
    let query_start = std::time::Instant::now();
    let result = resolve_kv_entries_inner(state, namespace, keys).await;
    let elapsed_ms = query_start.elapsed().as_millis() as u64;
    let tool = namespace.into();

    if let Ok(sizes) = &result {
        for key in keys {
            let scoped = namespace.scoped_key(key);
            if let Some(&size) = sizes.get(&scoped) {
                state.cache_ops.record(
                    tool,
                    super::cache_ops::Op::Query,
                    super::cache_ops::OpResult::Hit,
                    false,
                    size,
                    elapsed_ms,
                );
            } else {
                state.cache_ops.record(
                    tool,
                    super::cache_ops::Op::Query,
                    super::cache_ops::OpResult::Miss,
                    false,
                    0,
                    elapsed_ms,
                );
                state.cache_ops.record_miss(tool, key);
            }
        }
    }

    result
}

async fn resolve_kv_entries_inner(
    state: &AppState,
    namespace: KvNamespace,
    keys: &[&str],
) -> Result<HashMap<String, u64>, RegistryError> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }

    let mut sizes = HashMap::new();
    let scoped_keys: Vec<String> = keys.iter().map(|k| namespace.scoped_key(k)).collect();

    {
        let pending = state.kv_pending.read().await;
        for scoped in &scoped_keys {
            if let Some(blob) = pending.get(scoped) {
                sizes.insert(scoped.clone(), blob.size_bytes);
            }
        }
    }

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    {
        let flushing = state.kv_flushing.read().await;
        if let Some(snapshot) = flushing.as_ref() {
            for scoped in &scoped_keys {
                if sizes.contains_key(scoped) {
                    continue;
                }
                if let Some(blob) = snapshot.get(scoped) {
                    sizes.insert(scoped.clone(), blob.size_bytes);
                }
            }
        }
    }

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    let sizes_key = lookup_flight_key_for_sizes(&scoped_keys);
    match begin_lookup_flight(state, sizes_key.clone()) {
        LookupFlight::Follower(notified) => {
            if !await_flight("sizes", &sizes_key, notified).await {
                clear_lookup_flight_entry(state, &sizes_key);
            }
            populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;
            Ok(sizes)
        }
        LookupFlight::Leader(_lookup_flight) => {
            populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;
            if sizes.len() == scoped_keys.len() {
                return Ok(sizes);
            }

            maybe_refresh_published_index_for_lookup(state).await?;

            populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;
            Ok(sizes)
        }
    }
}

pub(crate) async fn resolve_hit(
    state: &AppState,
    tag: &str,
) -> Result<CacheResolutionEntry, RegistryError> {
    let response = tokio::time::timeout(
        KV_RESOLVE_HIT_TIMEOUT,
        state
            .api_client
            .restore(&state.workspace, &[tag.to_string()], false),
    )
    .await
    .map_err(|_| {
        RegistryError::internal(format!(
            "Timed out resolving cache key after {}s",
            KV_RESOLVE_HIT_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| RegistryError::internal(format!("Failed to resolve cache key: {e}")))?;

    response
        .into_iter()
        .find(|entry| entry.status == "hit")
        .ok_or_else(|| RegistryError::not_found("Cache key not found"))
}

async fn fetch_pointer(
    state: &AppState,
    hit: &CacheResolutionEntry,
) -> Result<crate::cas_file::FilePointer, RegistryError> {
    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| RegistryError::internal("Cache hit is missing manifest_url"))?;

    let pointer_response = tokio::time::timeout(
        KV_FETCH_POINTER_TIMEOUT,
        state.api_client.transfer_client().get(manifest_url).send(),
    )
    .await
    .map_err(|_| {
        RegistryError::internal(format!(
            "Timed out fetching manifest pointer after {}s",
            KV_FETCH_POINTER_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| RegistryError::internal(format!("Failed to fetch manifest pointer: {e}")))?
    .error_for_status()
    .map_err(|e| RegistryError::internal(format!("Manifest pointer request failed: {e}")))?;
    let pointer_bytes = tokio::time::timeout(KV_FETCH_POINTER_TIMEOUT, pointer_response.bytes())
        .await
        .map_err(|_| {
            RegistryError::internal(format!(
                "Timed out reading manifest pointer after {}s",
                KV_FETCH_POINTER_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| {
            RegistryError::internal(format!("Failed to read manifest pointer bytes: {e}"))
        })?;

    crate::cas_file::parse_pointer(pointer_bytes.as_ref())
        .map_err(|e| RegistryError::internal(format!("Invalid file CAS pointer: {e}")))
}

fn is_invalid_file_pointer_error(error: &RegistryError) -> bool {
    error.message().contains("Invalid file CAS pointer")
}

fn build_index_pointer(
    entries: &BTreeMap<String, BlobDescriptor>,
    blob_order: &[BlobDescriptor],
) -> Result<(Vec<u8>, Vec<BlobDescriptor>), RegistryError> {
    let mut blob_sizes: BTreeMap<String, u64> = BTreeMap::new();
    let mut pointer_entries = Vec::with_capacity(entries.len());

    for (key, blob) in entries {
        if let Some(existing_size) = blob_sizes.get(&blob.digest) {
            if *existing_size != blob.size_bytes {
                return Err(RegistryError::internal(format!(
                    "Digest {} has inconsistent sizes ({} vs {})",
                    blob.digest, existing_size, blob.size_bytes
                )));
            }
        } else {
            blob_sizes.insert(blob.digest.clone(), blob.size_bytes);
        }

        pointer_entries.push(crate::cas_file::FilePointerEntry {
            path: key.clone(),
            entry_type: EntryType::File,
            size_bytes: blob.size_bytes,
            executable: None,
            target: None,
            digest: Some(blob.digest.clone()),
        });
    }

    let mut blobs = Vec::with_capacity(blob_sizes.len());
    let mut seen = HashSet::new();
    for blob in blob_order {
        let digest = blob.digest.clone();
        let Some(size_bytes) = blob_sizes.get(&digest) else {
            continue;
        };
        if seen.insert(digest.clone()) {
            blobs.push(BlobDescriptor {
                digest,
                size_bytes: *size_bytes,
            });
        }
    }
    for (digest, size_bytes) in &blob_sizes {
        if seen.insert(digest.clone()) {
            blobs.push(BlobDescriptor {
                digest: digest.clone(),
                size_bytes: *size_bytes,
            });
        }
    }

    let pointer = crate::cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: pointer_entries,
        blobs: blobs
            .iter()
            .enumerate()
            .map(|(sequence, blob)| crate::cas_file::FilePointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
                sequence: Some(sequence as u64),
            })
            .collect(),
    };
    let pointer_bytes = serde_json::to_vec(&pointer)
        .map_err(|e| RegistryError::internal(format!("Failed to serialize file pointer: {e}")))?;

    Ok((pointer_bytes, blobs))
}

fn pointer_blob_order(
    pointer: &crate::cas_file::FilePointer,
    entries: &BTreeMap<String, BlobDescriptor>,
) -> Vec<BlobDescriptor> {
    let mut size_by_digest = BTreeMap::new();
    for blob in entries.values() {
        size_by_digest
            .entry(blob.digest.clone())
            .or_insert(blob.size_bytes);
    }

    let mut pointer_blobs = pointer.blobs.clone();
    if pointer_blobs.iter().any(|blob| blob.sequence.is_some()) {
        pointer_blobs.sort_by(|left, right| {
            left.sequence
                .unwrap_or(u64::MAX)
                .cmp(&right.sequence.unwrap_or(u64::MAX))
                .then_with(|| left.digest.cmp(&right.digest))
        });
    }

    let mut ordered = Vec::with_capacity(size_by_digest.len());
    let mut seen = HashSet::new();
    for blob in pointer_blobs {
        let digest = blob.digest;
        let Some(size_bytes) = size_by_digest.get(&digest) else {
            continue;
        };
        if seen.insert(digest.clone()) {
            ordered.push(BlobDescriptor {
                digest,
                size_bytes: *size_bytes,
            });
        }
    }

    for (digest, size_bytes) in size_by_digest {
        if seen.insert(digest.clone()) {
            ordered.push(BlobDescriptor { digest, size_bytes });
        }
    }

    ordered
}

fn merge_blob_order(
    merged_entries: &BTreeMap<String, BlobDescriptor>,
    base_blob_order: &[BlobDescriptor],
    pending_blob_sequences: &HashMap<String, u64>,
) -> Vec<BlobDescriptor> {
    let mut size_by_digest = BTreeMap::new();
    for blob in merged_entries.values() {
        size_by_digest
            .entry(blob.digest.clone())
            .or_insert(blob.size_bytes);
    }

    let mut ordered = Vec::with_capacity(size_by_digest.len());
    let mut seen = HashSet::new();
    for blob in base_blob_order {
        let digest = blob.digest.clone();
        let Some(size_bytes) = size_by_digest.get(&digest) else {
            continue;
        };
        if seen.insert(digest.clone()) {
            ordered.push(BlobDescriptor {
                digest,
                size_bytes: *size_bytes,
            });
        }
    }

    let mut pending_digests: Vec<(u64, String)> = pending_blob_sequences
        .iter()
        .map(|(digest, sequence)| (*sequence, digest.clone()))
        .collect();
    pending_digests.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for (_, digest) in pending_digests {
        let Some(size_bytes) = size_by_digest.get(&digest) else {
            continue;
        };
        if seen.insert(digest.clone()) {
            ordered.push(BlobDescriptor {
                digest,
                size_bytes: *size_bytes,
            });
        }
    }

    for (digest, size_bytes) in size_by_digest {
        if seen.insert(digest.clone()) {
            ordered.push(BlobDescriptor { digest, size_bytes });
        }
    }

    ordered
}

pub(crate) enum FlushResult {
    Ok,
    Conflict,
    Error,
    Permanent,
}

#[derive(Debug)]
enum FlushError {
    Conflict(String),
    Transient(String),
    Permanent(String),
}

enum KvConfirmOutcome {
    Published,
    Pending(PendingMetadata),
}

fn kv_confirm_pending_metadata(outcome: &KvConfirmOutcome) -> Option<&PendingMetadata> {
    match outcome {
        KvConfirmOutcome::Published => None,
        KvConfirmOutcome::Pending(metadata) => Some(metadata),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlushMode {
    Normal,
    Shutdown,
}

pub(crate) struct FlushScheduleGuard {
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for FlushScheduleGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

pub(crate) fn try_schedule_flush(state: &AppState) -> Option<FlushScheduleGuard> {
    if state
        .kv_flush_scheduled
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }

    Some(FlushScheduleGuard {
        flag: state.kv_flush_scheduled.clone(),
    })
}

fn classify_flush_error(error: &anyhow::Error, context: &str) -> FlushError {
    let message = format!("{context}: {error}");
    let lower = message.to_ascii_lowercase();

    if let Some(bc_error) = error.downcast_ref::<BoringCacheError>() {
        match bc_error {
            BoringCacheError::CacheConflict { .. } => {
                return FlushError::Conflict(message);
            }
            BoringCacheError::CachePending { .. } => {
                if context.contains("confirm") {
                    return FlushError::Transient(message);
                }
                return FlushError::Conflict(message);
            }
            BoringCacheError::NetworkError(_) | BoringCacheError::ConnectionError(_) => {
                return FlushError::Transient(message);
            }
            BoringCacheError::ConfigNotFound
            | BoringCacheError::TokenNotFound
            | BoringCacheError::RequestConfiguration(_)
            | BoringCacheError::WorkspaceNotFound(_)
            | BoringCacheError::AuthenticationFailed(_) => {
                return FlushError::Permanent(message);
            }
            _ => {}
        }
    }

    let is_conflict = lower.contains("another cache upload is in progress");
    let conflict_status = has_status_code(&lower, 409)
        || has_status_code(&lower, 412)
        || has_status_code(&lower, 423);
    let conflict_hint = lower.contains("precondition failed")
        || lower.contains("etag mismatch")
        || lower.contains("manifest digest mismatch");
    if is_conflict || conflict_status || conflict_hint {
        return FlushError::Conflict(message);
    }

    let transient_status = has_status_code(&lower, 429)
        || has_status_code(&lower, 500)
        || has_status_code(&lower, 502)
        || has_status_code(&lower, 503)
        || has_status_code(&lower, 504);
    let transient_hint = lower.contains("transient error")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("deadline has elapsed")
        || lower.contains("connect error")
        || lower.contains("temporarily unavailable")
        || lower.contains("rate limit exceeded")
        || lower.contains("cannot connect")
        || lower.contains("connection refused")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
        || lower.contains("unexpected eof")
        || lower.contains("unexpected-eof")
        || lower.contains("close_notify")
        || is_blob_verification_pending_message(&lower);
    if transient_status || transient_hint {
        return FlushError::Transient(message);
    }

    let permanent_status = has_status_code(&lower, 400)
        || has_status_code(&lower, 401)
        || has_status_code(&lower, 403)
        || has_status_code(&lower, 404)
        || has_status_code(&lower, 405)
        || has_status_code(&lower, 410)
        || has_status_code(&lower, 411)
        || has_status_code(&lower, 413)
        || has_status_code(&lower, 414)
        || has_status_code(&lower, 415)
        || has_status_code(&lower, 422);
    let permanent_hint = lower.contains("authentication failed")
        || lower.contains("invalid or expired token")
        || lower.contains("access forbidden")
        || lower.contains("workspace not found")
        || lower.contains("unprocessable");
    if permanent_status || permanent_hint {
        return FlushError::Permanent(message);
    }

    FlushError::Transient(message)
}

async fn confirm_kv_flush(
    state: &AppState,
    cache_entry_id: &str,
    confirm_request: &ConfirmRequest,
    flush_mode: FlushMode,
) -> Result<KvConfirmOutcome, FlushError> {
    let started_at = std::time::Instant::now();
    let mut attempt = 0u32;

    loop {
        let result: Result<KvConfirmOutcome, anyhow::Error> = match flush_mode {
            FlushMode::Shutdown => state
                .api_client
                .confirm_wait_for_publish_or_shutdown_pending(
                    &state.workspace,
                    cache_entry_id,
                    confirm_request,
                    state.shutdown_requested.as_ref(),
                )
                .await
                .map(|response| match response {
                    crate::api::client::ConfirmPublishResult::Published(_) => {
                        KvConfirmOutcome::Published
                    }
                    crate::api::client::ConfirmPublishResult::Pending(metadata) => {
                        KvConfirmOutcome::Pending(metadata)
                    }
                }),
            FlushMode::Normal => state
                .api_client
                .confirm_wait_for_publish_or_pending_timeout(
                    &state.workspace,
                    cache_entry_id,
                    confirm_request,
                )
                .await
                .map(|response| match response {
                    crate::api::client::ConfirmPublishResult::Published(_) => {
                        KvConfirmOutcome::Published
                    }
                    crate::api::client::ConfirmPublishResult::Pending(metadata) => {
                        KvConfirmOutcome::Pending(metadata)
                    }
                }),
        };

        match result {
            Ok(outcome) => return Ok(outcome),
            Err(error) => {
                let message = format!("confirm failed: {error}");
                let classified = classify_flush_error(&error, "confirm failed");
                if started_at.elapsed() < KV_CONFIRM_VERIFICATION_RETRY_TIMEOUT
                    && let Some(reason) = confirm_retry_reason(&message, &classified)
                {
                    attempt = attempt.saturating_add(1);
                    let delay = kv_confirm_verification_retry_delay(attempt);
                    eprintln!(
                        "KV confirm: {reason} for cache entry {cache_entry_id}; retrying in {:.1}s (attempt {attempt})",
                        delay.as_secs_f32()
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }

                return Err(classified);
            }
        }
    }
}

fn confirm_retry_reason(message: &str, classified: &FlushError) -> Option<&'static str> {
    if is_blob_verification_pending_message(message) {
        return Some("blob verification pending");
    }

    if matches!(classified, FlushError::Transient(_)) {
        return Some("transient backend error");
    }

    None
}

fn has_status_code(lower: &str, code: u16) -> bool {
    let code = code.to_string();
    lower.contains(&format!("http {code}"))
        || lower.contains(&format!("status {code}"))
        || lower.contains(&format!("({code})"))
}

async fn set_next_flush_at_with_jitter(state: &AppState, base_ms: u64, jitter_ms: u64) {
    let jitter = if jitter_ms == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..jitter_ms)
    };
    let backoff = std::time::Duration::from_millis(base_ms + jitter);
    let mut next = state.kv_next_flush_at.write().await;
    *next = Some(std::time::Instant::now() + backoff);
}

async fn cleanup_blob_files(paths: &HashMap<String, PathBuf>) {
    let removals = paths.values().map(tokio::fs::remove_file);
    for result in join_all(removals).await {
        if let Err(error) = result {
            if error.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            log::warn!("KV cleanup: failed to remove blob temp file: {error}");
        }
    }
}

async fn cleanup_paths(paths: Vec<PathBuf>) {
    let removals = paths.into_iter().map(tokio::fs::remove_file);
    for result in join_all(removals).await {
        if let Err(error) = result {
            if error.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            log::warn!("KV cleanup: failed to remove temp file: {error}");
        }
    }
}

async fn promote_pending_blobs_to_read_cache(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
) -> usize {
    let mut blob_sizes = HashMap::new();
    for blob in pending_entries.values() {
        blob_sizes
            .entry(blob.digest.clone())
            .or_insert(blob.size_bytes);
    }

    let mut promoted = 0usize;
    for (digest, path) in pending_blob_paths {
        let size = blob_sizes.get(digest).copied().unwrap_or(0);
        match state.blob_read_cache.promote(digest, path, size).await {
            Ok(true) => promoted = promoted.saturating_add(1),
            Ok(false) => {}
            Err(error) => {
                log::warn!("KV blob read cache promote failed for {digest}: {error}");
            }
        }
    }
    promoted
}

pub(crate) async fn flush_kv_index(state: &AppState) -> FlushResult {
    flush_kv_index_with_mode(state, FlushMode::Normal).await
}

pub(crate) async fn flush_kv_index_on_shutdown(state: &AppState) -> FlushResult {
    flush_kv_index_with_mode(state, FlushMode::Shutdown).await
}

async fn flush_kv_index_with_mode(state: &AppState, flush_mode: FlushMode) -> FlushResult {
    let guard = state.kv_flush_lock.lock().await;

    let (pending_entries, pending_blob_paths, pending_blob_sequences) = {
        let mut pending = state.kv_pending.write().await;
        if pending.is_empty() {
            return FlushResult::Ok;
        }
        pending.take_all()
    };

    if pending_entries.is_empty() {
        return FlushResult::Ok;
    }

    {
        let mut flushing = state.kv_flushing.write().await;
        *flushing = Some(KvFlushingSnapshot::new(
            pending_entries.clone(),
            pending_blob_paths
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ));
    }

    let entry_count = pending_entries.len();

    let result = match do_flush(
        state,
        &pending_entries,
        &pending_blob_paths,
        &pending_blob_sequences,
        flush_mode,
    )
    .await
    {
        Ok((merged_entries, merged_blob_order, cache_entry_id)) => {
            {
                let mut published = state.kv_published_index.write().await;
                published.update(
                    merged_entries.into_iter().collect(),
                    merged_blob_order,
                    cache_entry_id.clone(),
                );
            }
            {
                let mut flushing = state.kv_flushing.write().await;
                *flushing = None;
            }
            clear_root_tag_misses(state);

            let promoted =
                promote_pending_blobs_to_read_cache(state, &pending_entries, &pending_blob_paths)
                    .await;
            cleanup_blob_files(&pending_blob_paths).await;
            state.kv_last_put.store(0, Ordering::Release);

            eprintln!(
                "KV batch: flushed {entry_count} new entries ({} blobs cleaned up, {promoted} promoted to read cache)",
                pending_blob_paths.len(),
            );
            drop(guard);
            preload_download_urls(state, &cache_entry_id).await;
            spawn_preload_blobs(state, &cache_entry_id);
            FlushResult::Ok
        }
        Err(FlushError::Conflict(msg)) => {
            eprintln!("KV batch flush: skipped — tag conflict ({msg})");
            let mut pending = state.kv_pending.write().await;
            let paths_to_cleanup =
                pending.restore(pending_entries, pending_blob_paths, pending_blob_sequences);
            drop(pending);
            cleanup_paths(paths_to_cleanup).await;
            let (base_ms, jitter_ms) = conflict_backoff_window(&msg);
            set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
            FlushResult::Conflict
        }
        Err(FlushError::Transient(msg)) => {
            eprintln!("KV batch flush failed: {msg}");
            let mut pending = state.kv_pending.write().await;
            let paths_to_cleanup =
                pending.restore(pending_entries, pending_blob_paths, pending_blob_sequences);
            drop(pending);
            cleanup_paths(paths_to_cleanup).await;
            let (base_ms, jitter_ms) = transient_backoff_window(&msg);
            set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
            FlushResult::Error
        }
        Err(FlushError::Permanent(msg)) => {
            eprintln!("KV batch flush dropped permanently: {msg}");
            cleanup_blob_files(&pending_blob_paths).await;
            state.kv_last_put.store(0, Ordering::Release);
            FlushResult::Permanent
        }
    };

    if should_clear_flushing_after_flush(&result) {
        let mut flushing = state.kv_flushing.write().await;
        *flushing = None;
    }

    result
}

fn should_clear_flushing_after_flush(result: &FlushResult) -> bool {
    !matches!(result, FlushResult::Ok)
}

pub(crate) async fn refresh_kv_index(state: &AppState) {
    if state.kv_flush_scheduled.load(Ordering::Acquire) {
        return;
    }
    if state.kv_flushing.read().await.is_some() {
        return;
    }

    let mut live_hit: Option<(String, CacheResolutionEntry)> = None;
    for candidate_tag in kv_root_tags(state) {
        match resolve_hit_for_index_load(state, &candidate_tag, true).await {
            Ok(hit) => {
                if candidate_tag != state.registry_root_tag.trim() {
                    eprintln!("KV root fallback hit: refreshing from legacy tag {candidate_tag}");
                }
                live_hit = Some((candidate_tag, hit));
                break;
            }
            Err(error) if error.status == StatusCode::NOT_FOUND => {}
            Err(error) => {
                log::warn!("KV index refresh failed during resolve: {error:?}");
                return;
            }
        }
    }

    let Some((tag, hit)) = live_hit else {
        let had_entries = {
            let published = state.kv_published_index.read().await;
            published.entry_count() > 0
        };
        if had_entries {
            let mut published = state.kv_published_index.write().await;
            published.touch_refresh();
            clear_root_tag_misses(state);
            eprintln!("KV index refresh: preserving in-memory index (no backend index)");
            return;
        }
        {
            let mut published = state.kv_published_index.write().await;
            published.set_empty();
        }
        clear_root_tag_misses(state);
        if had_entries {
            eprintln!("KV index refresh: cleared stale entries (no backend index)");
        }
        return;
    };

    let cache_entry_id = match hit.cache_entry_id.clone() {
        Some(id) => id,
        None => {
            log::warn!("KV index refresh: live hit missing cache_entry_id");
            return;
        }
    };
    let manifest_root_digest = hit
        .manifest_root_digest
        .clone()
        .or(hit.manifest_digest.clone());
    let should_fence = {
        let published = state.kv_published_index.read().await;
        if published
            .cache_entry_id()
            .is_some_and(|current| current == cache_entry_id.as_str())
        {
            drop(published);
            let mut published = state.kv_published_index.write().await;
            published.touch_refresh();
            return;
        }
        published
            .cache_entry_id()
            .is_some_and(|current| current != cache_entry_id.as_str())
    };
    if should_fence
        && !refresh_fence_allows_update(
            state,
            &tag,
            &cache_entry_id,
            manifest_root_digest.as_deref(),
        )
        .await
    {
        return;
    }

    let pointer = match fetch_pointer(state, &hit).await {
        Ok(pointer) => pointer,
        Err(error) => {
            log::warn!("KV index refresh failed to fetch pointer: {error:?}");
            return;
        }
    };

    let mut entries = HashMap::new();
    for entry in &pointer.entries {
        if !matches!(entry.entry_type, EntryType::File) {
            continue;
        }
        if let Some(digest) = &entry.digest {
            entries.insert(
                entry.path.clone(),
                BlobDescriptor {
                    digest: digest.clone(),
                    size_bytes: entry.size_bytes,
                },
            );
        }
    }
    let entry_map: BTreeMap<String, BlobDescriptor> = entries
        .iter()
        .map(|(key, blob)| (key.clone(), blob.clone()))
        .collect();
    let blob_order = pointer_blob_order(&pointer, &entry_map);

    let (published_entries, published_entry_count) = {
        let published = state.kv_published_index.read().await;
        (published.entries_snapshot(), published.entry_count())
    };
    let gap_counts = count_published_gaps_in_backend(&entry_map, published_entries.as_ref());
    if published_entry_count > 0 && (gap_counts.missing_keys > 0 || gap_counts.mismatched_keys > 0)
    {
        let mut published = state.kv_published_index.write().await;
        published.touch_refresh();
        clear_root_tag_misses(state);
        eprintln!(
            "KV index refresh: preserving in-memory index (backend={} published={} missing_keys={} mismatched_keys={})",
            entry_map.len(),
            published_entry_count,
            gap_counts.missing_keys,
            gap_counts.mismatched_keys
        );
        return;
    }

    if entries.is_empty() {
        let had_entries = {
            let published = state.kv_published_index.read().await;
            published.entry_count() > 0
        };
        if had_entries {
            let mut published = state.kv_published_index.write().await;
            published.touch_refresh();
            clear_root_tag_misses(state);
            eprintln!("KV index refresh: preserving in-memory index (empty pointer)");
            return;
        }
        {
            let mut published = state.kv_published_index.write().await;
            published.set_empty();
        }
        clear_root_tag_misses(state);
        if had_entries {
            eprintln!("KV index refresh: cleared stale entries (empty pointer)");
        }
        return;
    }

    let count = entries.len();
    {
        let mut published = state.kv_published_index.write().await;
        published.update(entries, blob_order, cache_entry_id.clone());
    }
    clear_root_tag_misses(state);
    eprintln!("KV index refresh: {count} entries loaded");
    preload_download_urls(state, &cache_entry_id).await;
    spawn_preload_blobs(state, &cache_entry_id);
}

pub(crate) async fn refresh_kv_index_keys_only(state: &AppState) {
    if state.kv_flush_scheduled.load(Ordering::Acquire) {
        return;
    }
    if state.kv_flushing.read().await.is_some() {
        return;
    }

    let mut live_hit: Option<(String, CacheResolutionEntry)> = None;
    for candidate_tag in kv_root_tags(state) {
        match resolve_hit_for_index_load(state, &candidate_tag, true).await {
            Ok(hit) => {
                if candidate_tag != state.registry_root_tag.trim() {
                    eprintln!("KV root fallback hit: refreshing from legacy tag {candidate_tag}");
                }
                live_hit = Some((candidate_tag, hit));
                break;
            }
            Err(error) if error.status == StatusCode::NOT_FOUND => {}
            Err(error) => {
                log::warn!("KV version-triggered refresh failed during resolve: {error:?}");
                return;
            }
        }
    }

    let Some((tag, hit)) = live_hit else {
        return;
    };

    let cache_entry_id = match hit.cache_entry_id.clone() {
        Some(id) => id,
        None => {
            log::warn!("KV version-triggered refresh: live hit missing cache_entry_id");
            return;
        }
    };
    let manifest_root_digest = hit
        .manifest_root_digest
        .clone()
        .or(hit.manifest_digest.clone());
    let should_fence = {
        let published = state.kv_published_index.read().await;
        if published
            .cache_entry_id()
            .is_some_and(|current| current == cache_entry_id.as_str())
        {
            drop(published);
            let mut published = state.kv_published_index.write().await;
            published.touch_refresh();
            return;
        }
        published
            .cache_entry_id()
            .is_some_and(|current| current != cache_entry_id.as_str())
    };
    if should_fence
        && !refresh_fence_allows_update(
            state,
            &tag,
            &cache_entry_id,
            manifest_root_digest.as_deref(),
        )
        .await
    {
        return;
    }

    let pointer = match fetch_pointer(state, &hit).await {
        Ok(pointer) => pointer,
        Err(error) => {
            log::warn!("KV version-triggered refresh failed to fetch pointer: {error:?}");
            return;
        }
    };

    let mut entries = HashMap::new();
    for entry in &pointer.entries {
        if !matches!(entry.entry_type, EntryType::File) {
            continue;
        }
        if let Some(digest) = &entry.digest {
            entries.insert(
                entry.path.clone(),
                BlobDescriptor {
                    digest: digest.clone(),
                    size_bytes: entry.size_bytes,
                },
            );
        }
    }
    let entry_map: BTreeMap<String, BlobDescriptor> = entries
        .iter()
        .map(|(key, blob)| (key.clone(), blob.clone()))
        .collect();
    let blob_order = pointer_blob_order(&pointer, &entry_map);

    let (published_entries, published_entry_count) = {
        let published = state.kv_published_index.read().await;
        (published.entries_snapshot(), published.entry_count())
    };
    let gap_counts = count_published_gaps_in_backend(&entry_map, published_entries.as_ref());
    if published_entry_count > 0 && (gap_counts.missing_keys > 0 || gap_counts.mismatched_keys > 0)
    {
        let mut published = state.kv_published_index.write().await;
        published.touch_refresh();
        clear_root_tag_misses(state);
        eprintln!(
            "KV version-triggered refresh: preserving in-memory index (backend={} published={} missing_keys={} mismatched_keys={})",
            entry_map.len(),
            published_entry_count,
            gap_counts.missing_keys,
            gap_counts.mismatched_keys
        );
        return;
    }

    if entries.is_empty() {
        let had_entries = {
            let published = state.kv_published_index.read().await;
            published.entry_count() > 0
        };
        if had_entries {
            let mut published = state.kv_published_index.write().await;
            published.touch_refresh();
            clear_root_tag_misses(state);
            return;
        }
        {
            let mut published = state.kv_published_index.write().await;
            published.set_empty();
        }
        clear_root_tag_misses(state);
        return;
    }

    let count = entries.len();
    {
        let mut published = state.kv_published_index.write().await;
        published.update(entries, blob_order, cache_entry_id.clone());
    }
    clear_root_tag_misses(state);
    eprintln!("KV version-triggered refresh: {count} entries loaded (no blob prefetch)");
}

pub(crate) async fn poll_tag_version_loop(state: &AppState) {
    let mut last_etag: Option<String> = None;
    let mut last_cache_entry_id: Option<String> = {
        let published = state.kv_published_index.read().await;
        published.cache_entry_id().map(|s| s.to_string())
    };
    let mut polls: u64 = 0;
    let mut changes: u64 = 0;
    let mut refreshes: u64 = 0;
    let mut skipped_refreshes: u64 = 0;
    let refreshing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let last_refresh_completed_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));

    loop {
        let is_active = is_proxy_active(state);
        let base_ms = if is_active {
            KV_VERSION_POLL_ACTIVE_SECS * 1000
        } else {
            KV_VERSION_POLL_IDLE_SECS * 1000
        };
        let jitter = rand::thread_rng().gen_range(0..=KV_VERSION_POLL_JITTER_MS * 2);
        let sleep_ms = base_ms.saturating_sub(KV_VERSION_POLL_JITTER_MS) + jitter;
        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;

        if refreshing.load(Ordering::Acquire) {
            continue;
        }

        let primary_tag = state.registry_root_tag.trim().to_string();
        let poll_result = tokio::time::timeout(
            KV_VERSION_POLL_TIMEOUT,
            state
                .api_client
                .tag_pointer(&state.workspace, &primary_tag, last_etag.as_deref()),
        )
        .await;

        polls += 1;

        let poll_result = match poll_result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                log::warn!("Tag version poll failed: {error}");
                last_etag = None;
                continue;
            }
            Err(_) => {
                log::warn!("Tag version poll timed out");
                continue;
            }
        };

        use crate::api::client::TagPointerPollResult;
        match poll_result {
            TagPointerPollResult::NotModified => {}
            TagPointerPollResult::NotFound => {
                last_etag = None;
            }
            TagPointerPollResult::Changed { pointer, etag } => {
                last_etag = etag;

                let new_cache_entry_id = pointer.cache_entry_id.as_deref();
                let changed = match (&last_cache_entry_id, new_cache_entry_id) {
                    (Some(old), Some(new)) => old != new,
                    (None, Some(_)) => true,
                    _ => false,
                };

                if changed {
                    changes += 1;
                    let new_id = new_cache_entry_id.unwrap().to_string();
                    last_cache_entry_id = Some(new_id.clone());

                    let now_ms = crate::serve::state::unix_time_ms_now();
                    let last_ms = last_refresh_completed_ms.load(Ordering::Acquire);
                    let cooldown_ms = KV_VERSION_REFRESH_COOLDOWN.as_millis() as u64;
                    if last_ms > 0 && now_ms.saturating_sub(last_ms) < cooldown_ms {
                        skipped_refreshes += 1;
                        eprintln!(
                            "Tag version changed: {} (poll={} changes={} mode={} refresh=cooldown skipped={})",
                            &new_id[..8.min(new_id.len())],
                            polls,
                            changes,
                            if is_active { "active" } else { "idle" },
                            skipped_refreshes,
                        );
                        continue;
                    }

                    eprintln!(
                        "Tag version changed: {} (poll={} changes={} mode={})",
                        &new_id[..8.min(new_id.len())],
                        polls,
                        changes,
                        if is_active { "active" } else { "idle" }
                    );

                    let refresh_state = state.clone();
                    let refresh_flag = refreshing.clone();
                    let refresh_completed = last_refresh_completed_ms.clone();
                    refresh_flag.store(true, Ordering::Release);
                    refreshes += 1;
                    let refresh_count = refreshes;
                    tokio::spawn(async move {
                        let started = std::time::Instant::now();
                        refresh_kv_index_keys_only(&refresh_state).await;
                        let duration_ms = started.elapsed().as_millis();
                        let completed_ms = crate::serve::state::unix_time_ms_now();
                        refresh_completed.store(completed_ms, Ordering::Release);
                        eprintln!(
                            "Tag version refresh complete: {}ms (refreshes={})",
                            duration_ms, refresh_count
                        );
                        refresh_flag.store(false, Ordering::Release);
                    });
                }
            }
        }
    }
}

async fn refresh_fence_allows_update(
    state: &AppState,
    tag: &str,
    expected_cache_entry_id: &str,
    expected_manifest_root_digest: Option<&str>,
) -> bool {
    let live_hit = match resolve_hit(state, tag).await {
        Ok(hit) => hit,
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            tokio::time::sleep(KV_RESOLVE_NOT_FOUND_RETRY_DELAY).await;
            match resolve_hit(state, tag).await {
                Ok(hit) => hit,
                Err(error) => {
                    log::warn!(
                        "KV index refresh fence: live resolve failed (skipping update): {}",
                        error.status
                    );
                    return false;
                }
            }
        }
        Err(error) => {
            log::warn!(
                "KV index refresh fence: live resolve failed (skipping update): {}",
                error.status
            );
            return false;
        }
    };

    let live_cache_entry_id = match live_hit.cache_entry_id.as_deref() {
        Some(id) => id,
        None => {
            log::warn!("KV index refresh fence: live hit missing cache_entry_id");
            return false;
        }
    };
    if live_cache_entry_id != expected_cache_entry_id {
        eprintln!(
            "KV index refresh fence: skipping stale update (expected entry {}, live entry {})",
            expected_cache_entry_id, live_cache_entry_id
        );
        return false;
    }

    if let (Some(expected_digest), Some(live_digest)) = (
        expected_manifest_root_digest,
        live_hit
            .manifest_root_digest
            .as_deref()
            .or(live_hit.manifest_digest.as_deref()),
    ) && expected_digest != live_digest
    {
        eprintln!(
            "KV index refresh fence: skipping stale update (expected digest {}, live digest {})",
            expected_digest, live_digest
        );
        return false;
    }

    true
}

fn spawn_preload_blobs(state: &AppState, cache_entry_id: &str) {
    let preload_state = state.clone();
    let preload_cache_entry_id = cache_entry_id.to_string();
    tokio::spawn(async move {
        match tokio::time::timeout(
            KV_BLOB_PRELOAD_TIMEOUT,
            preload_blobs(&preload_state, &preload_cache_entry_id),
        )
        .await
        {
            Ok(()) => {}
            Err(_) => eprintln!(
                "KV blob preload: timed out after {}s",
                KV_BLOB_PRELOAD_TIMEOUT.as_secs()
            ),
        }
    });
}

async fn preload_download_urls(state: &AppState, cache_entry_id: &str) {
    let blobs = {
        let published = state.kv_published_index.read().await;
        published.unique_blobs()
    };

    if blobs.is_empty() {
        return;
    }

    let batch_size = blobs.len() as u64;
    emit_serve_event(
        Some(&state.workspace),
        SERVE_PRELOAD_INDEX_OPERATION,
        SERVE_PRELOAD_INDEX_PATH,
        format!("resolve_download_urls:start batch_size={batch_size}"),
    );
    let started_at = std::time::Instant::now();

    match state
        .api_client
        .blob_download_urls_verified(&state.workspace, cache_entry_id, &blobs)
        .await
    {
        Ok(response) => {
            let urls: HashMap<String, String> = response
                .download_urls
                .into_iter()
                .map(|u| (u.digest, u.url))
                .collect();
            let url_count = urls.len();
            let mut published = state.kv_published_index.write().await;
            published.set_download_urls(urls);
            eprintln!("KV index preload: resolved {url_count} download URLs");
            emit_serve_phase_metric(
                Some(&state.workspace),
                Some(cache_entry_id),
                SERVE_PRELOAD_INDEX_OPERATION,
                SERVE_PRELOAD_INDEX_PATH,
                200,
                started_at.elapsed().as_millis() as u64,
                Some(batch_size),
            );
            emit_serve_event(
                Some(&state.workspace),
                SERVE_PRELOAD_INDEX_OPERATION,
                SERVE_PRELOAD_INDEX_PATH,
                format!("resolve_download_urls:done resolved={url_count}"),
            );
        }
        Err(e) => {
            log::warn!("KV index preload: failed to resolve download URLs: {e}");
            observability::emit(
                observability::ObservabilityEvent::failure(
                    SERVE_METRIC_SOURCE,
                    SERVE_PRELOAD_INDEX_OPERATION,
                    "PHASE",
                    SERVE_PRELOAD_INDEX_PATH.to_string(),
                    e.to_string(),
                    started_at.elapsed().as_millis() as u64,
                    None,
                )
                .with_workspace(Some(state.workspace.clone()))
                .with_cache_entry_id(Some(cache_entry_id.to_string())),
            );
        }
    }
}

fn kv_blob_preload_max_blob_bytes() -> u64 {
    parse_positive_u64_env(KV_BLOB_PRELOAD_MAX_BLOB_BYTES_ENV)
        .unwrap_or(KV_BLOB_PRELOAD_MAX_BLOB_BYTES)
}

fn kv_blob_preload_max_blobs() -> usize {
    parse_positive_usize_env(KV_BLOB_PRELOAD_MAX_BLOBS_ENV).unwrap_or(KV_BLOB_PRELOAD_MAX_BLOBS)
}

fn kv_startup_prefetch_max_blobs() -> usize {
    parse_positive_usize_env(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV)
        .unwrap_or(KV_STARTUP_PREFETCH_MAX_BLOBS)
}

fn kv_startup_prefetch_max_total_bytes(cache_max: u64) -> u64 {
    parse_positive_u64_env(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV).unwrap_or_else(|| {
        cache_max.saturating_div(4).clamp(
            KV_STARTUP_PREFETCH_MIN_TOTAL_BYTES,
            KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES,
        )
    })
}

fn kv_blob_prefetch_max_inflight_bytes(cache_max: u64) -> u64 {
    if let Some(configured) = parse_positive_u64_env(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV) {
        return configured;
    }
    // Keep defaults conservative for small nodes while still scaling on larger caches.
    cache_max
        .saturating_div(4)
        .clamp(64 * 1024 * 1024, 512 * 1024 * 1024)
}

fn should_skip_blob_preload(used_bytes: u64, max_bytes: u64) -> bool {
    if max_bytes == 0 {
        return true;
    }
    used_bytes.saturating_mul(100) >= max_bytes.saturating_mul(KV_BLOB_PRELOAD_SKIP_USED_PCT)
}

fn select_startup_prefetch_slice(
    blobs: &[BlobDescriptor],
    max_blobs: usize,
    max_total_bytes: u64,
) -> Vec<BlobDescriptor> {
    let mut selected = Vec::new();
    let mut remaining_bytes = max_total_bytes;

    for blob in blobs {
        if selected.len() >= max_blobs {
            break;
        }
        if blob.size_bytes == 0 {
            continue;
        }
        if blob.size_bytes > remaining_bytes {
            break;
        }
        remaining_bytes = remaining_bytes.saturating_sub(blob.size_bytes);
        selected.push(blob.clone());
    }

    selected
}

async fn preload_single_blob(
    state: AppState,
    cache_entry_id: String,
    blob: BlobDescriptor,
    url: String,
) -> anyhow::Result<bool> {
    if state
        .blob_read_cache
        .get_handle(&blob.digest)
        .await
        .is_some()
    {
        return Ok(false);
    }

    download_blob_to_cache(&state, &cache_entry_id, &blob, Some(&url))
        .await
        .map_err(|error| anyhow::anyhow!("download_blob_to_cache failed: {:?}", error))?;

    Ok(true)
}

pub(crate) async fn preload_blobs(state: &AppState, cache_entry_id: &str) {
    let max_blob_bytes = kv_blob_preload_max_blob_bytes();
    let max_blobs = kv_blob_preload_max_blobs();
    let cache_used = state.blob_read_cache.total_bytes();
    let cache_max = state.blob_read_cache.max_bytes();
    if should_skip_blob_preload(cache_used, cache_max) {
        eprintln!(
            "KV blob preload: skipped, cache near capacity used={} max={}",
            cache_used, cache_max
        );
        return;
    }
    let inflight_budget_cap = kv_blob_prefetch_max_inflight_bytes(cache_max);
    let mut preload_budget = cache_max
        .saturating_sub(cache_used)
        .min(inflight_budget_cap);
    if preload_budget == 0 {
        emit_serve_event(
            Some(&state.workspace),
            SERVE_PREFETCH_OPERATION,
            SERVE_PREFETCH_PATH,
            "skipped: prefetch budget is zero".to_string(),
        );
        return;
    }
    let mut candidates = {
        let published = state.kv_published_index.read().await;
        let mut values = Vec::new();
        for blob in published.unique_blobs() {
            if blob.size_bytes == 0 || blob.size_bytes > max_blob_bytes {
                continue;
            }
            if blob.size_bytes > preload_budget {
                continue;
            }
            if let Some(url) = published.download_url(&blob.digest) {
                let blob_size = blob.size_bytes;
                values.push((blob, url.to_string()));
                preload_budget = preload_budget.saturating_sub(blob_size);
            }
            if values.len() >= max_blobs {
                break;
            }
        }
        values
    };

    if candidates.is_empty() {
        return;
    }

    let mut targets = Vec::new();
    for (blob, url) in candidates.drain(..) {
        if state
            .blob_read_cache
            .get_handle(&blob.digest)
            .await
            .is_none()
        {
            targets.push((blob, url));
        }
    }
    if targets.is_empty() {
        return;
    }

    let scheduled = targets.len();
    let scheduled_bytes = targets
        .iter()
        .map(|(blob, _)| blob.size_bytes)
        .fold(0u64, |acc, size| acc.saturating_add(size));
    emit_serve_event(
        Some(&state.workspace),
        SERVE_PREFETCH_OPERATION,
        SERVE_PREFETCH_PATH,
        format!(
            "start: scheduled={scheduled} scheduled_bytes={scheduled_bytes} max_blobs={max_blobs} max_blob_bytes={max_blob_bytes} inflight_budget_cap={inflight_budget_cap}"
        ),
    );
    let prefetch_started_at = std::time::Instant::now();

    let prefetch_semaphore = state.blob_prefetch_semaphore.clone();
    let mut tasks = tokio::task::JoinSet::new();
    for (blob, url) in targets {
        let state = state.clone();
        let cache_entry_id = cache_entry_id.to_string();
        let prefetch_semaphore = prefetch_semaphore.clone();
        tasks.spawn(async move {
            let _permit = prefetch_semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow::anyhow!("prefetch semaphore closed: {error}"))?;
            let result = preload_single_blob(state, cache_entry_id, blob, url).await;
            drop(_permit);
            result
        });
    }

    let mut inserted = 0usize;
    let mut failures = 0usize;
    loop {
        let next_result = tasks.join_next().await;
        let Some(result) = next_result else {
            break;
        };
        match result {
            Ok(Ok(true)) => inserted = inserted.saturating_add(1),
            Ok(Ok(false)) => {}
            Ok(Err(error)) => {
                failures = failures.saturating_add(1);
                log::warn!("KV blob preload failed: {error}");
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                log::warn!("KV blob preload task failed: {error}");
            }
        }
    }

    let status = if failures == 0 {
        200
    } else if inserted > 0 {
        207
    } else {
        500
    };
    emit_serve_phase_metric(
        Some(&state.workspace),
        Some(cache_entry_id),
        SERVE_PREFETCH_OPERATION,
        SERVE_PREFETCH_PATH,
        status,
        prefetch_started_at.elapsed().as_millis() as u64,
        Some(scheduled as u64),
    );
    emit_serve_event(
        Some(&state.workspace),
        SERVE_PREFETCH_OPERATION,
        SERVE_PREFETCH_PATH,
        format!(
            "done: inserted={inserted} scheduled={scheduled} failures={failures} scheduled_bytes={scheduled_bytes}"
        ),
    );

    if inserted > 0 || failures > 0 {
        eprintln!(
            "KV blob preload: inserted={inserted} scheduled={scheduled} failures={failures} cache_size={} bytes",
            state.blob_read_cache.total_bytes()
        );
    }
}

const KV_PREFETCH_READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub(crate) async fn prefetch_manifest_blobs(state: &AppState) {
    eprintln!("Prefetch: loading index and warming startup slice before serving...");
    let started_at = std::time::Instant::now();

    emit_serve_event(
        Some(&state.workspace),
        SERVE_PRELOAD_INDEX_OPERATION,
        SERVE_PRELOAD_INDEX_PATH,
        "sync:start".to_string(),
    );

    match load_existing_index_with_fallback(state, true).await {
        Ok((entries, blob_order, Some(cache_entry_id), _manifest_root_digest))
            if !entries.is_empty() =>
        {
            let count = entries.len();
            {
                let mut published = state.kv_published_index.write().await;
                published.update(
                    entries.into_iter().collect(),
                    blob_order,
                    cache_entry_id.clone(),
                );
            }
            clear_root_tag_misses(state);
            eprintln!("Prefetch: {count} entries loaded, resolving download URLs...");

            preload_download_urls(state, &cache_entry_id).await;

            eprintln!("Prefetch: warming startup slice...");
            match tokio::time::timeout(
                KV_PREFETCH_READINESS_TIMEOUT,
                prefetch_all_blobs(state, &cache_entry_id),
            )
            .await
            {
                Ok(()) => {
                    eprintln!(
                        "Prefetch: complete in {:.1}s, cache_size={} bytes",
                        started_at.elapsed().as_secs_f64(),
                        state.blob_read_cache.total_bytes(),
                    );
                }
                Err(_) => {
                    eprintln!(
                        "Prefetch: timed out after {}s (partial prefetch, continuing)",
                        KV_PREFETCH_READINESS_TIMEOUT.as_secs(),
                    );
                }
            }
        }
        Ok(_) => {
            {
                let mut published = state.kv_published_index.write().await;
                published.set_empty_incomplete();
            }
            eprintln!("Prefetch: no existing entries, skipping");
        }
        Err(e) => {
            if is_invalid_file_pointer_error(&e) {
                let mut published = state.kv_published_index.write().await;
                published.set_empty_incomplete();
                eprintln!("Prefetch: invalid file pointer, degraded to empty index");
                return;
            }
            log::warn!("Prefetch: index load failed: {e:?}");
        }
    }
}

async fn prefetch_all_blobs(state: &AppState, cache_entry_id: &str) {
    let cache_used = state.blob_read_cache.total_bytes();
    let cache_max = state.blob_read_cache.max_bytes();
    if should_skip_blob_preload(cache_used, cache_max) {
        eprintln!(
            "Prefetch: startup slice skipped, cache near capacity used={} max={}",
            cache_used, cache_max
        );
        return;
    }

    let startup_max_blobs = kv_startup_prefetch_max_blobs();
    let startup_max_total_bytes =
        kv_startup_prefetch_max_total_bytes(cache_max).min(cache_max.saturating_sub(cache_used));
    if startup_max_total_bytes == 0 {
        eprintln!("Prefetch: startup slice skipped, budget is zero");
        return;
    }

    let (total_unique_blobs, startup_slice) = {
        let published = state.kv_published_index.read().await;
        let unique_blobs = published.unique_blobs();
        let total_unique_blobs = unique_blobs.len();
        let startup_slice = select_startup_prefetch_slice(
            &unique_blobs,
            startup_max_blobs,
            startup_max_total_bytes,
        )
        .into_iter()
        .filter_map(|blob| {
            published
                .download_url(&blob.digest)
                .map(|url| (blob, url.to_string()))
        })
        .collect::<Vec<_>>();
        (total_unique_blobs, startup_slice)
    };

    if startup_slice.is_empty() {
        eprintln!(
            "Prefetch: startup slice selected 0/{total_unique_blobs} blobs under budget={} bytes",
            startup_max_total_bytes
        );
        return;
    }

    let mut targets = Vec::new();
    for (blob, url) in startup_slice {
        if state
            .blob_read_cache
            .get_handle(&blob.digest)
            .await
            .is_none()
        {
            targets.push((blob, url));
        }
    }

    if targets.is_empty() {
        eprintln!(
            "Prefetch: startup slice already warm under budget={} bytes",
            startup_max_total_bytes
        );
        return;
    }

    let scheduled = targets.len();
    let scheduled_bytes: u64 = targets.iter().map(|(b, _)| b.size_bytes).sum();
    eprintln!(
        "Prefetch: warming startup slice {scheduled}/{total_unique_blobs} blobs ({:.1} MB)",
        scheduled_bytes as f64 / (1024.0 * 1024.0),
    );

    let prefetch_started_at = std::time::Instant::now();
    let prefetch_semaphore = state.blob_prefetch_semaphore.clone();
    let mut tasks = tokio::task::JoinSet::new();
    for (blob, url) in targets {
        let state = state.clone();
        let cache_entry_id = cache_entry_id.to_string();
        let prefetch_semaphore = prefetch_semaphore.clone();
        tasks.spawn(async move {
            let _permit = prefetch_semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow::anyhow!("prefetch semaphore closed: {error}"))?;
            let result = preload_single_blob(state, cache_entry_id, blob, url).await;
            drop(_permit);
            result
        });
    }

    let mut inserted = 0usize;
    let mut failures = 0usize;
    let log_interval = (scheduled / 10).max(1);
    let mut completed = 0usize;
    loop {
        let next_result = tasks.join_next().await;
        let Some(result) = next_result else {
            break;
        };
        match result {
            Ok(Ok(true)) => inserted = inserted.saturating_add(1),
            Ok(Ok(false)) => {}
            Ok(Err(error)) => {
                failures = failures.saturating_add(1);
                log::warn!("Prefetch startup blob failed: {error}");
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                log::warn!("Prefetch startup task failed: {error}");
            }
        }
        completed = completed.saturating_add(1);
        if completed.is_multiple_of(log_interval) {
            eprintln!(
                "Prefetch: startup slice {completed}/{scheduled} blobs ({inserted} inserted, {failures} failed, {:.1}s)",
                prefetch_started_at.elapsed().as_secs_f64(),
            );
        }
    }

    let status = if failures == 0 {
        200
    } else if inserted > 0 {
        207
    } else {
        500
    };
    emit_serve_phase_metric(
        Some(&state.workspace),
        Some(cache_entry_id),
        SERVE_PREFETCH_OPERATION,
        SERVE_PREFETCH_PATH,
        status,
        prefetch_started_at.elapsed().as_millis() as u64,
        Some(scheduled as u64),
    );

    eprintln!(
        "Prefetch: startup slice done inserted={inserted} scheduled={scheduled} failures={failures} cache_size={} bytes in {:.1}s",
        state.blob_read_cache.total_bytes(),
        prefetch_started_at.elapsed().as_secs_f64(),
    );
}

async fn do_flush(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
    pending_blob_sequences: &HashMap<String, u64>,
    flush_mode: FlushMode,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        String,
    ),
    FlushError,
> {
    let flush_started_at = std::time::Instant::now();
    let tag = state.registry_root_tag.trim().to_string();

    let (published_snapshot, published_blob_order) = {
        let published = state.kv_published_index.read().await;
        (published.entries_snapshot(), published.unique_blobs())
    };

    let (backend_entries, backend_blob_order) =
        match load_existing_index_with_fallback(state, false).await {
            Ok((existing, blob_order, _, _)) => (existing, blob_order),
            Err(e) => {
                log::warn!("KV flush: failed to load existing index: {e:?}");
                (BTreeMap::new(), Vec::new())
            }
        };
    let (mut entries, base_selection) =
        select_flush_base_entries(backend_entries, published_snapshot.as_ref());
    let base_blob_order = match base_selection {
        FlushBaseSelection::Backend => backend_blob_order,
        FlushBaseSelection::PublishedFallback { .. } => published_blob_order,
    };
    let existing_count = entries.len();
    let (
        filtered_pending_entries,
        filtered_pending_blob_paths,
        filtered_pending_blob_sequences,
        missing_pending_digests,
        missing_pending_entries,
    ) = filter_pending_entries_with_local_blobs(
        pending_entries,
        pending_blob_paths,
        pending_blob_sequences,
    );
    if let FlushBaseSelection::PublishedFallback {
        backend_entry_count,
        published_entry_count,
        missing_published_keys,
        mismatched_published_keys,
    } = base_selection
    {
        if backend_entry_count == 0 {
            eprintln!(
                "KV flush: backend index empty, using published snapshot with {published_entry_count} entries"
            );
        } else {
            eprintln!(
                "KV flush: backend index stale (backend={backend_entry_count}, published={published_entry_count}, missing_keys={missing_published_keys}, mismatched_keys={mismatched_published_keys}); preserving in-memory snapshot"
            );
        }
    }
    if missing_pending_entries > 0 {
        eprintln!(
            "KV flush: dropped {missing_pending_entries} pending entries with missing local blobs ({} digests)",
            missing_pending_digests.len()
        );
    }
    entries.extend(
        filtered_pending_entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );
    let merged_blob_order =
        merge_blob_order(&entries, &base_blob_order, &filtered_pending_blob_sequences);
    let total_count = entries.len();
    eprintln!(
        "KV flush: merging {existing_count} existing + {} pending = {total_count} total entries",
        filtered_pending_entries.len()
    );

    let (pointer_bytes, blobs) = build_index_pointer(&entries, &merged_blob_order)
        .map_err(|e| FlushError::Transient(format!("build pointer failed: {e:?}")))?;

    let manifest_root_digest = crate::cas_file::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_size = pointer_bytes.len() as u64;
    let blob_count = blobs.len() as u64;
    let blob_total_size_bytes: u64 = blobs.iter().map(|b| b.size_bytes).sum();
    let file_count = entries.len().min(u32::MAX as usize) as u32;

    let request = SaveRequest {
        tag: tag.clone(),
        write_scope_tag: kv_primary_write_scope_tag(state),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout: Some("file-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes: blob_total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(file_count),
        expected_manifest_digest: Some(manifest_root_digest.clone()),
        expected_manifest_size: Some(expected_manifest_size),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let save_response = match state
        .api_client
        .save_entry(&state.workspace, &request)
        .await
    {
        Ok(resp) => {
            state.backend_breaker.record_success();
            resp
        }
        Err(e) => {
            state.backend_breaker.record_failure();
            return Err(classify_flush_error(&e, "save_entry failed"));
        }
    };
    let confirm_cache_entry_id = save_response.cache_entry_id.clone();
    let confirm_manifest_digest = manifest_root_digest.clone();
    let confirm_tag = tag.clone();
    let confirm_write_scope_tag = kv_primary_write_scope_tag(state);

    if save_response.should_skip_existing_uploads() {
        let mut pending_blob_by_digest: HashMap<String, u64> = HashMap::new();
        for blob in filtered_pending_entries.values() {
            pending_blob_by_digest
                .entry(blob.digest.clone())
                .or_insert(blob.size_bytes);
        }
        let pending_blobs: Vec<BlobDescriptor> = pending_blob_by_digest
            .into_iter()
            .map(|(digest, size_bytes)| BlobDescriptor { digest, size_bytes })
            .collect();

        if !pending_blobs.is_empty() {
            match upload_blobs(
                state,
                &save_response.cache_entry_id,
                &pending_blobs,
                &filtered_pending_blob_paths,
            )
            .await
            {
                Ok(heal_stats) => {
                    if let Err(error) = try_commit_blob_receipts(
                        &state.api_client,
                        &state.workspace,
                        save_response.upload_session_id.as_deref(),
                        heal_stats.uploaded_receipts.clone(),
                    )
                    .await
                    {
                        log::warn!(
                            "KV flush: exists=true blob reconcile receipt commit failed: {error:#}"
                        );
                    }
                    if heal_stats.uploaded_count > 0 || heal_stats.missing_local_count > 0 {
                        eprintln!(
                            "KV flush: exists=true blob reconcile uploaded={} already_present={} missing_local={}",
                            heal_stats.uploaded_count,
                            heal_stats.already_present_count,
                            heal_stats.missing_local_count
                        );
                    }
                }
                Err(error) => {
                    log::warn!("KV flush: exists=true blob reconcile failed: {error}");
                }
            }
        }

        let confirm_request = ConfirmRequest {
            manifest_digest: confirm_manifest_digest.clone(),
            manifest_size: expected_manifest_size,
            manifest_etag: None,
            archive_size: None,
            archive_etag: None,
            blob_count: Some(blob_count),
            blob_total_size_bytes: Some(blob_total_size_bytes),
            file_count: Some(file_count),
            uncompressed_size: None,
            compressed_size: None,
            storage_mode: Some("cas".to_string()),
            tag: Some(confirm_tag.clone()),
            write_scope_tag: confirm_write_scope_tag.clone(),
        };
        let confirm_outcome =
            confirm_kv_flush(state, &confirm_cache_entry_id, &confirm_request, flush_mode).await?;
        let pending_alias_count = bind_kv_alias_tags(
            state,
            &manifest_root_digest,
            expected_manifest_size,
            blob_count,
            blob_total_size_bytes,
            file_count,
            flush_mode,
        )
        .await?;
        persist_kv_pending_publish_handoff(
            state,
            &entries,
            &merged_blob_order,
            &save_response.cache_entry_id,
            kv_confirm_pending_metadata(&confirm_outcome),
            pending_alias_count > 0,
        )
        .await;

        let (publish_state, upload_session_id, publish_attempt_id) = match &confirm_outcome {
            KvConfirmOutcome::Pending(metadata) => (
                "pending",
                metadata.upload_session_id.as_deref().unwrap_or("-"),
                metadata.publish_attempt_id.as_deref().unwrap_or("-"),
            ),
            KvConfirmOutcome::Published => ("published", "-", "-"),
        };

        eprintln!(
            "KV flush root publish: tag={} cache_entry_id={} state={} upload_session_id={} publish_attempt_id={} pending_alias_tags={}",
            tag,
            save_response.cache_entry_id,
            publish_state,
            upload_session_id,
            publish_attempt_id,
            pending_alias_count
        );
        if let KvConfirmOutcome::Pending(metadata) = &confirm_outcome {
            eprintln!(
                "KV publish accepted for server-side completion: cache_entry_id={} upload_session_id={} publish_attempt_id={} pending_alias_tags={}",
                save_response.cache_entry_id,
                metadata.upload_session_id.as_deref().unwrap_or("-"),
                metadata.publish_attempt_id.as_deref().unwrap_or("-"),
                pending_alias_count
            );
        } else if pending_alias_count > 0 {
            eprintln!(
                "KV alias publish accepted for server-side completion: cache_entry_id={} pending_alias_tags={}",
                save_response.cache_entry_id, pending_alias_count
            );
        }

        eprintln!(
            "KV flush: save_entry returned exists=true ({total_count} entries, {blob_count} blobs, digest={manifest_root_digest})"
        );
        return Ok((entries, merged_blob_order, save_response.cache_entry_id));
    }
    eprintln!(
        "KV flush: uploading {total_count} entries, {blob_count} blobs, pointer={expected_manifest_size} bytes"
    );

    let upload_stats_holder = Arc::new(std::sync::Mutex::new(BlobUploadStats::default()));
    let publish_upload_stats = upload_stats_holder.clone();
    let confirm_outcome = crate::serve::cas_publish::publish_after_save(
        &state.api_client,
        &state.workspace,
        &save_response,
        manifest_root_digest.clone(),
        expected_manifest_size,
        |save_response| {
            let cache_entry_id = save_response.cache_entry_id.clone();
            async move {
                let upload_stats = if !blobs.is_empty() {
                    upload_blobs(state, &cache_entry_id, &blobs, &filtered_pending_blob_paths)
                        .await
                        .map_err(|e| classify_flush_error(&e, "blob upload failed"))?
                } else {
                    BlobUploadStats::default()
                };

                *publish_upload_stats.lock().unwrap() = upload_stats.clone();
                Ok(upload_stats.uploaded_receipts)
            }
        },
        |save_response| {
            let manifest_upload_url = save_response.manifest_upload_url.clone();
            let upload_headers = save_response.upload_headers.clone();
            async move {
                let manifest_upload_url = manifest_upload_url
                    .as_ref()
                    .ok_or(FlushError::Permanent("missing manifest upload URL".into()))?;

                upload_payload(
                    state.api_client.transfer_client(),
                    manifest_upload_url,
                    &pointer_bytes,
                    "application/cbor",
                    &upload_headers,
                )
                .await
                .map_err(|e| classify_flush_error(&e, "manifest upload failed"))
            }
        },
        |manifest_etag| async move {
            let confirm_request = ConfirmRequest {
                manifest_digest: confirm_manifest_digest.clone(),
                manifest_size: expected_manifest_size,
                manifest_etag,
                archive_size: None,
                archive_etag: None,
                blob_count: Some(blob_count),
                blob_total_size_bytes: Some(blob_total_size_bytes),
                file_count: Some(file_count),
                uncompressed_size: None,
                compressed_size: None,
                storage_mode: Some("cas".to_string()),
                tag: Some(confirm_tag.clone()),
                write_scope_tag: confirm_write_scope_tag.clone(),
            };

            confirm_kv_flush(state, &confirm_cache_entry_id, &confirm_request, flush_mode).await
        },
    )
    .await?;
    let upload_stats = upload_stats_holder.lock().unwrap().clone();

    let pending_alias_count = bind_kv_alias_tags(
        state,
        &manifest_root_digest,
        expected_manifest_size,
        blob_count,
        blob_total_size_bytes,
        file_count,
        flush_mode,
    )
    .await?;
    persist_kv_pending_publish_handoff(
        state,
        &entries,
        &merged_blob_order,
        &save_response.cache_entry_id,
        kv_confirm_pending_metadata(&confirm_outcome),
        pending_alias_count > 0,
    )
    .await;

    let (publish_state, upload_session_id, publish_attempt_id) = match &confirm_outcome {
        KvConfirmOutcome::Pending(metadata) => (
            "pending",
            metadata.upload_session_id.as_deref().unwrap_or("-"),
            metadata.publish_attempt_id.as_deref().unwrap_or("-"),
        ),
        KvConfirmOutcome::Published => ("published", "-", "-"),
    };

    eprintln!(
        "KV flush root publish: tag={} cache_entry_id={} state={} upload_session_id={} publish_attempt_id={} pending_alias_tags={}",
        tag,
        save_response.cache_entry_id,
        publish_state,
        upload_session_id,
        publish_attempt_id,
        pending_alias_count
    );

    if let KvConfirmOutcome::Pending(metadata) = &confirm_outcome {
        eprintln!(
            "KV publish accepted for server-side completion: cache_entry_id={} upload_session_id={} publish_attempt_id={} pending_alias_tags={}",
            save_response.cache_entry_id,
            metadata.upload_session_id.as_deref().unwrap_or("-"),
            metadata.publish_attempt_id.as_deref().unwrap_or("-"),
            pending_alias_count
        );
    } else if pending_alias_count > 0 {
        eprintln!(
            "KV alias publish accepted for server-side completion: cache_entry_id={} pending_alias_tags={}",
            save_response.cache_entry_id, pending_alias_count
        );
    }

    eprintln!(
        "KV flush summary: entries={} unique_blobs={} uploaded={} already_present={} skipped_local={} bytes={} duration_ms={}",
        total_count,
        blob_count,
        upload_stats.uploaded_count,
        upload_stats.already_present_count,
        upload_stats.missing_local_count,
        blob_total_size_bytes,
        flush_started_at.elapsed().as_millis()
    );

    Ok((entries, merged_blob_order, save_response.cache_entry_id))
}

type FilteredPendingEntries = (
    BTreeMap<String, BlobDescriptor>,
    HashMap<String, PathBuf>,
    HashMap<String, u64>,
    Vec<String>,
    usize,
);

fn filter_pending_entries_with_local_blobs(
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
    pending_blob_sequences: &HashMap<String, u64>,
) -> FilteredPendingEntries {
    let mut missing_digests = HashSet::new();
    let mut filtered_blob_paths = HashMap::new();
    let mut filtered_blob_sequences = HashMap::new();

    for blob in pending_entries.values() {
        if missing_digests.contains(&blob.digest) || filtered_blob_paths.contains_key(&blob.digest)
        {
            continue;
        }

        let Some(path) = pending_blob_paths.get(&blob.digest) else {
            missing_digests.insert(blob.digest.clone());
            continue;
        };

        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {
                filtered_blob_paths.insert(blob.digest.clone(), path.clone());
                if let Some(sequence) = pending_blob_sequences.get(&blob.digest) {
                    filtered_blob_sequences.insert(blob.digest.clone(), *sequence);
                }
            }
            Ok(_) => {
                missing_digests.insert(blob.digest.clone());
            }
            Err(_) => {
                missing_digests.insert(blob.digest.clone());
            }
        }
    }

    let mut filtered_entries = BTreeMap::new();
    let mut missing_entry_count = 0usize;
    for (key, blob) in pending_entries {
        if missing_digests.contains(&blob.digest) {
            missing_entry_count = missing_entry_count.saturating_add(1);
            continue;
        }
        filtered_entries.insert(key.clone(), blob.clone());
    }

    (
        filtered_entries,
        filtered_blob_paths,
        filtered_blob_sequences,
        missing_digests.into_iter().collect(),
        missing_entry_count,
    )
}

#[allow(clippy::too_many_arguments)]
async fn bind_kv_alias_tag(
    state: &AppState,
    alias_tag: &str,
    manifest_root_digest: &str,
    manifest_size: u64,
    blob_count: u64,
    blob_total_size_bytes: u64,
    file_count: u32,
    flush_mode: FlushMode,
) -> anyhow::Result<bool> {
    let alias_request = SaveRequest {
        tag: alias_tag.to_string(),
        write_scope_tag: None,
        manifest_root_digest: manifest_root_digest.to_string(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout: Some("file-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes: blob_total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(file_count),
        expected_manifest_digest: Some(manifest_root_digest.to_string()),
        expected_manifest_size: Some(manifest_size),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let alias_save = state
        .api_client
        .save_entry(&state.workspace, &alias_request)
        .await?;

    let alias_confirm = ConfirmRequest {
        manifest_digest: manifest_root_digest.to_string(),
        manifest_size,
        manifest_etag: None,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        file_count: Some(file_count),
        uncompressed_size: None,
        compressed_size: None,
        storage_mode: Some("cas".to_string()),
        tag: Some(alias_tag.to_string()),
        write_scope_tag: None,
    };

    let result = confirm_kv_flush(
        state,
        &alias_save.cache_entry_id,
        &alias_confirm,
        flush_mode,
    )
    .await
    .map_err(|error| anyhow::anyhow!("alias confirm failed: {:?}", error))?;

    Ok(matches!(result, KvConfirmOutcome::Pending(_)))
}

async fn bind_kv_alias_tags(
    state: &AppState,
    manifest_root_digest: &str,
    manifest_size: u64,
    blob_count: u64,
    blob_total_size_bytes: u64,
    file_count: u32,
    flush_mode: FlushMode,
) -> Result<usize, FlushError> {
    let mut pending_count = 0usize;
    for alias_tag in kv_alias_tags(state) {
        let bind_result = bind_kv_alias_tag(
            state,
            &alias_tag,
            manifest_root_digest,
            manifest_size,
            blob_count,
            blob_total_size_bytes,
            file_count,
            flush_mode,
        )
        .await;
        match bind_result {
            Ok(pending) => {
                if pending {
                    pending_count = pending_count.saturating_add(1);
                }
            }
            Err(error) => {
                if state.fail_on_cache_error {
                    let stage = format!("alias bind failed for tag {alias_tag}");
                    return Err(classify_flush_error(&error, &stage));
                }
                log::warn!("KV flush: alias bind failed for tag {alias_tag}: {error}");
            }
        }
    }
    Ok(pending_count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlushBaseSelection {
    Backend,
    PublishedFallback {
        backend_entry_count: usize,
        published_entry_count: usize,
        missing_published_keys: usize,
        mismatched_published_keys: usize,
    },
}

fn select_flush_base_entries(
    backend_entries: BTreeMap<String, BlobDescriptor>,
    published_entries: &HashMap<String, BlobDescriptor>,
) -> (BTreeMap<String, BlobDescriptor>, FlushBaseSelection) {
    if backend_entries.is_empty() && !published_entries.is_empty() {
        return (
            published_entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 0,
                published_entry_count: published_entries.len(),
                missing_published_keys: published_entries.len(),
                mismatched_published_keys: 0,
            },
        );
    }
    if backend_entries.is_empty() || published_entries.is_empty() {
        return (backend_entries, FlushBaseSelection::Backend);
    }

    let mut missing_published_keys = 0usize;
    let mut mismatched_published_keys = 0usize;
    for (key, published_blob) in published_entries {
        match backend_entries.get(key) {
            Some(backend_blob)
                if backend_blob.digest == published_blob.digest
                    && backend_blob.size_bytes == published_blob.size_bytes => {}
            Some(_) => {
                mismatched_published_keys = mismatched_published_keys.saturating_add(1);
            }
            None => {
                missing_published_keys = missing_published_keys.saturating_add(1);
            }
        }
    }

    if missing_published_keys == 0 && mismatched_published_keys == 0 {
        return (backend_entries, FlushBaseSelection::Backend);
    }

    let backend_entry_count = backend_entries.len();
    let published_entry_count = published_entries.len();
    // Backend reads can lag right after publish; preserve local monotonic state to avoid pointer shrink.
    let mut merged = backend_entries;
    for (key, value) in published_entries {
        merged.insert(key.clone(), value.clone());
    }

    (
        merged,
        FlushBaseSelection::PublishedFallback {
            backend_entry_count,
            published_entry_count,
            missing_published_keys,
            mismatched_published_keys,
        },
    )
}

async fn load_existing_index(
    state: &AppState,
    tag: &str,
    retry_not_found: bool,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        Option<String>,
        Option<String>,
    ),
    RegistryError,
> {
    let hit = match resolve_hit_for_index_load(state, tag, retry_not_found).await {
        Ok(hit) => hit,
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            return Ok((BTreeMap::new(), Vec::new(), None, None));
        }
        Err(error) => return Err(error),
    };

    let cache_entry_id = hit.cache_entry_id.clone();
    let manifest_root_digest = hit
        .manifest_root_digest
        .clone()
        .or(hit.manifest_digest.clone());
    let pointer = fetch_pointer(state, &hit).await?;
    let mut map = BTreeMap::new();
    for entry in &pointer.entries {
        if !matches!(entry.entry_type, EntryType::File) {
            continue;
        }
        if let Some(digest) = &entry.digest {
            map.insert(
                entry.path.clone(),
                BlobDescriptor {
                    digest: digest.clone(),
                    size_bytes: entry.size_bytes,
                },
            );
        }
    }
    let blob_order = pointer_blob_order(&pointer, &map);
    Ok((map, blob_order, cache_entry_id, manifest_root_digest))
}

async fn load_existing_index_with_fallback(
    state: &AppState,
    retry_not_found: bool,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        Option<String>,
        Option<String>,
    ),
    RegistryError,
> {
    let tags = kv_root_tags(state);
    for (idx, tag) in tags.iter().enumerate() {
        let (entries, blob_order, cache_entry_id, manifest_root_digest) =
            match load_existing_index(state, tag, retry_not_found).await {
                Ok(result) => result,
                Err(error) if is_invalid_file_pointer_error(&error) => {
                    log::warn!(
                        "KV root fallback: skipping tag {tag} due to invalid pointer ({})",
                        error.message()
                    );
                    continue;
                }
                Err(error) => return Err(error),
            };
        if cache_entry_id.is_some() || !entries.is_empty() {
            if idx > 0 {
                eprintln!("KV root fallback hit: loaded legacy tag {tag}");
            }
            return Ok((entries, blob_order, cache_entry_id, manifest_root_digest));
        }
    }
    Ok((BTreeMap::new(), Vec::new(), None, None))
}

async fn resolve_hit_for_index_load(
    state: &AppState,
    tag: &str,
    retry_not_found: bool,
) -> Result<CacheResolutionEntry, RegistryError> {
    let first = resolve_hit(state, tag).await;
    if !retry_not_found {
        return first;
    }

    match first {
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            tokio::time::sleep(KV_RESOLVE_NOT_FOUND_RETRY_DELAY).await;
            resolve_hit(state, tag).await
        }
        other => other,
    }
}

async fn cleanup_temp_file(path: &PathBuf) {
    let _ = tokio::fs::remove_file(path).await;
}

async fn write_body_to_temp_file(
    state: &AppState,
    body: Body,
    put_probe: &super::PutProbeGuard,
) -> Result<(PathBuf, u64, String), RegistryError> {
    let temp_dir = state.kv_blob_temp_dir.clone();
    let path = temp_dir.join(uuid::Uuid::new_v4().to_string());
    let ingest_start = std::time::Instant::now();

    put_probe.stage("ensure_tmpdir");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to create temp dir: {e}")))?;

    put_probe.stage("open_temp");
    let mut file = match tokio::fs::File::create(&path).await {
        Ok(file) => file,
        Err(e) => {
            return Err(RegistryError::internal(format!(
                "Failed to create temp file: {e}"
            )));
        }
    };

    let mut stream = body.into_data_stream();
    let mut total_size = 0u64;
    let mut hasher = Sha256::new();
    let mut slow_logged = false;

    loop {
        put_probe.stage("read_chunk_wait");
        let next_chunk = tokio::time::timeout(KV_PUT_BODY_CHUNK_TIMEOUT, stream.next()).await;
        let Some(chunk_result) = (match next_chunk {
            Ok(next) => next,
            Err(_) => {
                put_probe.stage("read_chunk_timeout");
                drop(file);
                cleanup_temp_file(&path).await;
                return Err(RegistryError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    format!(
                        "KV PUT body read timed out after {}s (received {} bytes)",
                        KV_PUT_BODY_CHUNK_TIMEOUT.as_secs(),
                        total_size
                    ),
                ));
            }
        }) else {
            break;
        };
        let chunk = chunk_result
            .map_err(|e| RegistryError::internal(format!("Failed to read request body: {e}")));
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                drop(file);
                cleanup_temp_file(&path).await;
                return Err(error);
            }
        };
        if chunk.is_empty() {
            continue;
        }
        put_probe.stage("read_chunk_got");
        put_probe.add_read(chunk.len() as u64);
        if !slow_logged && ingest_start.elapsed() >= KV_PUT_BODY_SLOW_WARN_THRESHOLD {
            slow_logged = true;
            log::warn!(
                "KV PUT body ingest is slow: elapsed={}ms bytes={}",
                ingest_start.elapsed().as_millis(),
                total_size
            );
        }
        put_probe.stage("write_chunk_wait");
        if let Err(e) = file.write_all(&chunk).await {
            put_probe.stage("write_chunk_error");
            drop(file);
            cleanup_temp_file(&path).await;
            return Err(RegistryError::internal(format!(
                "Failed to write temp file: {e}"
            )));
        }
        put_probe.add_written(chunk.len() as u64);
        put_probe.stage("write_chunk_done");
        hasher.update(&chunk);
        total_size = total_size.saturating_add(chunk.len() as u64);
    }

    put_probe.stage("flush_file");
    if let Err(e) = file.flush().await {
        drop(file);
        cleanup_temp_file(&path).await;
        return Err(RegistryError::internal(format!(
            "Failed to flush temp file: {e}"
        )));
    }
    drop(file);

    if ingest_start.elapsed() >= KV_PUT_BODY_SLOW_WARN_THRESHOLD {
        log::warn!(
            "KV PUT body ingest completed slowly: elapsed={}ms bytes={}",
            ingest_start.elapsed().as_millis(),
            total_size
        );
    }

    put_probe.stage("body_ingest_done");
    let digest = format!("sha256:{:x}", hasher.finalize());
    Ok((path, total_size, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::client::ApiClient;
    use crate::api::models::cache::ConfirmRequest;
    use crate::git::GitContext;
    use crate::serve::state::{
        AppState, BackendCircuitBreaker, BlobLocatorCache, BlobReadCache, KvPendingStore,
        KvPublishedIndex, UploadSessionStore,
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
            blob_download_max_concurrency: 16,
            blob_download_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
            blob_prefetch_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            cache_ops: std::sync::Arc::new(
                crate::serve::cache_registry::cache_ops::Aggregator::new(),
            ),
            oci_manifest_cache: std::sync::Arc::new(dashmap::DashMap::new()),
            backend_breaker: std::sync::Arc::new(BackendCircuitBreaker::new()),
            prefetch_complete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
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
            blob_download_max_concurrency: 16,
            blob_download_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
            blob_prefetch_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            cache_ops: std::sync::Arc::new(
                crate::serve::cache_registry::cache_ops::Aggregator::new(),
            ),
            oci_manifest_cache: std::sync::Arc::new(dashmap::DashMap::new()),
            backend_breaker: std::sync::Arc::new(BackendCircuitBreaker::new()),
            prefetch_complete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
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
        if !networking_available() {
            eprintln!(
                "skipping shutdown_confirm_hands_off_pending_publish: networking disabled in sandbox"
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

        capabilities.assert_async().await;
        pointer_initial.assert_async().await;
        publish.assert_async().await;
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
            Some(&pending),
            false,
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
            Some(&pending),
            false,
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

    #[test]
    fn should_clear_flushing_after_flush_skips_ok_path() {
        assert!(!should_clear_flushing_after_flush(&FlushResult::Ok));
        assert!(should_clear_flushing_after_flush(&FlushResult::Conflict));
        assert!(should_clear_flushing_after_flush(&FlushResult::Error));
        assert!(should_clear_flushing_after_flush(&FlushResult::Permanent));
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
    fn kv_root_tags_include_legacy_human_root_when_distinct() {
        let tags =
            kv_root_tags_from_values("bc_registry_root_v2_abc", &[String::from("grpc-bazel")]);
        assert_eq!(
            tags,
            vec![
                "bc_registry_root_v2_abc".to_string(),
                "grpc-bazel".to_string()
            ]
        );
    }

    #[test]
    fn kv_root_tags_skip_empty_or_duplicate_legacy_root() {
        let duplicate = kv_root_tags_from_values(
            "grpc-bazel",
            &[String::from("grpc-bazel"), String::from(" ")],
        );
        assert_eq!(duplicate, vec!["grpc-bazel".to_string()]);

        let empty = kv_root_tags_from_values("grpc-bazel", &[String::from(" ")]);
        assert_eq!(empty, vec!["grpc-bazel".to_string()]);
    }

    #[test]
    fn kv_root_tags_include_all_distinct_human_aliases() {
        let tags = kv_root_tags_from_values(
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
    fn kv_blob_preload_limits_allow_env_overrides() {
        let _guard = test_env::lock();

        test_env::set_var(KV_BLOB_PRELOAD_MAX_BLOBS_ENV, "32");
        test_env::set_var(KV_BLOB_PRELOAD_MAX_BLOB_BYTES_ENV, "1048576");
        assert_eq!(kv_blob_preload_max_blobs(), 32);
        assert_eq!(kv_blob_preload_max_blob_bytes(), 1_048_576);
        test_env::remove_var(KV_BLOB_PRELOAD_MAX_BLOBS_ENV);
        test_env::remove_var(KV_BLOB_PRELOAD_MAX_BLOB_BYTES_ENV);
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
    fn kv_blob_prefetch_max_inflight_bytes_uses_env_override() {
        let _guard = test_env::lock();

        test_env::set_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV, "12345");
        assert_eq!(kv_blob_prefetch_max_inflight_bytes(1024 * 1024), 12_345);
        test_env::remove_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV);
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
