use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use rand::Rng;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use crate::api::models::cache::{
    BlobDescriptor, CacheResolutionEntry, ConfirmRequest, SaveRequest,
};
use crate::cas_transport::upload_payload;
use crate::error::BoringCacheError;
use crate::manifest::EntryType;
use crate::progress::TransferProgress;
use crate::serve::state::AppState;

use super::error::RegistryError;

const KV_MISS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const KV_CONFLICT_BACKOFF_MS: u64 = 5_000;
const KV_CONFLICT_JITTER_MS: u64 = 3_000;
const KV_CONFLICT_IN_PROGRESS_BACKOFF_MS: u64 = 30_000;
const KV_CONFLICT_IN_PROGRESS_JITTER_MS: u64 = 10_000;
const KV_TRANSIENT_BACKOFF_MS: u64 = 2_000;
const KV_TRANSIENT_JITTER_MS: u64 = 2_000;
const KV_TRANSIENT_WRITE_PATH_BACKOFF_MS: u64 = 20_000;
const KV_TRANSIENT_WRITE_PATH_JITTER_MS: u64 = 5_000;
const KV_INDEX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
const KV_EMPTY_INDEX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
const KV_BLOB_UPLOAD_MAX_ATTEMPTS: u32 = 3;
const KV_BLOB_UPLOAD_RETRY_BASE_MS: u64 = 300;
const KV_BLOB_UPLOAD_RETRY_MAX_MS: u64 = 1_500;

fn kv_miss_cache_key(registry_root_tag: &str, scoped_key: &str) -> String {
    format!("{}\u{0}{}", registry_root_tag.trim(), scoped_key)
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum KvNamespace {
    BazelAc,
    BazelCas,
    Gradle,
    Turborepo,
    Sccache,
}

impl KvNamespace {
    pub(crate) fn normalize_key(self, key: &str) -> String {
        match self {
            KvNamespace::BazelAc | KvNamespace::BazelCas | KvNamespace::Gradle => {
                key.to_ascii_lowercase()
            }
            KvNamespace::Turborepo | KvNamespace::Sccache => key.to_string(),
        }
    }

    fn namespace_prefix(self) -> &'static str {
        match self {
            KvNamespace::BazelAc => "bazel_ac",
            KvNamespace::BazelCas => "bazel_cas",
            KvNamespace::Gradle => "gradle",
            KvNamespace::Turborepo => "turbo",
            KvNamespace::Sccache => "sccache",
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
    {
        let pending = state.kv_pending.read().await;
        if pending.total_spool_bytes() >= crate::serve::state::MAX_SPOOL_BYTES {
            return Err(RegistryError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "KV spool budget exceeded, try again after flush",
            ));
        }
    }

    let (path, blob_size, blob_digest) = write_body_to_temp_file(body).await?;
    let scoped_key = namespace.scoped_key(key);
    let miss_key = kv_miss_cache_key(&state.registry_root_tag, &scoped_key);

    let redundant = {
        let mut pending = state.kv_pending.write().await;
        pending.insert(
            scoped_key.clone(),
            BlobDescriptor {
                digest: blob_digest.clone(),
                size_bytes: blob_size,
            },
            path,
        )
    };
    {
        let mut misses = state.kv_recent_misses.write().await;
        misses.remove(&miss_key);
    }
    if let Some(redundant_path) = redundant {
        let _ = tokio::fs::remove_file(&redundant_path).await;
    }

    {
        let mut last_put = state.kv_last_put.write().await;
        *last_put = Some(std::time::Instant::now());
    }

    {
        let gated = {
            let gate = state.kv_next_flush_at.read().await;
            gate.is_some_and(|t| std::time::Instant::now() < t)
        };
        if !gated {
            let pending = state.kv_pending.read().await;
            let should_flush = pending.blob_count() >= crate::serve::state::FLUSH_BLOB_THRESHOLD
                || pending.total_spool_bytes() >= crate::serve::state::FLUSH_SIZE_THRESHOLD;
            drop(pending);

            if should_flush {
                if let Some(flush_guard) = try_schedule_flush(state) {
                    let flush_state = state.clone();
                    tokio::spawn(async move {
                        let _flush_guard = flush_guard;
                        flush_kv_index(&flush_state).await;
                    });
                }
            }
        }
    }

    log::debug!("KV PUT {scoped_key}: queued ({blob_size} bytes, digest={blob_digest})");
    Ok((put_status, Body::empty()).into_response())
}

async fn resolve_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
) -> Result<String, RegistryError> {
    let download_urls = state
        .api_client
        .blob_download_urls(&state.workspace, cache_entry_id, std::slice::from_ref(blob))
        .await
        .map_err(|e| {
            RegistryError::internal(format!("Failed to resolve blob download URL: {e}"))
        })?;

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

    let (download_url, from_cache) = if let Some(url) = cached_url {
        (url.to_string(), true)
    } else {
        let resolved = resolve_download_url(state, cache_entry_id, blob).await?;
        {
            let mut published = state.kv_published_index.write().await;
            published.set_download_url(blob.digest.clone(), resolved.clone());
        }
        (resolved, false)
    };

    let download_result = state
        .api_client
        .transfer_client()
        .get(&download_url)
        .send()
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to download blob bytes: {e}")))?;

    if from_cache && download_result.status() == StatusCode::FORBIDDEN {
        {
            let mut published = state.kv_published_index.write().await;
            published.invalidate_download_url(&blob.digest);
        }
        let fresh_url = resolve_download_url(state, cache_entry_id, blob).await?;
        {
            let mut published = state.kv_published_index.write().await;
            published.set_download_url(blob.digest.clone(), fresh_url.clone());
        }
        let retry_response = state
            .api_client
            .transfer_client()
            .get(&fresh_url)
            .send()
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to download blob bytes: {e}")))?
            .error_for_status()
            .map_err(|e| RegistryError::internal(format!("Blob storage returned an error: {e}")))?;
        let body = Body::from_stream(retry_response.bytes_stream());
        return Ok((StatusCode::OK, response_headers, body).into_response());
    }

    let download_response = download_result
        .error_for_status()
        .map_err(|e| RegistryError::internal(format!("Blob storage returned an error: {e}")))?;
    let body = Body::from_stream(download_response.bytes_stream());

    Ok((StatusCode::OK, response_headers, body).into_response())
}

async fn is_recent_kv_miss(state: &AppState, scoped_key: &str) -> bool {
    let now = std::time::Instant::now();
    let mut misses = state.kv_recent_misses.write().await;

    match misses.get(scoped_key).copied() {
        Some(expires_at) if expires_at > now => true,
        Some(_) => {
            misses.remove(scoped_key);
            false
        }
        None => false,
    }
}

async fn mark_kv_miss(state: &AppState, scoped_key: &str) {
    let mut misses = state.kv_recent_misses.write().await;
    misses.insert(
        scoped_key.to_string(),
        std::time::Instant::now() + KV_MISS_CACHE_TTL,
    );
}

async fn clear_kv_miss(state: &AppState, scoped_key: &str) {
    let mut misses = state.kv_recent_misses.write().await;
    misses.remove(scoped_key);
}

async fn clear_tag_misses(state: &AppState, registry_root_tag: &str) {
    let prefix = format!("{}\u{0}", registry_root_tag.trim());
    let now = std::time::Instant::now();
    let mut misses = state.kv_recent_misses.write().await;
    misses.retain(|key, expires_at| *expires_at > now && !key.starts_with(&prefix));
}

fn kv_blob_upload_retry_delay(attempt: u32) -> std::time::Duration {
    let exponent = attempt.saturating_sub(1);
    let backoff = KV_BLOB_UPLOAD_RETRY_BASE_MS.saturating_mul(2_u64.pow(exponent));
    std::time::Duration::from_millis(backoff.min(KV_BLOB_UPLOAD_RETRY_MAX_MS))
}

fn is_retryable_blob_upload_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("http 408")
        || lower.contains("http 429")
        || lower.contains("http 500")
        || lower.contains("http 502")
        || lower.contains("http 503")
        || lower.contains("http 504")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("connection refused")
        || lower.contains("temporarily unavailable")
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

async fn refresh_published_index_for_lookup(state: &AppState) -> Result<(), RegistryError> {
    let tag = state.registry_root_tag.trim().to_string();
    let (entries, cache_entry_id, _) = load_existing_index(state, &tag).await?;

    {
        let mut published = state.kv_published_index.write().await;
        if entries.is_empty() {
            published.set_empty();
        } else if let Some(cache_entry_id) = cache_entry_id {
            published.update(entries.into_iter().collect(), cache_entry_id);
        } else {
            published.set_empty();
        }
    }
    clear_tag_misses(state, &tag).await;

    Ok(())
}

pub(crate) async fn get_or_head_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let scoped_key = namespace.scoped_key(key);
    let miss_key = kv_miss_cache_key(&state.registry_root_tag, &scoped_key);

    let local = {
        let pending = state.kv_pending.read().await;
        pending.get(&scoped_key).and_then(|blob| {
            pending
                .blob_path(&blob.digest)
                .map(|path| (blob.clone(), path.clone()))
        })
    };

    if let Some((blob, path)) = local {
        match serve_local_blob(&blob, &path, is_head).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                log::warn!("KV local blob read failed, falling back to backend: {e:?}");
            }
        }
    }

    if let Some((blob, cache_entry_id, cached_url)) =
        lookup_published_blob(state, &scoped_key).await
    {
        clear_kv_miss(state, &miss_key).await;
        return serve_backend_blob(
            state,
            &cache_entry_id,
            &blob,
            cached_url.as_deref(),
            is_head,
        )
        .await;
    }

    if is_recent_kv_miss(state, &miss_key).await {
        return Err(RegistryError::not_found("Cache key not found"));
    }

    let _lookup_guard = state.kv_lookup_lock.lock().await;

    if is_recent_kv_miss(state, &miss_key).await {
        return Err(RegistryError::not_found("Cache key not found"));
    }

    if let Some((blob, cache_entry_id, cached_url)) =
        lookup_published_blob(state, &scoped_key).await
    {
        clear_kv_miss(state, &miss_key).await;
        return serve_backend_blob(
            state,
            &cache_entry_id,
            &blob,
            cached_url.as_deref(),
            is_head,
        )
        .await;
    }

    if should_refresh_published_index_for_lookup(state).await {
        refresh_published_index_for_lookup(state).await?;
    }

    if let Some((blob, cache_entry_id, cached_url)) =
        lookup_published_blob(state, &scoped_key).await
    {
        clear_kv_miss(state, &miss_key).await;
        return serve_backend_blob(
            state,
            &cache_entry_id,
            &blob,
            cached_url.as_deref(),
            is_head,
        )
        .await;
    }

    mark_kv_miss(state, &miss_key).await;
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

pub(crate) async fn resolve_kv_entries(
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

    populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    let _lookup_guard = state.kv_lookup_lock.lock().await;

    populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;
    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    if should_refresh_published_index_for_lookup(state).await {
        refresh_published_index_for_lookup(state).await?;
    }

    populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;

    Ok(sizes)
}

pub(crate) async fn resolve_hit(
    state: &AppState,
    tag: &str,
) -> Result<CacheResolutionEntry, RegistryError> {
    let response = state
        .api_client
        .restore(&state.workspace, &[tag.to_string()])
        .await
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

    let pointer_response = state
        .api_client
        .transfer_client()
        .get(manifest_url)
        .send()
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to fetch manifest pointer: {e}")))?
        .error_for_status()
        .map_err(|e| RegistryError::internal(format!("Manifest pointer request failed: {e}")))?;
    let pointer_bytes = pointer_response
        .bytes()
        .await
        .map_err(|e| {
            RegistryError::internal(format!("Failed to read manifest pointer bytes: {e}"))
        })?
        .to_vec();

    crate::cas_file::parse_pointer(&pointer_bytes)
        .map_err(|e| RegistryError::internal(format!("Invalid file CAS pointer: {e}")))
}

fn build_index_pointer(
    entries: &BTreeMap<String, BlobDescriptor>,
) -> Result<(Vec<u8>, Vec<BlobDescriptor>), RegistryError> {
    let mut blob_sizes: HashMap<String, u64> = HashMap::new();
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

    let mut blobs: Vec<BlobDescriptor> = blob_sizes
        .into_iter()
        .map(|(digest, size_bytes)| BlobDescriptor { digest, size_bytes })
        .collect();
    blobs.sort_by(|left, right| left.digest.cmp(&right.digest));

    let pointer = crate::cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: pointer_entries,
        blobs: blobs
            .iter()
            .map(|blob| crate::cas_file::FilePointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            })
            .collect(),
    };
    let pointer_bytes = serde_json::to_vec(&pointer)
        .map_err(|e| RegistryError::internal(format!("Failed to serialize file pointer: {e}")))?;

    Ok((pointer_bytes, blobs))
}

pub(crate) enum FlushResult {
    Ok,
    Conflict,
    Error,
    Permanent,
}

enum FlushError {
    Conflict(String),
    Transient(String),
    Permanent(String),
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

    let is_conflict = error
        .downcast_ref::<BoringCacheError>()
        .and_then(BoringCacheError::conflict_message)
        .is_some()
        || lower.contains("another cache upload is in progress");
    let conflict_status = lower.contains("http 409") || lower.contains("http 412");
    let conflict_hint = lower.contains("precondition failed")
        || lower.contains("etag mismatch")
        || lower.contains("manifest digest mismatch");
    if is_conflict || conflict_status || conflict_hint {
        return FlushError::Conflict(message);
    }

    let transient_status = lower.contains("http 429")
        || lower.contains("http 500")
        || lower.contains("http 502")
        || lower.contains("http 503")
        || lower.contains("http 504");
    let transient_hint = lower.contains("transient error")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("temporarily unavailable")
        || lower.contains("rate limit exceeded")
        || lower.contains("cannot connect")
        || lower.contains("connection refused")
        || lower.contains("broken pipe")
        || lower.contains("connection reset");
    let transient_kind = error.downcast_ref::<BoringCacheError>().is_some_and(|bc| {
        matches!(
            bc,
            BoringCacheError::NetworkError(_)
                | BoringCacheError::ConnectionError(_)
                | BoringCacheError::CachePending
        )
    });
    if transient_status || transient_hint || transient_kind {
        return FlushError::Transient(message);
    }

    let permanent_status = lower.contains("http 400")
        || lower.contains("http 401")
        || lower.contains("http 403")
        || lower.contains("http 404")
        || lower.contains("http 405")
        || lower.contains("http 410")
        || lower.contains("http 411")
        || lower.contains("http 413")
        || lower.contains("http 414")
        || lower.contains("http 415")
        || lower.contains("http 422");
    let permanent_hint = lower.contains("authentication failed")
        || lower.contains("invalid or expired token")
        || lower.contains("access forbidden")
        || lower.contains("workspace")
        || lower.contains("unprocessable");
    let permanent_kind = error.downcast_ref::<BoringCacheError>().is_some_and(|bc| {
        matches!(
            bc,
            BoringCacheError::ConfigNotFound
                | BoringCacheError::TokenNotFound
                | BoringCacheError::WorkspaceNotFound(_)
                | BoringCacheError::AuthenticationFailed(_)
        )
    });
    if permanent_status || permanent_hint || permanent_kind {
        return FlushError::Permanent(message);
    }

    FlushError::Transient(message)
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

pub(crate) async fn flush_kv_index(state: &AppState) -> FlushResult {
    let _guard = state.kv_flush_lock.lock().await;

    let (pending_entries, pending_blob_paths) = {
        let mut pending = state.kv_pending.write().await;
        if pending.is_empty() {
            return FlushResult::Ok;
        }
        pending.take_all()
    };

    if pending_entries.is_empty() {
        return FlushResult::Ok;
    }

    let entry_count = pending_entries.len();

    match do_flush(state, &pending_entries, &pending_blob_paths).await {
        Ok((merged_entries, cache_entry_id)) => {
            for path in pending_blob_paths.values() {
                let _ = tokio::fs::remove_file(path).await;
            }

            {
                let mut published = state.kv_published_index.write().await;
                published.update(merged_entries.into_iter().collect(), cache_entry_id.clone());
            }
            clear_tag_misses(state, &state.registry_root_tag).await;

            {
                let mut last_put = state.kv_last_put.write().await;
                *last_put = None;
            }

            eprintln!(
                "KV batch: flushed {entry_count} new entries ({} blobs cleaned up)",
                pending_blob_paths.len()
            );
            preload_download_urls(state, &cache_entry_id).await;
            FlushResult::Ok
        }
        Err(FlushError::Conflict(msg)) => {
            eprintln!("KV batch flush: skipped — tag conflict ({msg})");
            let mut pending = state.kv_pending.write().await;
            pending.restore(pending_entries, pending_blob_paths);
            drop(pending);
            let (base_ms, jitter_ms) = conflict_backoff_window(&msg);
            set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
            FlushResult::Conflict
        }
        Err(FlushError::Transient(msg)) => {
            eprintln!("KV batch flush failed: {msg}");
            let mut pending = state.kv_pending.write().await;
            pending.restore(pending_entries, pending_blob_paths);
            let (base_ms, jitter_ms) = transient_backoff_window(&msg);
            set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
            FlushResult::Error
        }
        Err(FlushError::Permanent(msg)) => {
            eprintln!("KV batch flush dropped permanently: {msg}");
            for path in pending_blob_paths.values() {
                let _ = tokio::fs::remove_file(path).await;
            }
            {
                let mut last_put = state.kv_last_put.write().await;
                *last_put = None;
            }
            FlushResult::Permanent
        }
    }
}

pub(crate) async fn preload_kv_index(state: &AppState) {
    let tag = state.registry_root_tag.trim().to_string();
    match load_existing_index(state, &tag).await {
        Ok((entries, Some(cache_entry_id), _manifest_root_digest)) if !entries.is_empty() => {
            let count = entries.len();
            {
                let mut published = state.kv_published_index.write().await;
                if published.entry_count() > 0 {
                    eprintln!("KV index preload: skipped, flush already published");
                    return;
                }
                published.update(entries.into_iter().collect(), cache_entry_id.clone());
            }
            clear_tag_misses(state, &tag).await;
            eprintln!("KV index preloaded: {count} entries, resolving download URLs...");
            preload_download_urls(state, &cache_entry_id).await;
        }
        Ok(_) => {
            {
                let mut published = state.kv_published_index.write().await;
                published.set_empty();
            }
            eprintln!("KV index preload: no existing entries");
        }
        Err(e) => {
            log::warn!("KV index preload failed: {e:?}");
        }
    }
}

pub(crate) async fn refresh_kv_index(state: &AppState) {
    if state.kv_flush_scheduled.load(Ordering::Acquire) {
        return;
    }

    let tag = state.registry_root_tag.trim().to_string();
    match load_existing_index(state, &tag).await {
        Ok((entries, Some(cache_entry_id), manifest_root_digest)) if !entries.is_empty() => {
            let should_fence = {
                let published = state.kv_published_index.read().await;
                published
                    .cache_entry_id()
                    .is_some_and(|current| current != cache_entry_id)
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

            let count = entries.len();
            {
                let mut published = state.kv_published_index.write().await;
                published.update(entries.into_iter().collect(), cache_entry_id.clone());
            }
            clear_tag_misses(state, &tag).await;
            eprintln!("KV index refresh: {count} entries loaded");
            preload_download_urls(state, &cache_entry_id).await;
        }
        Ok(_) => {
            let had_entries = {
                let published = state.kv_published_index.read().await;
                published.entry_count() > 0
            };
            {
                let mut published = state.kv_published_index.write().await;
                published.set_empty();
            }
            clear_tag_misses(state, &tag).await;
            if had_entries {
                eprintln!("KV index refresh: cleared stale entries (no backend index)");
            }
        }
        Err(e) => {
            log::warn!("KV index refresh failed: {e:?}");
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
    ) {
        if expected_digest != live_digest {
            eprintln!(
                "KV index refresh fence: skipping stale update (expected digest {}, live digest {})",
                expected_digest, live_digest
            );
            return false;
        }
    }

    true
}

async fn preload_download_urls(state: &AppState, cache_entry_id: &str) {
    let blobs = {
        let published = state.kv_published_index.read().await;
        published.unique_blobs()
    };

    if blobs.is_empty() {
        return;
    }

    match state
        .api_client
        .blob_download_urls(&state.workspace, cache_entry_id, &blobs)
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
        }
        Err(e) => {
            log::warn!("KV index preload: failed to resolve download URLs: {e}");
        }
    }
}

async fn do_flush(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
) -> Result<(BTreeMap<String, BlobDescriptor>, String), FlushError> {
    let flush_started_at = std::time::Instant::now();
    let tag = state.registry_root_tag.trim().to_string();

    let published_snapshot = {
        let published = state.kv_published_index.read().await;
        published.entries_snapshot()
    };

    let backend_entries = match load_existing_index(state, &tag).await {
        Ok((existing, _, _)) => existing,
        Err(e) => {
            log::warn!("KV flush: failed to load existing index: {e:?}");
            BTreeMap::new()
        }
    };
    let (mut entries, used_published_fallback) =
        select_flush_base_entries(backend_entries, published_snapshot);
    let existing_count = entries.len();
    if used_published_fallback {
        eprintln!(
            "KV flush: backend index empty, using published snapshot with {existing_count} entries"
        );
    }
    entries.extend(pending_entries.iter().map(|(k, v)| (k.clone(), v.clone())));
    let total_count = entries.len();
    eprintln!(
        "KV flush: merging {existing_count} existing + {} pending = {total_count} total entries",
        pending_entries.len()
    );

    let (pointer_bytes, blobs) = build_index_pointer(&entries)
        .map_err(|e| FlushError::Transient(format!("build pointer failed: {e:?}")))?;

    let manifest_root_digest = crate::cas_file::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_size = pointer_bytes.len() as u64;
    let blob_count = blobs.len() as u64;
    let blob_total_size_bytes: u64 = blobs.iter().map(|b| b.size_bytes).sum();
    let file_count = entries.len().min(u32::MAX as usize) as u32;

    let request = SaveRequest {
        tag: tag.clone(),
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
        Ok(resp) => resp,
        Err(e) => return Err(classify_flush_error(&e, "save_entry failed")),
    };

    if save_response.exists {
        eprintln!("KV flush: save_entry returned exists=true ({total_count} entries, {blob_count} blobs, digest={manifest_root_digest})");
        return Ok((entries, save_response.cache_entry_id));
    }
    eprintln!("KV flush: uploading {total_count} entries, {blob_count} blobs, pointer={expected_manifest_size} bytes");

    let upload_stats = if !blobs.is_empty() {
        upload_blobs(
            state,
            &save_response.cache_entry_id,
            &blobs,
            pending_blob_paths,
        )
        .await
        .map_err(|e| classify_flush_error(&e, "blob upload failed"))?
    } else {
        BlobUploadStats::default()
    };

    let manifest_upload_url = save_response
        .manifest_upload_url
        .as_ref()
        .ok_or(FlushError::Permanent("missing manifest upload URL".into()))?;

    upload_payload(
        state.api_client.transfer_client(),
        manifest_upload_url,
        &pointer_bytes,
        "application/cbor",
        &save_response.upload_headers,
    )
    .await
    .map_err(|e| classify_flush_error(&e, "manifest upload failed"))?;

    let confirm_request = ConfirmRequest {
        manifest_digest: manifest_root_digest,
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
        tag: Some(tag),
    };

    state
        .api_client
        .confirm(
            &state.workspace,
            &save_response.cache_entry_id,
            &confirm_request,
        )
        .await
        .map_err(|e| classify_flush_error(&e, "confirm failed"))?;

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

    Ok((entries, save_response.cache_entry_id))
}

fn select_flush_base_entries(
    backend_entries: BTreeMap<String, BlobDescriptor>,
    published_entries: HashMap<String, BlobDescriptor>,
) -> (BTreeMap<String, BlobDescriptor>, bool) {
    if backend_entries.is_empty() && !published_entries.is_empty() {
        return (published_entries.into_iter().collect(), true);
    }
    (backend_entries, false)
}

#[derive(Default)]
struct BlobUploadStats {
    uploaded_count: u64,
    already_present_count: u64,
    missing_local_count: u64,
}

async fn upload_blobs(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    local_blob_paths: &HashMap<String, PathBuf>,
) -> anyhow::Result<BlobUploadStats> {
    let upload_plan = state
        .api_client
        .blob_upload_urls(&state.workspace, cache_entry_id, blobs)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get blob upload URLs: {e}"))?;

    let mut stats = BlobUploadStats {
        uploaded_count: 0,
        already_present_count: upload_plan.already_present.len() as u64,
        missing_local_count: 0,
    };

    let blobs_by_digest: HashMap<String, BlobDescriptor> = blobs
        .iter()
        .map(|blob| (blob.digest.clone(), blob.clone()))
        .collect();

    for upload in &upload_plan.upload_urls {
        let blob_path = match local_blob_paths.get(&upload.digest) {
            Some(path) => path,
            None => {
                log::warn!(
                    "KV batch flush: skipping blob {} (no local file)",
                    upload.digest
                );
                stats.missing_local_count = stats.missing_local_count.saturating_add(1);
                continue;
            }
        };
        let mut upload_url = upload.url.clone();
        let mut upload_headers = upload.headers.clone();
        let mut completed = false;
        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 1..=KV_BLOB_UPLOAD_MAX_ATTEMPTS {
            let progress = TransferProgress::new_noop();
            match crate::multipart_upload::upload_via_single_url(
                blob_path.as_path(),
                &upload_url,
                &progress,
                state.api_client.transfer_client(),
                &upload_headers,
            )
            .await
            {
                Ok(_) => {
                    stats.uploaded_count = stats.uploaded_count.saturating_add(1);
                    completed = true;
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt >= KV_BLOB_UPLOAD_MAX_ATTEMPTS {
                        break;
                    }

                    let retryable = last_error
                        .as_ref()
                        .map(|err| is_retryable_blob_upload_error(&err.to_string()))
                        .unwrap_or(false);
                    if !retryable {
                        break;
                    }

                    if let Some(blob) = blobs_by_digest.get(&upload.digest) {
                        match state
                            .api_client
                            .blob_upload_urls(
                                &state.workspace,
                                cache_entry_id,
                                std::slice::from_ref(blob),
                            )
                            .await
                        {
                            Ok(retry_plan) => {
                                if retry_plan
                                    .already_present
                                    .iter()
                                    .any(|d| d == &upload.digest)
                                {
                                    stats.already_present_count =
                                        stats.already_present_count.saturating_add(1);
                                    completed = true;
                                    break;
                                }
                                if let Some(fresh_upload) = retry_plan
                                    .upload_urls
                                    .iter()
                                    .find(|item| item.digest == upload.digest)
                                {
                                    upload_url = fresh_upload.url.clone();
                                    upload_headers = fresh_upload.headers.clone();
                                }
                            }
                            Err(stage_error) => {
                                log::warn!(
                                    "KV batch flush: failed to refresh upload URL for {}: {stage_error}",
                                    upload.digest
                                );
                            }
                        }
                    }

                    tokio::time::sleep(kv_blob_upload_retry_delay(attempt)).await;
                }
            }
        }

        if !completed {
            let error = last_error.unwrap_or_else(|| anyhow::anyhow!("unknown blob upload error"));
            return Err(anyhow::anyhow!(
                "Failed to upload blob {}: {error}",
                upload.digest
            ));
        }
    }

    Ok(stats)
}

async fn load_existing_index(
    state: &AppState,
    tag: &str,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Option<String>,
        Option<String>,
    ),
    RegistryError,
> {
    let hit = match resolve_hit(state, tag).await {
        Ok(hit) => hit,
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            return Ok((BTreeMap::new(), None, None));
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
    Ok((map, cache_entry_id, manifest_root_digest))
}

async fn write_body_to_temp_file(body: Body) -> Result<(PathBuf, u64, String), RegistryError> {
    let temp_dir = std::env::temp_dir().join("boringcache-kv-blobs");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to create temp dir: {e}")))?;
    let path = temp_dir.join(uuid::Uuid::new_v4().to_string());

    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to create temp file: {e}")))?;

    let mut stream = body.into_data_stream();
    let mut total_size = 0u64;
    let mut hasher = Sha256::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result
            .map_err(|e| RegistryError::internal(format!("Failed to read request body: {e}")))?;
        if chunk.is_empty() {
            continue;
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to write temp file: {e}")))?;
        hasher.update(&chunk);
        total_size = total_size.saturating_add(chunk.len() as u64);
    }

    file.flush()
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to flush temp file: {e}")))?;

    let digest = format!("sha256:{:x}", hasher.finalize());
    Ok((path, total_size, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_flush_error_treats_precondition_failed_as_conflict() {
        let error = anyhow::anyhow!("HTTP 412 from backend: precondition failed");
        let classified = classify_flush_error(&error, "confirm failed");
        assert!(matches!(classified, FlushError::Conflict(_)));
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
    fn select_flush_base_entries_uses_backend_when_available() {
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
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, used_fallback) = select_flush_base_entries(backend.clone(), published);
        assert!(!used_fallback);
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

        let (selected, used_fallback) = select_flush_base_entries(backend, published);
        assert!(used_fallback);
        assert_eq!(selected.len(), 1);
        assert!(selected.contains_key("k2"));
    }
}
