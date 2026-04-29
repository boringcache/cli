use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use tokio_util::io::ReaderStream;

use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci;
use crate::serve::engines::oci::uploads::{find_local_uploaded_blob, has_remote_blob};
use crate::serve::http::error::OciError;
use crate::serve::http::flight::{
    Flight, FlightGuard, await_flight, begin_flight, clear_flight_entry,
};
use crate::serve::http::oci_route::{insert_digest_etag, insert_header};
use crate::serve::state::{AppState, BlobLocatorEntry, BlobReadHandle, OciNegativeCacheReason};
use crate::telemetry::StorageMetrics;

const DOWNLOAD_URL_CACHE_TTL: Duration = Duration::from_secs(45 * 60);
const OCI_API_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const OCI_TRANSFER_CALL_TIMEOUT: Duration = Duration::from_secs(300);
const OCI_BLOB_DOWNLOAD_MAX_ATTEMPTS: usize = 4;
const OCI_BLOB_DOWNLOAD_RETRY_BASE_MS: u64 = 500;
const OCI_STREAM_THROUGH_MIN_BYTES_ENV: &str = "BORINGCACHE_OCI_STREAM_THROUGH_MIN_BYTES";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobRange {
    start: u64,
    end: u64,
}

impl BlobRange {
    fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlobRangeSelection {
    Full,
    Partial(BlobRange),
    Unsatisfiable,
}

struct BlobBodyResponse {
    response: Response,
    served_bytes: u64,
    partial: bool,
    unsatisfiable: bool,
    body_read: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BlobPrefetchStats {
    pub(crate) total_unique_blobs: usize,
    pub(crate) scheduled: usize,
    pub(crate) inserted: usize,
    pub(crate) failures: usize,
    pub(crate) already_local: usize,
    pub(crate) scheduled_bytes: u64,
    pub(crate) duration_ms: u64,
}

struct BlobPrefetchTarget {
    blob: BlobDescriptor,
    cached_url: Option<String>,
}

pub(crate) async fn get_blob(
    method: Method,
    headers: &HeaderMap,
    state: AppState,
    name: String,
    digest: String,
) -> Result<Response, OciError> {
    if !cas_oci::is_valid_sha256_digest(&digest) {
        return Err(OciError::digest_invalid(format!(
            "unsupported blob digest format: {digest}"
        )));
    }

    if headers.get(header::RANGE).is_some() && method == Method::GET {
        state.oci_engine_diagnostics.record_range_request();
    }

    let request_started_at = std::time::Instant::now();
    if let Some(handle) = find_local_uploaded_blob(&state, &name, &digest).await {
        let blob_response = local_blob_response(&method, headers, &digest, &handle).await?;
        record_local_blob_response(&state, &blob_response, request_started_at);
        return Ok(blob_response.response);
    }

    if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
        let blob_response = local_blob_response(&method, headers, &digest, &handle).await?;
        record_local_blob_response(&state, &blob_response, request_started_at);
        return Ok(blob_response.response);
    }

    if state.oci_negative_cache.contains_blob_locator_miss(
        &state.workspace,
        &state.registry_root_tag,
        &name,
        &digest,
    ) {
        state
            .oci_engine_diagnostics
            .record_negative_cache_hit(OciNegativeCacheReason::BlobLocator);
        state.oci_engine_diagnostics.record_miss("blob-locator");
        return Err(OciError::blob_unknown(format!("{name}@{digest}")));
    }

    let Some((cache_entry_id, size_bytes, cached_download_url)) = ({
        let locator_start = std::time::Instant::now();
        let locator = state.blob_locator.read().await;
        let elapsed = locator_start.elapsed();
        if elapsed > Duration::from_millis(100) {
            log::warn!(
                "blob_locator.read() took {}ms for {}/{}",
                elapsed.as_millis(),
                name,
                &digest[..8]
            );
        }
        locator.get(&name, &digest).map(|entry| {
            (
                entry.cache_entry_id.clone(),
                entry.size_bytes,
                fresh_download_url(entry),
            )
        })
    }) else {
        state.oci_negative_cache.insert_blob_locator_miss(
            &state.workspace,
            &state.registry_root_tag,
            &name,
            &digest,
        );
        state
            .oci_engine_diagnostics
            .record_negative_cache_insert(OciNegativeCacheReason::BlobLocator);
        state.oci_engine_diagnostics.record_miss("blob-locator");
        return Err(OciError::blob_unknown(format!("{name}@{digest}")));
    };

    if method == Method::HEAD {
        let mut negative_cache_hit = false;
        let blob_exists = if cached_download_url.is_some() {
            true
        } else if state.oci_negative_cache.contains_remote_blob_miss(
            &state.workspace,
            &state.registry_root_tag,
            &name,
            &digest,
        ) {
            negative_cache_hit = true;
            state
                .oci_engine_diagnostics
                .record_negative_cache_hit(OciNegativeCacheReason::RemoteBlob);
            false
        } else {
            match has_remote_blob(&state, &digest).await {
                Ok(exists) => exists,
                Err(error) => {
                    log::warn!(
                        "OCI HEAD remote blob existence check failed for {}@{} ({})",
                        name,
                        digest,
                        error.message()
                    );
                    state
                        .oci_engine_diagnostics
                        .record_remote_blob_check_error();
                    return Err(OciError::blob_unknown(format!("{name}@{digest}")));
                }
            }
        };
        if !blob_exists {
            if !negative_cache_hit {
                state.oci_negative_cache.insert_remote_blob_miss(
                    &state.workspace,
                    &state.registry_root_tag,
                    &name,
                    &digest,
                );
                state
                    .oci_engine_diagnostics
                    .record_negative_cache_insert(OciNegativeCacheReason::RemoteBlob);
            }
            state.oci_engine_diagnostics.record_miss("remote-blob");
            return Err(OciError::blob_unknown(format!("{name}@{digest}")));
        }
        return blob_head_response(&digest, size_bytes);
    }

    if state.oci_negative_cache.contains_remote_blob_miss(
        &state.workspace,
        &state.registry_root_tag,
        &name,
        &digest,
    ) {
        state
            .oci_engine_diagnostics
            .record_negative_cache_hit(OciNegativeCacheReason::RemoteBlob);
        state.oci_engine_diagnostics.record_miss("remote-blob");
        return Err(OciError::blob_unknown(format!("{name}@{digest}")));
    }

    if matches!(
        select_blob_range(headers, &digest, size_bytes)?,
        BlobRangeSelection::Unsatisfiable
    ) {
        state.oci_engine_diagnostics.record_invalid_range();
        return range_not_satisfiable_response(&digest, size_bytes);
    }

    if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
        let blob_response = local_blob_response(&method, headers, &digest, &handle).await?;
        record_local_blob_response(&state, &blob_response, request_started_at);
        return Ok(blob_response.response);
    }

    let blob_desc = BlobDescriptor {
        digest: digest.clone(),
        size_bytes,
    };
    let flight_key = format!("blob:{digest}");
    loop {
        if state.oci_negative_cache.contains_remote_blob_miss(
            &state.workspace,
            &state.registry_root_tag,
            &name,
            &digest,
        ) {
            state
                .oci_engine_diagnostics
                .record_negative_cache_hit(OciNegativeCacheReason::RemoteBlob);
            state.oci_engine_diagnostics.record_miss("remote-blob");
            return Err(OciError::blob_unknown(format!("{name}@{digest}")));
        }
        match begin_flight(
            &state.oci_lookup_inflight,
            flight_key.clone(),
            &state.singleflight_metrics,
            "oci-blob",
        ) {
            Flight::Leader(guard) => {
                if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
                    let blob_response =
                        local_blob_response(&method, headers, &digest, &handle).await?;
                    record_local_blob_response(&state, &blob_response, request_started_at);
                    return Ok(blob_response.response);
                }

                let (download_url, from_cache) = if let Some(url) = fresh_locator_download_url(
                    &state,
                    &name,
                    &digest,
                    cached_download_url.as_deref(),
                )
                .await
                {
                    (url, true)
                } else {
                    let url = resolve_oci_download_url(
                        &state,
                        &cache_entry_id,
                        &blob_desc,
                        &name,
                        &digest,
                    )
                    .await?;
                    (url, false)
                };
                if should_stream_through_blob(&method, headers, size_bytes) {
                    let permit = state
                        .blob_download_semaphore
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| OciError::internal("Blob download semaphore closed"))?;
                    return stream_oci_blob_to_client(
                        state,
                        cache_entry_id,
                        blob_desc,
                        name,
                        digest,
                        download_url,
                        from_cache,
                        request_started_at,
                        guard,
                        permit,
                    )
                    .await;
                }

                let _flight_guard = guard;
                let _permit = state
                    .blob_download_semaphore
                    .acquire()
                    .await
                    .map_err(|_| OciError::internal("Blob download semaphore closed"))?;

                if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
                    let blob_response =
                        local_blob_response(&method, headers, &digest, &handle).await?;
                    record_local_blob_response(&state, &blob_response, request_started_at);
                    return Ok(blob_response.response);
                }

                let handle = download_oci_blob_to_cache(
                    &state,
                    &cache_entry_id,
                    &blob_desc,
                    &name,
                    &digest,
                    download_url,
                    from_cache,
                )
                .await?;
                let fetched_bytes = handle.size_bytes();
                let blob_response = local_blob_response(&method, headers, &digest, &handle).await?;
                if method != Method::HEAD && !blob_response.unsatisfiable {
                    state.oci_body_metrics.record_remote(
                        fetched_bytes,
                        request_started_at.elapsed().as_millis() as u64,
                    );
                    state.oci_engine_diagnostics.record_remote_blob_read(
                        blob_response.served_bytes,
                        fetched_bytes,
                        blob_response.partial,
                    );
                } else if blob_response.unsatisfiable {
                    state.oci_engine_diagnostics.record_invalid_range();
                }
                return Ok(blob_response.response);
            }
            Flight::Follower(notified) => {
                if !await_flight(
                    &state.singleflight_metrics,
                    "oci-blob",
                    &flight_key,
                    notified,
                )
                .await
                {
                    state.singleflight_metrics.record_takeover("oci-blob");
                    clear_flight_entry(&state.oci_lookup_inflight, &flight_key);
                }
                if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
                    state
                        .singleflight_metrics
                        .record_post_flight_local_hit("oci-blob");
                    let blob_response =
                        local_blob_response(&method, headers, &digest, &handle).await?;
                    record_local_blob_response(&state, &blob_response, request_started_at);
                    return Ok(blob_response.response);
                }
                state
                    .singleflight_metrics
                    .record_post_flight_retry_miss("oci-blob");
            }
        }
    }
}

pub(crate) async fn prefetch_blob_bodies(
    state: &AppState,
    name: &str,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    cached_urls: &HashMap<String, String>,
    log_label: &str,
) -> BlobPrefetchStats {
    let mut stats = BlobPrefetchStats {
        total_unique_blobs: blobs.len(),
        ..BlobPrefetchStats::default()
    };
    if blobs.is_empty() {
        return stats;
    }

    let mut pending_targets = Vec::new();
    let mut cached_url_count = 0usize;
    for blob in blobs {
        let cached_url = cached_urls.get(&blob.digest).cloned();
        if cached_url.is_some() {
            cached_url_count = cached_url_count.saturating_add(1);
        }
        if state
            .blob_read_cache
            .get_handle(&blob.digest)
            .await
            .is_some()
        {
            stats.already_local = stats.already_local.saturating_add(1);
        } else {
            pending_targets.push(BlobPrefetchTarget {
                blob: blob.clone(),
                cached_url,
            });
        }
    }

    if pending_targets.is_empty() {
        eprintln!(
            "{log_label}: already warm (cached_urls={} unresolved_urls={} already_local={})",
            cached_url_count,
            blobs.len().saturating_sub(cached_url_count),
            stats.already_local,
        );
        return stats;
    }

    stats.scheduled = pending_targets.len();
    stats.scheduled_bytes = pending_targets
        .iter()
        .map(|target| target.blob.size_bytes)
        .sum();
    eprintln!(
        "{log_label}: hydrating {}/{} OCI blobs ({:.1} MB, cached_urls={}, unresolved_urls={}, already_local={})",
        stats.scheduled,
        stats.total_unique_blobs,
        stats.scheduled_bytes as f64 / (1024.0 * 1024.0),
        cached_url_count,
        blobs.len().saturating_sub(cached_url_count),
        stats.already_local,
    );

    let prefetch_started_at = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for target in pending_targets {
        let state = state.clone();
        let name = name.to_string();
        let cache_entry_id = cache_entry_id.to_string();
        let prefetch_semaphore = state.blob_prefetch_semaphore.clone();
        tasks.spawn(async move {
            let prefetch_permit = prefetch_semaphore.acquire_owned().await.map_err(|error| {
                OciError::internal(format!("prefetch semaphore closed: {error}"))
            })?;
            let result = prefetch_one_blob(
                &state,
                &name,
                &cache_entry_id,
                target.blob,
                target.cached_url,
            )
            .await;
            drop(prefetch_permit);
            result
        });
    }

    let log_interval = (stats.scheduled / 10).max(1);
    let mut completed = 0usize;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(true)) => stats.inserted = stats.inserted.saturating_add(1),
            Ok(Ok(false)) => {}
            Ok(Err(error)) => {
                stats.failures = stats.failures.saturating_add(1);
                log::warn!("{log_label} blob failed: {}", error.message());
            }
            Err(error) => {
                stats.failures = stats.failures.saturating_add(1);
                log::warn!("{log_label} task failed: {error}");
            }
        }
        completed = completed.saturating_add(1);
        if completed.is_multiple_of(log_interval) {
            eprintln!(
                "{log_label}: {completed}/{} OCI blobs ({} inserted, {} failed, {:.1}s)",
                stats.scheduled,
                stats.inserted,
                stats.failures,
                prefetch_started_at.elapsed().as_secs_f64(),
            );
        }
    }

    stats.duration_ms = prefetch_started_at.elapsed().as_millis() as u64;
    eprintln!(
        "{log_label}: done inserted={} scheduled={} failures={} cache_size={} bytes in {:.1}s",
        stats.inserted,
        stats.scheduled,
        stats.failures,
        state.blob_read_cache.total_bytes(),
        prefetch_started_at.elapsed().as_secs_f64(),
    );
    stats
}

async fn prefetch_one_blob(
    state: &AppState,
    name: &str,
    cache_entry_id: &str,
    blob: BlobDescriptor,
    cached_url: Option<String>,
) -> Result<bool, OciError> {
    if state
        .blob_read_cache
        .get_handle(&blob.digest)
        .await
        .is_some()
    {
        return Ok(false);
    }

    let (download_url, from_cache) = match cached_url {
        Some(url) => (url, true),
        None => (
            resolve_oci_download_url(state, cache_entry_id, &blob, name, &blob.digest).await?,
            false,
        ),
    };
    let digest = blob.digest.clone();
    let handle = download_oci_blob_to_cache(
        state,
        cache_entry_id,
        &blob,
        name,
        &digest,
        download_url,
        from_cache,
    )
    .await?;
    state.oci_engine_diagnostics.record_remote_blob_read(
        handle.size_bytes(),
        handle.size_bytes(),
        false,
    );
    Ok(true)
}

fn record_local_blob_response(
    state: &AppState,
    blob_response: &BlobBodyResponse,
    request_started_at: std::time::Instant,
) {
    if blob_response.body_read
        && (blob_response.response.status() == StatusCode::OK
            || blob_response.response.status() == StatusCode::PARTIAL_CONTENT)
    {
        state.oci_body_metrics.record_local(
            blob_response.served_bytes,
            request_started_at.elapsed().as_millis() as u64,
        );
        state
            .oci_engine_diagnostics
            .record_local_blob_read(blob_response.served_bytes, blob_response.partial);
    } else if blob_response.unsatisfiable {
        state.oci_engine_diagnostics.record_invalid_range();
    }
}

async fn local_blob_response(
    method: &Method,
    headers: &HeaderMap,
    digest: &str,
    handle: &BlobReadHandle,
) -> Result<BlobBodyResponse, OciError> {
    if *method == Method::HEAD {
        let response = blob_head_response(digest, handle.size_bytes())?;
        return Ok(BlobBodyResponse {
            response,
            served_bytes: 0,
            partial: false,
            unsatisfiable: false,
            body_read: false,
        });
    }

    match select_blob_range(headers, digest, handle.size_bytes())? {
        BlobRangeSelection::Full => {
            let mut headers = blob_headers(digest, handle.size_bytes())?;
            insert_header(
                &mut headers,
                "Content-Length",
                &handle.size_bytes().to_string(),
            )?;
            let body = cached_blob_body(handle, None).await?;
            Ok(BlobBodyResponse {
                response: (StatusCode::OK, headers, body).into_response(),
                served_bytes: handle.size_bytes(),
                partial: false,
                unsatisfiable: false,
                body_read: true,
            })
        }
        BlobRangeSelection::Partial(range) => {
            let mut headers = blob_headers(digest, handle.size_bytes())?;
            insert_header(&mut headers, "Content-Length", &range.len().to_string())?;
            insert_header(
                &mut headers,
                "Content-Range",
                &format!(
                    "bytes {}-{}/{}",
                    range.start,
                    range.end,
                    handle.size_bytes()
                ),
            )?;
            let body = cached_blob_body(handle, Some(range)).await?;
            Ok(BlobBodyResponse {
                response: (StatusCode::PARTIAL_CONTENT, headers, body).into_response(),
                served_bytes: range.len(),
                partial: true,
                unsatisfiable: false,
                body_read: true,
            })
        }
        BlobRangeSelection::Unsatisfiable => {
            let response = range_not_satisfiable_response(digest, handle.size_bytes())?;
            Ok(BlobBodyResponse {
                response,
                served_bytes: 0,
                partial: false,
                unsatisfiable: true,
                body_read: false,
            })
        }
    }
}

fn blob_head_response(digest: &str, size_bytes: u64) -> Result<Response, OciError> {
    let mut headers = blob_headers(digest, size_bytes)?;
    insert_header(&mut headers, "Content-Length", &size_bytes.to_string())?;
    Ok((StatusCode::OK, headers, Body::empty()).into_response())
}

fn blob_headers(digest: &str, _size_bytes: u64) -> Result<HeaderMap, OciError> {
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", digest)?;
    insert_digest_etag(&mut headers, digest)?;
    insert_header(&mut headers, "Content-Type", "application/octet-stream")?;
    insert_header(&mut headers, "Accept-Ranges", "bytes")?;
    insert_header(
        &mut headers,
        "Docker-Distribution-API-Version",
        "registry/2.0",
    )?;
    Ok(headers)
}

fn range_not_satisfiable_response(digest: &str, size_bytes: u64) -> Result<Response, OciError> {
    let mut headers = blob_headers(digest, size_bytes)?;
    insert_header(&mut headers, "Content-Length", "0")?;
    insert_header(
        &mut headers,
        "Content-Range",
        &format!("bytes */{size_bytes}"),
    )?;
    Ok((StatusCode::RANGE_NOT_SATISFIABLE, headers, Body::empty()).into_response())
}

fn select_blob_range(
    headers: &HeaderMap,
    digest: &str,
    size_bytes: u64,
) -> Result<BlobRangeSelection, OciError> {
    let Some(range_header) = headers.get(header::RANGE) else {
        return Ok(BlobRangeSelection::Full);
    };

    if let Some(if_range) = headers.get(header::IF_RANGE)
        && !if_range_matches(if_range, digest)?
    {
        return Ok(BlobRangeSelection::Full);
    }

    let range_header = range_header
        .to_str()
        .map_err(|e| OciError::digest_invalid(format!("Invalid Range header: {e}")))?;
    parse_byte_range(range_header, size_bytes)
}

fn if_range_matches(value: &axum::http::HeaderValue, digest: &str) -> Result<bool, OciError> {
    let value = value
        .to_str()
        .map_err(|e| OciError::digest_invalid(format!("Invalid If-Range header: {e}")))?
        .trim();
    Ok(value == digest || value == format!("\"{digest}\""))
}

fn parse_byte_range(value: &str, size_bytes: u64) -> Result<BlobRangeSelection, OciError> {
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return Ok(BlobRangeSelection::Unsatisfiable);
    };
    if spec.contains(',') || size_bytes == 0 {
        return Ok(BlobRangeSelection::Unsatisfiable);
    }
    let Some((start_raw, end_raw)) = spec.split_once('-') else {
        return Ok(BlobRangeSelection::Unsatisfiable);
    };
    let start_raw = start_raw.trim();
    let end_raw = end_raw.trim();

    if start_raw.is_empty() {
        let Ok(suffix_len) = end_raw.parse::<u64>() else {
            return Ok(BlobRangeSelection::Unsatisfiable);
        };
        if suffix_len == 0 {
            return Ok(BlobRangeSelection::Unsatisfiable);
        }
        let len = suffix_len.min(size_bytes);
        return Ok(BlobRangeSelection::Partial(BlobRange {
            start: size_bytes - len,
            end: size_bytes - 1,
        }));
    }

    let Ok(start) = start_raw.parse::<u64>() else {
        return Ok(BlobRangeSelection::Unsatisfiable);
    };
    if start >= size_bytes {
        return Ok(BlobRangeSelection::Unsatisfiable);
    }
    let end = if end_raw.is_empty() {
        size_bytes - 1
    } else {
        let Ok(end) = end_raw.parse::<u64>() else {
            return Ok(BlobRangeSelection::Unsatisfiable);
        };
        if end < start {
            return Ok(BlobRangeSelection::Unsatisfiable);
        }
        end.min(size_bytes - 1)
    };

    Ok(BlobRangeSelection::Partial(BlobRange { start, end }))
}

fn should_stream_through_blob(method: &Method, headers: &HeaderMap, size_bytes: u64) -> bool {
    if *method != Method::GET || headers.get(header::RANGE).is_some() {
        return false;
    }
    let Some(min_bytes) = stream_through_min_bytes() else {
        return false;
    };
    size_bytes >= min_bytes
}

fn stream_through_min_bytes() -> Option<u64> {
    let value = std::env::var(OCI_STREAM_THROUGH_MIN_BYTES_ENV).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

pub(crate) async fn resolve_oci_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob_desc: &BlobDescriptor,
    name: &str,
    digest: &str,
) -> Result<String, OciError> {
    if state.oci_negative_cache.contains_download_url_miss(
        &state.workspace,
        &state.registry_root_tag,
        name,
        digest,
        cache_entry_id,
    ) {
        state
            .oci_engine_diagnostics
            .record_negative_cache_hit(OciNegativeCacheReason::DownloadUrl);
        state.oci_engine_diagnostics.record_miss("download-url");
        return Err(OciError::blob_unknown(format!(
            "No download URL for {digest}"
        )));
    }

    let url = crate::serve::blob_download_urls::resolve_verified_blob_download_url(
        state,
        cache_entry_id,
        blob_desc,
        OCI_API_CALL_TIMEOUT,
    )
    .await
    .map_err(|error| OciError::internal(format!("Failed to get blob download URL: {error}")))?
    .ok_or_else(|| {
        state.oci_negative_cache.insert_download_url_miss(
            &state.workspace,
            &state.registry_root_tag,
            name,
            digest,
            cache_entry_id,
        );
        state
            .oci_engine_diagnostics
            .record_negative_cache_insert(OciNegativeCacheReason::DownloadUrl);
        state.oci_engine_diagnostics.record_miss("download-url");
        OciError::blob_unknown(format!("No download URL for {digest}"))
    })?;
    {
        let mut locator = state.blob_locator.write().await;
        if let Some(entry) = locator.get_mut(name, digest) {
            entry.download_url = Some(url.clone());
            entry.download_url_cached_at = Some(std::time::Instant::now());
        }
    }
    Ok(url)
}

async fn cached_blob_body(
    handle: &BlobReadHandle,
    range: Option<BlobRange>,
) -> Result<Body, OciError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let mut file = tokio::fs::File::open(handle.path())
        .await
        .map_err(|e| OciError::internal(format!("Failed to open cached blob: {e}")))?;
    let (offset, size_bytes) = match range {
        Some(range) => (handle.offset().saturating_add(range.start), range.len()),
        None => (handle.offset(), handle.size_bytes()),
    };
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| OciError::internal(format!("Failed to seek cached blob: {e}")))?;
    }
    let stream = ReaderStream::new(file.take(size_bytes));
    Ok(Body::from_stream(stream))
}

#[allow(clippy::too_many_arguments)]
async fn stream_oci_blob_to_client(
    state: AppState,
    cache_entry_id: String,
    blob_desc: BlobDescriptor,
    name: String,
    digest: String,
    mut download_url: String,
    mut from_cached_url: bool,
    request_started_at: std::time::Instant,
    flight_guard: FlightGuard,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, OciError> {
    let digest_hex = crate::cas_file::sha256_hex(digest.as_bytes());
    let temp_dir = state.runtime_temp_dir.join("oci-downloads");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp dir: {e}")))?;

    let max_attempts = OCI_BLOB_DOWNLOAD_MAX_ATTEMPTS + usize::from(from_cached_url);
    let mut last_error = None;
    for attempt in 1..=max_attempts {
        let storage_get_started_at = std::time::Instant::now();
        let response = match tokio::time::timeout(
            OCI_TRANSFER_CALL_TIMEOUT,
            state.api_client.transfer_client().get(&download_url).send(),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let message = format!("Failed to stream blob: {error}");
                if attempt < max_attempts {
                    state.oci_engine_diagnostics.record_storage_get_retry();
                    log_oci_blob_download_retry(&digest, attempt, max_attempts, &message);
                    sleep_oci_blob_download_retry(attempt).await;
                    continue;
                }
                state.oci_engine_diagnostics.record_storage_get_error();
                return Err(OciError::internal(message));
            }
            Err(_) => {
                let message = format!(
                    "Timed out streaming blob after {}s",
                    OCI_TRANSFER_CALL_TIMEOUT.as_secs()
                );
                state.oci_engine_diagnostics.record_storage_get_timeout();
                if attempt < max_attempts {
                    state.oci_engine_diagnostics.record_storage_get_retry();
                    log_oci_blob_download_retry(&digest, attempt, max_attempts, &message);
                    sleep_oci_blob_download_retry(attempt).await;
                    continue;
                }
                state.oci_engine_diagnostics.record_storage_get_error();
                return Err(OciError::internal(message));
            }
        };

        if from_cached_url
            && (response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::NOT_FOUND)
        {
            let mut locator = state.blob_locator.write().await;
            if let Some(entry) = locator.get_mut(&name, &digest) {
                entry.download_url = None;
                entry.download_url_cached_at = None;
            }
            drop(locator);
            download_url =
                resolve_oci_download_url(&state, &cache_entry_id, &blob_desc, &name, &digest)
                    .await?;
            from_cached_url = false;
            state.oci_engine_diagnostics.record_storage_get_retry();
            last_error = Some(format!(
                "Cached OCI blob URL returned {}",
                response.status()
            ));
            continue;
        }

        if !from_cached_url && response.status() == StatusCode::NOT_FOUND {
            state.oci_negative_cache.insert_remote_blob_miss(
                &state.workspace,
                &state.registry_root_tag,
                &name,
                &digest,
            );
            state
                .oci_engine_diagnostics
                .record_negative_cache_insert(OciNegativeCacheReason::RemoteBlob);
            state.oci_engine_diagnostics.record_miss("remote-blob");
            return Err(OciError::blob_unknown(format!("{name}@{digest}")));
        }

        if is_retryable_oci_blob_storage_status(response.status()) && attempt < max_attempts {
            let message = format!("Blob storage returned {}", response.status());
            state.oci_engine_diagnostics.record_storage_get_retry();
            log_oci_blob_download_retry(&digest, attempt, max_attempts, &message);
            sleep_oci_blob_download_retry(attempt).await;
            continue;
        }

        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                state.oci_engine_diagnostics.record_storage_get_error();
                return Err(OciError::internal(format!(
                    "Blob storage returned error: {error}"
                )));
            }
        };
        let storage_metrics = StorageMetrics::from_headers(response.headers());
        let temp_path = temp_dir.join(format!(
            "blob-{}-{}",
            &digest_hex[..16],
            uuid::Uuid::new_v4()
        ));
        let file = tokio::fs::File::create(&temp_path)
            .await
            .map_err(|e| OciError::internal(format!("Failed to create temp blob file: {e}")))?;

        let mut headers = blob_headers(&digest, blob_desc.size_bytes)?;
        insert_header(
            &mut headers,
            "Content-Length",
            &blob_desc.size_bytes.to_string(),
        )?;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        tokio::spawn(stream_oci_blob_body(
            state.clone(),
            name,
            digest.clone(),
            download_url,
            from_cached_url,
            blob_desc.size_bytes,
            response,
            file,
            temp_path,
            storage_get_started_at,
            storage_metrics,
            request_started_at,
            tx,
            flight_guard,
            permit,
        ));
        return Ok((
            StatusCode::OK,
            headers,
            Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
        )
            .into_response());
    }

    Err(OciError::internal(format!(
        "Blob stream-through failed after {} attempts: {}",
        max_attempts,
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )))
}

#[allow(clippy::too_many_arguments)]
async fn stream_oci_blob_body(
    state: AppState,
    name: String,
    digest: String,
    download_url: String,
    from_cached_url: bool,
    expected_size: u64,
    response: reqwest::Response,
    mut file: tokio::fs::File,
    temp_path: std::path::PathBuf,
    storage_get_started_at: std::time::Instant,
    storage_metrics: StorageMetrics,
    request_started_at: std::time::Instant,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    _flight_guard: FlightGuard,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    use tokio::io::AsyncWriteExt;

    let mut stream = response.bytes_stream();
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut first_chunk_ms = None;
    let body_started_at = std::time::Instant::now();
    let mut spool_write_duration_ms = 0u64;
    let mut previous_chunk: Option<Bytes> = None;

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(chunk) => chunk,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                state.oci_engine_diagnostics.record_storage_get_error();
                let _ = tx
                    .send(Err(std::io::Error::other(format!(
                        "Failed to read blob stream: {error}"
                    ))))
                    .await;
                return;
            }
        };
        if chunk.is_empty() {
            continue;
        }
        if first_chunk_ms.is_none() {
            first_chunk_ms = Some(storage_get_started_at.elapsed().as_millis() as u64);
        }
        let write_started_at = std::time::Instant::now();
        if let Err(error) = file.write_all(&chunk).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let _ = tx
                .send(Err(std::io::Error::other(format!(
                    "Failed to write temp blob file: {error}"
                ))))
                .await;
            return;
        }
        spool_write_duration_ms =
            spool_write_duration_ms.saturating_add(write_started_at.elapsed().as_millis() as u64);
        hasher.update(&chunk);
        written = written.saturating_add(chunk.len() as u64);

        if let Some(previous) = previous_chunk.replace(chunk)
            && tx.send(Ok(previous)).await.is_err()
        {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return;
        }
    }

    if let Err(error) = file.flush().await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = tx
            .send(Err(std::io::Error::other(format!(
                "Failed to flush temp blob file: {error}"
            ))))
            .await;
        return;
    }

    let verify_started_at = std::time::Instant::now();
    let actual_digest = format!("sha256:{:x}", hasher.finalize());
    let verify_duration_ms = verify_started_at.elapsed().as_millis() as u64;
    state.oci_engine_diagnostics.record_storage_get(
        written,
        first_chunk_ms.unwrap_or_else(|| storage_get_started_at.elapsed().as_millis() as u64),
        body_started_at.elapsed().as_millis() as u64,
        spool_write_duration_ms,
        verify_duration_ms,
        Some(&storage_metrics),
    );

    if actual_digest != digest {
        let _ = tokio::fs::remove_file(&temp_path).await;
        state.oci_engine_diagnostics.record_digest_verify_failure();
        state.oci_engine_diagnostics.record_storage_get_error();
        state
            .oci_engine_diagnostics
            .record_stream_through_verify_failure();
        let _ = tx
            .send(Err(std::io::Error::other(format!(
                "Downloaded blob digest mismatch for {digest}: got {actual_digest}"
            ))))
            .await;
        return;
    }

    if written != expected_size {
        let _ = tokio::fs::remove_file(&temp_path).await;
        state.oci_engine_diagnostics.record_storage_get_error();
        state
            .oci_engine_diagnostics
            .record_stream_through_verify_failure();
        let _ = tx
            .send(Err(std::io::Error::other(format!(
                "Downloaded blob size mismatch for {digest}: expected {expected_size}, got {written}"
            ))))
            .await;
        return;
    }

    if !from_cached_url {
        let mut locator = state.blob_locator.write().await;
        if let Some(entry) = locator.get_mut(&name, &digest) {
            entry.download_url = Some(download_url);
            entry.download_url_cached_at = Some(std::time::Instant::now());
        }
    }

    let promote_started_at = std::time::Instant::now();
    let cache_promotion_ok = match state
        .blob_read_cache
        .promote(&digest, &temp_path, written)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            log::warn!("OCI blob stream-through cache promote failed for {digest}: {error}");
            let _ = tokio::fs::remove_file(&temp_path).await;
            false
        }
    };
    let promotion_duration_ms = promote_started_at.elapsed().as_millis() as u64;
    state
        .oci_engine_diagnostics
        .record_cache_promotion(promotion_duration_ms, cache_promotion_ok);
    state.oci_engine_diagnostics.record_stream_through(
        written,
        verify_duration_ms,
        cache_promotion_ok,
    );
    state
        .oci_body_metrics
        .record_remote(written, request_started_at.elapsed().as_millis() as u64);
    state
        .oci_engine_diagnostics
        .record_remote_blob_read(written, written, false);

    if let Some(final_chunk) = previous_chunk {
        let _ = tx.send(Ok(final_chunk)).await;
    }
}

async fn download_oci_blob_to_cache(
    state: &AppState,
    cache_entry_id: &str,
    blob_desc: &BlobDescriptor,
    name: &str,
    digest: &str,
    mut download_url: String,
    mut from_cached_url: bool,
) -> Result<BlobReadHandle, OciError> {
    use tokio::io::AsyncWriteExt;

    let digest_hex = crate::cas_file::sha256_hex(digest.as_bytes());
    let temp_dir = state.runtime_temp_dir.join("oci-downloads");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp dir: {e}")))?;

    let max_attempts = OCI_BLOB_DOWNLOAD_MAX_ATTEMPTS + usize::from(from_cached_url);
    let mut last_error = None;
    for attempt in 1..=max_attempts {
        let storage_get_started_at = std::time::Instant::now();
        let response = match tokio::time::timeout(
            OCI_TRANSFER_CALL_TIMEOUT,
            state.api_client.transfer_client().get(&download_url).send(),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let message = format!("Failed to download blob: {error}");
                if attempt < max_attempts {
                    state.oci_engine_diagnostics.record_storage_get_retry();
                    log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                    sleep_oci_blob_download_retry(attempt).await;
                    continue;
                }
                state.oci_engine_diagnostics.record_storage_get_error();
                return Err(OciError::internal(message));
            }
            Err(_) => {
                let message = format!(
                    "Timed out downloading blob after {}s",
                    OCI_TRANSFER_CALL_TIMEOUT.as_secs()
                );
                state.oci_engine_diagnostics.record_storage_get_timeout();
                if attempt < max_attempts {
                    state.oci_engine_diagnostics.record_storage_get_retry();
                    log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                    sleep_oci_blob_download_retry(attempt).await;
                    continue;
                }
                state.oci_engine_diagnostics.record_storage_get_error();
                return Err(OciError::internal(message));
            }
        };

        if from_cached_url
            && (response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::NOT_FOUND)
        {
            let mut locator = state.blob_locator.write().await;
            if let Some(entry) = locator.get_mut(name, digest) {
                entry.download_url = None;
                entry.download_url_cached_at = None;
            }
            drop(locator);
            download_url =
                resolve_oci_download_url(state, cache_entry_id, blob_desc, name, digest).await?;
            from_cached_url = false;
            state.oci_engine_diagnostics.record_storage_get_retry();
            last_error = Some(format!(
                "Cached OCI blob URL returned {}",
                response.status()
            ));
            continue;
        }

        if !from_cached_url && response.status() == StatusCode::NOT_FOUND {
            state.oci_negative_cache.insert_remote_blob_miss(
                &state.workspace,
                &state.registry_root_tag,
                name,
                digest,
            );
            state
                .oci_engine_diagnostics
                .record_negative_cache_insert(OciNegativeCacheReason::RemoteBlob);
            state.oci_engine_diagnostics.record_miss("remote-blob");
            return Err(OciError::blob_unknown(format!("{name}@{digest}")));
        }

        if is_retryable_oci_blob_storage_status(response.status()) && attempt < max_attempts {
            let message = format!("Blob storage returned {}", response.status());
            state.oci_engine_diagnostics.record_storage_get_retry();
            log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
            sleep_oci_blob_download_retry(attempt).await;
            continue;
        }

        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                state.oci_engine_diagnostics.record_storage_get_error();
                return Err(OciError::internal(format!(
                    "Blob storage returned error: {error}"
                )));
            }
        };
        let storage_metrics = StorageMetrics::from_headers(response.headers());

        let temp_path = temp_dir.join(format!(
            "blob-{}-{}",
            &digest_hex[..16],
            uuid::Uuid::new_v4()
        ));

        let mut file = tokio::fs::File::create(&temp_path)
            .await
            .map_err(|e| OciError::internal(format!("Failed to create temp blob file: {e}")))?;
        let mut stream = response.bytes_stream();
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        let mut first_chunk_ms = None;
        let mut spool_write_duration_ms = 0u64;
        let body_started_at = std::time::Instant::now();
        let mut stream_error = None;
        loop {
            let next_chunk = stream.next().await;
            let Some(chunk) = next_chunk else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    stream_error = Some(format!("Failed to read blob stream: {error}"));
                    break;
                }
            };
            if first_chunk_ms.is_none() {
                first_chunk_ms = Some(storage_get_started_at.elapsed().as_millis() as u64);
            }
            let write_started_at = std::time::Instant::now();
            if let Err(error) = file.write_all(&chunk).await {
                stream_error = Some(format!("Failed to write temp blob file: {error}"));
                break;
            }
            spool_write_duration_ms = spool_write_duration_ms
                .saturating_add(write_started_at.elapsed().as_millis() as u64);
            hasher.update(&chunk);
            written = written.saturating_add(chunk.len() as u64);
        }
        if let Some(message) = stream_error {
            let _ = tokio::fs::remove_file(&temp_path).await;
            if attempt < max_attempts {
                state.oci_engine_diagnostics.record_storage_get_retry();
                log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                sleep_oci_blob_download_retry(attempt).await;
                last_error = Some(message);
                continue;
            }
            state.oci_engine_diagnostics.record_storage_get_error();
            return Err(OciError::internal(message));
        }
        file.flush()
            .await
            .map_err(|e| OciError::internal(format!("Failed to flush temp blob file: {e}")))?;

        let verify_started_at = std::time::Instant::now();
        let actual_digest = format!("sha256:{:x}", hasher.finalize());
        let verify_duration_ms = verify_started_at.elapsed().as_millis() as u64;
        state.oci_engine_diagnostics.record_storage_get(
            written,
            first_chunk_ms.unwrap_or_else(|| storage_get_started_at.elapsed().as_millis() as u64),
            body_started_at.elapsed().as_millis() as u64,
            spool_write_duration_ms,
            verify_duration_ms,
            Some(&storage_metrics),
        );
        if actual_digest != digest {
            let _ = tokio::fs::remove_file(&temp_path).await;
            state.oci_engine_diagnostics.record_digest_verify_failure();
            state.oci_engine_diagnostics.record_storage_get_error();
            return Err(OciError::digest_invalid(format!(
                "Downloaded blob digest mismatch for {digest}: got {actual_digest}"
            )));
        }

        if written != blob_desc.size_bytes {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let message = format!(
                "Downloaded blob size mismatch for {digest}: expected {}, got {}",
                blob_desc.size_bytes, written
            );
            if attempt < max_attempts {
                state.oci_engine_diagnostics.record_storage_get_retry();
                log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                sleep_oci_blob_download_retry(attempt).await;
                last_error = Some(message);
                continue;
            }
            state.oci_engine_diagnostics.record_storage_get_error();
            return Err(OciError::internal(message));
        }

        if !from_cached_url {
            let mut locator = state.blob_locator.write().await;
            if let Some(entry) = locator.get_mut(name, digest) {
                entry.download_url = Some(download_url.clone());
                entry.download_url_cached_at = Some(std::time::Instant::now());
            }
        }

        if written > 0 {
            let promote_started_at = std::time::Instant::now();
            match state
                .blob_read_cache
                .promote(digest, &temp_path, written)
                .await
            {
                Ok(_) => {
                    state.oci_engine_diagnostics.record_cache_promotion(
                        promote_started_at.elapsed().as_millis() as u64,
                        true,
                    );
                }
                Err(error) => {
                    state.oci_engine_diagnostics.record_cache_promotion(
                        promote_started_at.elapsed().as_millis() as u64,
                        false,
                    );
                    log::warn!("OCI blob read cache promote failed for {digest}: {error}");
                }
            }
        }

        if let Some(handle) = state.blob_read_cache.get_handle(digest).await {
            return Ok(handle);
        }

        if tokio::fs::metadata(&temp_path).await.is_ok() {
            return Ok(BlobReadHandle::from_file(temp_path, written));
        }

        last_error = Some("Downloaded blob missing after cache promotion".to_string());
    }

    Err(OciError::internal(format!(
        "Blob download failed after {} attempts: {}",
        max_attempts,
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )))
}

pub(crate) fn is_retryable_oci_blob_storage_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn log_oci_blob_download_retry(digest: &str, attempt: usize, max_attempts: usize, message: &str) {
    log::warn!(
        "OCI blob body download failed for {} on attempt {}/{}: {}; retrying",
        digest,
        attempt,
        max_attempts,
        message
    );
}

async fn sleep_oci_blob_download_retry(attempt: usize) {
    tokio::time::sleep(Duration::from_millis(
        OCI_BLOB_DOWNLOAD_RETRY_BASE_MS.saturating_mul(attempt as u64),
    ))
    .await;
}

fn fresh_download_url(entry: &BlobLocatorEntry) -> Option<String> {
    let cached_at = entry.download_url_cached_at?;
    if cached_at.elapsed() >= DOWNLOAD_URL_CACHE_TTL {
        return None;
    }
    entry.download_url.clone()
}

async fn fresh_locator_download_url(
    state: &AppState,
    name: &str,
    digest: &str,
    fallback: Option<&str>,
) -> Option<String> {
    {
        let locator = state.blob_locator.read().await;
        if let Some(entry) = locator.get(name, digest)
            && let Some(url) = fresh_download_url(entry)
        {
            return Some(url);
        }
    }
    fallback.map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{BlobRange, BlobRangeSelection, is_retryable_oci_blob_storage_status};

    #[test]
    fn parses_standard_byte_range() {
        assert_eq!(
            super::parse_byte_range("bytes=2-5", 10).expect("range"),
            BlobRangeSelection::Partial(BlobRange { start: 2, end: 5 })
        );
    }

    #[test]
    fn parses_suffix_byte_range() {
        assert_eq!(
            super::parse_byte_range("bytes=-4", 10).expect("range"),
            BlobRangeSelection::Partial(BlobRange { start: 6, end: 9 })
        );
    }

    #[test]
    fn clamps_open_ended_byte_range() {
        assert_eq!(
            super::parse_byte_range("bytes=8-", 10).expect("range"),
            BlobRangeSelection::Partial(BlobRange { start: 8, end: 9 })
        );
    }

    #[test]
    fn rejects_unsatisfiable_byte_range() {
        assert_eq!(
            super::parse_byte_range("bytes=10-11", 10).expect("range"),
            BlobRangeSelection::Unsatisfiable
        );
    }

    #[test]
    fn retries_transient_oci_blob_storage_statuses() {
        assert!(is_retryable_oci_blob_storage_status(
            StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(is_retryable_oci_blob_storage_status(
            StatusCode::BAD_GATEWAY
        ));
        assert!(is_retryable_oci_blob_storage_status(
            StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(is_retryable_oci_blob_storage_status(
            StatusCode::REQUEST_TIMEOUT
        ));
    }

    #[test]
    fn does_not_retry_permanent_oci_blob_storage_statuses() {
        assert!(!is_retryable_oci_blob_storage_status(StatusCode::OK));
        assert!(!is_retryable_oci_blob_storage_status(StatusCode::NOT_FOUND));
        assert!(!is_retryable_oci_blob_storage_status(StatusCode::FORBIDDEN));
        assert!(!is_retryable_oci_blob_storage_status(
            StatusCode::UNPROCESSABLE_ENTITY
        ));
    }
}
