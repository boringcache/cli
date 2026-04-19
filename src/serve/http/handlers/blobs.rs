use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use tokio_util::io::ReaderStream;

use crate::api::models::cache::BlobDescriptor;
use crate::serve::http::error::OciError;
use crate::serve::http::flight::{Flight, await_flight, begin_flight, clear_flight_entry};
use crate::serve::http::oci_route::insert_header;
use crate::serve::state::{AppState, BlobLocatorEntry, BlobReadHandle};

use super::uploads::find_local_uploaded_blob;
use super::{DOWNLOAD_URL_CACHE_TTL, OCI_API_CALL_TIMEOUT, OCI_TRANSFER_CALL_TIMEOUT};

const OCI_BLOB_DOWNLOAD_MAX_ATTEMPTS: usize = 4;
const OCI_BLOB_DOWNLOAD_RETRY_BASE_MS: u64 = 500;

pub(super) async fn get_blob(
    method: Method,
    state: AppState,
    name: String,
    digest: String,
) -> Result<Response, OciError> {
    let request_started_at = std::time::Instant::now();
    if let Some(handle) = find_local_uploaded_blob(&state, &name, &digest).await {
        if method != Method::HEAD {
            state.oci_body_metrics.record_local(
                handle.size_bytes(),
                request_started_at.elapsed().as_millis() as u64,
            );
        }
        return local_blob_response(method, &digest, &handle).await;
    }

    if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
        if method != Method::HEAD {
            state.oci_body_metrics.record_local(
                handle.size_bytes(),
                request_started_at.elapsed().as_millis() as u64,
            );
        }
        return local_blob_response(method, &digest, &handle).await;
    }

    let Some((cache_entry_id, size_bytes, cached_download_url)) = ({
        let locator_start = std::time::Instant::now();
        let locator = state.blob_locator.read().await;
        let elapsed = locator_start.elapsed();
        if elapsed > std::time::Duration::from_millis(100) {
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
        return Err(OciError::blob_unknown(format!("{name}@{digest}")));
    };

    if method == Method::HEAD {
        let blob_exists = if cached_download_url.is_some() {
            true
        } else {
            match has_remote_blob(&state, &digest).await {
                Ok(exists) => exists,
                Err(error) => {
                    log::warn!(
                        "OCI HEAD degraded to miss after remote blob existence check failed for {}@{} ({})",
                        name,
                        digest,
                        error.message()
                    );
                    false
                }
            }
        };
        if !blob_exists {
            return Err(OciError::blob_unknown(format!("{name}@{digest}")));
        }
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, "Docker-Content-Digest", &digest)?;
        insert_header(&mut headers, "Content-Type", "application/octet-stream")?;
        insert_header(&mut headers, "Content-Length", &size_bytes.to_string())?;
        insert_header(
            &mut headers,
            "Docker-Distribution-API-Version",
            "registry/2.0",
        )?;
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", &digest)?;
    insert_header(&mut headers, "Content-Type", "application/octet-stream")?;
    insert_header(&mut headers, "Content-Length", &size_bytes.to_string())?;
    insert_header(
        &mut headers,
        "Docker-Distribution-API-Version",
        "registry/2.0",
    )?;

    if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
        state.oci_body_metrics.record_local(
            handle.size_bytes(),
            request_started_at.elapsed().as_millis() as u64,
        );
        let body = cached_blob_body(&handle).await?;
        return Ok((StatusCode::OK, headers, body).into_response());
    }

    let blob_desc = BlobDescriptor {
        digest: digest.clone(),
        size_bytes,
    };
    let flight_key = format!("blob:{digest}");
    loop {
        match begin_flight(&state.oci_lookup_inflight, flight_key.clone()) {
            Flight::Leader(_guard) => {
                if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
                    state.oci_body_metrics.record_local(
                        handle.size_bytes(),
                        request_started_at.elapsed().as_millis() as u64,
                    );
                    let body = cached_blob_body(&handle).await?;
                    return Ok((StatusCode::OK, headers, body).into_response());
                }

                let _permit = state
                    .blob_download_semaphore
                    .acquire()
                    .await
                    .map_err(|_| OciError::internal("Blob download semaphore closed"))?;

                if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
                    state.oci_body_metrics.record_local(
                        handle.size_bytes(),
                        request_started_at.elapsed().as_millis() as u64,
                    );
                    let body = cached_blob_body(&handle).await?;
                    return Ok((StatusCode::OK, headers, body).into_response());
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
                state.oci_body_metrics.record_remote(
                    handle.size_bytes(),
                    request_started_at.elapsed().as_millis() as u64,
                );
                let body = cached_blob_body(&handle).await?;
                return Ok((StatusCode::OK, headers, body).into_response());
            }
            Flight::Follower(notified) => {
                if !await_flight("oci-blob", &flight_key, notified).await {
                    clear_flight_entry(&state.oci_lookup_inflight, &flight_key);
                }
                if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
                    state.oci_body_metrics.record_local(
                        handle.size_bytes(),
                        request_started_at.elapsed().as_millis() as u64,
                    );
                    let body = cached_blob_body(&handle).await?;
                    return Ok((StatusCode::OK, headers, body).into_response());
                }
            }
        }
    }
}

async fn local_blob_response(
    method: Method,
    digest: &str,
    handle: &BlobReadHandle,
) -> Result<Response, OciError> {
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", digest)?;
    insert_header(&mut headers, "Content-Type", "application/octet-stream")?;
    insert_header(
        &mut headers,
        "Content-Length",
        &handle.size_bytes().to_string(),
    )?;
    insert_header(
        &mut headers,
        "Docker-Distribution-API-Version",
        "registry/2.0",
    )?;

    if method == Method::HEAD {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    let body = cached_blob_body(handle).await?;
    Ok((StatusCode::OK, headers, body).into_response())
}

pub(super) async fn has_remote_blob(state: &AppState, digest: &str) -> Result<bool, OciError> {
    let check = tokio::time::timeout(
        OCI_API_CALL_TIMEOUT,
        state.api_client.check_blobs_verified(
            &state.workspace,
            &[BlobDescriptor {
                digest: digest.to_string(),
                size_bytes: 0,
            }],
        ),
    )
    .await
    .map_err(|_| {
        OciError::internal(format!(
            "Timed out checking blob existence after {}s",
            OCI_API_CALL_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| OciError::internal(format!("Failed to check blob existence: {e}")))?;

    Ok(check
        .results
        .iter()
        .any(|result| result.digest == digest && result.exists))
}

pub(super) async fn resolve_oci_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob_desc: &BlobDescriptor,
    name: &str,
    digest: &str,
) -> Result<String, OciError> {
    let url = crate::serve::blob_download_urls::resolve_verified_blob_download_url(
        state,
        cache_entry_id,
        blob_desc,
        OCI_API_CALL_TIMEOUT,
    )
    .await
    .map_err(|error| OciError::internal(format!("Failed to get blob download URL: {error}")))?
    .ok_or_else(|| OciError::blob_unknown(format!("No download URL for {digest}")))?;
    {
        let mut locator = state.blob_locator.write().await;
        if let Some(entry) = locator.get_mut(name, digest) {
            entry.download_url = Some(url.clone());
            entry.download_url_cached_at = Some(std::time::Instant::now());
        }
    }
    Ok(url)
}

async fn cached_blob_body(handle: &BlobReadHandle) -> Result<Body, OciError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let mut file = tokio::fs::File::open(handle.path())
        .await
        .map_err(|e| OciError::internal(format!("Failed to open cached blob: {e}")))?;
    if handle.offset() > 0 {
        file.seek(std::io::SeekFrom::Start(handle.offset()))
            .await
            .map_err(|e| OciError::internal(format!("Failed to seek cached blob: {e}")))?;
    }
    let stream = ReaderStream::new(file.take(handle.size_bytes()));
    Ok(Body::from_stream(stream))
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
                    log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                    sleep_oci_blob_download_retry(attempt).await;
                    continue;
                }
                return Err(OciError::internal(message));
            }
            Err(_) => {
                let message = format!(
                    "Timed out downloading blob after {}s",
                    OCI_TRANSFER_CALL_TIMEOUT.as_secs()
                );
                if attempt < max_attempts {
                    log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                    sleep_oci_blob_download_retry(attempt).await;
                    continue;
                }
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
            last_error = Some(format!(
                "Cached OCI blob URL returned {}",
                response.status()
            ));
            continue;
        }

        if is_retryable_oci_blob_storage_status(response.status()) && attempt < max_attempts {
            let message = format!("Blob storage returned {}", response.status());
            log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
            sleep_oci_blob_download_retry(attempt).await;
            continue;
        }

        let response = response
            .error_for_status()
            .map_err(|e| OciError::internal(format!("Blob storage returned error: {e}")))?;

        let temp_path = temp_dir.join(format!(
            "blob-{}-{}",
            &digest_hex[..16],
            uuid::Uuid::new_v4()
        ));

        let mut file = tokio::fs::File::create(&temp_path)
            .await
            .map_err(|e| OciError::internal(format!("Failed to create temp blob file: {e}")))?;
        let mut stream = response.bytes_stream();
        let mut written = 0u64;
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
            if let Err(error) = file.write_all(&chunk).await {
                stream_error = Some(format!("Failed to write temp blob file: {error}"));
                break;
            }
            written = written.saturating_add(chunk.len() as u64);
        }
        if let Some(message) = stream_error {
            let _ = tokio::fs::remove_file(&temp_path).await;
            if attempt < max_attempts {
                log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                sleep_oci_blob_download_retry(attempt).await;
                last_error = Some(message);
                continue;
            }
            return Err(OciError::internal(message));
        }
        file.flush()
            .await
            .map_err(|e| OciError::internal(format!("Failed to flush temp blob file: {e}")))?;

        if written == 0 {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let message = "Downloaded blob was empty".to_string();
            if attempt < max_attempts {
                log_oci_blob_download_retry(digest, attempt, max_attempts, &message);
                sleep_oci_blob_download_retry(attempt).await;
                last_error = Some(message);
                continue;
            }
            return Err(OciError::internal(message));
        }

        if !from_cached_url {
            let mut locator = state.blob_locator.write().await;
            if let Some(entry) = locator.get_mut(name, digest) {
                entry.download_url = Some(download_url.clone());
                entry.download_url_cached_at = Some(std::time::Instant::now());
            }
        }

        if let Err(error) = state
            .blob_read_cache
            .promote(digest, &temp_path, written)
            .await
        {
            log::warn!("OCI blob read cache promote failed for {digest}: {error}");
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

fn is_retryable_oci_blob_storage_status(status: StatusCode) -> bool {
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
    tokio::time::sleep(std::time::Duration::from_millis(
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

    use super::is_retryable_oci_blob_storage_status;

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
