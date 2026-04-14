use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use tokio_util::io::ReaderStream;

use crate::api::models::cache::BlobDescriptor;
use crate::serve::http::error::OciError;
use crate::serve::http::oci_route::insert_header;
use crate::serve::state::{AppState, BlobLocatorEntry, BlobReadHandle};

use super::uploads::find_local_uploaded_blob;
use super::{DOWNLOAD_URL_CACHE_TTL, OCI_API_CALL_TIMEOUT, OCI_TRANSFER_CALL_TIMEOUT};

pub(super) async fn get_blob(
    method: Method,
    state: AppState,
    name: String,
    digest: String,
) -> Result<Response, OciError> {
    if let Some(handle) = find_local_uploaded_blob(&state, &name, &digest).await {
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, "Docker-Content-Digest", &digest)?;
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

        let body = cached_blob_body(&handle).await?;
        return Ok((StatusCode::OK, headers, body).into_response());
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

    let blob_desc = BlobDescriptor {
        digest: digest.clone(),
        size_bytes,
    };

    let (download_url, from_cache) = if let Some(url) = cached_download_url {
        (url, true)
    } else {
        let url =
            resolve_oci_download_url(&state, &cache_entry_id, &blob_desc, &name, &digest).await?;
        (url, false)
    };

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
        let body = cached_blob_body(&handle).await?;
        return Ok((StatusCode::OK, headers, body).into_response());
    }

    let _permit = state
        .blob_download_semaphore
        .acquire()
        .await
        .map_err(|_| OciError::internal("Blob download semaphore closed"))?;

    if let Some(handle) = state.blob_read_cache.get_handle(&digest).await {
        let body = cached_blob_body(&handle).await?;
        return Ok((StatusCode::OK, headers, body).into_response());
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
    let body = cached_blob_body(&handle).await?;

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
    let download_response = tokio::time::timeout(
        OCI_API_CALL_TIMEOUT,
        state.api_client.blob_download_urls_verified(
            &state.workspace,
            cache_entry_id,
            std::slice::from_ref(blob_desc),
        ),
    )
    .await
    .map_err(|_| {
        OciError::internal(format!(
            "Timed out resolving blob URL after {}s",
            OCI_API_CALL_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| OciError::internal(format!("Failed to get blob download URL: {e}")))?;

    let url = download_response
        .download_urls
        .first()
        .ok_or_else(|| OciError::blob_unknown(format!("No download URL for {digest}")))?
        .url
        .clone();
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

    let mut retried = false;
    let response = loop {
        let response = tokio::time::timeout(
            OCI_TRANSFER_CALL_TIMEOUT,
            state.api_client.transfer_client().get(&download_url).send(),
        )
        .await
        .map_err(|_| {
            OciError::internal(format!(
                "Timed out downloading blob after {}s",
                OCI_TRANSFER_CALL_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| OciError::internal(format!("Failed to download blob: {e}")))?;

        if retried
            || (response.status() != StatusCode::FORBIDDEN
                && response.status() != StatusCode::NOT_FOUND)
        {
            break response;
        }

        if from_cached_url {
            let mut locator = state.blob_locator.write().await;
            if let Some(entry) = locator.get_mut(name, digest) {
                entry.download_url = None;
                entry.download_url_cached_at = None;
            }
        }
        download_url =
            resolve_oci_download_url(state, cache_entry_id, blob_desc, name, digest).await?;
        from_cached_url = false;
        retried = true;
    };

    let response = response
        .error_for_status()
        .map_err(|e| OciError::internal(format!("Blob storage returned error: {e}")))?;

    let digest_hex = crate::cas_file::sha256_hex(digest.as_bytes());
    let temp_dir = state.runtime_temp_dir.join("oci-downloads");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp dir: {e}")))?;
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
    loop {
        let next_chunk = stream.next().await;
        let Some(chunk) = next_chunk else {
            break;
        };
        let chunk =
            chunk.map_err(|e| OciError::internal(format!("Failed to read blob stream: {e}")))?;
        file.write_all(&chunk)
            .await
            .map_err(|e| OciError::internal(format!("Failed to write temp blob file: {e}")))?;
        written = written.saturating_add(chunk.len() as u64);
    }
    file.flush()
        .await
        .map_err(|e| OciError::internal(format!("Failed to flush temp blob file: {e}")))?;

    if written == 0 {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(OciError::internal("Downloaded blob was empty"));
    }

    if !from_cached_url {
        let mut locator = state.blob_locator.write().await;
        if let Some(entry) = locator.get_mut(name, digest) {
            entry.download_url = Some(download_url);
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

    Err(OciError::internal(
        "Downloaded blob missing after cache promotion",
    ))
}

fn fresh_download_url(entry: &BlobLocatorEntry) -> Option<String> {
    let cached_at = entry.download_url_cached_at?;
    if cached_at.elapsed() >= DOWNLOAD_URL_CACHE_TTL {
        return None;
    }
    entry.download_url.clone()
}
