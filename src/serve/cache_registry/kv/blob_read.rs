use super::*;

pub(crate) async fn serve_local_blob(
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

fn emit_blob_read_elapsed_metric(
    state: &AppState,
    cache_entry_id: &str,
    source: BlobReadSource,
    blob: &BlobDescriptor,
    started_at: std::time::Instant,
) {
    emit_blob_read_metric(
        state,
        cache_entry_id,
        source,
        blob.size_bytes,
        started_at.elapsed().as_millis() as u64,
    );
}

pub(crate) async fn resolve_blob_url(
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

pub(crate) async fn do_download_blob_to_cache(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    cached_url: Option<&str>,
) -> Result<(BlobReadHandle, BlobReadSource), RegistryError> {
    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
        return Ok((cache_handle, BlobReadSource::LocalCache));
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
        return Ok((cache_handle, BlobReadSource::LocalCache));
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
        return Ok((cache_handle, BlobReadSource::RemoteFetch));
    }

    if tokio::fs::metadata(&temp_path).await.is_ok() {
        return Ok((
            BlobReadHandle::from_file(temp_path, written),
            BlobReadSource::RemoteFetch,
        ));
    }

    Err(RegistryError::internal(
        "Blob not found after download (promote may have moved it)",
    ))
}

pub(crate) async fn stream_blob_to_file(
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

pub(crate) fn short_digest(digest: &str) -> &str {
    if digest.len() > 16 {
        &digest[..16]
    } else {
        digest
    }
}

pub(crate) async fn download_blob_to_cache(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    cached_url: Option<&str>,
) -> Result<BlobReadHandle, RegistryError> {
    let started_at = std::time::Instant::now();
    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
        log::debug!("dl cache hit: {}", short_digest(&blob.digest));
        emit_blob_read_elapsed_metric(
            state,
            cache_entry_id,
            BlobReadSource::LocalCache,
            blob,
            started_at,
        );
        return Ok(cache_handle);
    }

    let flight_key = format!("dl:{}", blob.digest);
    let mut attempted_takeover = false;
    loop {
        match begin_lookup_flight(state, flight_key.clone()) {
            LookupFlight::Leader(_dl_guard) => {
                if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                    emit_blob_read_elapsed_metric(
                        state,
                        cache_entry_id,
                        BlobReadSource::LocalCache,
                        blob,
                        started_at,
                    );
                    return Ok(cache_handle);
                }

                let (cache_handle, source) =
                    do_download_blob_to_cache(state, cache_entry_id, blob, cached_url).await?;
                emit_blob_read_elapsed_metric(state, cache_entry_id, source, blob, started_at);
                return Ok(cache_handle);
            }
            LookupFlight::Follower(notified) => {
                let flight_completed = await_flight("dl", &flight_key, notified).await;
                if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                    emit_blob_read_elapsed_metric(
                        state,
                        cache_entry_id,
                        BlobReadSource::LocalCache,
                        blob,
                        started_at,
                    );
                    return Ok(cache_handle);
                }

                if attempted_takeover {
                    let reason = if flight_completed {
                        "completed without a cached blob"
                    } else {
                        "timed out waiting for the download owner"
                    };
                    return Err(RegistryError::internal(format!(
                        "Blob download {reason}: {}",
                        short_digest(&blob.digest)
                    )));
                }

                clear_lookup_flight_entry(state, &flight_key);
                attempted_takeover = true;
            }
        }
    }
}
