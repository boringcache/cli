use super::*;

pub(crate) async fn lookup_published_blob(
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

pub(crate) async fn populate_sizes_from_published(
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

pub(crate) async fn should_refresh_published_index_for_lookup(state: &AppState) -> bool {
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

pub(crate) async fn should_suppress_lookup_refresh_due_to_pending(state: &AppState) -> bool {
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

pub(crate) fn should_suppress_lookup_refresh_due_to_pending_values(
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

pub(crate) fn should_suppress_lookup_refresh_due_to_pending_or_flushing_values(
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
pub(crate) struct PublishedGapCounts {
    pub(crate) missing_keys: usize,
    pub(crate) mismatched_keys: usize,
}

pub(crate) fn count_published_gaps_in_backend(
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

pub(crate) async fn refresh_published_index_for_lookup(
    state: &AppState,
) -> Result<(), RegistryError> {
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

pub(crate) async fn refresh_published_index_for_lookup_with_timeout(
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

pub(crate) async fn maybe_refresh_published_index_for_lookup(
    state: &AppState,
) -> Result<(), RegistryError> {
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

pub(crate) fn content_length_bytes(response: &Response) -> u64 {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

pub(crate) fn expected_bazel_cas_blob_digest(namespace: KvNamespace, key: &str) -> Option<String> {
    if !matches!(namespace, KvNamespace::BazelCas) {
        return None;
    }
    Some(format!("sha256:{}", namespace.normalize_key(key)))
}

pub(crate) fn bazel_cas_blob_matches(
    namespace: KvNamespace,
    key: &str,
    blob: &BlobDescriptor,
) -> bool {
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
                super::super::cache_ops::Op::Get,
                super::super::cache_ops::OpResult::Hit,
                false,
                content_length_bytes(response),
                elapsed_ms,
            );
        }
        Err(e) if e.status == StatusCode::NOT_FOUND => {
            state.cache_ops.record(
                tool,
                super::super::cache_ops::Op::Get,
                super::super::cache_ops::OpResult::Miss,
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
                super::super::cache_ops::Op::Get,
                super::super::cache_ops::OpResult::Error,
                degraded,
                0,
                elapsed_ms,
            );
        }
    }

    result
}

pub(crate) async fn await_startup_prefetch_readiness(
    state: &AppState,
) -> Result<(), RegistryError> {
    loop {
        if state.prefetch_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        let notified = state.prefetch_complete_notify.notified();
        if state.prefetch_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        match tokio::time::timeout(KV_PREFETCH_READINESS_TIMEOUT, notified).await {
            Ok(()) => {}
            Err(_) => {
                return Err(RegistryError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "Cache registry is still warming after {}s",
                        KV_PREFETCH_READINESS_TIMEOUT.as_secs()
                    ),
                ));
            }
        }
    }
}

pub(crate) async fn get_or_head_kv_object_inner(
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

    await_startup_prefetch_readiness(state).await?;

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
        emit_blob_read_metric(
            state,
            cache_entry_id,
            BlobReadSource::LocalCache,
            blob.size_bytes,
            started_at.elapsed().as_millis() as u64,
        );
        return Ok(cache_handle);
    }

    let flight_key = format!("dl:{}", blob.digest);
    match begin_lookup_flight(state, flight_key.clone()) {
        LookupFlight::Leader(_dl_guard) => {
            if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                emit_blob_read_metric(
                    state,
                    cache_entry_id,
                    BlobReadSource::LocalCache,
                    blob.size_bytes,
                    started_at.elapsed().as_millis() as u64,
                );
                return Ok(cache_handle);
            }

            let (cache_handle, source) =
                do_download_blob_to_cache(state, cache_entry_id, blob, cached_url).await?;
            emit_blob_read_metric(
                state,
                cache_entry_id,
                source,
                blob.size_bytes,
                started_at.elapsed().as_millis() as u64,
            );
            Ok(cache_handle)
        }
        LookupFlight::Follower(notified) => {
            if !await_flight("dl", &flight_key, notified).await {
                clear_lookup_flight_entry(state, &flight_key);
            }
            if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                emit_blob_read_metric(
                    state,
                    cache_entry_id,
                    BlobReadSource::LocalCache,
                    blob.size_bytes,
                    started_at.elapsed().as_millis() as u64,
                );
                return Ok(cache_handle);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await {
                emit_blob_read_metric(
                    state,
                    cache_entry_id,
                    BlobReadSource::LocalCache,
                    blob.size_bytes,
                    started_at.elapsed().as_millis() as u64,
                );
                return Ok(cache_handle);
            }
            let retry_key = format!("dlretry:{}", blob.digest);
            match begin_lookup_flight(state, retry_key.clone()) {
                LookupFlight::Leader(_retry_guard) => {
                    if let Some(cache_handle) = state.blob_read_cache.get_handle(&blob.digest).await
                    {
                        emit_blob_read_metric(
                            state,
                            cache_entry_id,
                            BlobReadSource::LocalCache,
                            blob.size_bytes,
                            started_at.elapsed().as_millis() as u64,
                        );
                        return Ok(cache_handle);
                    }
                    let (cache_handle, source) =
                        do_download_blob_to_cache(state, cache_entry_id, blob, cached_url).await?;
                    emit_blob_read_metric(
                        state,
                        cache_entry_id,
                        source,
                        blob.size_bytes,
                        started_at.elapsed().as_millis() as u64,
                    );
                    Ok(cache_handle)
                }
                LookupFlight::Follower(retry_notified) => {
                    if !await_flight("dlretry", &retry_key, retry_notified).await {
                        clear_lookup_flight_entry(state, &retry_key);
                    }
                    let cache_handle = state
                        .blob_read_cache
                        .get_handle(&blob.digest)
                        .await
                        .ok_or_else(|| {
                            RegistryError::internal(format!(
                                "Blob download failed after retry: {}",
                                short_digest(&blob.digest)
                            ))
                        })?;
                    emit_blob_read_metric(
                        state,
                        cache_entry_id,
                        BlobReadSource::LocalCache,
                        blob.size_bytes,
                        started_at.elapsed().as_millis() as u64,
                    );
                    Ok(cache_handle)
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
                    super::super::cache_ops::Op::Query,
                    super::super::cache_ops::OpResult::Hit,
                    false,
                    size,
                    elapsed_ms,
                );
            } else {
                state.cache_ops.record(
                    tool,
                    super::super::cache_ops::Op::Query,
                    super::super::cache_ops::OpResult::Miss,
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

pub(crate) async fn resolve_kv_entries_inner(
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

pub(crate) async fn fetch_pointer(
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

pub(crate) fn is_invalid_file_pointer_error(error: &RegistryError) -> bool {
    error.message().contains("Invalid file CAS pointer")
}

pub(crate) fn build_index_pointer(
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

pub(crate) fn pointer_blob_order(
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

pub(crate) fn merge_blob_order(
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

pub(crate) fn spawn_preload_blobs(state: &AppState, cache_entry_id: &str) {
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

pub(crate) async fn preload_download_urls_for_blobs(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
) -> DownloadUrlPreloadStats {
    if blobs.is_empty() {
        return DownloadUrlPreloadStats::default();
    }

    let requested = blobs.len();
    let batch_size = requested as u64;
    emit_serve_event(
        Some(&state.workspace),
        SERVE_PRELOAD_INDEX_OPERATION,
        SERVE_PRELOAD_INDEX_PATH,
        format!("resolve_download_urls:start batch_size={batch_size}"),
    );
    let started_at = std::time::Instant::now();

    match state
        .api_client
        .blob_download_urls_verified(&state.workspace, cache_entry_id, blobs)
        .await
    {
        Ok(response) => {
            let urls: HashMap<String, String> = response
                .download_urls
                .into_iter()
                .map(|u| (u.digest, u.url))
                .collect();
            let url_count = urls.len();
            let missing_count = response.missing.len();
            let mut published = state.kv_published_index.write().await;
            published.merge_download_urls(urls);
            eprintln!(
                "KV index preload: resolved {url_count}/{requested} download URLs (missing={missing_count})"
            );
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
                format!("resolve_download_urls:done resolved={url_count} missing={missing_count}"),
            );
            DownloadUrlPreloadStats {
                requested,
                resolved: url_count,
                missing: missing_count,
            }
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
            DownloadUrlPreloadStats {
                requested,
                resolved: 0,
                missing: requested,
            }
        }
    }
}

pub(crate) async fn preload_download_urls(state: &AppState, cache_entry_id: &str) {
    let blobs = {
        let published = state.kv_published_index.read().await;
        published.unique_blobs()
    };
    let _ = preload_download_urls_for_blobs(state, cache_entry_id, &blobs).await;
}

pub(crate) fn kv_startup_prefetch_max_blobs(tuning_profile: CacheRegistryTuningProfile) -> usize {
    let _ = tuning_profile;
    parse_positive_usize_env(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV).unwrap_or(usize::MAX)
}

pub(crate) fn kv_startup_prefetch_max_total_bytes(
    cache_max: u64,
    tuning_profile: CacheRegistryTuningProfile,
) -> u64 {
    let _ = tuning_profile;
    parse_positive_u64_env(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV).unwrap_or(cache_max)
}

pub(crate) fn kv_blob_prefetch_max_inflight_bytes(
    cache_max: u64,
    tuning_profile: CacheRegistryTuningProfile,
) -> u64 {
    if let Some(configured) = parse_positive_u64_env(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV) {
        return configured;
    }
    match tuning_profile {
        CacheRegistryTuningProfile::Generic => cache_max
            .saturating_div(4)
            .clamp(64 * 1024 * 1024, 512 * 1024 * 1024),
        CacheRegistryTuningProfile::Bazel => cache_max
            .saturating_div(3)
            .clamp(128 * 1024 * 1024, 1024 * 1024 * 1024),
        CacheRegistryTuningProfile::Sccache => cache_max
            .saturating_div(2)
            .clamp(256 * 1024 * 1024, 2 * 1024 * 1024 * 1024),
    }
}

pub(crate) fn bazel_startup_blob_class(
    scoped_key: &str,
    blob: &BlobDescriptor,
) -> BazelStartupBlobClass {
    if scoped_key.starts_with("bazel_ac/") {
        BazelStartupBlobClass::ActionCache
    } else if scoped_key.starts_with("bazel_cas/")
        && blob.size_bytes > 0
        && blob.size_bytes <= KV_BAZEL_STARTUP_PREFETCH_SMALL_CAS_MAX_BLOB_BYTES
    {
        BazelStartupBlobClass::SmallCas
    } else {
        BazelStartupBlobClass::Other
    }
}

pub(crate) fn bazel_startup_prefetch_candidates(
    entries: &HashMap<String, BlobDescriptor>,
    blob_order: &[BlobDescriptor],
) -> StartupPrefetchCandidates {
    let mut class_by_digest: HashMap<&str, BazelStartupBlobClass> =
        HashMap::with_capacity(entries.len());
    for (scoped_key, blob) in entries {
        let candidate = bazel_startup_blob_class(scoped_key, blob);
        match class_by_digest.get_mut(blob.digest.as_str()) {
            Some(existing) if matches!(candidate, BazelStartupBlobClass::ActionCache) => {
                *existing = candidate;
            }
            Some(existing)
                if matches!(candidate, BazelStartupBlobClass::SmallCas)
                    && matches!(existing, BazelStartupBlobClass::Other) =>
            {
                *existing = candidate;
            }
            Some(_) => {}
            None => {
                class_by_digest.insert(blob.digest.as_str(), candidate);
            }
        }
    }

    let mut action_cache_blobs = Vec::new();
    let mut small_cas_blobs = Vec::new();
    let mut other_blobs = Vec::new();
    for blob in blob_order {
        match class_by_digest
            .get(blob.digest.as_str())
            .copied()
            .unwrap_or(BazelStartupBlobClass::Other)
        {
            BazelStartupBlobClass::ActionCache => action_cache_blobs.push(blob.clone()),
            BazelStartupBlobClass::SmallCas => small_cas_blobs.push(blob.clone()),
            BazelStartupBlobClass::Other => other_blobs.push(blob.clone()),
        }
    }

    let mut ordered_blobs =
        Vec::with_capacity(action_cache_blobs.len() + small_cas_blobs.len() + other_blobs.len());
    ordered_blobs.extend(action_cache_blobs.iter().cloned());
    ordered_blobs.extend(small_cas_blobs.iter().cloned());
    ordered_blobs.extend(other_blobs.iter().cloned());

    StartupPrefetchCandidates {
        ordered_blobs,
        bazel_action_cache_blobs: action_cache_blobs.len(),
        bazel_small_cas_blobs: small_cas_blobs.len(),
        bazel_other_blobs: other_blobs.len(),
    }
}

pub(crate) fn startup_prefetch_candidates(
    entries: &HashMap<String, BlobDescriptor>,
    blob_order: &[BlobDescriptor],
    tuning_profile: CacheRegistryTuningProfile,
) -> StartupPrefetchCandidates {
    match tuning_profile {
        CacheRegistryTuningProfile::Generic | CacheRegistryTuningProfile::Sccache => {
            StartupPrefetchCandidates {
                ordered_blobs: blob_order.to_vec(),
                bazel_action_cache_blobs: 0,
                bazel_small_cas_blobs: 0,
                bazel_other_blobs: blob_order.len(),
            }
        }
        CacheRegistryTuningProfile::Bazel => bazel_startup_prefetch_candidates(entries, blob_order),
    }
}

pub(crate) fn should_skip_blob_preload(used_bytes: u64, max_bytes: u64) -> bool {
    if max_bytes == 0 {
        return true;
    }
    used_bytes.saturating_mul(100) >= max_bytes.saturating_mul(KV_BLOB_PRELOAD_SKIP_USED_PCT)
}

pub(crate) fn select_startup_prefetch_slice(
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
            continue;
        }
        remaining_bytes = remaining_bytes.saturating_sub(blob.size_bytes);
        selected.push(blob.clone());
    }

    selected
}

pub(crate) fn startup_prefetch_blobs(
    ordered_blobs: &[BlobDescriptor],
    max_blobs: usize,
    max_total_bytes: u64,
    whole_tag_hydration: bool,
) -> Vec<BlobDescriptor> {
    if whole_tag_hydration {
        return ordered_blobs.to_vec();
    }

    select_startup_prefetch_slice(ordered_blobs, max_blobs, max_total_bytes)
}

pub(crate) fn startup_download_url_preload_blobs<'a>(
    unique_blobs: &'a [BlobDescriptor],
    startup_blobs: &'a [BlobDescriptor],
    tuning_profile: CacheRegistryTuningProfile,
) -> &'a [BlobDescriptor] {
    match tuning_profile {
        CacheRegistryTuningProfile::Bazel => unique_blobs,
        CacheRegistryTuningProfile::Generic | CacheRegistryTuningProfile::Sccache => startup_blobs,
    }
}

pub(crate) fn should_preload_remaining_download_urls(
    tuning_profile: CacheRegistryTuningProfile,
) -> bool {
    !matches!(tuning_profile, CacheRegistryTuningProfile::Bazel)
}

pub(crate) fn select_blob_preload_candidates<F>(
    ordered_blobs: &[BlobDescriptor],
    preload_budget: u64,
    mut download_url_for_digest: F,
) -> Vec<(BlobDescriptor, String)>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut remaining_budget = preload_budget;
    let mut candidates = Vec::new();

    for blob in ordered_blobs {
        if blob.size_bytes == 0 || blob.size_bytes > remaining_budget {
            continue;
        }
        if let Some(url) = download_url_for_digest(&blob.digest) {
            candidates.push((blob.clone(), url));
            remaining_budget = remaining_budget.saturating_sub(blob.size_bytes);
            if remaining_budget == 0 {
                break;
            }
        }
    }

    candidates
}

pub(crate) fn build_startup_prefetch_targets<F>(
    startup_blobs: &[BlobDescriptor],
    mut cached_url_for_digest: F,
) -> (Vec<StartupPrefetchTarget>, StartupPrefetchTargetSummary)
where
    F: FnMut(&str) -> Option<String>,
{
    let mut targets = Vec::with_capacity(startup_blobs.len());
    let mut cached_url_count = 0usize;

    for blob in startup_blobs {
        let cached_url = cached_url_for_digest(blob.digest.as_str());
        if cached_url.is_some() {
            cached_url_count = cached_url_count.saturating_add(1);
        }
        targets.push(StartupPrefetchTarget {
            blob: blob.clone(),
            cached_url,
        });
    }

    (
        targets,
        StartupPrefetchTargetSummary {
            cached_url_count,
            unresolved_url_count: startup_blobs.len().saturating_sub(cached_url_count),
        },
    )
}

pub(crate) async fn preload_single_blob(
    state: AppState,
    cache_entry_id: String,
    blob: BlobDescriptor,
    cached_url: Option<String>,
) -> anyhow::Result<bool> {
    if state
        .blob_read_cache
        .get_handle(&blob.digest)
        .await
        .is_some()
    {
        return Ok(false);
    }

    let mut retry_delay = std::time::Duration::from_millis(250);
    for attempt in 1..=4 {
        match download_blob_to_cache(&state, &cache_entry_id, &blob, cached_url.as_deref()).await {
            Ok(_) => return Ok(true),
            Err(error)
                if attempt < 4
                    && matches!(
                        error.status,
                        StatusCode::NOT_FOUND | StatusCode::SERVICE_UNAVAILABLE
                    ) =>
            {
                log::debug!(
                    "Prefetch startup blob retry {attempt}/4 digest={} status={} after {:?}",
                    short_digest(&blob.digest),
                    error.status,
                    retry_delay,
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = retry_delay.saturating_mul(2);
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "download_blob_to_cache failed for {}: {:?}",
                    blob.digest,
                    error
                ));
            }
        }
    }

    Err(anyhow::anyhow!(
        "download_blob_to_cache exhausted retries for {}",
        blob.digest
    ))
}

pub(crate) async fn preload_blobs(state: &AppState, cache_entry_id: &str) {
    let cache_used = state.blob_read_cache.total_bytes();
    let cache_max = state.blob_read_cache.max_bytes();
    if should_skip_blob_preload(cache_used, cache_max) {
        eprintln!(
            "KV blob preload: skipped, cache near capacity used={} max={}",
            cache_used, cache_max
        );
        return;
    }
    let inflight_budget_cap = kv_blob_prefetch_max_inflight_bytes(cache_max, state.tuning_profile);
    let preload_budget = cache_max
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
        let entries = published.entries_snapshot();
        let blob_order = startup_prefetch_candidates(
            entries.as_ref(),
            &published.unique_blobs(),
            state.tuning_profile,
        )
        .ordered_blobs;
        select_blob_preload_candidates(&blob_order, preload_budget, |digest| {
            published.download_url(digest).map(str::to_string)
        })
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
            "start: scheduled={scheduled} scheduled_bytes={scheduled_bytes} inflight_budget_cap={inflight_budget_cap}"
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
            let result = preload_single_blob(state, cache_entry_id, blob, Some(url)).await;
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
    state.prefetch_metrics.reset_startup();

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
            let cache_used = state.blob_read_cache.total_bytes();
            let cache_max = state.blob_read_cache.max_bytes();
            let startup_max_blobs = kv_startup_prefetch_max_blobs(state.tuning_profile);
            let startup_max_total_bytes =
                kv_startup_prefetch_max_total_bytes(cache_max, state.tuning_profile)
                    .min(cache_max.saturating_sub(cache_used));
            let (unique_blobs, entry_map) = {
                let published = state.kv_published_index.read().await;
                (published.unique_blobs(), published.entries_snapshot())
            };
            let startup_candidates = startup_prefetch_candidates(
                entry_map.as_ref(),
                &unique_blobs,
                state.tuning_profile,
            );
            let total_unique_blobs = unique_blobs.len();
            let total_unique_bytes: u64 =
                unique_blobs.iter().map(|blob| blob.size_bytes).sum::<u64>();
            let whole_tag_hydration = total_unique_blobs <= startup_max_blobs
                && total_unique_bytes <= startup_max_total_bytes;
            let startup_blobs = startup_prefetch_blobs(
                &startup_candidates.ordered_blobs,
                startup_max_blobs,
                startup_max_total_bytes,
                whole_tag_hydration,
            );
            let startup_url_preload_blobs = startup_download_url_preload_blobs(
                &unique_blobs,
                &startup_blobs,
                state.tuning_profile,
            );
            let startup_target_bytes: u64 = startup_blobs
                .iter()
                .map(|blob| blob.size_bytes)
                .sum::<u64>();
            state.prefetch_metrics.record_startup_plan(
                if whole_tag_hydration {
                    "whole_tag"
                } else {
                    "startup_slice"
                },
                total_unique_blobs,
                startup_blobs.len(),
                startup_target_bytes,
            );

            if whole_tag_hydration {
                eprintln!(
                    "Prefetch: {count} entries loaded, hydrating whole tag locally ({} blobs, {:.1} MB)",
                    total_unique_blobs,
                    total_unique_bytes as f64 / (1024.0 * 1024.0),
                );
            } else if state.tuning_profile == CacheRegistryTuningProfile::Bazel {
                eprintln!(
                    "Prefetch: {count} entries loaded, Bazel startup slice prioritizes AC={} small_cas={} deferred={} under {:.1} MB budget and resolves {}/{} download URLs before serving...",
                    startup_candidates.bazel_action_cache_blobs,
                    startup_candidates.bazel_small_cas_blobs,
                    startup_candidates.bazel_other_blobs,
                    startup_max_total_bytes as f64 / (1024.0 * 1024.0),
                    startup_url_preload_blobs.len(),
                    total_unique_blobs,
                );
            } else {
                eprintln!(
                    "Prefetch: {count} entries loaded, resolving startup download URLs for {}/{} blobs under {:.1} MB budget...",
                    startup_blobs.len(),
                    total_unique_blobs,
                    startup_max_total_bytes as f64 / (1024.0 * 1024.0),
                );
            }

            let startup_url_stats =
                preload_download_urls_for_blobs(state, &cache_entry_id, startup_url_preload_blobs)
                    .await;
            eprintln!(
                "Prefetch: startup URL coverage resolved={}/{} missing={}",
                startup_url_stats.resolved, startup_url_stats.requested, startup_url_stats.missing,
            );
            state
                .prefetch_metrics
                .record_startup_url_coverage(startup_url_stats.resolved, startup_url_stats.missing);

            eprintln!("Prefetch: warming startup slice...");
            match tokio::time::timeout(
                KV_PREFETCH_READINESS_TIMEOUT,
                prefetch_all_blobs(
                    state,
                    &cache_entry_id,
                    total_unique_blobs,
                    startup_max_total_bytes,
                    &startup_blobs,
                ),
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

            let remaining_blobs = if startup_blobs.len() >= unique_blobs.len() {
                Vec::new()
            } else {
                let startup_digests: HashSet<String> = startup_blobs
                    .iter()
                    .map(|blob| blob.digest.clone())
                    .collect();
                unique_blobs
                    .into_iter()
                    .filter(|blob| !startup_digests.contains(&blob.digest))
                    .collect::<Vec<_>>()
            };
            let preload_remaining_download_urls =
                should_preload_remaining_download_urls(state.tuning_profile);
            let background_state = state.clone();
            let background_cache_entry_id = cache_entry_id.clone();
            tokio::spawn(async move {
                if preload_remaining_download_urls && !remaining_blobs.is_empty() {
                    let _ = preload_download_urls_for_blobs(
                        &background_state,
                        &background_cache_entry_id,
                        &remaining_blobs,
                    )
                    .await;
                }
                preload_blobs(&background_state, &background_cache_entry_id).await;
            });
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

pub(crate) async fn prefetch_all_blobs(
    state: &AppState,
    cache_entry_id: &str,
    total_unique_blobs: usize,
    startup_max_total_bytes: u64,
    startup_blobs: &[BlobDescriptor],
) {
    let cache_used = state.blob_read_cache.total_bytes();
    let cache_max = state.blob_read_cache.max_bytes();
    if should_skip_blob_preload(cache_used, cache_max) {
        eprintln!(
            "Prefetch: startup slice skipped, cache near capacity used={} max={}",
            cache_used, cache_max
        );
        return;
    }

    let startup_budget = startup_max_total_bytes.min(cache_max.saturating_sub(cache_used));
    if startup_budget == 0 {
        eprintln!("Prefetch: startup slice skipped, budget is zero");
        return;
    }

    let (startup_targets, startup_summary) = {
        let published = state.kv_published_index.read().await;
        build_startup_prefetch_targets(startup_blobs, |digest| {
            published.download_url(digest).map(str::to_string)
        })
    };

    if startup_targets.is_empty() {
        eprintln!(
            "Prefetch: startup slice selected 0/{total_unique_blobs} blobs under budget={} bytes",
            startup_budget
        );
        return;
    }

    let mut targets = Vec::new();
    let mut already_local = 0usize;
    for target in startup_targets {
        if state
            .blob_read_cache
            .get_handle(&target.blob.digest)
            .await
            .is_none()
        {
            targets.push(target);
        } else {
            already_local = already_local.saturating_add(1);
        }
    }

    if targets.is_empty() {
        eprintln!(
            "Prefetch: startup slice already warm under budget={} bytes (cached_urls={} unresolved_urls={} already_local={})",
            startup_max_total_bytes,
            startup_summary.cached_url_count,
            startup_summary.unresolved_url_count,
            already_local,
        );
        return;
    }

    let scheduled = targets.len();
    let scheduled_bytes: u64 = targets.iter().map(|target| target.blob.size_bytes).sum();
    eprintln!(
        "Prefetch: warming startup slice {scheduled}/{total_unique_blobs} blobs ({:.1} MB, cached_urls={}, unresolved_urls={}, already_local={})",
        scheduled_bytes as f64 / (1024.0 * 1024.0),
        startup_summary.cached_url_count,
        startup_summary.unresolved_url_count,
        already_local,
    );

    let prefetch_started_at = std::time::Instant::now();
    let prefetch_semaphore = state.blob_prefetch_semaphore.clone();
    let mut tasks = tokio::task::JoinSet::new();
    for target in targets {
        let state = state.clone();
        let cache_entry_id = cache_entry_id.to_string();
        let prefetch_semaphore = prefetch_semaphore.clone();
        tasks.spawn(async move {
            let _permit = prefetch_semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow::anyhow!("prefetch semaphore closed: {error}"))?;
            let result =
                preload_single_blob(state, cache_entry_id, target.blob, target.cached_url).await;
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
    let duration_ms = prefetch_started_at.elapsed().as_millis() as u64;
    state
        .prefetch_metrics
        .record_startup_execution(already_local, inserted, failures, duration_ms);
    emit_serve_phase_metric(
        Some(&state.workspace),
        Some(cache_entry_id),
        SERVE_PREFETCH_OPERATION,
        SERVE_PREFETCH_PATH,
        status,
        duration_ms,
        Some(scheduled as u64),
    );

    eprintln!(
        "Prefetch: startup slice done inserted={inserted} scheduled={scheduled} failures={failures} cache_size={} bytes in {:.1}s",
        state.blob_read_cache.total_bytes(),
        prefetch_started_at.elapsed().as_secs_f64(),
    );
}

pub(crate) async fn load_existing_index(
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

pub(crate) async fn load_existing_index_with_fallback(
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

pub(crate) async fn resolve_hit_for_index_load(
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
