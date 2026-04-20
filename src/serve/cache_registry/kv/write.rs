use super::*;

pub(crate) async fn put_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    body: Body,
    put_status: StatusCode,
) -> Result<Response, RegistryError> {
    put_kv_object_with_integrity(state, namespace, key, body, put_status, None).await
}

pub(crate) async fn put_kv_object_with_integrity(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    body: Body,
    put_status: StatusCode,
    integrity: Option<KvBlobIntegrity>,
) -> Result<Response, RegistryError> {
    let put_start = std::time::Instant::now();
    let scoped_key = namespace.scoped_key(key);
    if state.read_only {
        state.cache_ops.record(
            namespace.into(),
            super::super::cache_ops::Op::Put,
            super::super::cache_ops::OpResult::Hit,
            false,
            0,
            put_start.elapsed().as_millis() as u64,
        );
        log::debug!("KV PUT {scoped_key}: ignored in read-only mode");
        return Ok((put_status, Body::empty()).into_response());
    }

    let use_miss_cache = use_kv_miss_cache(namespace);
    let put_probe = super::super::PutProbeGuard::start(&scoped_key);
    put_probe.stage("precheck_spool");
    let spool_limit = crate::serve::state::max_spool_bytes();
    {
        let pending = state.kv_pending.read().await;
        if pending.total_spool_bytes() >= spool_limit {
            state.kv_backlog_rejects.fetch_add(1, Ordering::AcqRel);
            state.cache_ops.record(
                namespace.into(),
                super::super::cache_ops::Op::Put,
                super::super::cache_ops::OpResult::Error,
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

    if let Some(policy) = integrity
        && let Err(error) = policy.validate_put_digest(key, &blob_digest)
    {
        cleanup_temp_file(&path).await;
        return Err(error);
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
                super::super::cache_ops::Op::Put,
                super::super::cache_ops::OpResult::Error,
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
        super::super::cache_ops::Op::Put,
        super::super::cache_ops::OpResult::Hit,
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

pub(crate) fn try_enqueue_replication_work(
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

pub(crate) async fn resolve_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
) -> Result<String, RegistryError> {
    let download_url = match crate::serve::blob_download_urls::resolve_verified_blob_download_url(
        state,
        cache_entry_id,
        blob,
        KV_BLOB_URL_RESOLVE_TIMEOUT,
    )
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

    if let Some(url) = download_url {
        return Ok(url);
    }

    Err(RegistryError::not_found(
        "Cache object is missing blob data",
    ))
}

pub(crate) async fn serve_backend_blob(
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

pub(crate) fn is_recent_kv_miss(state: &AppState, scoped_key: &str) -> bool {
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

pub(crate) fn mark_kv_miss(state: &AppState, scoped_key: &str) {
    state.kv_recent_misses.insert(
        scoped_key.to_string(),
        std::time::Instant::now() + KV_MISS_CACHE_TTL,
    );
}

pub(crate) fn clear_kv_miss(state: &AppState, scoped_key: &str) {
    state.kv_recent_misses.remove(scoped_key);
}

pub(crate) fn clear_tag_misses(state: &AppState, registry_root_tag: &str) {
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

pub(crate) fn kv_visibility_tags_from_values(
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

pub(crate) fn kv_visibility_tags(state: &AppState) -> Vec<String> {
    kv_visibility_tags_from_values(&state.registry_root_tag, &state.configured_human_tags)
}

pub(crate) fn kv_alias_tags_from_values(
    registry_root_tag: &str,
    configured_human_tags: &[String],
) -> Vec<String> {
    kv_visibility_tags_from_values(registry_root_tag, configured_human_tags)
        .into_iter()
        .skip(1)
        .collect()
}

pub(crate) fn kv_alias_tags(state: &AppState) -> Vec<String> {
    kv_alias_tags_from_values(&state.registry_root_tag, &state.configured_human_tags)
}

pub(crate) fn kv_primary_write_scope_tag(state: &AppState) -> Option<String> {
    state
        .configured_human_tags
        .first()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
}

pub(crate) async fn kv_publish_tags_visible(
    state: &AppState,
    expected_cache_entry_id: &str,
) -> bool {
    for tag in kv_visibility_tags(state) {
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
                    "KV tag visibility poll failed for {} tag={}: {}",
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

pub(crate) async fn cleanup_temp_file(path: &PathBuf) {
    let _ = tokio::fs::remove_file(path).await;
}

pub(crate) async fn write_body_to_temp_file(
    state: &AppState,
    body: Body,
    put_probe: &super::super::PutProbeGuard,
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
