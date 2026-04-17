use super::*;

pub(crate) enum FlushResult {
    Ok,
    Conflict,
    Error,
    Permanent,
}

#[derive(Debug)]
pub(crate) enum FlushError {
    Conflict(String),
    Transient(String),
    Permanent(String),
}

pub(crate) enum KvConfirmOutcome {
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlushMode {
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

pub(crate) fn classify_flush_error(error: &anyhow::Error, context: &str) -> FlushError {
    let message = format!("{context}: {error}");
    let lower = message.to_ascii_lowercase();

    if let Some(bc_error) = error.downcast_ref::<BoringCacheError>() {
        match bc_error {
            BoringCacheError::CacheConflict { .. } => {
                return FlushError::Conflict(message);
            }
            BoringCacheError::CachePending => {
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

pub(crate) async fn confirm_kv_flush(
    state: &AppState,
    cache_entry_id: &str,
    confirm_request: &ConfirmRequest,
    _flush_mode: FlushMode,
) -> Result<KvConfirmOutcome, FlushError> {
    let started_at = std::time::Instant::now();
    let mut attempt = 0u32;

    loop {
        let result: Result<KvConfirmOutcome, anyhow::Error> = state
            .api_client
            .confirm_with_retry(&state.workspace, cache_entry_id, confirm_request)
            .await
            .map(|_| KvConfirmOutcome::Published);

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

pub(crate) fn confirm_retry_reason(message: &str, classified: &FlushError) -> Option<&'static str> {
    if is_blob_verification_pending_message(message) {
        return Some("blob verification pending");
    }

    if matches!(classified, FlushError::Transient(_)) {
        return Some("transient backend error");
    }

    None
}

pub(crate) fn has_status_code(lower: &str, code: u16) -> bool {
    let code = code.to_string();
    lower.contains(&format!("http {code}"))
        || lower.contains(&format!("status {code}"))
        || lower.contains(&format!("({code})"))
}

pub(crate) async fn set_next_flush_at_with_jitter(state: &AppState, base_ms: u64, jitter_ms: u64) {
    let jitter = if jitter_ms == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..jitter_ms)
    };
    let backoff = std::time::Duration::from_millis(base_ms + jitter);
    let mut next = state.kv_next_flush_at.write().await;
    *next = Some(std::time::Instant::now() + backoff);
}

pub(crate) async fn cleanup_blob_files(paths: &HashMap<String, PathBuf>) {
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

pub(crate) async fn cleanup_paths(paths: Vec<PathBuf>) {
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

pub(crate) async fn promote_pending_blobs_to_read_cache(
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

pub(crate) async fn flush_kv_index_with_mode(
    state: &AppState,
    flush_mode: FlushMode,
) -> FlushResult {
    let guard = state.kv_flush_lock.lock().await;

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

    let result = match do_flush(state, &pending_entries, &pending_blob_paths, flush_mode).await {
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
            clear_tag_misses(state, &state.registry_root_tag);

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
            FlushResult::Ok
        }
        Err(FlushError::Conflict(msg)) => {
            eprintln!("KV batch flush: skipped — tag conflict ({msg})");
            let mut pending = state.kv_pending.write().await;
            let paths_to_cleanup = pending.restore(pending_entries, pending_blob_paths);
            drop(pending);
            cleanup_paths(paths_to_cleanup).await;
            let (base_ms, jitter_ms) = conflict_backoff_window(&msg);
            set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
            FlushResult::Conflict
        }
        Err(FlushError::Transient(msg)) => {
            eprintln!("KV batch flush failed: {msg}");
            let mut pending = state.kv_pending.write().await;
            let paths_to_cleanup = pending.restore(pending_entries, pending_blob_paths);
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

pub(crate) fn should_clear_flushing_after_flush(result: &FlushResult) -> bool {
    !matches!(result, FlushResult::Ok)
}

pub(crate) async fn do_flush(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
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
        match load_existing_index_snapshot(state, false).await {
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
        missing_pending_digests,
        missing_pending_entries,
    ) = filter_pending_entries_with_local_blobs(pending_entries, pending_blob_paths);
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
    let merged_blob_order = merge_blob_order(&entries, &base_blob_order);
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
                    if let Some(partial_stats) = partial_blob_upload_stats(&error) {
                        if let Err(commit_error) = try_commit_blob_receipts(
                            &state.api_client,
                            &state.workspace,
                            save_response.upload_session_id.as_deref(),
                            partial_stats.uploaded_receipts.clone(),
                        )
                        .await
                        {
                            log::warn!(
                                "KV flush: exists=true partial blob receipt commit failed: {commit_error:#}"
                            );
                        }
                        if partial_stats.uploaded_count > 0 || partial_stats.missing_local_count > 0
                        {
                            eprintln!(
                                "KV flush: exists=true preserved partial blob uploads uploaded={} already_present={} missing_local={}",
                                partial_stats.uploaded_count,
                                partial_stats.already_present_count,
                                partial_stats.missing_local_count
                            );
                        }
                    }
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
        confirm_kv_flush(state, &confirm_cache_entry_id, &confirm_request, flush_mode).await?;
        let alias_count = bind_kv_alias_tags(
            state,
            &manifest_root_digest,
            expected_manifest_size,
            blob_count,
            blob_total_size_bytes,
            file_count,
            flush_mode,
        )
        .await?;
        eprintln!(
            "KV flush root publish: tag={} cache_entry_id={} state=published alias_tags={}",
            tag, save_response.cache_entry_id, alias_count
        );
        if alias_count > 0 {
            eprintln!(
                "KV alias publish completed: cache_entry_id={} alias_tags={}",
                save_response.cache_entry_id, alias_count
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
    let all_blob_digests: Vec<String> = blobs.iter().map(|b| b.digest.clone()).collect();
    crate::serve::cas_publish::publish_after_save(
        &state.api_client,
        &state.workspace,
        &save_response,
        manifest_root_digest.clone(),
        expected_manifest_size,
        Some(all_blob_digests),
        |save_response| {
            let cache_entry_id = save_response.cache_entry_id.clone();
            let upload_session_id = save_response.upload_session_id.clone();
            async move {
                let upload_stats = if !blobs.is_empty() {
                    match upload_blobs(state, &cache_entry_id, &blobs, &filtered_pending_blob_paths)
                        .await
                    {
                        Ok(upload_stats) => upload_stats,
                        Err(error) => {
                            if let Some(partial_stats) = partial_blob_upload_stats(&error) {
                                if let Err(commit_error) = try_commit_blob_receipts(
                                    &state.api_client,
                                    &state.workspace,
                                    upload_session_id.as_deref(),
                                    partial_stats.uploaded_receipts.clone(),
                                )
                                .await
                                {
                                    log::warn!(
                                        "KV flush: partial blob receipt commit failed: {commit_error:#}"
                                    );
                                }
                                if partial_stats.uploaded_count > 0
                                    || partial_stats.missing_local_count > 0
                                {
                                    eprintln!(
                                        "KV flush: preserved partial blob uploads uploaded={} already_present={} missing_local={}",
                                        partial_stats.uploaded_count,
                                        partial_stats.already_present_count,
                                        partial_stats.missing_local_count
                                    );
                                }
                                *publish_upload_stats.lock().unwrap() = partial_stats;
                            }
                            return Err(classify_flush_error(&error, "blob upload failed"));
                        }
                    }
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

    let alias_count = bind_kv_alias_tags(
        state,
        &manifest_root_digest,
        expected_manifest_size,
        blob_count,
        blob_total_size_bytes,
        file_count,
        flush_mode,
    )
    .await?;
    eprintln!(
        "KV flush root publish: tag={} cache_entry_id={} state=published alias_tags={}",
        tag, save_response.cache_entry_id, alias_count
    );

    if alias_count > 0 {
        eprintln!(
            "KV alias publish completed: cache_entry_id={} alias_tags={}",
            save_response.cache_entry_id, alias_count
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
    Vec<String>,
    usize,
);

pub(crate) fn filter_pending_entries_with_local_blobs(
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
) -> FilteredPendingEntries {
    let mut missing_digests = HashSet::new();
    let mut filtered_blob_paths = HashMap::new();

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
        missing_digests.into_iter().collect(),
        missing_entry_count,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn bind_kv_alias_tag(
    state: &AppState,
    alias_tag: &str,
    manifest_root_digest: &str,
    manifest_size: u64,
    blob_count: u64,
    blob_total_size_bytes: u64,
    file_count: u32,
    flush_mode: FlushMode,
) -> anyhow::Result<()> {
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

    confirm_kv_flush(
        state,
        &alias_save.cache_entry_id,
        &alias_confirm,
        flush_mode,
    )
    .await
    .map_err(|error| anyhow::anyhow!("alias confirm failed: {:?}", error))
    .map(|_| ())
}

pub(crate) async fn bind_kv_alias_tags(
    state: &AppState,
    manifest_root_digest: &str,
    manifest_size: u64,
    blob_count: u64,
    blob_total_size_bytes: u64,
    file_count: u32,
    flush_mode: FlushMode,
) -> Result<usize, FlushError> {
    let mut alias_count = 0usize;
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
            Ok(()) => {
                alias_count = alias_count.saturating_add(1);
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
    Ok(alias_count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlushBaseSelection {
    Backend,
    PublishedFallback {
        backend_entry_count: usize,
        published_entry_count: usize,
        missing_published_keys: usize,
        mismatched_published_keys: usize,
    },
}

pub(crate) fn select_flush_base_entries(
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
