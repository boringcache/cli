use super::*;

pub(crate) enum FlushResult {
    Ok,
    Conflict,
    Error,
    Permanent,
    Deferred,
}

#[derive(Debug)]
pub(crate) enum FlushError {
    Conflict(String),
    Transient(String),
    Permanent(String),
}

pub(crate) enum KvConfirmOutcome {
    Published,
    Pending(PendingMetadata),
}

pub(crate) fn kv_confirm_pending_metadata(outcome: &KvConfirmOutcome) -> Option<&PendingMetadata> {
    match outcome {
        KvConfirmOutcome::Published => None,
        KvConfirmOutcome::Pending(metadata) => Some(metadata),
    }
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

pub(crate) async fn confirm_kv_flush(
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
            let should_defer_to_restart_handoff = flush_mode == FlushMode::Shutdown
                || state.shutdown_requested.load(Ordering::Acquire);
            if should_defer_to_restart_handoff {
                let blob_order = pending_entries.values().cloned().collect::<Vec<_>>();
                persist_kv_pending_publish_handoff(
                    state,
                    &pending_entries,
                    &blob_order,
                    "",
                    PendingPublishHandoffPersist {
                        root_pending: None,
                        pending_alias_tags: false,
                        pending_blob_paths: Some(&pending_blob_paths),
                        pending_blob_sequences: Some(&pending_blob_sequences),
                    },
                )
                .await;
                eprintln!(
                    "KV batch flush: deferred pending upload handoff with {entry_count} entries ({} blobs)",
                    pending_blob_paths.len()
                );
                FlushResult::Deferred
            } else {
                let mut pending = state.kv_pending.write().await;
                let paths_to_cleanup =
                    pending.restore(pending_entries, pending_blob_paths, pending_blob_sequences);
                drop(pending);
                cleanup_paths(paths_to_cleanup).await;
                let (base_ms, jitter_ms) = transient_backoff_window(&msg);
                set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
                FlushResult::Error
            }
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

pub(crate) async fn refresh_kv_index(state: &AppState) {
    if state.kv_flush_scheduled.load(Ordering::Acquire) {
        return;
    }
    if state.kv_flushing.read().await.is_some() {
        return;
    }

    let tag = state.registry_root_tag.trim().to_string();
    let hit = match resolve_hit_for_index_load(state, &tag, true).await {
        Ok(hit) => hit,
        Err(error) if error.status == StatusCode::NOT_FOUND => {
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
        }
        Err(error) => {
            log::warn!("KV index refresh failed during resolve: {error:?}");
            return;
        }
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

    let tag = state.registry_root_tag.trim().to_string();
    let hit = match resolve_hit_for_index_load(state, &tag, true).await {
        Ok(hit) => hit,
        Err(error) if error.status == StatusCode::NOT_FOUND => return,
        Err(error) => {
            log::warn!("KV version-triggered refresh failed during resolve: {error:?}");
            return;
        }
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

pub(crate) async fn refresh_fence_allows_update(
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

pub(crate) async fn do_flush(
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
            PendingPublishHandoffPersist {
                root_pending: kv_confirm_pending_metadata(&confirm_outcome),
                pending_alias_tags: pending_alias_count > 0,
                pending_blob_paths: None,
                pending_blob_sequences: None,
            },
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
        PendingPublishHandoffPersist {
            root_pending: kv_confirm_pending_metadata(&confirm_outcome),
            pending_alias_tags: pending_alias_count > 0,
            pending_blob_paths: None,
            pending_blob_sequences: None,
        },
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

pub(crate) fn filter_pending_entries_with_local_blobs(
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
pub(crate) async fn bind_kv_alias_tag(
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

pub(crate) async fn bind_kv_alias_tags(
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
