use super::*;

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
    let (_resolved_cache_tag, entries, blob_order, cache_entry_id, _) =
        match load_existing_index_snapshot_with_tag(state).await {
            Ok(result) => {
                state.backend_breaker.record_success();
                result
            }
            Err(error) => {
                state.backend_breaker.record_failure();
                return Err(error);
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
            published.update(
                entries.into_iter().collect(),
                blob_order,
                cache_entry_id,
                true,
            );
        } else if published_entry_count > 0 {
            log::warn!(
                "KV lookup refresh: backend returned entries without cache_entry_id; preserving in-memory index"
            );
            published.touch_refresh();
        } else {
            published.set_empty();
        }
    }
    clear_restore_tag_misses(state);

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
    match begin_lookup_flight(state, flight_key.clone(), "kv-lookup") {
        LookupFlight::Follower(notified) => {
            if !await_flight(state, "kv-lookup", &flight_key, notified).await {
                state.singleflight_metrics.record_takeover("kv-lookup");
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

pub(crate) fn merge_blob_order(
    merged_entries: &BTreeMap<String, BlobDescriptor>,
    base_blob_order: &[BlobDescriptor],
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

    for (digest, size_bytes) in size_by_digest {
        if seen.insert(digest.clone()) {
            ordered.push(BlobDescriptor { digest, size_bytes });
        }
    }

    ordered
}

pub(crate) async fn load_existing_index(
    state: &AppState,
    tag: &str,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        Option<String>,
        Option<String>,
    ),
    RegistryError,
> {
    load_existing_index_with_stream(state, tag, KvIndexStream::Full).await
}

pub(crate) async fn load_existing_current_version_index(
    state: &AppState,
    tag: &str,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        Option<String>,
        Option<String>,
    ),
    RegistryError,
> {
    load_existing_index_with_stream(state, tag, KvIndexStream::CurrentVersion).await
}

#[derive(Clone, Copy)]
enum KvIndexStream {
    Full,
    CurrentVersion,
}

async fn load_existing_index_with_stream(
    state: &AppState,
    tag: &str,
    stream: KvIndexStream,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        Option<String>,
        Option<String>,
    ),
    RegistryError,
> {
    let mut map = BTreeMap::new();
    let mut blobs_by_digest = HashMap::new();
    let mut stream_position = 0usize;
    let mut cursor = None;

    loop {
        let page = match stream {
            KvIndexStream::Full => {
                state
                    .api_client
                    .stream_cache_kv_entries(&state.workspace, tag, cursor.as_deref(), 5_000)
                    .await
            }
            KvIndexStream::CurrentVersion => {
                state
                    .api_client
                    .stream_current_cache_kv_entries(
                        &state.workspace,
                        tag,
                        cursor.as_deref(),
                        5_000,
                    )
                    .await
            }
        }
        .map_err(|error| {
            RegistryError::internal(format!(
                "Failed to stream KV entries for tag {tag}: {error}"
            ))
        })?;

        for entry in page.entries {
            record_streamed_blob_for_startup(&mut blobs_by_digest, stream_position, &entry);
            stream_position = stream_position.saturating_add(1);
            map.insert(entry.scoped_key, entry.blob);
        }

        let Some(next_cursor) = page.next_cursor.filter(|value| !value.trim().is_empty()) else {
            break;
        };
        cursor = Some(next_cursor);
    }

    let blob_order = startup_blob_order(blobs_by_digest);
    if map.is_empty() {
        return Ok((map, blob_order, None, None));
    }

    Ok((map, blob_order, Some(kv_direct_cache_entry_id(tag)), None))
}

#[derive(Debug)]
struct StartupBlobRank {
    blob: BlobDescriptor,
    namespace_priority: u8,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    first_seen: usize,
}

fn record_streamed_blob_for_startup(
    blobs_by_digest: &mut HashMap<String, StartupBlobRank>,
    stream_position: usize,
    entry: &crate::api::models::cache::CacheKvEntryRecord,
) {
    let digest = entry.blob.digest.clone();
    let incoming = StartupBlobRank {
        blob: entry.blob.clone(),
        namespace_priority: startup_namespace_priority(&entry.namespace),
        last_used_at: entry_last_used_at(entry),
        first_seen: stream_position,
    };

    match blobs_by_digest.entry(digest) {
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(incoming);
        }
        std::collections::hash_map::Entry::Occupied(mut slot) => {
            if startup_blob_rank_precedes(&incoming, slot.get()) {
                slot.insert(incoming);
            }
        }
    }
}

fn startup_blob_order(blobs_by_digest: HashMap<String, StartupBlobRank>) -> Vec<BlobDescriptor> {
    let mut ranked = blobs_by_digest.into_values().collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        left.namespace_priority
            .cmp(&right.namespace_priority)
            .then_with(|| right.last_used_at.cmp(&left.last_used_at))
            .then_with(|| left.first_seen.cmp(&right.first_seen))
            .then_with(|| left.blob.digest.cmp(&right.blob.digest))
    });
    ranked.into_iter().map(|rank| rank.blob).collect()
}

fn startup_blob_rank_precedes(left: &StartupBlobRank, right: &StartupBlobRank) -> bool {
    left.namespace_priority < right.namespace_priority
        || (left.namespace_priority == right.namespace_priority
            && left.last_used_at > right.last_used_at)
        || (left.namespace_priority == right.namespace_priority
            && left.last_used_at == right.last_used_at
            && left.first_seen < right.first_seen)
}

fn startup_namespace_priority(namespace: &str) -> u8 {
    match namespace {
        "bazel_ac" | "turborepo_meta" => 0,
        _ => 1,
    }
}

fn entry_last_used_at(
    entry: &crate::api::models::cache::CacheKvEntryRecord,
) -> Option<chrono::DateTime<chrono::Utc>> {
    [entry.last_read_at, entry.last_written_at, entry.updated_at]
        .into_iter()
        .flatten()
        .max()
}

pub(crate) async fn load_existing_index_snapshot_with_tag(
    state: &AppState,
) -> Result<
    (
        String,
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        Option<String>,
        Option<String>,
    ),
    RegistryError,
> {
    let restore_tags = ordered_restore_cache_tags(state);

    let mut first_empty = None;
    for (index, tag) in restore_tags.iter().enumerate() {
        let is_last = index + 1 == restore_tags.len();
        let result = match load_existing_index(state, tag).await {
            Ok(result) => result,
            Err(error) if !is_last && should_try_next_restore_cache_tag_after_error(&error) => {
                log::warn!(
                    "KV index restore tag {tag} failed with a transient backend error; trying next restore tag: {error:?}"
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        if result.2.is_some() || !result.0.is_empty() {
            return Ok((tag.clone(), result.0, result.1, result.2, result.3));
        }
        if first_empty.is_none() {
            first_empty = Some((tag.clone(), result.0, result.1, result.2, result.3));
        }
    }

    Ok(first_empty.unwrap_or_else(|| {
        (
            state.primary_cache_tag.trim().to_string(),
            BTreeMap::new(),
            Vec::new(),
            None,
            None,
        )
    }))
}

fn ordered_restore_cache_tags(state: &AppState) -> Vec<String> {
    let mut tags = Vec::new();
    let mut seen = HashSet::new();

    for tag in std::iter::once(state.primary_cache_tag.as_str())
        .chain(state.restore_cache_tags.iter().map(String::as_str))
    {
        let tag = tag.trim();
        if !tag.is_empty() && seen.insert(tag.to_string()) {
            tags.push(tag.to_string());
        }
    }

    if tags.is_empty() {
        tags.push(state.primary_cache_tag.trim().to_string());
    }

    tags
}

fn should_try_next_restore_cache_tag_after_error(error: &RegistryError) -> bool {
    error.status.is_server_error()
        || matches!(
            error.status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
        )
}
