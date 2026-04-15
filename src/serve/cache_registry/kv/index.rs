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
    let (entries, blob_order, cache_entry_id, _) =
        match load_existing_index_snapshot(state, true).await {
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
    clear_tag_misses(state, &state.registry_root_tag);

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
            .map(|blob| crate::cas_file::FilePointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
                sequence: None,
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

pub(crate) async fn load_existing_index_snapshot(
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
    load_existing_index(state, state.registry_root_tag.trim(), retry_not_found).await
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
