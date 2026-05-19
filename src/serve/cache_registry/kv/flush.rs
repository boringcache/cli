use super::*;

pub(crate) enum FlushResult {
    Ok,
    Conflict,
    Error,
    Permanent,
}

pub(crate) async fn flush_kv_index(state: &AppState) -> FlushResult {
    flush_kv_index_pending(state).await
}

pub(crate) async fn flush_kv_index_on_shutdown(state: &AppState) -> FlushResult {
    flush_kv_index_pending(state).await
}

pub(crate) async fn flush_kv_index_pending(state: &AppState) -> FlushResult {
    let guard = state.kv_flush_lock.lock().await;

    let Some((pending_entries, pending_blob_paths)) = ({
        let mut pending = state.kv_pending.write().await;
        if pending.is_empty() {
            None
        } else {
            Some(pending.take_all())
        }
    }) else {
        return flush_empty_pending().await;
    };

    if pending_entries.is_empty() {
        return flush_empty_pending().await;
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

    let result = match do_flush(state, &pending_entries, &pending_blob_paths).await {
        Ok((merged_entries, merged_blob_order, cache_entry_id, stable_publish)) => {
            let promoted =
                promote_pending_blobs_to_read_cache(state, &pending_entries, &pending_blob_paths)
                    .await;
            {
                let mut published = state.kv_published_index.write().await;
                published.update(
                    merged_entries.into_iter().collect(),
                    merged_blob_order,
                    cache_entry_id.clone(),
                    stable_publish,
                );
            }
            {
                let mut flushing = state.kv_flushing.write().await;
                *flushing = None;
            }
            clear_tag_misses(state, &state.primary_cache_tag);

            cleanup_blob_files(&pending_blob_paths).await;
            state.kv_last_put.store(0, Ordering::Release);

            if crate::serve::state::diagnostics_enabled() {
                eprintln!(
                    "KV batch: flushed {entry_count} new entries ({} blobs cleaned up, {promoted} promoted to read cache)",
                    pending_blob_paths.len(),
                );
            }
            drop(guard);
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
            if state.fail_on_cache_error {
                eprintln!(
                    "KV batch flush failed permanently; restored pending batch for strict shutdown retry: {msg}"
                );
                let mut pending = state.kv_pending.write().await;
                let paths_to_cleanup = pending.restore(pending_entries, pending_blob_paths);
                drop(pending);
                cleanup_paths(paths_to_cleanup).await;
            } else {
                eprintln!("KV batch flush dropped permanently: {msg}");
                cleanup_blob_files(&pending_blob_paths).await;
                state.kv_last_put.store(0, Ordering::Release);
            }
            FlushResult::Permanent
        }
    };

    if should_clear_flushing_after_flush(&result) {
        let mut flushing = state.kv_flushing.write().await;
        *flushing = None;
    }

    result
}

async fn flush_empty_pending() -> FlushResult {
    FlushResult::Ok
}

pub(crate) fn should_clear_flushing_after_flush(result: &FlushResult) -> bool {
    !matches!(result, FlushResult::Ok)
}

pub(crate) async fn do_flush(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        String,
        bool,
    ),
    FlushError,
> {
    let flush_started_at = std::time::Instant::now();
    let diagnostics = crate::serve::state::diagnostics_enabled();

    let (published_snapshot, published_blob_order) = {
        let published = state.kv_published_index.read().await;
        (published.entries_snapshot(), published.unique_blobs())
    };

    let mut entries: BTreeMap<String, BlobDescriptor> = published_snapshot
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let existing_count = entries.len();
    let (
        filtered_pending_entries,
        filtered_pending_blob_paths,
        missing_pending_digests,
        missing_pending_entries,
    ) = filter_pending_entries_with_local_blobs(pending_entries, pending_blob_paths);
    if missing_pending_entries > 0 {
        eprintln!(
            "KV flush: dropped {missing_pending_entries} pending entries with missing local blobs ({} digests)",
            missing_pending_digests.len()
        );
    }

    let pending_blob_order = merge_blob_order(&filtered_pending_entries, &[]);
    let blob_count = pending_blob_order.len() as u64;
    let blob_total_size_bytes: u64 = pending_blob_order.iter().map(|b| b.size_bytes).sum();
    let upload_stats = if pending_blob_order.is_empty() {
        BlobUploadStats::default()
    } else {
        match upload_blobs(state, "", &pending_blob_order, &filtered_pending_blob_paths).await {
            Ok(upload_stats) => upload_stats,
            Err(error) => {
                if let Some(partial_stats) = partial_blob_upload_stats(&error)
                    && (partial_stats.uploaded_count > 0 || partial_stats.missing_local_count > 0)
                {
                    eprintln!(
                        "KV row flush: preserved partial blob uploads uploaded={} already_present={} missing_local={}",
                        partial_stats.uploaded_count,
                        partial_stats.already_present_count,
                        partial_stats.missing_local_count
                    );
                }
                return Err(classify_flush_error(&error, "kv blob upload failed"));
            }
        }
    };

    upsert_kv_rows_for_visibility_tags(state, &filtered_pending_entries).await?;

    entries.extend(
        filtered_pending_entries
            .iter()
            .map(|(key, blob)| (key.clone(), blob.clone())),
    );
    let merged_blob_order = merge_blob_order(&entries, &published_blob_order);
    let total_count = entries.len();
    if diagnostics {
        eprintln!(
            "KV row flush: merged {existing_count} existing + {} pending = {total_count} total entries; unique_blobs={} uploaded={} already_present={} skipped_local={} bytes={} duration_ms={}",
            filtered_pending_entries.len(),
            blob_count,
            upload_stats.uploaded_count,
            upload_stats.already_present_count,
            upload_stats.missing_local_count,
            blob_total_size_bytes,
            flush_started_at.elapsed().as_millis()
        );
    }

    Ok((
        entries,
        merged_blob_order,
        kv_direct_cache_entry_id(&state.primary_cache_tag),
        true,
    ))
}

async fn upsert_kv_rows_for_visibility_tags(
    state: &AppState,
    entries: &BTreeMap<String, BlobDescriptor>,
) -> Result<(), FlushError> {
    if entries.is_empty() {
        return Ok(());
    }

    let rows = kv_upsert_items(entries)?;
    for tag in kv_visibility_tags(state) {
        state
            .api_client
            .upsert_cache_kv_entries(&state.workspace, &tag, &rows)
            .await
            .map_err(|error| classify_flush_error(&error, "kv row upsert failed"))?;
    }
    Ok(())
}

fn kv_upsert_items(
    entries: &BTreeMap<String, BlobDescriptor>,
) -> Result<Vec<crate::api::models::cache::CacheKvEntryUpsertItem>, FlushError> {
    entries
        .iter()
        .map(|(scoped_key, blob)| {
            let namespace = kv_namespace_from_scoped_key(scoped_key)?;
            Ok(crate::api::models::cache::CacheKvEntryUpsertItem {
                namespace: namespace.to_string(),
                scoped_key: scoped_key.clone(),
                blob_digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            })
        })
        .collect()
}

fn kv_namespace_from_scoped_key(scoped_key: &str) -> Result<&str, FlushError> {
    scoped_key
        .split_once('/')
        .map(|(namespace, _)| namespace)
        .filter(|namespace| !namespace.trim().is_empty())
        .ok_or_else(|| FlushError::Permanent(format!("invalid KV scoped key: {scoped_key}")))
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
            Ok(_) | Err(_) => {
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

#[cfg(test)]
mod flush_tests {
    use super::*;

    #[test]
    fn kv_namespace_from_scoped_key_uses_prefix() {
        assert_eq!(
            kv_namespace_from_scoped_key("bazel_cas/sha256").unwrap(),
            "bazel_cas"
        );
        assert!(matches!(
            kv_namespace_from_scoped_key("missing-prefix"),
            Err(FlushError::Permanent(_))
        ));
    }
}
