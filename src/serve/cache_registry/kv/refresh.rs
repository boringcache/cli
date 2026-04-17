use super::*;

fn is_proxy_active(state: &AppState) -> bool {
    let now_ms = crate::serve::state::unix_time_ms_now();
    let window_ms = KV_VERSION_POLL_ACTIVE_WINDOW.as_millis() as u64;

    let last_put_ms = state.kv_last_put.load(Ordering::Acquire);
    if last_put_ms > 0 && now_ms.saturating_sub(last_put_ms) < window_ms {
        return true;
    }

    !state.kv_recent_misses.is_empty()
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
                clear_tag_misses(state, &state.registry_root_tag);
                eprintln!("KV index refresh: preserving in-memory index (no backend index)");
                return;
            }
            {
                let mut published = state.kv_published_index.write().await;
                published.set_empty();
            }
            clear_tag_misses(state, &state.registry_root_tag);
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
        clear_tag_misses(state, &state.registry_root_tag);
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
            clear_tag_misses(state, &state.registry_root_tag);
            eprintln!("KV index refresh: preserving in-memory index (empty pointer)");
            return;
        }
        {
            let mut published = state.kv_published_index.write().await;
            published.set_empty();
        }
        clear_tag_misses(state, &state.registry_root_tag);
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
    clear_tag_misses(state, &state.registry_root_tag);
    eprintln!("KV index refresh: {count} entries loaded");
    preload_download_urls(state, &cache_entry_id).await;
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
        clear_tag_misses(state, &state.registry_root_tag);
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
            clear_tag_misses(state, &state.registry_root_tag);
            return;
        }
        {
            let mut published = state.kv_published_index.write().await;
            published.set_empty();
        }
        clear_tag_misses(state, &state.registry_root_tag);
        return;
    }

    let count = entries.len();
    {
        let mut published = state.kv_published_index.write().await;
        published.update(entries, blob_order, cache_entry_id.clone());
    }
    clear_tag_misses(state, &state.registry_root_tag);
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
