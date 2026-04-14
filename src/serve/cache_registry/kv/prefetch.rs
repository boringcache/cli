use super::*;

pub(crate) const KV_PREFETCH_READINESS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(300);

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

pub(crate) fn kv_startup_prefetch_max_blobs() -> usize {
    parse_positive_usize_env(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV).unwrap_or(usize::MAX)
}

pub(crate) fn kv_startup_prefetch_max_total_bytes(cache_max: u64) -> u64 {
    parse_positive_u64_env(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV).unwrap_or(cache_max)
}

pub(crate) fn kv_blob_prefetch_max_inflight_bytes(cache_max: u64) -> u64 {
    if let Some(configured) = parse_positive_u64_env(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV) {
        return configured;
    }
    cache_max
        .saturating_div(4)
        .clamp(64 * 1024 * 1024, 512 * 1024 * 1024)
}

pub(crate) fn startup_prefetch_candidates(
    blob_order: &[BlobDescriptor],
) -> StartupPrefetchCandidates {
    StartupPrefetchCandidates {
        ordered_blobs: blob_order.to_vec(),
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

pub(crate) fn startup_download_url_preload_blobs(
    startup_blobs: &[BlobDescriptor],
) -> &[BlobDescriptor] {
    startup_blobs
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
    let inflight_budget_cap = kv_blob_prefetch_max_inflight_bytes(cache_max);
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
        let blob_order = startup_prefetch_candidates(&published.unique_blobs()).ordered_blobs;
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
            let startup_max_blobs = kv_startup_prefetch_max_blobs();
            let startup_max_total_bytes = kv_startup_prefetch_max_total_bytes(cache_max)
                .min(cache_max.saturating_sub(cache_used));
            let unique_blobs = {
                let published = state.kv_published_index.read().await;
                published.unique_blobs()
            };
            let startup_candidates = startup_prefetch_candidates(&unique_blobs);
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
            let startup_url_preload_blobs = startup_download_url_preload_blobs(&startup_blobs);
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
            let background_state = state.clone();
            let background_cache_entry_id = cache_entry_id.clone();
            tokio::spawn(async move {
                if !remaining_blobs.is_empty() {
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
