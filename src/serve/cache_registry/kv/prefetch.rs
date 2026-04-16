use super::*;
use crate::observability;

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

async fn count_missing_local_blobs(state: &AppState, blobs: &[BlobDescriptor]) -> usize {
    let mut missing = 0usize;
    for blob in blobs {
        if state
            .blob_read_cache
            .get_handle(&blob.digest)
            .await
            .is_none()
        {
            missing = missing.saturating_add(1);
        }
    }
    missing
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

    match crate::serve::blob_download_urls::resolve_verified_blob_download_urls(
        state,
        cache_entry_id,
        blobs,
        KV_BLOB_URL_RESOLVE_TIMEOUT,
    )
    .await
    {
        Ok(response) => {
            let urls = response.urls;
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

#[cfg(test)]
pub(crate) fn kv_startup_prefetch_max_blobs() -> usize {
    parse_positive_usize_env(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV).unwrap_or(usize::MAX)
}

#[cfg(test)]
pub(crate) fn kv_startup_prefetch_max_total_bytes(cache_max: u64) -> u64 {
    parse_positive_u64_env(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV).unwrap_or(cache_max)
}

#[cfg(test)]
pub(crate) fn kv_blob_prefetch_max_inflight_bytes(cache_max: u64) -> u64 {
    if let Some(configured) = parse_positive_u64_env(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV) {
        return configured;
    }
    cache_max
        .saturating_div(4)
        .clamp(64 * 1024 * 1024, 512 * 1024 * 1024)
}

#[cfg(test)]
pub(crate) fn startup_prefetch_candidates(
    blob_order: &[BlobDescriptor],
) -> StartupPrefetchCandidates {
    StartupPrefetchCandidates {
        ordered_blobs: blob_order.to_vec(),
    }
}

#[cfg(test)]
pub(crate) fn should_skip_blob_preload(used_bytes: u64, max_bytes: u64) -> bool {
    if max_bytes == 0 {
        return true;
    }
    used_bytes.saturating_mul(100) >= max_bytes.saturating_mul(KV_BLOB_PRELOAD_SKIP_USED_PCT)
}

#[cfg(test)]
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
        if blob.size_bytes == 0 || blob.size_bytes > remaining_bytes {
            continue;
        }
        remaining_bytes = remaining_bytes.saturating_sub(blob.size_bytes);
        selected.push(blob.clone());
    }

    selected
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn startup_download_url_preload_blobs(
    startup_blobs: &[BlobDescriptor],
) -> &[BlobDescriptor] {
    startup_blobs
}

#[cfg(test)]
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

pub(crate) fn build_prefetch_targets<F>(
    blobs: &[BlobDescriptor],
    mut cached_url_for_digest: F,
) -> (Vec<StartupPrefetchTarget>, StartupPrefetchTargetSummary)
where
    F: FnMut(&str) -> Option<String>,
{
    let mut targets = Vec::with_capacity(blobs.len());
    let mut cached_url_count = 0usize;

    for blob in blobs {
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
            unresolved_url_count: blobs.len().saturating_sub(cached_url_count),
        },
    )
}

#[cfg(test)]
pub(crate) fn build_startup_prefetch_targets<F>(
    startup_blobs: &[BlobDescriptor],
    cached_url_for_digest: F,
) -> (Vec<StartupPrefetchTarget>, StartupPrefetchTargetSummary)
where
    F: FnMut(&str) -> Option<String>,
{
    build_prefetch_targets(startup_blobs, cached_url_for_digest)
}

pub(crate) async fn preload_single_blob(
    state: AppState,
    cache_entry_id: String,
    blob: BlobDescriptor,
    cached_url: Option<String>,
    acquired_permit: &tokio::sync::OwnedSemaphorePermit,
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
        match download_blob_to_cache_with_permit(
            &state,
            &cache_entry_id,
            &blob,
            cached_url.as_deref(),
            acquired_permit,
        )
        .await
        {
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
    let (total_unique_blobs, mut targets, summary) = {
        let published = state.kv_published_index.read().await;
        let blobs = published.unique_blobs();
        let total_unique_blobs = blobs.len();
        let (targets, summary) = build_prefetch_targets(&blobs, |digest| {
            published.download_url(digest).map(str::to_string)
        });
        (total_unique_blobs, targets, summary)
    };

    if targets.is_empty() {
        return;
    }

    let mut ready_targets = Vec::new();
    let mut already_local = 0usize;
    for target in targets.drain(..) {
        if state
            .blob_read_cache
            .get_handle(&target.blob.digest)
            .await
            .is_none()
        {
            ready_targets.push(target);
        } else {
            already_local = already_local.saturating_add(1);
        }
    }
    if ready_targets.is_empty() {
        return;
    }

    let scheduled = ready_targets.len();
    let scheduled_bytes = ready_targets
        .iter()
        .map(|target| target.blob.size_bytes)
        .fold(0u64, |acc, size| acc.saturating_add(size));
    emit_serve_event(
        Some(&state.workspace),
        SERVE_PREFETCH_OPERATION,
        SERVE_PREFETCH_PATH,
        format!(
            "start: scheduled={scheduled} scheduled_bytes={scheduled_bytes} total_unique_blobs={total_unique_blobs} cached_urls={} unresolved_urls={} already_local={already_local}",
            summary.cached_url_count, summary.unresolved_url_count,
        ),
    );
    let prefetch_started_at = std::time::Instant::now();

    let prefetch_semaphore = state.blob_prefetch_semaphore.clone();
    let mut tasks = tokio::task::JoinSet::new();
    for target in ready_targets {
        let state = state.clone();
        let cache_entry_id = cache_entry_id.to_string();
        let prefetch_semaphore = prefetch_semaphore.clone();
        tasks.spawn(async move {
            let prefetch_permit = prefetch_semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow::anyhow!("prefetch semaphore closed: {error}"))?;
            let result = preload_single_blob(
                state,
                cache_entry_id,
                target.blob,
                target.cached_url,
                &prefetch_permit,
            )
            .await;
            drop(prefetch_permit);
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

pub(crate) async fn prefetch_manifest_blobs(
    state: &AppState,
    require_full_warm: bool,
    oci_prefetch_refs: Vec<(String, String)>,
) -> Result<(), RegistryError> {
    if !oci_prefetch_refs.is_empty() {
        eprintln!(
            "Prefetch: prefetching {} selected OCI manifest refs",
            oci_prefetch_refs.len()
        );
        let mut failures = 0usize;
        for (name, reference) in oci_prefetch_refs {
            if let Err(error) = crate::serve::http::handlers::manifest::prefetch_manifest_reference(
                state, &name, &reference,
            )
            .await
            {
                failures = failures.saturating_add(1);
                let message = format!(
                    "Startup OCI manifest prefetch failed for {name}@{reference}: {error:#?}"
                );
                if require_full_warm {
                    return Err(RegistryError::internal(message));
                }
                log::warn!("{message}");
            }
        }
        if failures > 0 {
            log::warn!("Startup OCI manifest prefetch incomplete: {failures} failures");
        }
    }

    eprintln!("Prefetch: loading index and hydrating full tag before serving...");
    let started_at = std::time::Instant::now();
    state.prefetch_metrics.reset_startup();

    emit_serve_event(
        Some(&state.workspace),
        SERVE_PRELOAD_INDEX_OPERATION,
        SERVE_PRELOAD_INDEX_PATH,
        "sync:start".to_string(),
    );

    match load_existing_index_snapshot(state, true).await {
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
            clear_tag_misses(state, &state.registry_root_tag);
            let unique_blobs = {
                let published = state.kv_published_index.read().await;
                published.unique_blobs()
            };
            let total_unique_blobs = unique_blobs.len();
            let total_unique_bytes: u64 =
                unique_blobs.iter().map(|blob| blob.size_bytes).sum::<u64>();
            state.prefetch_metrics.record_startup_plan(
                "full_tag",
                total_unique_blobs,
                total_unique_blobs,
                total_unique_bytes,
            );

            eprintln!(
                "Prefetch: {count} entries loaded, hydrating full tag locally ({} blobs, {:.1} MB)",
                total_unique_blobs,
                total_unique_bytes as f64 / (1024.0 * 1024.0),
            );

            let startup_url_stats =
                preload_download_urls_for_blobs(state, &cache_entry_id, &unique_blobs).await;
            eprintln!(
                "Prefetch: full-tag URL coverage resolved={}/{} missing={}",
                startup_url_stats.resolved, startup_url_stats.requested, startup_url_stats.missing,
            );
            state
                .prefetch_metrics
                .record_startup_url_coverage(startup_url_stats.resolved, startup_url_stats.missing);

            eprintln!("Prefetch: warming full tag...");
            match tokio::time::timeout(
                KV_PREFETCH_READINESS_TIMEOUT,
                prefetch_all_blobs(state, &cache_entry_id, &unique_blobs),
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
                    let message = format!(
                        "Startup warmup timed out after {}s",
                        KV_PREFETCH_READINESS_TIMEOUT.as_secs()
                    );
                    eprintln!(
                        "Prefetch: timed out after {}s (partial prefetch, continuing)",
                        KV_PREFETCH_READINESS_TIMEOUT.as_secs(),
                    );
                    if require_full_warm {
                        return Err(RegistryError::internal(message));
                    }
                }
            }

            let missing_local_blobs = count_missing_local_blobs(state, &unique_blobs).await;
            if missing_local_blobs > 0 {
                let message = format!(
                    "Startup warmup incomplete: {missing_local_blobs}/{} blobs are still cold",
                    unique_blobs.len()
                );
                if require_full_warm {
                    return Err(RegistryError::internal(message));
                }
                log::warn!("{message}");
            }

            if !require_full_warm {
                spawn_preload_blobs(state, &cache_entry_id);
            }
        }
        Ok(_) => {
            {
                let mut published = state.kv_published_index.write().await;
                published.set_empty_incomplete();
            }
            eprintln!("Prefetch: no existing entries, skipping");
            return Ok(());
        }
        Err(e) => {
            if require_full_warm {
                return Err(e);
            }

            if is_invalid_file_pointer_error(&e) {
                let mut published = state.kv_published_index.write().await;
                published.set_empty_incomplete();
                eprintln!("Prefetch: invalid file pointer, degraded to empty index");
                return Ok(());
            }
            log::warn!("Prefetch: index load failed: {e:?}");
        }
    }

    Ok(())
}

pub(crate) async fn prefetch_all_blobs(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
) {
    let total_unique_blobs = blobs.len();

    let (startup_targets, startup_summary) = {
        let published = state.kv_published_index.read().await;
        build_prefetch_targets(blobs, |digest| {
            published.download_url(digest).map(str::to_string)
        })
    };

    if startup_targets.is_empty() {
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
            "Prefetch: full tag already warm (cached_urls={} unresolved_urls={} already_local={})",
            startup_summary.cached_url_count, startup_summary.unresolved_url_count, already_local,
        );
        return;
    }

    let scheduled = targets.len();
    let scheduled_bytes: u64 = targets.iter().map(|target| target.blob.size_bytes).sum();
    eprintln!(
        "Prefetch: warming full tag {scheduled}/{total_unique_blobs} blobs ({:.1} MB, cached_urls={}, unresolved_urls={}, already_local={})",
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
            let prefetch_permit = prefetch_semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow::anyhow!("prefetch semaphore closed: {error}"))?;
            let result = preload_single_blob(
                state,
                cache_entry_id,
                target.blob,
                target.cached_url,
                &prefetch_permit,
            )
            .await;
            drop(prefetch_permit);
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
                "Prefetch: full tag {completed}/{scheduled} blobs ({inserted} inserted, {failures} failed, {:.1}s)",
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
        "Prefetch: full tag done inserted={inserted} scheduled={scheduled} failures={failures} cache_size={} bytes in {:.1}s",
        state.blob_read_cache.total_bytes(),
        prefetch_started_at.elapsed().as_secs_f64(),
    );
}
