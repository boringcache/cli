use super::*;
use crate::observability;

pub(crate) const KV_PREFETCH_READINESS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(300);
const PREFETCH_BLOB_DOWNLOAD_ATTEMPTS: usize = 3;
const STARTUP_PREFETCH_MANY_BLOB_COUNT: usize = 1_000;
const STARTUP_PREFETCH_SMALL_BLOB_BYTES: u64 = 64 * 1024;
const STARTUP_PREFETCH_MEDIUM_BLOB_BYTES: u64 = 1024 * 1024;
const STARTUP_PREFETCH_LARGE_BLOB_BYTES: u64 = 8 * 1024 * 1024;
const STARTUP_PREFETCH_MANY_SMALL_BLOB_CAP: usize = 10;
const STARTUP_PREFETCH_MEDIUM_BLOB_CAP: usize = 8;
const STARTUP_PREFETCH_LARGE_BLOB_CAP: usize = 4;

pub(crate) async fn count_missing_local_blobs(state: &AppState, blobs: &[BlobDescriptor]) -> usize {
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
            if crate::serve::state::diagnostics_enabled() {
                eprintln!(
                    "KV index preload: resolved {url_count}/{requested} download URLs (missing={missing_count})"
                );
            }
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

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BlobPrefetchStats {
    pub(crate) total_unique_blobs: usize,
    pub(crate) scheduled: usize,
    pub(crate) inserted: usize,
    pub(crate) failures: usize,
    pub(crate) already_local: usize,
    pub(crate) scheduled_bytes: u64,
    pub(crate) duration_ms: u64,
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
    for attempt in 1..=PREFETCH_BLOB_DOWNLOAD_ATTEMPTS {
        match download_blob_to_cache(&state, &cache_entry_id, &blob, cached_url.as_deref()).await {
            Ok(_) => return Ok(true),
            Err(error)
                if attempt < PREFETCH_BLOB_DOWNLOAD_ATTEMPTS
                    && should_retry_prefetch_blob_error(error.status) =>
            {
                log::debug!(
                    "Prefetch startup blob retry {attempt}/{PREFETCH_BLOB_DOWNLOAD_ATTEMPTS} digest={} status={} after {:?}",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StartupPrefetchConcurrencyPlan {
    pub(crate) max_concurrency: usize,
    pub(crate) effective_concurrency: usize,
    pub(crate) source: &'static str,
    pub(crate) reason: &'static str,
}

pub(crate) fn adaptive_startup_prefetch_concurrency(
    max_concurrency: usize,
    explicit_override: bool,
    target_blobs: usize,
    target_bytes: u64,
) -> StartupPrefetchConcurrencyPlan {
    let max_concurrency = max_concurrency.max(1);
    if target_blobs == 0 {
        return StartupPrefetchConcurrencyPlan {
            max_concurrency,
            effective_concurrency: 1,
            source: "auto",
            reason: "empty",
        };
    }

    if explicit_override {
        return StartupPrefetchConcurrencyPlan {
            max_concurrency,
            effective_concurrency: max_concurrency.min(target_blobs).max(1),
            source: "env",
            reason: "explicit_override",
        };
    }

    let average_blob_bytes = target_bytes / target_blobs as u64;
    let (cap, reason) = if target_blobs >= STARTUP_PREFETCH_MANY_BLOB_COUNT
        && average_blob_bytes <= STARTUP_PREFETCH_SMALL_BLOB_BYTES
    {
        (
            STARTUP_PREFETCH_MANY_SMALL_BLOB_CAP,
            "many_small_blobs_measured_cap",
        )
    } else if average_blob_bytes >= STARTUP_PREFETCH_LARGE_BLOB_BYTES {
        (STARTUP_PREFETCH_LARGE_BLOB_CAP, "large_blobs")
    } else if average_blob_bytes >= STARTUP_PREFETCH_MEDIUM_BLOB_BYTES {
        (STARTUP_PREFETCH_MEDIUM_BLOB_CAP, "medium_blobs")
    } else {
        (max_concurrency, "machine_governor")
    };

    StartupPrefetchConcurrencyPlan {
        max_concurrency,
        effective_concurrency: max_concurrency.min(cap).min(target_blobs).max(1),
        source: "auto",
        reason,
    }
}

fn should_retry_prefetch_blob_error(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::SERVICE_UNAVAILABLE
    ) || status.is_server_error()
}

async fn prefetch_blob_targets(
    state: &AppState,
    cache_entry_id: &str,
    total_unique_blobs: usize,
    targets: Vec<StartupPrefetchTarget>,
    summary: StartupPrefetchTargetSummary,
    concurrency_plan: StartupPrefetchConcurrencyPlan,
    log_label: &str,
) -> BlobPrefetchStats {
    let mut stats = BlobPrefetchStats {
        total_unique_blobs,
        ..BlobPrefetchStats::default()
    };

    if targets.is_empty() {
        return stats;
    }

    let mut pending_targets = Vec::new();
    for target in targets {
        if state
            .blob_read_cache
            .get_handle(&target.blob.digest)
            .await
            .is_none()
        {
            pending_targets.push(target);
        } else {
            stats.already_local = stats.already_local.saturating_add(1);
        }
    }

    if pending_targets.is_empty() {
        if crate::serve::state::diagnostics_enabled() {
            eprintln!(
                "{log_label}: already warm (cached_urls={} unresolved_urls={} already_local={})",
                summary.cached_url_count, summary.unresolved_url_count, stats.already_local,
            );
        }
        return stats;
    }

    stats.scheduled = pending_targets.len();
    stats.scheduled_bytes = pending_targets
        .iter()
        .map(|target| target.blob.size_bytes)
        .sum();
    let diagnostics = crate::serve::state::diagnostics_enabled();
    if diagnostics {
        eprintln!(
            "{log_label}: warming {}/{} blobs ({:.1} MB, concurrency={}/{}, source={}, reason={}, cached_urls={}, unresolved_urls={}, already_local={})",
            stats.scheduled,
            stats.total_unique_blobs,
            stats.scheduled_bytes as f64 / (1024.0 * 1024.0),
            concurrency_plan.effective_concurrency,
            concurrency_plan.max_concurrency,
            concurrency_plan.source,
            concurrency_plan.reason,
            summary.cached_url_count,
            summary.unresolved_url_count,
            stats.already_local,
        );
    }

    let prefetch_started_at = std::time::Instant::now();
    let mut pending_iter = pending_targets.into_iter();
    let mut tasks = tokio::task::JoinSet::new();

    fn spawn_prefetch_task(
        tasks: &mut tokio::task::JoinSet<anyhow::Result<bool>>,
        state: AppState,
        cache_entry_id: String,
        target: StartupPrefetchTarget,
    ) {
        let prefetch_semaphore = state.blob_prefetch_semaphore.clone();
        tasks.spawn(async move {
            let prefetch_permit = prefetch_semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow::anyhow!("prefetch semaphore closed: {error}"))?;
            let result =
                preload_single_blob(state, cache_entry_id, target.blob, target.cached_url).await;
            drop(prefetch_permit);
            result
        });
    }

    let max_in_flight = concurrency_plan
        .effective_concurrency
        .min(stats.scheduled)
        .max(1);
    for _ in 0..max_in_flight {
        let Some(target) = pending_iter.next() else {
            break;
        };
        let state = state.clone();
        let cache_entry_id = cache_entry_id.to_string();
        spawn_prefetch_task(&mut tasks, state, cache_entry_id, target);
    }

    let log_interval = (stats.scheduled / 10).max(1);
    let mut completed = 0usize;
    loop {
        let next_result = tasks.join_next().await;
        let Some(result) = next_result else {
            break;
        };
        match result {
            Ok(Ok(true)) => stats.inserted = stats.inserted.saturating_add(1),
            Ok(Ok(false)) => {}
            Ok(Err(error)) => {
                stats.failures = stats.failures.saturating_add(1);
                log::warn!("{log_label} blob failed: {error}");
            }
            Err(error) => {
                stats.failures = stats.failures.saturating_add(1);
                log::warn!("{log_label} task failed: {error}");
            }
        }
        completed = completed.saturating_add(1);
        if diagnostics && completed.is_multiple_of(log_interval) {
            eprintln!(
                "{log_label}: {completed}/{} blobs ({} inserted, {} failed, {:.1}s)",
                stats.scheduled,
                stats.inserted,
                stats.failures,
                prefetch_started_at.elapsed().as_secs_f64(),
            );
        }
        if let Some(target) = pending_iter.next() {
            let state = state.clone();
            let cache_entry_id = cache_entry_id.to_string();
            spawn_prefetch_task(&mut tasks, state, cache_entry_id, target);
        }
    }

    stats.duration_ms = prefetch_started_at.elapsed().as_millis() as u64;
    if diagnostics {
        eprintln!(
            "{log_label}: done inserted={} scheduled={} failures={} cache_size={} bytes in {:.1}s",
            stats.inserted,
            stats.scheduled,
            stats.failures,
            state.blob_read_cache.total_bytes(),
            prefetch_started_at.elapsed().as_secs_f64(),
        );
    }
    stats
}

pub(crate) async fn prefetch_manifest_blobs(
    state: &AppState,
    require_full_warm: bool,
    oci_prefetch_refs: Vec<(String, String)>,
    oci_hydration_policy: crate::serve::OciHydrationPolicy,
) {
    if !require_full_warm {
        return;
    }

    state.prefetch_metrics.reset_startup();

    crate::serve::engines::oci::prefetch::prefetch_selected_refs(
        state,
        oci_prefetch_refs,
        oci_hydration_policy,
    )
    .await;

    let diagnostics = crate::serve::state::diagnostics_enabled();
    if diagnostics {
        eprintln!("Prefetch: loading index and hydrating full tag before serving...");
    }
    let started_at = std::time::Instant::now();

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
            let concurrency_plan = adaptive_startup_prefetch_concurrency(
                state.blob_prefetch_max_concurrency,
                state.blob_prefetch_concurrency_from_env,
                total_unique_blobs,
                total_unique_bytes,
            );
            state
                .prefetch_metrics
                .record_startup_plan(crate::serve::state::StartupPrefetchPlan {
                    mode: "full_tag",
                    total_unique_blobs,
                    target_blobs: total_unique_blobs,
                    target_bytes: total_unique_bytes,
                    max_concurrency: concurrency_plan.max_concurrency,
                    effective_concurrency: concurrency_plan.effective_concurrency,
                    concurrency_source: concurrency_plan.source,
                    concurrency_reason: concurrency_plan.reason,
                });

            if diagnostics {
                eprintln!(
                    "Prefetch: {count} entries loaded, hydrating full tag locally ({} blobs, {:.1} MB, concurrency={}/{}, source={}, reason={})",
                    total_unique_blobs,
                    total_unique_bytes as f64 / (1024.0 * 1024.0),
                    concurrency_plan.effective_concurrency,
                    concurrency_plan.max_concurrency,
                    concurrency_plan.source,
                    concurrency_plan.reason,
                );
            }

            let startup_url_stats =
                preload_download_urls_for_blobs(state, &cache_entry_id, &unique_blobs).await;
            if diagnostics {
                eprintln!(
                    "Prefetch: full-tag URL coverage resolved={}/{} missing={}",
                    startup_url_stats.resolved,
                    startup_url_stats.requested,
                    startup_url_stats.missing,
                );
            }
            state
                .prefetch_metrics
                .record_startup_url_coverage(startup_url_stats.resolved, startup_url_stats.missing);

            if diagnostics {
                eprintln!("Prefetch: warming full tag...");
            }
            match tokio::time::timeout(
                KV_PREFETCH_READINESS_TIMEOUT,
                prefetch_all_blobs(state, &cache_entry_id, &unique_blobs, concurrency_plan),
            )
            .await
            {
                Ok(()) => {
                    if diagnostics {
                        eprintln!(
                            "Prefetch: complete in {:.1}s, cache_size={} bytes",
                            started_at.elapsed().as_secs_f64(),
                            state.blob_read_cache.total_bytes(),
                        );
                    }
                }
                Err(_) => {
                    let message = format!(
                        "Startup warmup timed out after {}s",
                        KV_PREFETCH_READINESS_TIMEOUT.as_secs()
                    );
                    log::warn!("{message}");
                }
            }

            let missing_local_blobs = count_missing_local_blobs(state, &unique_blobs).await;
            state
                .prefetch_metrics
                .record_startup_cold_blobs(missing_local_blobs);
            if missing_local_blobs > 0 {
                let message = format!(
                    "Startup warmup incomplete: {missing_local_blobs}/{} blobs are still cold",
                    unique_blobs.len()
                );
                log::warn!("{message}");
                eprintln!("Prefetch: {message}; serving remaining blobs on demand");
            }
        }
        Ok(_) => {
            {
                let mut published = state.kv_published_index.write().await;
                published.set_empty_incomplete();
            }
            if diagnostics {
                eprintln!("Prefetch: no existing entries, skipping");
            }
        }
        Err(e) => {
            let mut published = state.kv_published_index.write().await;
            published.set_empty_incomplete();
            log::warn!("Prefetch: index load failed: {e:?}");
            eprintln!("Prefetch: index load failed; serving cache reads on demand");
        }
    }
}

pub(crate) async fn prefetch_all_blobs(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    concurrency_plan: StartupPrefetchConcurrencyPlan,
) {
    let (startup_targets, startup_summary) = {
        let published = state.kv_published_index.read().await;
        build_prefetch_targets(blobs, |digest| {
            published.download_url(digest).map(str::to_string)
        })
    };

    let stats = prefetch_blob_targets(
        state,
        cache_entry_id,
        blobs.len(),
        startup_targets,
        startup_summary,
        concurrency_plan,
        "Prefetch: full tag",
    )
    .await;

    let status = if stats.failures == 0 {
        200
    } else if stats.inserted > 0 {
        207
    } else {
        500
    };
    state.prefetch_metrics.record_startup_execution(
        stats.already_local,
        stats.inserted,
        stats.failures,
        stats.duration_ms,
    );
    emit_serve_phase_metric(
        Some(&state.workspace),
        Some(cache_entry_id),
        SERVE_PREFETCH_OPERATION,
        SERVE_PREFETCH_PATH,
        status,
        stats.duration_ms,
        Some(stats.scheduled as u64),
    );
}
