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
                    eprintln!(
                        "Prefetch: timed out after {}s (partial prefetch, continuing)",
                        KV_PREFETCH_READINESS_TIMEOUT.as_secs(),
                    );
                }
            }
            spawn_preload_blobs(state, &cache_entry_id);
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
