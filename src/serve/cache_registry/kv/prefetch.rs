use super::*;
use crate::observability;

pub(crate) const KV_PREFETCH_READINESS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(300);
const PREFETCH_BLOB_DOWNLOAD_ATTEMPTS: usize = 3;
const STARTUP_PREFETCH_MANY_BLOB_COUNT: usize = 1_000;
const STARTUP_PREFETCH_SMALL_BLOB_BYTES: u64 = 64 * 1024;
const STARTUP_PREFETCH_MEDIUM_BLOB_BYTES: u64 = 1024 * 1024;
const STARTUP_PREFETCH_LARGE_BLOB_BYTES: u64 = 8 * 1024 * 1024;
const STARTUP_PREFETCH_MANY_SMALL_BLOB_CAP: usize = 100;
const STARTUP_PREFETCH_ADAPTIVE_INITIAL_CONCURRENCY: usize = 20;
const STARTUP_PREFETCH_ADAPTIVE_MIN_CONCURRENCY: usize = 10;
const STARTUP_PREFETCH_ADAPTIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
const STARTUP_PREFETCH_GOODPUT_GAIN_THRESHOLD: f64 = 1.15;
const STARTUP_PREFETCH_GOODPUT_DROP_THRESHOLD: f64 = 0.85;
const STARTUP_PREFETCH_GOODPUT_EMA_OLD_WEIGHT: f64 = 0.70;
const STARTUP_PREFETCH_GOODPUT_EMA_NEW_WEIGHT: f64 = 0.30;
const STARTUP_PREFETCH_LATENCY_EMA_OLD_WEIGHT: f64 = 0.80;
const STARTUP_PREFETCH_LATENCY_EMA_NEW_WEIGHT: f64 = 0.20;
const STARTUP_PREFETCH_LATENCY_HOLD_MULTIPLIER: u64 = 3;
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
    pub(crate) final_concurrency: usize,
    pub(crate) max_observed_concurrency: usize,
}

#[derive(Debug)]
pub(crate) struct StartupPrefetchBlobError {
    status: StatusCode,
    retry_after: Option<std::time::Duration>,
    message: String,
}

impl StartupPrefetchBlobError {
    fn from_registry_error(blob: &BlobDescriptor, error: RegistryError) -> Self {
        Self {
            status: error.status,
            retry_after: error.retry_after,
            message: format!(
                "download_blob_to_cache failed for {}: {error:?}",
                blob.digest
            ),
        }
    }

    fn exhausted(blob: &BlobDescriptor) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            retry_after: None,
            message: format!(
                "download_blob_to_cache exhausted retries for {}",
                blob.digest
            ),
        }
    }
}

impl std::fmt::Display for StartupPrefetchBlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub(crate) async fn preload_single_blob(
    state: AppState,
    cache_entry_id: String,
    blob: BlobDescriptor,
    cached_url: Option<String>,
) -> Result<bool, StartupPrefetchBlobError> {
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
            Err(error) if error.status == StatusCode::TOO_MANY_REQUESTS => {
                return Err(StartupPrefetchBlobError::from_registry_error(&blob, error));
            }
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
                return Err(StartupPrefetchBlobError::from_registry_error(&blob, error));
            }
        }
    }

    Err(StartupPrefetchBlobError::exhausted(&blob))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StartupPrefetchConcurrencyPlan {
    pub(crate) max_concurrency: usize,
    pub(crate) effective_concurrency: usize,
    pub(crate) initial_concurrency: usize,
    pub(crate) adaptive: bool,
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
            initial_concurrency: 1,
            adaptive: false,
            source: "auto",
            reason: "empty",
        };
    }

    if explicit_override {
        return StartupPrefetchConcurrencyPlan {
            max_concurrency,
            effective_concurrency: max_concurrency.min(target_blobs).max(1),
            initial_concurrency: max_concurrency.min(target_blobs).max(1),
            adaptive: false,
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
            "many_small_blobs_rtt_bound",
        )
    } else if average_blob_bytes >= STARTUP_PREFETCH_LARGE_BLOB_BYTES {
        (STARTUP_PREFETCH_LARGE_BLOB_CAP, "large_blobs")
    } else if average_blob_bytes >= STARTUP_PREFETCH_MEDIUM_BLOB_BYTES {
        (STARTUP_PREFETCH_MEDIUM_BLOB_CAP, "medium_blobs")
    } else {
        (max_concurrency, "machine_governor")
    };

    let effective_concurrency = max_concurrency.min(cap).min(target_blobs).max(1);
    let adaptive = matches!(reason, "many_small_blobs_rtt_bound" | "machine_governor")
        && effective_concurrency > 1;
    let initial_concurrency = if adaptive {
        STARTUP_PREFETCH_ADAPTIVE_INITIAL_CONCURRENCY.min(effective_concurrency)
    } else {
        effective_concurrency
    };

    StartupPrefetchConcurrencyPlan {
        max_concurrency,
        effective_concurrency,
        initial_concurrency,
        adaptive,
        source: "auto",
        reason,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupPrefetchAdjustment {
    Disabled,
    Increase,
    Hold,
    DropFast,
    DropSlow,
    RateLimited,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StartupPrefetchWindowSample {
    pub(crate) elapsed: std::time::Duration,
    pub(crate) completed: usize,
    pub(crate) bytes: u64,
    pub(crate) failures: usize,
    pub(crate) rate_limited: bool,
    pub(crate) retry_after: Option<std::time::Duration>,
    pub(crate) p95_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StartupPrefetchTuningState {
    smoothed_goodput_bps: Option<f64>,
    baseline_p95_ms: Option<u64>,
}

impl StartupPrefetchTuningState {
    pub(crate) fn new() -> Self {
        Self {
            smoothed_goodput_bps: None,
            baseline_p95_ms: None,
        }
    }
}

fn startup_prefetch_adaptive_floor(max: usize) -> usize {
    max.clamp(1, STARTUP_PREFETCH_ADAPTIVE_MIN_CONCURRENCY)
}

pub(crate) fn tune_startup_prefetch_concurrency(
    current: usize,
    max: usize,
    adaptive: bool,
    state: &mut StartupPrefetchTuningState,
    sample: StartupPrefetchWindowSample,
    resource_pressure_high: bool,
) -> (usize, StartupPrefetchAdjustment) {
    if !adaptive {
        return (current, StartupPrefetchAdjustment::Disabled);
    }
    if sample.completed == 0 || sample.elapsed.is_zero() {
        return (current, StartupPrefetchAdjustment::Hold);
    }

    let p95_ms = sample.p95_ms;
    let baseline = state.baseline_p95_ms.unwrap_or(p95_ms.max(1));
    let refreshed_baseline = ((baseline as f64 * STARTUP_PREFETCH_LATENCY_EMA_OLD_WEIGHT)
        + (p95_ms.max(1) as f64 * STARTUP_PREFETCH_LATENCY_EMA_NEW_WEIGHT))
        .round()
        .max(1.0) as u64;
    state.baseline_p95_ms = Some(refreshed_baseline);

    if sample.failures > 0 {
        state.smoothed_goodput_bps = None;
        let floor = startup_prefetch_adaptive_floor(max);
        let adjustment = if sample.rate_limited {
            StartupPrefetchAdjustment::RateLimited
        } else {
            StartupPrefetchAdjustment::DropFast
        };
        return ((current / 2).max(floor).min(max), adjustment);
    }

    let goodput_bps = sample.bytes as f64 / sample.elapsed.as_secs_f64().max(0.001);
    let previous_goodput_bps = state.smoothed_goodput_bps;

    if p95_ms > baseline.saturating_mul(STARTUP_PREFETCH_LATENCY_HOLD_MULTIPLIER)
        && previous_goodput_bps.is_some_and(|previous| {
            goodput_bps < previous * STARTUP_PREFETCH_GOODPUT_DROP_THRESHOLD
        })
    {
        let next = ((current as f64) * 0.85).floor() as usize;
        return (
            next.max(startup_prefetch_adaptive_floor(max)).min(max),
            StartupPrefetchAdjustment::DropSlow,
        );
    }

    let improved = previous_goodput_bps
        .map(|previous| goodput_bps > previous * STARTUP_PREFETCH_GOODPUT_GAIN_THRESHOLD)
        .unwrap_or(true);
    state.smoothed_goodput_bps = Some(
        state
            .smoothed_goodput_bps
            .map(|previous| {
                previous * STARTUP_PREFETCH_GOODPUT_EMA_OLD_WEIGHT
                    + goodput_bps * STARTUP_PREFETCH_GOODPUT_EMA_NEW_WEIGHT
            })
            .unwrap_or(goodput_bps),
    );

    if resource_pressure_high {
        return (current, StartupPrefetchAdjustment::Hold);
    }

    if improved && current < max {
        let step = ((current as f64) * 0.10).ceil() as usize;
        return (
            current.saturating_add(step.max(5)).min(max),
            StartupPrefetchAdjustment::Increase,
        );
    }

    (current, StartupPrefetchAdjustment::Hold)
}

pub(crate) struct AdaptiveStartupPrefetch {
    current: usize,
    max: usize,
    adaptive: bool,
    tuning: StartupPrefetchTuningState,
    window_started_at: std::time::Instant,
    completed: usize,
    bytes: u64,
    failures: usize,
    rate_limited: bool,
    retry_after: Option<std::time::Duration>,
    latencies_ms: Vec<u64>,
    hold_until: Option<std::time::Instant>,
}

impl AdaptiveStartupPrefetch {
    pub(crate) fn new(plan: StartupPrefetchConcurrencyPlan) -> Self {
        Self {
            current: plan.initial_concurrency.max(1),
            max: plan.effective_concurrency.max(1),
            adaptive: plan.adaptive,
            tuning: StartupPrefetchTuningState::new(),
            window_started_at: std::time::Instant::now(),
            completed: 0,
            bytes: 0,
            failures: 0,
            rate_limited: false,
            retry_after: None,
            latencies_ms: Vec::new(),
            hold_until: None,
        }
    }

    pub(crate) fn current(&self) -> usize {
        self.current
    }

    pub(crate) fn pause_remaining(&self) -> Option<std::time::Duration> {
        self.hold_until
            .and_then(|deadline| deadline.checked_duration_since(std::time::Instant::now()))
    }

    pub(crate) fn target_in_flight(&mut self) -> usize {
        if self.pause_remaining().is_some() {
            0
        } else {
            self.hold_until = None;
            self.current
        }
    }

    pub(crate) fn record(&mut self, report: &StartupPrefetchTaskReport) {
        self.completed = self.completed.saturating_add(1);
        self.bytes = self.bytes.saturating_add(report.size_bytes);
        if report.error.is_some() {
            self.failures = self.failures.saturating_add(1);
        }
        if report.status == Some(StatusCode::TOO_MANY_REQUESTS) {
            self.rate_limited = true;
        }
        if let Some(retry_after) = report.retry_after {
            self.retry_after = Some(
                self.retry_after
                    .map_or(retry_after, |current| current.max(retry_after)),
            );
        }
        self.latencies_ms.push(report.duration_ms);
    }

    pub(crate) fn maybe_adjust(&mut self) -> Option<(StartupPrefetchAdjustment, usize, usize)> {
        if !self.adaptive || self.window_started_at.elapsed() < STARTUP_PREFETCH_ADAPTIVE_WINDOW {
            return None;
        }

        let window = self.snapshot_window();
        self.completed = 0;
        self.bytes = 0;
        self.failures = 0;
        self.rate_limited = false;
        self.retry_after = None;
        self.latencies_ms.clear();
        self.window_started_at = std::time::Instant::now();

        if self
            .hold_until
            .is_some_and(|deadline| deadline > self.window_started_at)
        {
            return Some((StartupPrefetchAdjustment::Hold, self.current, self.current));
        }
        self.hold_until = None;

        let previous = self.current;
        let (next, adjustment) = tune_startup_prefetch_concurrency(
            self.current,
            self.max,
            self.adaptive,
            &mut self.tuning,
            window,
            crate::platform::resources::proxy_resource_pressure_high(),
        );
        self.current = next;

        if adjustment == StartupPrefetchAdjustment::RateLimited
            && let Some(retry_after) = window.retry_after
        {
            self.hold_until = Some(std::time::Instant::now() + retry_after);
        }

        Some((adjustment, previous, next))
    }

    #[cfg(test)]
    pub(crate) fn force_window_elapsed_for_test(&mut self) {
        self.window_started_at = std::time::Instant::now() - STARTUP_PREFETCH_ADAPTIVE_WINDOW;
    }

    fn snapshot_window(&mut self) -> StartupPrefetchWindowSample {
        self.latencies_ms.sort_unstable();
        let p95_ms = if self.latencies_ms.is_empty() {
            0
        } else {
            let index = ((self.latencies_ms.len() as f64) * 0.95).ceil() as usize;
            let index = index.saturating_sub(1).min(self.latencies_ms.len() - 1);
            self.latencies_ms[index]
        };
        StartupPrefetchWindowSample {
            elapsed: self.window_started_at.elapsed(),
            completed: self.completed,
            bytes: self.bytes,
            failures: self.failures,
            rate_limited: self.rate_limited,
            retry_after: self.retry_after,
            p95_ms,
        }
    }
}

#[derive(Debug)]
pub(crate) struct StartupPrefetchTaskReport {
    pub(crate) inserted: bool,
    pub(crate) size_bytes: u64,
    pub(crate) duration_ms: u64,
    pub(crate) status: Option<StatusCode>,
    pub(crate) retry_after: Option<std::time::Duration>,
    pub(crate) error: Option<String>,
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
        stats.final_concurrency = concurrency_plan.initial_concurrency;
        stats.max_observed_concurrency = 0;
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
            "{log_label}: warming {}/{} blobs ({:.1} MB, concurrency_initial={}, concurrency_ceiling={}, resource_max={}, source={}, reason={}, adaptive={}, cached_urls={}, unresolved_urls={}, already_local={})",
            stats.scheduled,
            stats.total_unique_blobs,
            stats.scheduled_bytes as f64 / (1024.0 * 1024.0),
            concurrency_plan.initial_concurrency,
            concurrency_plan.effective_concurrency,
            concurrency_plan.max_concurrency,
            concurrency_plan.source,
            concurrency_plan.reason,
            concurrency_plan.adaptive,
            summary.cached_url_count,
            summary.unresolved_url_count,
            stats.already_local,
        );
    }

    let prefetch_started_at = std::time::Instant::now();
    let mut pending_iter = pending_targets.into_iter();
    let mut tasks = tokio::task::JoinSet::new();

    let mut controller = AdaptiveStartupPrefetch::new(concurrency_plan);
    let mut max_observed_concurrency = 0usize;
    spawn_until_target(
        &mut tasks,
        &mut pending_iter,
        state,
        cache_entry_id,
        controller.current().min(stats.scheduled).max(1),
        &mut max_observed_concurrency,
    );

    let log_interval = (stats.scheduled / 10).max(1);
    let mut completed = 0usize;
    loop {
        let next_result = tasks.join_next().await;
        let Some(result) = next_result else {
            break;
        };
        match result {
            Ok(report) => {
                controller.record(&report);
                if report.inserted {
                    stats.inserted = stats.inserted.saturating_add(1);
                }
                if let Some(error) = report.error {
                    stats.failures = stats.failures.saturating_add(1);
                    log::warn!("{log_label} blob failed: {error}");
                }
            }
            Err(error) => {
                stats.failures = stats.failures.saturating_add(1);
                log::warn!("{log_label} blob failed: {error}");
            }
        }
        completed = completed.saturating_add(1);
        if let Some((adjustment, previous, next)) = controller.maybe_adjust()
            && adjustment != StartupPrefetchAdjustment::Disabled
            && previous != next
        {
            let adjustment_label = format!("{adjustment:?}");
            state
                .prefetch_metrics
                .record_startup_concurrency_adjustment(&adjustment_label, previous, next);
            if diagnostics {
                eprintln!(
                    "{log_label}: adaptive concurrency {adjustment_label} {previous}->{next}"
                );
            }
        }
        if diagnostics && completed.is_multiple_of(log_interval) {
            eprintln!(
                "{log_label}: {completed}/{} blobs ({} inserted, {} failed, {:.1}s)",
                stats.scheduled,
                stats.inserted,
                stats.failures,
                prefetch_started_at.elapsed().as_secs_f64(),
            );
        }
        let target_in_flight = controller.target_in_flight();
        if target_in_flight > 0 {
            spawn_until_target(
                &mut tasks,
                &mut pending_iter,
                state,
                cache_entry_id,
                target_in_flight,
                &mut max_observed_concurrency,
            );
        } else if tasks.is_empty()
            && pending_iter.len() > 0
            && let Some(pause_remaining) = controller.pause_remaining()
        {
            tokio::time::sleep(pause_remaining).await;
            spawn_until_target(
                &mut tasks,
                &mut pending_iter,
                state,
                cache_entry_id,
                controller.target_in_flight(),
                &mut max_observed_concurrency,
            );
        }
    }

    stats.duration_ms = prefetch_started_at.elapsed().as_millis() as u64;
    stats.final_concurrency = controller.current();
    stats.max_observed_concurrency = max_observed_concurrency;
    if diagnostics {
        eprintln!(
            "{log_label}: done inserted={} scheduled={} failures={} cache_size={} bytes concurrency_final={} concurrency_max_observed={} in {:.1}s",
            stats.inserted,
            stats.scheduled,
            stats.failures,
            state.blob_read_cache.total_bytes(),
            controller.current(),
            max_observed_concurrency,
            prefetch_started_at.elapsed().as_secs_f64(),
        );
    }
    stats
}

fn spawn_until_target(
    tasks: &mut tokio::task::JoinSet<StartupPrefetchTaskReport>,
    pending_iter: &mut std::vec::IntoIter<StartupPrefetchTarget>,
    state: &AppState,
    cache_entry_id: &str,
    target_in_flight: usize,
    max_observed_concurrency: &mut usize,
) {
    while tasks.len() < target_in_flight {
        let Some(target) = pending_iter.next() else {
            break;
        };
        let state = state.clone();
        let cache_entry_id = cache_entry_id.to_string();
        let in_flight = tasks.len().saturating_add(1);
        *max_observed_concurrency = (*max_observed_concurrency).max(in_flight);
        let prefetch_semaphore = state.blob_prefetch_semaphore.clone();
        tasks.spawn(async move {
            let size_bytes = target.blob.size_bytes;
            let prefetch_permit = prefetch_semaphore
                .acquire_owned()
                .await
                .map_err(|error| format!("prefetch semaphore closed: {error}"));
            let permit = match prefetch_permit {
                Ok(permit) => permit,
                Err(error) => {
                    return StartupPrefetchTaskReport {
                        inserted: false,
                        size_bytes,
                        duration_ms: 0,
                        status: None,
                        retry_after: None,
                        error: Some(error),
                    };
                }
            };
            let started_at = std::time::Instant::now();
            let result =
                preload_single_blob(state, cache_entry_id, target.blob, target.cached_url).await;
            drop(permit);
            let duration_ms = started_at.elapsed().as_millis() as u64;
            let (inserted, status, retry_after, error) = match result {
                Ok(inserted) => (inserted, None, None, None),
                Err(error) => (
                    false,
                    Some(error.status),
                    error.retry_after,
                    Some(error.to_string()),
                ),
            };
            StartupPrefetchTaskReport {
                inserted,
                size_bytes,
                duration_ms,
                status,
                retry_after,
                error,
            }
        });
    }
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
                    initial_concurrency: concurrency_plan.initial_concurrency,
                    concurrency_source: concurrency_plan.source,
                    concurrency_reason: concurrency_plan.reason,
                });

            if diagnostics {
                eprintln!(
                    "Prefetch: {count} entries loaded, hydrating full tag locally ({} blobs, {:.1} MB, concurrency_initial={}, concurrency_ceiling={}, resource_max={}, source={}, reason={}, adaptive={})",
                    total_unique_blobs,
                    total_unique_bytes as f64 / (1024.0 * 1024.0),
                    concurrency_plan.initial_concurrency,
                    concurrency_plan.effective_concurrency,
                    concurrency_plan.max_concurrency,
                    concurrency_plan.source,
                    concurrency_plan.reason,
                    concurrency_plan.adaptive,
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
    state.prefetch_metrics.record_startup_concurrency_observed(
        stats.final_concurrency,
        stats.max_observed_concurrency,
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
