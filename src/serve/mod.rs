pub mod cache_registry;
pub mod error;
pub mod handlers;
pub mod routes;
pub mod state;

use anyhow::{Context, Result};
use axum::serve::ListenerExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, RwLock};

use crate::api::client::ApiClient;
use crate::serve::state::{
    diagnostics_enabled, env_bool, unix_time_ms_now, AppState, BlobLocatorCache, BlobReadCache,
    KvPendingStore, KvPublishedIndex, UploadSessionStore, WriteMode,
    DEFAULT_BLOB_READ_CACHE_MAX_BYTES,
};
use crate::tag_utils::TagResolver;

const KV_REFRESH_TASK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn spawn_runtime_watchdog(
    cache_ops: Arc<cache_registry::cache_ops::Aggregator>,
    diagnostics: bool,
) {
    let rt_handle = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(10));
            let mut stuck_count: u32 = 0;
            loop {
                let started_at = std::time::Instant::now();
                let ts = chrono::Utc::now().format("%H:%M:%S%.3f");
                let (tx, rx) = std::sync::mpsc::channel();
                rt_handle.spawn(async move {
                    let _ = tx.send(());
                });
                match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok(()) => {
                        if diagnostics && stuck_count > 0 {
                            eprintln!(
                                "WATCHDOG ts={ts} runtime=recovered after_stuck={stuck_count}"
                            );
                        }
                        cache_ops.record(
                            cache_registry::cache_ops::Tool::Runtime,
                            cache_registry::cache_ops::Op::Query,
                            cache_registry::cache_ops::OpResult::Hit,
                            false,
                            0,
                            started_at.elapsed().as_millis() as u64,
                        );
                        stuck_count = 0;
                    }
                    Err(_) => {
                        stuck_count += 1;
                        if diagnostics {
                            eprintln!("WATCHDOG ts={ts} runtime=STUCK consecutive={stuck_count}",);
                            crate::serve::cache_registry::dump_stuck_puts(5, 2_000);
                        }
                        cache_ops.record(
                            cache_registry::cache_ops::Tool::Runtime,
                            cache_registry::cache_ops::Op::Query,
                            cache_registry::cache_ops::OpResult::Error,
                            true,
                            0,
                            started_at.elapsed().as_millis() as u64,
                        );
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        })
        .expect("Failed to spawn watchdog thread");
}

pub struct ServeHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<Result<()>>,
    pub port: u16,
}

impl ServeHandle {
    pub async fn shutdown_and_flush(mut self) -> Result<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        self.server_task
            .await
            .context("Cache registry server task panicked")??;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
    registry_root_tag: String,
    fail_on_cache_error: bool,
) -> Result<()> {
    let (state, listener) = build_server_runtime(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        fail_on_cache_error,
    )
    .await?;

    spawn_maintenance_tasks(&state);
    let router = routes::build_router(state.clone());

    let listener = listener.tap_io(|tcp_stream| {
        let _ = tcp_stream.set_nodelay(true);
    });
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    eprintln!("Shutdown: flushing pending KV entries");
    flush_pending_on_shutdown(&state).await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_server_background(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
    registry_root_tag: String,
    fail_on_cache_error: bool,
) -> Result<ServeHandle> {
    let (state, listener) = build_server_runtime(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        fail_on_cache_error,
    )
    .await?;

    spawn_maintenance_tasks(&state);
    let router = routes::build_router(state.clone());
    let bound_port = listener
        .local_addr()
        .context("Failed to determine proxy port")?
        .port();

    let listener = listener.tap_io(|tcp_stream| {
        let _ = tcp_stream.set_nodelay(true);
    });
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal_with_channel(shutdown_rx))
            .await?;

        eprintln!("Shutdown: flushing pending KV entries");
        flush_pending_on_shutdown(&state).await;
        Ok(())
    });

    Ok(ServeHandle {
        shutdown_tx: Some(shutdown_tx),
        server_task,
        port: bound_port,
    })
}

#[allow(clippy::too_many_arguments)]
async fn build_server_runtime(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
    registry_root_tag: String,
    fail_on_cache_error: bool,
) -> Result<(AppState, TcpListener)> {
    let blob_read_cache = Arc::new(BlobReadCache::new(blob_read_cache_max_bytes())?);
    let (kv_warm_enabled, kv_warm_from_env) = kv_manifest_warm_enabled();
    let (write_mode, write_mode_from_env) = kv_write_mode();
    let (dl_concurrency, dl_from_env) = blob_download_concurrency();
    let (pf_concurrency, pf_from_env) = blob_prefetch_concurrency(dl_concurrency);
    let blob_download_semaphore = Arc::new(tokio::sync::Semaphore::new(dl_concurrency));
    let blob_prefetch_semaphore = Arc::new(tokio::sync::Semaphore::new(pf_concurrency));
    let state = AppState {
        api_client,
        workspace: workspace.clone(),
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        fail_on_cache_error,
        kv_manifest_warm_enabled: kv_warm_enabled,
        write_mode,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(tokio::sync::Mutex::new(())),
        kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        kv_last_put: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_next_flush_at: Arc::new(RwLock::new(None)),
        kv_flush_scheduled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_published_index: Arc::new(RwLock::new(KvPublishedIndex::default())),
        kv_flushing: Arc::new(RwLock::new(None)),
        kv_recent_misses: Arc::new(dashmap::DashMap::new()),
        kv_miss_generations: Arc::new(dashmap::DashMap::new()),
        blob_read_cache,
        blob_download_max_concurrency: dl_concurrency,
        blob_download_semaphore,
        blob_prefetch_semaphore,
        cache_ops: Arc::new(cache_registry::cache_ops::Aggregator::new()),
        oci_manifest_cache: Arc::new(dashmap::DashMap::new()),
        backend_breaker: Arc::new(state::BackendCircuitBreaker::new()),
    };

    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await?;

    eprintln!("BoringCache cache registry proxy listening on {addr}");
    eprintln!("  Workspace: {workspace}");
    if !state.configured_human_tags.is_empty() {
        eprintln!(
            "  OCI Human Tags: {}",
            state.configured_human_tags.join(", ")
        );
    }
    eprintln!("  Internal Registry Root Tag: {}", state.registry_root_tag);
    eprintln!(
        "  Strict Cache Errors: {}",
        if state.fail_on_cache_error {
            "enabled"
        } else {
            "disabled (best-effort)"
        }
    );
    eprintln!("  OCI: --cache-from/--cache-to type=registry,ref={host}:{port}/CACHE_NAME:TAG");
    eprintln!("  Bazel HTTP: http://{host}:{port}/ac/{{sha256}} and /cas/{{sha256}}");
    eprintln!("  Gradle HTTP: http://{host}:{port}/cache/{{cache-key}}");
    eprintln!(
        "  Maven cache: http://{host}:{port}/v1.1/{{groupId}}/{{artifactId}}/{{checksum}}/{{filename}} (also /v1/...)"
    );
    eprintln!("  Nx Cache: http://{host}:{port}/v1/cache/{{hash}}");
    eprintln!("  Turborepo: http://{host}:{port}/v8/artifacts/{{hash}}");
    eprintln!("  sccache WebDAV: http://{host}:{port}/<prefix>/a/b/c/<key>");
    eprintln!("  Go cache object API: http://{host}:{port}/gocache/{{action-id}}");
    eprintln!("  GOCACHEPROG helper: boringcache go-cacheprog --endpoint http://{host}:{port}");
    eprintln!(
        "  Blob Read Cache: {} (max {} bytes)",
        state.blob_read_cache.cache_dir().display(),
        state.blob_read_cache.max_bytes()
    );
    let src = |from_env: bool| if from_env { "env" } else { "auto" };
    let pf_label = if pf_concurrency == 0 {
        format!("disabled ({})", src(pf_from_env))
    } else {
        format!("{pf_concurrency} max ({})", src(pf_from_env))
    };
    eprintln!(
        "  Blob Download Concurrency: {dl_concurrency} max ({}), prefetch: {pf_label}",
        src(dl_from_env)
    );
    eprintln!(
        "  Manifest warm: {} ({})",
        if state.kv_manifest_warm_enabled {
            "enabled"
        } else {
            "disabled"
        },
        src(kv_warm_from_env)
    );
    eprintln!(
        "  KV write mode: {} ({})",
        match state.write_mode {
            WriteMode::WriteBack => "write_back",
            WriteMode::WriteThrough => "write_through",
        },
        src(write_mode_from_env)
    );

    for dir_name in ["boringcache-kv-blobs", "boringcache-uploads"] {
        let stale_dir = std::env::temp_dir().join(dir_name);
        if stale_dir.exists() {
            let _ = tokio::fs::remove_dir_all(&stale_dir).await;
        }
    }
    tokio::fs::create_dir_all(std::env::temp_dir().join("boringcache-kv-blobs"))
        .await
        .context("Failed to create KV temp dir")?;

    Ok((state, listener))
}

fn spawn_maintenance_tasks(state: &AppState) {
    let diagnostics = diagnostics_enabled();
    spawn_runtime_watchdog(state.cache_ops.clone(), diagnostics);

    if diagnostics {
        let heartbeat_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            interval.tick().await;
            loop {
                interval.tick().await;
                let ts = chrono::Utc::now().format("%H:%M:%S");
                eprintln!("HEARTBEAT ts={ts} phase=tick");
                let pending_count = {
                    let p = heartbeat_state.kv_pending.read().await;
                    p.entry_count()
                };
                let published_count = {
                    let p = heartbeat_state.kv_published_index.read().await;
                    p.entry_count()
                };
                let flights = heartbeat_state.kv_lookup_inflight.len();
                let cache_bytes = heartbeat_state.blob_read_cache.total_bytes();
                let breaker_open = heartbeat_state.backend_breaker.is_open();
                let (inflight, total) = cache_registry::request_counters();
                let cache_ops_queue_depth = heartbeat_state.cache_ops.queue_depth();
                let cache_ops_dropped_total = heartbeat_state.cache_ops.dropped_events_total();
                eprintln!(
                    "HEARTBEAT ts={ts} reqs={total} inflight={inflight} pending={} published={} flights={} cache_bytes={} breaker={} ops_q={} ops_drop={}",
                    pending_count,
                    published_count,
                    flights,
                    cache_bytes,
                    if breaker_open { "OPEN" } else { "closed" },
                    cache_ops_queue_depth,
                    cache_ops_dropped_total,
                );
            }
        });
    }

    if state.kv_manifest_warm_enabled {
        let preload_state = state.clone();
        tokio::spawn(async move {
            cache_registry::preload_kv_index(&preload_state).await;
        });
    }

    let refresh_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            if tokio::time::timeout(
                KV_REFRESH_TASK_TIMEOUT,
                cache_registry::refresh_kv_index(&refresh_state),
            )
            .await
            .is_err()
            {
                log::warn!(
                    "KV index refresh timed out after {}s",
                    KV_REFRESH_TASK_TIMEOUT.as_secs()
                );
            }
        }
    });

    let miss_cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            cache_registry::cleanup_expired_kv_misses(&miss_cleanup_state);
        }
    });

    let upload_sessions = state.upload_sessions.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let expired = {
                let mut sessions = upload_sessions.write().await;
                sessions.cleanup_expired(std::time::Duration::from_secs(1800))
            };
            for session in expired {
                let _ = tokio::fs::remove_file(&session.temp_path).await;
            }
        }
    });

    let flush_state = state.clone();
    tokio::spawn(async move {
        use crate::serve::state::{FLUSH_BLOB_THRESHOLD, FLUSH_SIZE_THRESHOLD};
        use rand::Rng;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.tick().await;
        let mut consecutive_failures: u32 = 0;
        loop {
            interval.tick().await;

            {
                let gate = flush_state.kv_next_flush_at.read().await;
                if let Some(next) = *gate {
                    if std::time::Instant::now() < next {
                        continue;
                    }
                }
            }

            if consecutive_failures > 0 {
                let base_secs: u64 = match consecutive_failures {
                    1 => 2,
                    2 => 5,
                    3 => 15,
                    4 => 30,
                    _ => 60,
                };
                let jitter_ms: u64 = rand::thread_rng().gen_range(0..3000);
                tokio::time::sleep(std::time::Duration::from_millis(
                    base_secs * 1000 + jitter_ms,
                ))
                .await;
            }

            let should_flush = {
                let pending = flush_state.kv_pending.read().await;
                if pending.is_empty() {
                    false
                } else if pending.blob_count() >= FLUSH_BLOB_THRESHOLD
                    || pending.total_spool_bytes() >= FLUSH_SIZE_THRESHOLD
                {
                    true
                } else {
                    let last_put_ms = flush_state.kv_last_put.load(Ordering::Acquire);
                    last_put_ms > 0 && unix_time_ms_now().saturating_sub(last_put_ms) >= 10_000
                }
            };

            if should_flush {
                let Some(_flush_guard) = cache_registry::try_schedule_flush(&flush_state) else {
                    continue;
                };
                match cache_registry::flush_kv_index(&flush_state).await {
                    cache_registry::FlushResult::Ok => {
                        consecutive_failures = 0;
                        let mut gate = flush_state.kv_next_flush_at.write().await;
                        *gate = None;
                    }
                    cache_registry::FlushResult::Conflict => {}
                    cache_registry::FlushResult::Error => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                    }
                    cache_registry::FlushResult::Permanent => {
                        consecutive_failures = 0;
                        let mut gate = flush_state.kv_next_flush_at.write().await;
                        *gate = None;
                    }
                }
            }
        }
    });

    let ops_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            flush_cache_ops(&ops_state).await;
        }
    });
}

async fn flush_cache_ops(state: &AppState) {
    if state.cache_ops.is_empty() {
        return;
    }
    let (rollups, missed_keys) = state.cache_ops.drain();
    if rollups.is_empty() && missed_keys.is_empty() {
        return;
    }
    let batch = crate::api::models::cache_rollups::BatchParams {
        rollups: rollups
            .iter()
            .map(|r| crate::api::models::cache_rollups::RollupParam {
                bucket_at: chrono::DateTime::from_timestamp(r.bucket_epoch_secs as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default(),
                tool: r.tool.clone(),
                operation: r.operation.clone(),
                result: r.result.clone(),
                degraded: r.degraded,
                event_count: r.event_count,
                bytes_total: r.bytes_total,
                latency_sum_ms: r.latency_sum_ms,
                latency_count: r.latency_count,
            })
            .collect(),
        missed_keys: missed_keys
            .iter()
            .map(|mk| crate::api::models::cache_rollups::MissedKeyParam {
                key_hash: mk.key_hash.clone(),
                tool: mk.tool.clone(),
                miss_count: mk.miss_count,
                sampled_key_prefix: mk.sampled_key_prefix.clone(),
            })
            .collect(),
    };
    if let Err(error) = state
        .api_client
        .send_cache_rollups(&state.workspace, batch)
        .await
    {
        state.cache_ops.restore(rollups, missed_keys);
        log::debug!("Cache ops flush failed: {error}");
    }
}

fn blob_read_cache_max_bytes() -> u64 {
    std::env::var("BORINGCACHE_BLOB_READ_CACHE_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_BLOB_READ_CACHE_MAX_BYTES)
}

fn kv_manifest_warm_enabled() -> (bool, bool) {
    if let Some(enabled) = env_bool("BORINGCACHE_KV_MANIFEST_WARM") {
        return (enabled, true);
    }

    (true, false)
}

fn kv_write_mode() -> (WriteMode, bool) {
    let Some(raw_mode) = std::env::var("BORINGCACHE_KV_WRITE_MODE").ok() else {
        return (WriteMode::WriteBack, false);
    };

    let normalized = raw_mode.trim().to_ascii_lowercase();
    let mode = match normalized.as_str() {
        "write_back" | "write-back" | "wb" => Some(WriteMode::WriteBack),
        "write_through" | "write-through" | "wt" => Some(WriteMode::WriteThrough),
        _ => None,
    };

    match mode {
        Some(mode) => (mode, true),
        None => {
            log::warn!("Invalid BORINGCACHE_KV_WRITE_MODE={raw_mode}; defaulting to write_back");
            (WriteMode::WriteBack, false)
        }
    }
}

fn blob_download_concurrency() -> (usize, bool) {
    if let Some(configured) = std::env::var("BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
    {
        return (configured.clamp(1, 128), true);
    }

    use crate::platform::resources::{MemoryStrategy, SystemResources};
    let resources = SystemResources::detect();
    let mut n = resources.max_parallel_chunks.clamp(2, 16);
    if matches!(resources.memory_strategy, MemoryStrategy::Balanced) {
        n = n.min(8);
    }
    (n, false)
}

fn blob_prefetch_concurrency(download_concurrency: usize) -> (usize, bool) {
    if let Some(configured) = std::env::var("BORINGCACHE_BLOB_PREFETCH_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    {
        return (configured.clamp(0, 16), true);
    }

    use crate::platform::resources::{MemoryStrategy, SystemResources};
    let resources = SystemResources::detect();
    if matches!(resources.memory_strategy, MemoryStrategy::Balanced) {
        return (1, false);
    }
    ((download_concurrency / 8).clamp(1, 2), false)
}

async fn flush_pending_on_shutdown(state: &AppState) {
    flush_cache_ops(state).await;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);

    loop {
        let pending_entries = {
            let pending = state.kv_pending.read().await;
            pending.entry_count()
        };
        if pending_entries == 0 {
            return;
        }

        if let Some(_flush_guard) = cache_registry::try_schedule_flush(state) {
            match cache_registry::flush_kv_index(state).await {
                cache_registry::FlushResult::Ok | cache_registry::FlushResult::Permanent => {
                    let mut gate = state.kv_next_flush_at.write().await;
                    *gate = None;
                }
                cache_registry::FlushResult::Conflict | cache_registry::FlushResult::Error => {}
            }
        } else {
            let _running_flush = state.kv_flush_lock.lock().await;
            drop(_running_flush);
        }

        if std::time::Instant::now() >= deadline {
            let pending_entries = {
                let pending = state.kv_pending.read().await;
                pending.entry_count()
            };
            eprintln!(
                "Shutdown: flush timeout reached with {pending_entries} pending entries remaining"
            );
            return;
        }

        let delay = {
            let gate = state.kv_next_flush_at.read().await;
            match *gate {
                Some(next) => next.saturating_duration_since(std::time::Instant::now()),
                None => std::time::Duration::from_secs(1),
            }
        };
        tokio::time::sleep(delay.min(std::time::Duration::from_secs(10))).await;
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            log::warn!("Failed to install Ctrl+C handler: {error}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                log::warn!("Failed to install SIGTERM handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    eprintln!("\nShutting down...");
}

async fn shutdown_signal_with_channel(mut shutdown_rx: oneshot::Receiver<()>) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            log::warn!("Failed to install Ctrl+C handler: {error}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                log::warn!("Failed to install SIGTERM handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = &mut shutdown_rx => {},
    }

    eprintln!("\nShutting down...");
}
