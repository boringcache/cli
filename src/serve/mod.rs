pub mod cache_registry;
pub mod error;
pub mod handlers;
pub mod routes;
pub mod state;

use anyhow::{Context, Result};
use axum::serve::ListenerExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::{lookup_host, TcpListener, TcpSocket};
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::api::client::ApiClient;
use crate::observability;
use crate::serve::state::{
    diagnostics_enabled, unix_time_ms_now, AppState, BlobLocatorCache, BlobReadCache,
    KvPendingStore, KvPublishedIndex, KvReplicationWork, UploadSessionStore,
    DEFAULT_BLOB_READ_CACHE_MAX_BYTES, KV_BACKLOG_POLICY, KV_REPLICATION_WORK_QUEUE_CAPACITY,
};
use crate::tag_utils::TagResolver;

const KV_REFRESH_TASK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const KV_REPLICATION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const BLOB_DOWNLOAD_CONCURRENCY_ENV: &str = "BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY";
const CACHE_PREFETCH_CONCURRENCY_ENV: &str = "BORINGCACHE_CACHE_PREFETCH_CONCURRENCY";
const TCP_LISTEN_BACKLOG_ENV: &str = "BORINGCACHE_TCP_LISTEN_BACKLOG";
const DEFAULT_TCP_LISTEN_BACKLOG: u32 = 1024;

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
    let (state, listener, replication_rx) = build_server_runtime(
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

    spawn_maintenance_tasks(&state, replication_rx);
    let router = routes::build_router(state.clone());

    let listener = listener.tap_io(|tcp_stream| {
        let _ = tcp_stream.set_nodelay(true);
    });

    if state.kv_manifest_warm_enabled {
        let prefetch_state = state.clone();
        tokio::spawn(async move {
            cache_registry::prefetch_manifest_blobs(&prefetch_state).await;
            prefetch_state
                .prefetch_complete
                .store(true, Ordering::Release);
        });
    } else {
        state.prefetch_complete.store(true, Ordering::Release);
    }

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
    let (state, listener, replication_rx) = build_server_runtime(
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

    spawn_maintenance_tasks(&state, replication_rx);

    if state.kv_manifest_warm_enabled {
        let prefetch_state = state.clone();
        tokio::spawn(async move {
            cache_registry::prefetch_manifest_blobs(&prefetch_state).await;
            prefetch_state
                .prefetch_complete
                .store(true, Ordering::Release);
        });
    } else {
        state.prefetch_complete.store(true, Ordering::Release);
    }

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
) -> Result<(AppState, TcpListener, mpsc::Receiver<KvReplicationWork>)> {
    let blob_read_cache = Arc::new(BlobReadCache::new(blob_read_cache_max_bytes())?);
    let (dl_concurrency, dl_from_env) = blob_download_concurrency();
    let (pf_concurrency, pf_from_env) = blob_prefetch_concurrency(dl_concurrency);
    let (kv_replication_work_tx, kv_replication_work_rx) =
        mpsc::channel(KV_REPLICATION_WORK_QUEUE_CAPACITY);
    let blob_download_semaphore = Arc::new(tokio::sync::Semaphore::new(dl_concurrency));
    let blob_prefetch_semaphore = Arc::new(tokio::sync::Semaphore::new(dl_concurrency));
    let state = AppState {
        api_client,
        workspace: workspace.clone(),
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        fail_on_cache_error,
        kv_manifest_warm_enabled: true,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(tokio::sync::Mutex::new(())),
        kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        kv_last_put: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_backlog_rejects: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_enqueue_deferred: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_conflict: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_error: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_flush_permanent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_queue_depth: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        kv_replication_work_tx,
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
        kv_put_semaphore: Arc::new(tokio::sync::Semaphore::new(state::kv_put_max_concurrent())),
        prefetch_complete: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    let addr = format!("{host}:{port}");
    let mut resolved = lookup_host(&addr)
        .await
        .with_context(|| format!("failed to resolve bind address {addr}"))?;
    let bind_addr = resolved
        .next()
        .with_context(|| format!("no bind addresses resolved for {addr}"))?;

    let listen_backlog = tcp_listen_backlog();
    let socket = if bind_addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(bind_addr)?;
    let listener = socket.listen(listen_backlog)?;

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
    eprintln!("  Replication queue: {KV_REPLICATION_WORK_QUEUE_CAPACITY} (bounded)");
    eprintln!(
        "  Manifest warm: {} (auto)",
        if state.kv_manifest_warm_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    eprintln!("  KV backlog policy: {KV_BACKLOG_POLICY}");
    eprintln!(
        "  TCP listen backlog: {listen_backlog} ({})",
        if std::env::var(TCP_LISTEN_BACKLOG_ENV).is_ok() {
            "env"
        } else {
            "default"
        }
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

    Ok((state, listener, kv_replication_work_rx))
}

fn spawn_maintenance_tasks(
    state: &AppState,
    mut replication_rx: mpsc::Receiver<KvReplicationWork>,
) {
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
                let (pending_count, pending_bytes, pending_oldest_ms) = {
                    let now_ms = unix_time_ms_now();
                    let p = heartbeat_state.kv_pending.read().await;
                    (
                        p.entry_count(),
                        p.total_spool_bytes(),
                        p.oldest_entry_age_ms(now_ms).unwrap_or(0),
                    )
                };
                let published_count = {
                    let p = heartbeat_state.kv_published_index.read().await;
                    p.entry_count()
                };
                let flush_gate_delay_ms = {
                    let gate = heartbeat_state.kv_next_flush_at.read().await;
                    gate.map(|next| {
                        next.saturating_duration_since(std::time::Instant::now())
                            .as_millis() as u64
                    })
                    .unwrap_or(0)
                };
                let flights = heartbeat_state.kv_lookup_inflight.len();
                let cache_bytes = heartbeat_state.blob_read_cache.total_bytes();
                let breaker_open = heartbeat_state.backend_breaker.is_open();
                let (inflight, total) = cache_registry::request_counters();
                let cache_ops_queue_depth = heartbeat_state.cache_ops.queue_depth();
                let cache_ops_dropped_total = heartbeat_state.cache_ops.dropped_events_total();
                let observability_queue_depth = observability::queue_depth();
                let observability_dropped_total = observability::dropped_events_total();
                let backlog_rejects = heartbeat_state.kv_backlog_rejects.load(Ordering::Acquire);
                let replication_deferred = heartbeat_state
                    .kv_replication_enqueue_deferred
                    .load(Ordering::Acquire);
                let replication_queue_depth = heartbeat_state
                    .kv_replication_queue_depth
                    .load(Ordering::Acquire);
                let replication_flush_ok = heartbeat_state
                    .kv_replication_flush_ok
                    .load(Ordering::Acquire);
                let replication_flush_conflict = heartbeat_state
                    .kv_replication_flush_conflict
                    .load(Ordering::Acquire);
                let replication_flush_error = heartbeat_state
                    .kv_replication_flush_error
                    .load(Ordering::Acquire);
                let replication_flush_permanent = heartbeat_state
                    .kv_replication_flush_permanent
                    .load(Ordering::Acquire);
                eprintln!(
                    "HEARTBEAT ts={ts} reqs={total} inflight={inflight} pending={} pending_bytes={} pending_oldest_ms={} flush_gate_ms={} backlog_rejects={} repl_q={} repl_q_max={} repl_deferred={} repl_ok={} repl_conflict={} repl_error={} repl_permanent={} published={} flights={} cache_bytes={} breaker={} ops_q={} ops_drop={} obs_q={} obs_drop={}",
                    pending_count,
                    pending_bytes,
                    pending_oldest_ms,
                    flush_gate_delay_ms,
                    backlog_rejects,
                    replication_queue_depth,
                    KV_REPLICATION_WORK_QUEUE_CAPACITY,
                    replication_deferred,
                    replication_flush_ok,
                    replication_flush_conflict,
                    replication_flush_error,
                    replication_flush_permanent,
                    published_count,
                    flights,
                    cache_bytes,
                    if breaker_open { "OPEN" } else { "closed" },
                    cache_ops_queue_depth,
                    cache_ops_dropped_total,
                    observability_queue_depth,
                    observability_dropped_total,
                );
            }
        });
    }

    let version_poll_state = state.clone();
    tokio::spawn(async move {
        cache_registry::poll_tag_version_loop(&version_poll_state).await;
    });

    let refresh_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
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

    let replication_state = state.clone();
    tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        while let Some(work) = replication_rx.recv().await {
            decrement_replication_queue_depth(&replication_state);
            let mut urgent = matches!(work, KvReplicationWork::FlushHint { urgent: true });
            while let Ok(extra) = replication_rx.try_recv() {
                decrement_replication_queue_depth(&replication_state);
                if matches!(extra, KvReplicationWork::FlushHint { urgent: true }) {
                    urgent = true;
                }
            }
            process_replication_work(&replication_state, urgent, &mut consecutive_failures).await;
        }
    });

    let sweep_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(KV_REPLICATION_SWEEP_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            let pending_count = {
                let pending = sweep_state.kv_pending.read().await;
                pending.entry_count()
            };
            if pending_count == 0 {
                continue;
            }

            if sweep_state
                .kv_replication_queue_depth
                .load(Ordering::Acquire)
                > 0
            {
                continue;
            }

            let _ = cache_registry::enqueue_replication_flush_hint(&sweep_state, false, false);
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

fn decrement_replication_queue_depth(state: &AppState) {
    let _ = state.kv_replication_queue_depth.fetch_update(
        Ordering::AcqRel,
        Ordering::Acquire,
        |depth| Some(depth.saturating_sub(1)),
    );
}

async fn should_flush_pending(state: &AppState, urgent: bool) -> bool {
    use crate::serve::state::FLUSH_SIZE_THRESHOLD;

    let pending = state.kv_pending.read().await;
    if pending.is_empty() {
        return false;
    }
    if urgent {
        return true;
    }
    if pending.blob_count() >= crate::serve::state::flush_blob_threshold()
        || pending.total_spool_bytes() >= FLUSH_SIZE_THRESHOLD
    {
        return true;
    }

    let last_put_ms = state.kv_last_put.load(Ordering::Acquire);
    last_put_ms > 0 && unix_time_ms_now().saturating_sub(last_put_ms) >= 10_000
}

async fn process_replication_work(state: &AppState, urgent: bool, consecutive_failures: &mut u32) {
    {
        let gate = state.kv_next_flush_at.read().await;
        if let Some(next) = *gate {
            if std::time::Instant::now() < next {
                return;
            }
        }
    }

    if *consecutive_failures > 0 {
        use rand::Rng;
        let base_secs: u64 = match *consecutive_failures {
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

    if !should_flush_pending(state, urgent).await {
        return;
    }

    let Some(_flush_guard) = cache_registry::try_schedule_flush(state) else {
        return;
    };
    let flush_result = cache_registry::flush_kv_index(state).await;
    update_consecutive_failures_on_flush_result(&flush_result, consecutive_failures);
    match flush_result {
        cache_registry::FlushResult::Ok => {
            let mut gate = state.kv_next_flush_at.write().await;
            *gate = None;
            state.kv_replication_flush_ok.fetch_add(1, Ordering::AcqRel);
        }
        cache_registry::FlushResult::Conflict => {
            state
                .kv_replication_flush_conflict
                .fetch_add(1, Ordering::AcqRel);
        }
        cache_registry::FlushResult::Error => {
            state
                .kv_replication_flush_error
                .fetch_add(1, Ordering::AcqRel);
        }
        cache_registry::FlushResult::Permanent => {
            let mut gate = state.kv_next_flush_at.write().await;
            *gate = None;
            state
                .kv_replication_flush_permanent
                .fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn update_consecutive_failures_on_flush_result(
    result: &cache_registry::FlushResult,
    consecutive_failures: &mut u32,
) {
    match result {
        cache_registry::FlushResult::Error => {
            *consecutive_failures = consecutive_failures.saturating_add(1);
        }
        cache_registry::FlushResult::Ok
        | cache_registry::FlushResult::Conflict
        | cache_registry::FlushResult::Permanent => {
            *consecutive_failures = 0;
        }
    }
}

async fn flush_cache_ops(state: &AppState) {
    if state.cache_ops.is_empty() {
        return;
    }
    let (rollups, missed_keys, sessions) = state.cache_ops.drain();
    if rollups.is_empty() && missed_keys.is_empty() && sessions.is_empty() {
        return;
    }
    let batch = crate::api::models::cache_rollups::BatchParams {
        rollups: rollups
            .iter()
            .map(|r| crate::api::models::cache_rollups::RollupParam {
                bucket_at: chrono::DateTime::from_timestamp(r.bucket_epoch_secs as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default(),
                session_id: r.session_id.clone(),
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
        sessions: sessions
            .iter()
            .map(|session| crate::api::models::cache_rollups::SessionParam {
                session_id: session.session_id.clone(),
                tool: session.tool.clone(),
                session_duration_ms: session.session_duration_ms,
                hit_count: session.hit_count,
                miss_count: session.miss_count,
                error_count: session.error_count,
                bytes_read: session.bytes_read,
                bytes_written: session.bytes_written,
                top_missed_keys: session
                    .top_missed_keys
                    .iter()
                    .map(
                        |miss| crate::api::models::cache_rollups::SessionMissedKeyParam {
                            key_hash: miss.key_hash.clone(),
                            miss_count: miss.miss_count,
                            sampled_key_prefix: miss.sampled_key_prefix.clone(),
                        },
                    )
                    .collect(),
            })
            .collect(),
    };
    if let Err(error) = state
        .api_client
        .send_cache_rollups(&state.workspace, batch)
        .await
    {
        state.cache_ops.restore(rollups, missed_keys, sessions);
        log::debug!("Cache ops flush failed: {error}");
    }
}

fn blob_read_cache_max_bytes() -> u64 {
    let resources = crate::platform::resources::SystemResources::detect();
    let auto_max = match resources.memory_strategy {
        crate::platform::resources::MemoryStrategy::Balanced => 1024_u64 * 1024 * 1024,
        crate::platform::resources::MemoryStrategy::Aggressive => DEFAULT_BLOB_READ_CACHE_MAX_BYTES,
        crate::platform::resources::MemoryStrategy::UltraAggressive => {
            DEFAULT_BLOB_READ_CACHE_MAX_BYTES.saturating_mul(2)
        }
    };
    auto_max.max(512_u64 * 1024 * 1024)
}

fn auto_transfer_concurrency() -> usize {
    let resources = crate::platform::resources::SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();
    resources.recommended_download_concurrency(is_ci)
}

fn parse_positive_usize_env(name: &str) -> Option<usize> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<usize>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
}

fn parse_positive_u32_env(name: &str) -> Option<u32> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u32>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
}

fn tcp_listen_backlog() -> u32 {
    parse_positive_u32_env(TCP_LISTEN_BACKLOG_ENV).unwrap_or(DEFAULT_TCP_LISTEN_BACKLOG)
}

fn blob_download_concurrency() -> (usize, bool) {
    if let Some(configured) = parse_positive_usize_env(BLOB_DOWNLOAD_CONCURRENCY_ENV) {
        return (configured, true);
    }
    (auto_transfer_concurrency(), false)
}

fn blob_prefetch_concurrency(download_concurrency: usize) -> (usize, bool) {
    let max_download = download_concurrency.max(1);
    if let Some(configured) = parse_positive_usize_env(CACHE_PREFETCH_CONCURRENCY_ENV) {
        return (configured.min(max_download), true);
    }
    let adaptive = (max_download / 4).clamp(2, 16).min(max_download);
    (adaptive.max(1), false)
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
            // A running flush drains kv_pending before publish finalization.
            // Wait for any in-flight flush to finish so shutdown cannot exit
            // mid-publish and lose persisted warm state for the next proxy start.
            {
                let _running_flush = state.kv_flush_lock.lock().await;
            }

            let pending_after_flush = {
                let pending = state.kv_pending.read().await;
                pending.entry_count()
            };
            if pending_after_flush == 0 {
                return;
            }
            continue;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_consecutive_failures_resets_on_conflict() {
        let mut consecutive_failures = 3;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Conflict,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 0);
    }

    #[test]
    fn update_consecutive_failures_increments_on_error() {
        let mut consecutive_failures = 2;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Error,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 3);
    }

    #[test]
    fn update_consecutive_failures_resets_on_ok_and_permanent() {
        let mut consecutive_failures = 2;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Ok,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 0);

        consecutive_failures = 5;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Permanent,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 0);
    }

    #[test]
    fn tcp_listen_backlog_defaults_when_unset_or_invalid() {
        unsafe {
            std::env::remove_var(TCP_LISTEN_BACKLOG_ENV);
        }
        assert_eq!(tcp_listen_backlog(), DEFAULT_TCP_LISTEN_BACKLOG);

        unsafe {
            std::env::set_var(TCP_LISTEN_BACKLOG_ENV, "0");
        }
        assert_eq!(tcp_listen_backlog(), DEFAULT_TCP_LISTEN_BACKLOG);

        unsafe {
            std::env::set_var(TCP_LISTEN_BACKLOG_ENV, "not-a-number");
        }
        assert_eq!(tcp_listen_backlog(), DEFAULT_TCP_LISTEN_BACKLOG);

        unsafe {
            std::env::remove_var(TCP_LISTEN_BACKLOG_ENV);
        }
    }

    #[test]
    fn tcp_listen_backlog_honors_positive_env_override() {
        unsafe {
            std::env::set_var(TCP_LISTEN_BACKLOG_ENV, "4096");
        }
        assert_eq!(tcp_listen_backlog(), 4096);
        unsafe {
            std::env::remove_var(TCP_LISTEN_BACKLOG_ENV);
        }
    }
}
