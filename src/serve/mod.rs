pub mod cache_registry;
pub mod cas_publish;
pub mod error;
pub mod handlers;
pub(crate) mod oci_route;
pub(crate) mod oci_tags;
pub mod routes;
pub mod state;

use anyhow::{Context, Result};
use axum::serve::ListenerExt;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpListener, TcpSocket, lookup_host};
use tokio::sync::{RwLock, mpsc, oneshot};
use tower::ServiceExt;

use crate::api::client::ApiClient;
use crate::observability;
use crate::serve::state::{
    AppState, BlobLocatorCache, BlobReadCache, BlobReadMetrics, CacheRegistryTuningProfile,
    DEFAULT_BLOB_READ_CACHE_MAX_BYTES, KV_BACKLOG_POLICY, KV_REPLICATION_WORK_QUEUE_CAPACITY,
    KvPendingStore, KvPublishedIndex, KvReplicationWork, UploadSessionStore, diagnostics_enabled,
    unix_time_ms_now,
};
use crate::tag_utils::TagResolver;

const KV_REFRESH_TASK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const KV_REPLICATION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const KV_IDLE_FLUSH_WINDOW_DEFAULT_MS: u64 = 10_000;
const KV_IDLE_FLUSH_WINDOW_SMALL_BATCH_MS: u64 = 2_000;
const KV_SMALL_BATCH_IDLE_FLUSH_MAX_BLOBS: usize = 64;
const KV_SMALL_BATCH_IDLE_FLUSH_MAX_BYTES: u64 = 64 * 1024 * 1024;
const BLOB_DOWNLOAD_CONCURRENCY_ENV: &str = "BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY";
const CACHE_PREFETCH_CONCURRENCY_ENV: &str = "BORINGCACHE_CACHE_PREFETCH_CONCURRENCY";
const BLOB_READ_CACHE_MAX_BYTES_ENV: &str = "BORINGCACHE_BLOB_READ_CACHE_MAX_BYTES";
const TCP_LISTEN_BACKLOG_ENV: &str = "BORINGCACHE_TCP_LISTEN_BACKLOG";
const DEFAULT_TCP_LISTEN_BACKLOG: u32 = 1024;
const HTTP_VERSION_ENV: &str = "BORINGCACHE_HTTP_VERSION";
const PUBLIC_PROXY_TUNING_ENVS: &[&str] =
    &[BLOB_DOWNLOAD_CONCURRENCY_ENV, BLOB_READ_CACHE_MAX_BYTES_ENV];
const INTERNAL_PROXY_TUNING_ENVS: &[&str] = &[
    CACHE_PREFETCH_CONCURRENCY_ENV,
    "BORINGCACHE_CACHE_PREFETCH_BATCH_MAX",
    "BORINGCACHE_CACHE_PREFETCH_MAX_BLOB_BYTES",
    "BORINGCACHE_STARTUP_PREFETCH_MAX_BLOBS",
    "BORINGCACHE_STARTUP_PREFETCH_MAX_TOTAL_BYTES",
    "BORINGCACHE_BLOB_PREFETCH_MAX_INFLIGHT_BYTES",
    "BORINGCACHE_CACHE_CHECK_BATCH_MAX",
    "BORINGCACHE_CACHE_CHECK_BATCH_CONCURRENCY",
    "BORINGCACHE_CACHE_URL_BATCH_MAX",
    "BORINGCACHE_CACHE_URL_BATCH_CONCURRENCY",
];
const H2_INITIAL_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
const H2_INITIAL_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
const H2_MAX_CONCURRENT_STREAMS: u32 = 1024;
const RUNTIME_TEMP_DIR_PREFIX: &str = "boringcache-proxy";
const SHUTDOWN_TAG_VISIBILITY_HANDOFF_GRACE: std::time::Duration =
    std::time::Duration::from_secs(5);

fn new_runtime_temp_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "{RUNTIME_TEMP_DIR_PREFIX}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create runtime temp dir {}", dir.display()))?;
    Ok(dir)
}

async fn cleanup_runtime_temp_dir(state: &AppState) {
    if cache_registry::should_preserve_runtime_temp_dir_for_shutdown_handoff(state).await {
        eprintln!(
            "Shutdown: preserving runtime temp dir {} for pending upload handoff",
            state.runtime_temp_dir.display()
        );
        return;
    }
    if let Err(error) = tokio::fs::remove_dir_all(&state.runtime_temp_dir).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!(
            "Failed to clean runtime temp dir {}: {error}",
            state.runtime_temp_dir.display()
        );
    }
}

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
    shutdown_requested: Arc<AtomicBool>,
    pub port: u16,
}

impl ServeHandle {
    pub async fn shutdown_and_flush(mut self) -> Result<()> {
        self.shutdown_requested.store(true, Ordering::Release);
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
    proxy_metadata_hints: BTreeMap<String, String>,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<()> {
    let (state, listener, replication_rx) = build_server_runtime(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        proxy_metadata_hints,
        fail_on_cache_error,
        read_only,
    )
    .await?;

    spawn_maintenance_tasks(&state, replication_rx);
    let router = routes::build_router(state.clone());

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

    if force_http1() {
        eprintln!("  HTTP transport: h1 only ({}=1)", HTTP_VERSION_ENV);
        let listener = listener.tap_io(|tcp_stream| {
            let _ = tcp_stream.set_nodelay(true);
        });
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal(state.shutdown_requested.clone()))
            .await?;
    } else {
        serve_with_h2c(
            listener,
            router,
            shutdown_signal(state.shutdown_requested.clone()),
        )
        .await?;
    }

    eprintln!("Shutdown: flushing pending KV entries");
    flush_pending_on_shutdown(&state).await;
    cleanup_runtime_temp_dir(&state).await;

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
    proxy_metadata_hints: BTreeMap<String, String>,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<ServeHandle> {
    let (state, listener, replication_rx) = build_server_runtime(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        proxy_metadata_hints,
        fail_on_cache_error,
        read_only,
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

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shutdown_requested = state.shutdown_requested.clone();
    let shutdown_handle_flag = state.shutdown_requested.clone();
    let server_state = state.clone();
    let server_task = tokio::spawn(async move {
        let shutdown = shutdown_signal_with_channel(shutdown_rx, shutdown_requested);
        if force_http1() {
            let listener = listener.tap_io(|tcp_stream| {
                let _ = tcp_stream.set_nodelay(true);
            });
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown)
                .await?;
        } else {
            serve_with_h2c(listener, router, shutdown).await?;
        }

        eprintln!("Shutdown: flushing pending KV entries");
        flush_pending_on_shutdown(&server_state).await;
        cleanup_runtime_temp_dir(&server_state).await;
        Ok(())
    });

    Ok(ServeHandle {
        shutdown_tx: Some(shutdown_tx),
        server_task,
        shutdown_requested: shutdown_handle_flag,
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
    proxy_metadata_hints: BTreeMap<String, String>,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<(AppState, TcpListener, mpsc::Receiver<KvReplicationWork>)> {
    let tuning_profile =
        cache_registry_tuning_profile(&configured_human_tags, &proxy_metadata_hints);
    let blob_read_cache = Arc::new(BlobReadCache::new(blob_read_cache_max_bytes(
        tuning_profile,
    ))?);
    let blob_read_metrics = Arc::new(BlobReadMetrics::new());
    let prefetch_metrics = Arc::new(state::PrefetchMetrics::new());
    let (dl_concurrency, dl_from_env) = blob_download_concurrency(tuning_profile);
    let (pf_concurrency, pf_from_env) = blob_prefetch_concurrency(dl_concurrency, tuning_profile);
    let (kv_replication_work_tx, kv_replication_work_rx) =
        mpsc::channel(KV_REPLICATION_WORK_QUEUE_CAPACITY);
    let blob_download_semaphore = Arc::new(tokio::sync::Semaphore::new(dl_concurrency));
    let blob_prefetch_semaphore = Arc::new(tokio::sync::Semaphore::new(pf_concurrency));
    let runtime_temp_dir = new_runtime_temp_dir()?;
    let kv_blob_temp_dir = runtime_temp_dir.join("kv-blobs");
    let oci_upload_temp_dir = runtime_temp_dir.join("oci-uploads");
    std::fs::create_dir_all(&kv_blob_temp_dir).with_context(|| {
        format!(
            "Failed to create KV blob temp dir {}",
            kv_blob_temp_dir.display()
        )
    })?;
    std::fs::create_dir_all(&oci_upload_temp_dir).with_context(|| {
        format!(
            "Failed to create OCI upload temp dir {}",
            oci_upload_temp_dir.display()
        )
    })?;
    let state = AppState {
        api_client,
        workspace: workspace.clone(),
        runtime_temp_dir,
        kv_blob_temp_dir,
        oci_upload_temp_dir,
        read_only,
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
        shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_recent_misses: Arc::new(dashmap::DashMap::new()),
        kv_miss_generations: Arc::new(dashmap::DashMap::new()),
        blob_read_cache,
        blob_read_metrics,
        prefetch_metrics,
        tuning_profile,
        blob_download_max_concurrency: dl_concurrency,
        blob_download_semaphore,
        blob_prefetch_semaphore,
        cache_ops: Arc::new(
            cache_registry::cache_ops::Aggregator::new_with_metadata_hints(
                proxy_metadata_hints.clone(),
            ),
        ),
        oci_manifest_cache: Arc::new(dashmap::DashMap::new()),
        backend_breaker: Arc::new(state::BackendCircuitBreaker::new()),
        prefetch_complete: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    cache_registry::restore_kv_pending_publish_handoff(&state).await;

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
    if state.read_only {
        eprintln!("  Mode: read-only");
    }
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
    if proxy_metadata_hints.is_empty() {
        eprintln!("  Proxy Metadata Hints: none");
    } else {
        eprintln!(
            "  Proxy Metadata Hints: {}",
            proxy_metadata_hints
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
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
    eprintln!("  Tuning Profile: {}", state.tuning_profile.as_str());
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
    let expert_overrides = configured_env_overrides(PUBLIC_PROXY_TUNING_ENVS);
    if expert_overrides.is_empty() {
        eprintln!("  Expert Tuning Overrides: none");
    } else {
        eprintln!("  Expert Tuning Overrides: {}", expert_overrides.join(", "));
    }
    let internal_overrides = configured_env_overrides(INTERNAL_PROXY_TUNING_ENVS);
    if !internal_overrides.is_empty() {
        eprintln!(
            "  Internal Debug Overrides: {}",
            internal_overrides.join(", ")
        );
    }
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
    eprintln!("  Runtime Temp: {}", state.runtime_temp_dir.display());

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
        loop {
            let next_work = replication_rx.recv().await;
            let Some(work) = next_work else {
                break;
            };
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
    let pending_blob_count = pending.blob_count();
    let pending_spool_bytes = pending.total_spool_bytes();
    let last_put_ms = state.kv_last_put.load(Ordering::Acquire);
    should_flush_pending_values(
        urgent,
        pending_blob_count,
        pending_spool_bytes,
        last_put_ms,
        unix_time_ms_now(),
        crate::serve::state::flush_blob_threshold(),
        FLUSH_SIZE_THRESHOLD,
    )
}

fn flush_idle_window_ms(pending_blob_count: usize, pending_spool_bytes: u64) -> u64 {
    if pending_blob_count <= KV_SMALL_BATCH_IDLE_FLUSH_MAX_BLOBS
        && pending_spool_bytes <= KV_SMALL_BATCH_IDLE_FLUSH_MAX_BYTES
    {
        return KV_IDLE_FLUSH_WINDOW_SMALL_BATCH_MS;
    }

    KV_IDLE_FLUSH_WINDOW_DEFAULT_MS
}

fn should_flush_pending_values(
    urgent: bool,
    pending_blob_count: usize,
    pending_spool_bytes: u64,
    last_put_ms: u64,
    now_ms: u64,
    flush_blob_threshold: usize,
    flush_size_threshold: u64,
) -> bool {
    if pending_blob_count == 0 {
        return false;
    }
    if urgent {
        return true;
    }
    if pending_blob_count >= flush_blob_threshold || pending_spool_bytes >= flush_size_threshold {
        return true;
    }

    let idle_window_ms = flush_idle_window_ms(pending_blob_count, pending_spool_bytes);
    if idle_window_ms == 0 {
        return true;
    }

    last_put_ms > 0 && now_ms.saturating_sub(last_put_ms) >= idle_window_ms
}

async fn process_replication_work(state: &AppState, urgent: bool, consecutive_failures: &mut u32) {
    {
        let gate = state.kv_next_flush_at.read().await;
        if let Some(next) = *gate
            && std::time::Instant::now() < next
        {
            return;
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
            let remaining_pending = {
                let pending = state.kv_pending.read().await;
                pending.entry_count()
            };
            if remaining_pending > 0 {
                eprintln!(
                    "KV flush: {remaining_pending} pending entries arrived during flush, scheduling follow-up"
                );
                let _ = cache_registry::enqueue_replication_flush_hint(state, true, false);
            }
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
        cache_registry::FlushResult::Deferred => {
            state
                .kv_replication_flush_error
                .fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn update_consecutive_failures_on_flush_result(
    result: &cache_registry::FlushResult,
    consecutive_failures: &mut u32,
) {
    match result {
        cache_registry::FlushResult::Error | cache_registry::FlushResult::Deferred => {
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
    let blob_read_hints = state.blob_read_metrics.metadata_hints();
    if !blob_read_hints.is_empty() {
        state
            .cache_ops
            .merge_session_metadata_hints(blob_read_hints);
    }
    let prefetch_hints = state.prefetch_metrics.metadata_hints();
    if !prefetch_hints.is_empty() {
        state.cache_ops.merge_session_metadata_hints(prefetch_hints);
    }
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
                metadata_hints: session.metadata_hints.clone(),
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

fn cache_registry_tuning_profile(
    configured_human_tags: &[String],
    proxy_metadata_hints: &BTreeMap<String, String>,
) -> CacheRegistryTuningProfile {
    let hinted_tool = proxy_metadata_hints.get("tool");
    let tag_matches = |needle: &str| {
        configured_human_tags.iter().any(|tag| {
            tag.split([':', ',', '/', '-', '_'])
                .any(|part| part.eq_ignore_ascii_case(needle))
        })
    };

    if hinted_tool.is_some_and(|tool| tool.eq_ignore_ascii_case("sccache"))
        || tag_matches("sccache")
    {
        CacheRegistryTuningProfile::Sccache
    } else if hinted_tool.is_some_and(|tool| tool.eq_ignore_ascii_case("bazel"))
        || tag_matches("bazel")
    {
        CacheRegistryTuningProfile::Bazel
    } else {
        CacheRegistryTuningProfile::Generic
    }
}

fn blob_read_cache_max_bytes(tuning_profile: CacheRegistryTuningProfile) -> u64 {
    if let Some(configured) = parse_positive_u64_env(BLOB_READ_CACHE_MAX_BYTES_ENV) {
        return configured;
    }

    let resources = crate::platform::resources::SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();
    let auto_max = match resources.memory_strategy {
        crate::platform::resources::MemoryStrategy::Balanced => {
            if is_ci {
                DEFAULT_BLOB_READ_CACHE_MAX_BYTES
            } else {
                1024_u64 * 1024 * 1024
            }
        }
        crate::platform::resources::MemoryStrategy::Aggressive => {
            if is_ci {
                DEFAULT_BLOB_READ_CACHE_MAX_BYTES.saturating_mul(2)
            } else {
                DEFAULT_BLOB_READ_CACHE_MAX_BYTES
            }
        }
        crate::platform::resources::MemoryStrategy::UltraAggressive => {
            DEFAULT_BLOB_READ_CACHE_MAX_BYTES.saturating_mul(2)
        }
    };
    let auto_max = match tuning_profile {
        CacheRegistryTuningProfile::Generic => auto_max,
        CacheRegistryTuningProfile::Bazel if is_ci => {
            auto_max.max(DEFAULT_BLOB_READ_CACHE_MAX_BYTES)
        }
        CacheRegistryTuningProfile::Bazel => auto_max,
        CacheRegistryTuningProfile::Sccache if is_ci => {
            auto_max.max(DEFAULT_BLOB_READ_CACHE_MAX_BYTES.saturating_mul(2))
        }
        CacheRegistryTuningProfile::Sccache => auto_max.max(DEFAULT_BLOB_READ_CACHE_MAX_BYTES),
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

fn parse_positive_u64_env(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u64>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
}

fn configured_env_overrides(names: &[&'static str]) -> Vec<&'static str> {
    names
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some())
        .collect()
}

fn tcp_listen_backlog() -> u32 {
    parse_positive_u32_env(TCP_LISTEN_BACKLOG_ENV).unwrap_or(DEFAULT_TCP_LISTEN_BACKLOG)
}

fn blob_download_concurrency(tuning_profile: CacheRegistryTuningProfile) -> (usize, bool) {
    if let Some(configured) = parse_positive_usize_env(BLOB_DOWNLOAD_CONCURRENCY_ENV) {
        return (configured, true);
    }

    let resources = crate::platform::resources::SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();
    let mut adaptive = auto_transfer_concurrency();

    let floor = match tuning_profile {
        CacheRegistryTuningProfile::Generic => 0,
        CacheRegistryTuningProfile::Bazel if is_ci => {
            if resources.available_memory_gb >= 8.0 && resources.cpu_cores >= 4 {
                12
            } else if resources.cpu_cores >= 4 {
                8
            } else {
                6
            }
        }
        CacheRegistryTuningProfile::Bazel => {
            if resources.available_memory_gb >= 8.0 && resources.cpu_cores >= 4 {
                6
            } else {
                4
            }
        }
        CacheRegistryTuningProfile::Sccache if is_ci => {
            if resources.available_memory_gb >= 12.0 && resources.cpu_cores >= 4 {
                16
            } else if resources.available_memory_gb >= 8.0 && resources.cpu_cores >= 4 {
                12
            } else if resources.cpu_cores >= 4 {
                8
            } else {
                6
            }
        }
        CacheRegistryTuningProfile::Sccache => {
            if resources.available_memory_gb >= 8.0 && resources.cpu_cores >= 4 {
                8
            } else {
                6
            }
        }
    };
    if floor > 0 {
        adaptive = adaptive.max(floor);
    }

    (adaptive.clamp(1, 32), false)
}

fn blob_prefetch_concurrency(
    download_concurrency: usize,
    tuning_profile: CacheRegistryTuningProfile,
) -> (usize, bool) {
    let max_download = download_concurrency.max(1);
    if let Some(configured) = parse_positive_usize_env(CACHE_PREFETCH_CONCURRENCY_ENV) {
        return (configured.min(max_download), true);
    }

    let adaptive = match tuning_profile {
        CacheRegistryTuningProfile::Generic => (max_download / 2).clamp(2, 16).min(max_download),
        CacheRegistryTuningProfile::Bazel => {
            ((max_download * 3) / 4).clamp(3, 16).min(max_download)
        }
        CacheRegistryTuningProfile::Sccache => max_download.clamp(4, 32).min(max_download),
    };
    (adaptive.max(1), false)
}

async fn flush_pending_on_shutdown(state: &AppState) {
    flush_cache_ops(state).await;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    let mut expected_root_cache_entry_id: Option<String> = None;

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
                if expected_root_cache_entry_id.is_none() {
                    expected_root_cache_entry_id = {
                        let published = state.kv_published_index.read().await;
                        published.cache_entry_id().map(|value| value.to_string())
                    };
                }
                if let Some(cache_entry_id) = expected_root_cache_entry_id.as_deref() {
                    if cache_registry::should_skip_shutdown_tag_visibility_wait(
                        state,
                        cache_entry_id,
                    )
                    .await
                    {
                        let handoff_deadline = shutdown_handoff_visibility_deadline(deadline);
                        if wait_for_tag_visibility(state, cache_entry_id, handoff_deadline).await {
                            return;
                        }
                        eprintln!(
                            "Shutdown: deferred tag visibility wait for cache_entry_id={} via pending publish handoff",
                            cache_entry_id
                        );
                    } else {
                        let _ = wait_for_tag_visibility(state, cache_entry_id, deadline).await;
                    }
                }
                return;
            }
            continue;
        }

        let flush_guard = cache_registry::try_schedule_flush(state);
        match flush_guard {
            Some(_flush_guard) => {
                let flush_result = cache_registry::flush_kv_index_on_shutdown(state).await;
                match flush_result {
                    cache_registry::FlushResult::Ok => {
                        let published_entry = {
                            let published = state.kv_published_index.read().await;
                            published.cache_entry_id().map(|value| value.to_string())
                        };
                        expected_root_cache_entry_id = published_entry;
                        {
                            let mut gate = state.kv_next_flush_at.write().await;
                            *gate = None;
                        }
                    }
                    cache_registry::FlushResult::Permanent => {
                        let mut gate = state.kv_next_flush_at.write().await;
                        *gate = None;
                    }
                    cache_registry::FlushResult::Deferred => {
                        let mut gate = state.kv_next_flush_at.write().await;
                        *gate = None;
                        eprintln!("Shutdown: deferred pending upload flush via restart handoff");
                        return;
                    }
                    cache_registry::FlushResult::Conflict | cache_registry::FlushResult::Error => {}
                }
            }
            None => {
                let _running_flush = state.kv_flush_lock.lock().await;
                drop(_running_flush);
            }
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

fn shutdown_handoff_visibility_deadline(deadline: std::time::Instant) -> std::time::Instant {
    let handoff_deadline = std::time::Instant::now() + SHUTDOWN_TAG_VISIBILITY_HANDOFF_GRACE;
    if handoff_deadline < deadline {
        handoff_deadline
    } else {
        deadline
    }
}

fn visibility_tags_from_values(
    registry_root_tag: &str,
    configured_human_tags: &[String],
) -> Vec<String> {
    let mut tags = Vec::with_capacity(1 + configured_human_tags.len());

    let root = registry_root_tag.trim();
    if !root.is_empty() {
        tags.push(root.to_string());
    }

    for tag in configured_human_tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() || tags.iter().any(|existing| existing == trimmed) {
            continue;
        }
        tags.push(trimmed.to_string());
    }

    tags
}

async fn wait_for_tag_visibility(
    state: &AppState,
    expected_cache_entry_id: &str,
    deadline: std::time::Instant,
) -> bool {
    let tags = visibility_tags_from_values(&state.registry_root_tag, &state.configured_human_tags);
    let mut attempts = 0u32;

    loop {
        attempts = attempts.saturating_add(1);
        let mut missing_tags = Vec::new();

        for tag in &tags {
            match state
                .api_client
                .tag_pointer(&state.workspace, tag, None)
                .await
            {
                Ok(crate::api::client::TagPointerPollResult::Changed { pointer, .. }) => {
                    if pointer.cache_entry_id.as_deref() != Some(expected_cache_entry_id) {
                        missing_tags.push(tag.clone());
                    }
                }
                Ok(crate::api::client::TagPointerPollResult::NotModified) => {
                    missing_tags.push(tag.clone());
                }
                Ok(crate::api::client::TagPointerPollResult::NotFound) => {
                    missing_tags.push(tag.clone());
                }
                Err(error) => {
                    log::warn!(
                        "Shutdown: tag visibility poll failed for {} tag={}: {}",
                        expected_cache_entry_id,
                        tag,
                        error
                    );
                    missing_tags.push(tag.clone());
                }
            }
        }

        if missing_tags.is_empty() {
            eprintln!(
                "Shutdown: registry root and human tags visible for cache_entry_id={} after {} poll(s)",
                expected_cache_entry_id, attempts
            );
            return true;
        }

        if std::time::Instant::now() >= deadline {
            eprintln!(
                "Shutdown: tags did not converge to cache_entry_id={} before timeout (missing: {})",
                expected_cache_entry_id,
                missing_tags.join(", ")
            );
            return false;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn shutdown_signal(shutdown_requested: Arc<AtomicBool>) {
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

    shutdown_requested.store(true, Ordering::Release);
    eprintln!("\nShutting down...");
}

async fn shutdown_signal_with_channel(
    mut shutdown_rx: oneshot::Receiver<()>,
    shutdown_requested: Arc<AtomicBool>,
) {
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

    shutdown_requested.store(true, Ordering::Release);
    eprintln!("\nShutting down...");
}

fn force_http1() -> bool {
    matches!(
        std::env::var(HTTP_VERSION_ENV).as_deref(),
        Ok("1" | "h1" | "http1")
    )
}

fn build_http_connection_builder() -> HttpConnectionBuilder<TokioExecutor> {
    let mut builder = HttpConnectionBuilder::new(TokioExecutor::new());
    builder
        .http2()
        .initial_stream_window_size(H2_INITIAL_STREAM_WINDOW)
        .initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW)
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    builder
}

async fn serve_with_h2c(
    listener: TcpListener,
    router: axum::Router,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let builder = build_http_connection_builder();

    eprintln!(
        "  HTTP transport: h1+h2c auto (stream_window={}MB, conn_window={}MB, max_streams={})",
        H2_INITIAL_STREAM_WINDOW / (1024 * 1024),
        H2_INITIAL_CONNECTION_WINDOW / (1024 * 1024),
        H2_MAX_CONCURRENT_STREAMS,
    );

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _addr) = match result {
                    Ok(conn) => conn,
                    Err(err) => {
                        log::warn!("accept error: {err}");
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let builder = builder.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                        let router = router.clone();
                        async move {
                            router
                                .oneshot(req.map(axum::body::Body::new))
                                .await
                        }
                    });
                    let io = TokioIo::new(stream);
                    if let Err(err) = builder
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        log::debug!("connection closed: {err}");
                    }
                });
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;

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
        let _guard = test_env::lock();
        test_env::remove_var(TCP_LISTEN_BACKLOG_ENV);
        assert_eq!(tcp_listen_backlog(), DEFAULT_TCP_LISTEN_BACKLOG);

        test_env::set_var(TCP_LISTEN_BACKLOG_ENV, "0");
        assert_eq!(tcp_listen_backlog(), DEFAULT_TCP_LISTEN_BACKLOG);

        test_env::set_var(TCP_LISTEN_BACKLOG_ENV, "not-a-number");
        assert_eq!(tcp_listen_backlog(), DEFAULT_TCP_LISTEN_BACKLOG);

        test_env::remove_var(TCP_LISTEN_BACKLOG_ENV);
    }

    #[test]
    fn tcp_listen_backlog_honors_positive_env_override() {
        let _guard = test_env::lock();
        test_env::set_var(TCP_LISTEN_BACKLOG_ENV, "4096");
        assert_eq!(tcp_listen_backlog(), 4096);
        test_env::remove_var(TCP_LISTEN_BACKLOG_ENV);
    }

    #[test]
    fn blob_read_cache_max_bytes_honors_env_override() {
        let _guard = test_env::lock();
        test_env::set_var(BLOB_READ_CACHE_MAX_BYTES_ENV, "3145728");
        assert_eq!(
            blob_read_cache_max_bytes(CacheRegistryTuningProfile::Generic),
            3_145_728
        );
        test_env::remove_var(BLOB_READ_CACHE_MAX_BYTES_ENV);
    }

    #[test]
    fn blob_read_cache_max_bytes_scales_up_on_ci() {
        let _guard = test_env::lock();
        test_env::remove_var(BLOB_READ_CACHE_MAX_BYTES_ENV);
        test_env::set_var("CI", "1");
        let max = blob_read_cache_max_bytes(CacheRegistryTuningProfile::Generic);
        assert!(max >= DEFAULT_BLOB_READ_CACHE_MAX_BYTES);
        test_env::remove_var("CI");
    }

    #[test]
    fn blob_prefetch_concurrency_defaults_to_half_of_downloads() {
        assert_eq!(
            blob_prefetch_concurrency(8, CacheRegistryTuningProfile::Generic),
            (4, false)
        );
        assert_eq!(
            blob_prefetch_concurrency(16, CacheRegistryTuningProfile::Generic),
            (8, false)
        );
    }

    #[test]
    fn blob_prefetch_concurrency_keeps_sccache_prefetch_aggressive() {
        assert_eq!(
            blob_prefetch_concurrency(8, CacheRegistryTuningProfile::Sccache),
            (8, false)
        );
        assert_eq!(
            blob_prefetch_concurrency(16, CacheRegistryTuningProfile::Sccache),
            (16, false)
        );
    }

    #[test]
    fn blob_prefetch_concurrency_keeps_bazel_more_eager_than_generic() {
        assert_eq!(
            blob_prefetch_concurrency(8, CacheRegistryTuningProfile::Bazel),
            (6, false)
        );
        assert_eq!(
            blob_prefetch_concurrency(16, CacheRegistryTuningProfile::Bazel),
            (12, false)
        );
    }

    #[test]
    fn cache_registry_tuning_profile_detects_bazel_from_metadata_hint() {
        let hints = BTreeMap::from([("tool".to_string(), "bazel".to_string())]);
        assert_eq!(
            cache_registry_tuning_profile(&[], &hints),
            CacheRegistryTuningProfile::Bazel
        );
    }

    #[test]
    fn cache_registry_tuning_profile_detects_bazel_from_tags() {
        let tags = vec!["grpc-bazel".to_string(), "digest-sha256-abc".to_string()];
        assert_eq!(
            cache_registry_tuning_profile(&tags, &BTreeMap::new()),
            CacheRegistryTuningProfile::Bazel
        );
    }

    #[test]
    fn cache_registry_tuning_profile_detects_sccache_from_metadata_hint() {
        let hints = BTreeMap::from([("tool".to_string(), "sccache".to_string())]);
        assert_eq!(
            cache_registry_tuning_profile(&[], &hints),
            CacheRegistryTuningProfile::Sccache
        );
    }

    #[test]
    fn cache_registry_tuning_profile_detects_sccache_from_tags() {
        let tags = vec![
            "mode-sccache-linux".to_string(),
            "digest-sha256-abc".to_string(),
        ];
        assert_eq!(
            cache_registry_tuning_profile(&tags, &BTreeMap::new()),
            CacheRegistryTuningProfile::Sccache
        );
    }

    #[test]
    fn visibility_tags_include_root_and_human_tags_without_duplicates() {
        let tags = visibility_tags_from_values(
            "bc_registry_root_v2_123",
            &[
                "mode-docker-ubuntu-24-x86_64".to_string(),
                "mode-docker-ubuntu-24-x86_64".to_string(),
                "digest-sha256-abc".to_string(),
                "".to_string(),
            ],
        );

        assert_eq!(
            tags,
            vec![
                "bc_registry_root_v2_123".to_string(),
                "mode-docker-ubuntu-24-x86_64".to_string(),
                "digest-sha256-abc".to_string(),
            ]
        );
    }

    #[test]
    fn should_flush_pending_values_coalesces_tiny_batches_with_short_idle_window() {
        let now_ms = 10_000;
        assert!(!should_flush_pending_values(
            false,
            2,
            1_024,
            now_ms - 1_500,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            2,
            1_024,
            now_ms - 2_000,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_uses_short_idle_window_for_small_batches() {
        let now_ms = 10_000;
        assert!(!should_flush_pending_values(
            false,
            32,
            4 * 1024 * 1024,
            now_ms - 1_500,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            32,
            4 * 1024 * 1024,
            now_ms - 2_000,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_uses_default_idle_window_for_large_batches() {
        let now_ms = 20_000;
        assert!(!should_flush_pending_values(
            false,
            128,
            128 * 1024 * 1024,
            now_ms - 9_500,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            128,
            128 * 1024 * 1024,
            now_ms - 10_000,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_flushes_when_threshold_is_reached() {
        let now_ms = 10_000;
        assert!(should_flush_pending_values(
            false,
            2_000,
            1_024,
            now_ms,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            1,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
            now_ms,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_respects_urgent_signal() {
        assert!(should_flush_pending_values(
            true,
            1,
            1_024,
            0,
            0,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn shutdown_handoff_visibility_deadline_caps_wait_to_short_grace() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let bounded = shutdown_handoff_visibility_deadline(deadline);
        let wait = bounded.saturating_duration_since(std::time::Instant::now());
        assert!(wait <= SHUTDOWN_TAG_VISIBILITY_HANDOFF_GRACE);
    }

    #[test]
    fn shutdown_handoff_visibility_deadline_respects_earlier_deadline() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
        let bounded = shutdown_handoff_visibility_deadline(deadline);
        assert!(bounded <= deadline);
    }
}
