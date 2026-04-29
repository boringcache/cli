use anyhow::{Context, Result};
use axum::serve::ListenerExt;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpSocket, lookup_host};
use tokio::sync::{RwLock, mpsc};
use tower::ServiceExt;

use crate::api::client::ApiClient;
use crate::serve::cache_registry;
use crate::serve::state::{
    self, AppState, BlobLocatorCache, BlobReadCache, BlobReadMetrics, KV_BACKLOG_POLICY,
    KV_REPLICATION_WORK_QUEUE_CAPACITY, KvPendingStore, KvPublishedIndex, KvReplicationWork,
    UploadSessionStore,
};
use crate::tag_utils::TagResolver;

const BLOB_DOWNLOAD_CONCURRENCY_ENV: &str = "BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY";
const BLOB_PREFETCH_CONCURRENCY_ENV: &str = "BORINGCACHE_BLOB_PREFETCH_CONCURRENCY";
const TCP_LISTEN_BACKLOG_ENV: &str = "BORINGCACHE_TCP_LISTEN_BACKLOG";
const DEFAULT_TCP_LISTEN_BACKLOG: u32 = 1024;
const HTTP_VERSION_ENV: &str = "BORINGCACHE_HTTP_VERSION";
const BLOB_READ_CACHE_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const H2_INITIAL_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
const H2_INITIAL_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
const H2_MAX_CONCURRENT_STREAMS: u32 = 1024;
const RUNTIME_TEMP_DIR_PREFIX: &str = "boringcache-proxy";

#[allow(clippy::too_many_arguments)]
pub(super) async fn build_server_runtime(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
    registry_root_tag: String,
    oci_alias_promotion_refs: Vec<String>,
    proxy_metadata_hints: BTreeMap<String, String>,
    startup_warm: bool,
    oci_hydration_policy: crate::serve::OciHydrationPolicy,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<(AppState, TcpListener, mpsc::Receiver<KvReplicationWork>)> {
    let blob_read_cache = Arc::new(BlobReadCache::new(BLOB_READ_CACHE_MAX_BYTES)?);
    let blob_read_metrics = Arc::new(BlobReadMetrics::new());
    let oci_body_metrics = Arc::new(state::OciBodyMetrics::new());
    let oci_engine_diagnostics = Arc::new(state::OciEngineDiagnostics::new());
    let oci_negative_cache = Arc::new(state::OciNegativeCache::new());
    let singleflight_metrics = Arc::new(state::SingleflightMetrics::new());
    let prefetch_metrics = Arc::new(state::PrefetchMetrics::new());
    let kv_blob_upload_metrics = Arc::new(state::KvBlobUploadMetrics::new());
    let proxy_skip_rules = Arc::new(load_proxy_skip_rules_from_current_dir()?);
    let skip_rule_metrics = Arc::new(state::ProxySkipRuleMetrics::new());
    let (dl_concurrency, dl_from_env) = blob_download_concurrency();
    let (prefetch_concurrency, prefetch_from_env) = blob_prefetch_concurrency(dl_concurrency);
    let (kv_replication_work_tx, kv_replication_work_rx) =
        mpsc::channel(KV_REPLICATION_WORK_QUEUE_CAPACITY);
    let blob_download_semaphore = Arc::new(tokio::sync::Semaphore::new(dl_concurrency));
    let blob_prefetch_semaphore = Arc::new(tokio::sync::Semaphore::new(prefetch_concurrency));
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
        started_at: std::time::Instant::now(),
        cache_session_summary_id: format!("proxy-summary-{}", uuid::Uuid::new_v4()),
        runtime_temp_dir,
        kv_blob_temp_dir,
        oci_upload_temp_dir,
        read_only,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        oci_alias_promotion_refs,
        proxy_metadata_hints: proxy_metadata_hints.clone(),
        proxy_skip_rules,
        proxy_ci_run_context: crate::ci_detection::detect_ci_context()
            .run_context()
            .cloned(),
        fail_on_cache_error,
        oci_hydration_policy,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(tokio::sync::Mutex::new(())),
        kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        oci_lookup_inflight: Arc::new(dashmap::DashMap::new()),
        oci_negative_cache,
        singleflight_metrics,
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
        oci_body_metrics,
        oci_engine_diagnostics,
        prefetch_metrics,
        kv_blob_upload_metrics,
        skip_rule_metrics,
        blob_download_max_concurrency: dl_concurrency,
        blob_prefetch_max_concurrency: prefetch_concurrency,
        blob_prefetch_concurrency_from_env: prefetch_from_env,
        blob_download_semaphore,
        blob_prefetch_semaphore,
        cache_ops: Arc::new(
            cache_registry::cache_ops::Aggregator::new_with_metadata_hints(
                proxy_metadata_hints.clone(),
            ),
        ),
        oci_manifest_cache: Arc::new(dashmap::DashMap::new()),
        backend_breaker: Arc::new(state::BackendCircuitBreaker::new()),
        prefetch_complete: Arc::new(std::sync::atomic::AtomicBool::new(!startup_warm)),
        prefetch_complete_notify: Arc::new(tokio::sync::Notify::new()),
        prefetch_error: Arc::new(RwLock::new(None)),
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

    eprintln!("BoringCache proxy listening on {addr}");
    eprintln!("  Workspace: {workspace}");
    if state.read_only {
        eprintln!("  Mode: read-only");
    }
    if !state.configured_human_tags.is_empty() {
        eprintln!(
            "  {}: {}",
            cache_tag_label(&state.proxy_metadata_hints),
            state.configured_human_tags.join(", ")
        );
    }
    eprintln!(
        "  {}: {}",
        internal_root_tag_label(&state.proxy_metadata_hints),
        state.registry_root_tag
    );
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
    for endpoint in endpoint_lines(&state.proxy_metadata_hints, &host, port) {
        eprintln!("{endpoint}");
    }
    eprintln!(
        "  Blob Read Cache: {} (max {} bytes)",
        state.blob_read_cache.cache_dir().display(),
        state.blob_read_cache.max_bytes()
    );
    let src = |from_env: bool| if from_env { "env" } else { "auto" };
    eprintln!(
        "  Blob Download Concurrency: {dl_concurrency} max ({}), prefetch budget: {prefetch_concurrency} ({})",
        src(dl_from_env),
        src(prefetch_from_env)
    );
    match (dl_from_env, prefetch_from_env) {
        (false, false) => eprintln!("  Expert Tuning Overrides: none"),
        (true, false) => eprintln!("  Expert Tuning Overrides: {BLOB_DOWNLOAD_CONCURRENCY_ENV}"),
        (false, true) => eprintln!("  Expert Tuning Overrides: {BLOB_PREFETCH_CONCURRENCY_ENV}"),
        (true, true) => eprintln!(
            "  Expert Tuning Overrides: {BLOB_DOWNLOAD_CONCURRENCY_ENV}, {BLOB_PREFETCH_CONCURRENCY_ENV}"
        ),
    }
    eprintln!("  Replication queue: {KV_REPLICATION_WORK_QUEUE_CAPACITY} (bounded)");
    eprintln!(
        "  Startup mode: {}",
        if startup_warm { "warm" } else { "on-demand" }
    );
    eprintln!(
        "  {}: {}",
        body_hydration_label(&state.proxy_metadata_hints),
        state.oci_hydration_policy.as_str()
    );
    eprintln!(
        "  Full-tag hydration: {}",
        if startup_warm {
            "before ready"
        } else {
            "per-request only"
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

fn cache_tag_label(proxy_metadata_hints: &BTreeMap<String, String>) -> &'static str {
    if proxy_tool(proxy_metadata_hints) == Some("oci") {
        "OCI Tags"
    } else {
        "Cache Tags"
    }
}

fn internal_root_tag_label(proxy_metadata_hints: &BTreeMap<String, String>) -> &'static str {
    if proxy_tool(proxy_metadata_hints) == Some("oci") {
        "Internal Registry Root Tag"
    } else {
        "Internal Cache Root Tag"
    }
}

fn body_hydration_label(proxy_metadata_hints: &BTreeMap<String, String>) -> &'static str {
    if proxy_tool(proxy_metadata_hints) == Some("oci") {
        "OCI body hydration"
    } else {
        "Cache body hydration"
    }
}

fn proxy_tool(proxy_metadata_hints: &BTreeMap<String, String>) -> Option<&str> {
    proxy_metadata_hints
        .get("tool")
        .or_else(|| proxy_metadata_hints.get("adapter"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

fn endpoint_lines(
    proxy_metadata_hints: &BTreeMap<String, String>,
    host: &str,
    port: u16,
) -> Vec<String> {
    let selected = proxy_tool(proxy_metadata_hints);
    let mut lines = Vec::new();
    let mut push = |line: String| lines.push(line);

    match selected {
        Some("oci") | None => push(format!(
            "  OCI registry: --cache-from/--cache-to type=registry,ref={host}:{port}/CACHE_NAME:TAG"
        )),
        _ => {}
    }
    if matches!(selected, Some("bazel") | None) {
        push(format!(
            "  Bazel HTTP cache: http://{host}:{port}/ac/{{sha256}} and /cas/{{sha256}}"
        ));
    }
    if matches!(selected, Some("gradle") | None) {
        push(format!(
            "  Gradle remote cache: http://{host}:{port}/cache/{{cache-key}}"
        ));
    }
    if matches!(selected, Some("maven") | None) {
        push(format!(
            "  Maven remote cache: http://{host}:{port}/v1.1/{{groupId}}/{{artifactId}}/{{checksum}}/{{filename}} (also /v1/...)"
        ));
    }
    if matches!(selected, Some("nx") | None) {
        push(format!(
            "  Nx cache: http://{host}:{port}/v1/cache/{{hash}}"
        ));
    }
    if matches!(selected, Some("turborepo") | None) {
        push(format!(
            "  Turborepo cache: http://{host}:{port}/v8/artifacts/{{hash}}"
        ));
    }
    if matches!(selected, Some("sccache") | None) {
        push(format!(
            "  sccache WebDAV: http://{host}:{port}/<prefix>/a/b/c/<key>"
        ));
    }
    if matches!(selected, Some("gocache") | None) {
        push(format!(
            "  Go cache object API: http://{host}:{port}/gocache/{{action-id}}"
        ));
        push(format!(
            "  GOCACHEPROG helper: boringcache go-cacheprog --endpoint http://{host}:{port}"
        ));
    }

    lines
}

pub(super) async fn serve_router<F>(
    listener: TcpListener,
    router: axum::Router,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if force_http1() {
        eprintln!("  HTTP transport: h1 only ({}=1)", HTTP_VERSION_ENV);
        let listener = listener.tap_io(|tcp_stream| {
            let _ = tcp_stream.set_nodelay(true);
        });
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
    } else {
        serve_with_h2c(listener, router, shutdown).await?;
    }

    Ok(())
}

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

fn load_proxy_skip_rules_from_current_dir() -> Result<Vec<state::ProxySkipRule>> {
    let current_dir = std::env::current_dir().context("Failed to determine current directory")?;
    let Some(loaded) = crate::project_config::discover(&current_dir)
        .context("Failed to load repo cache config")?
    else {
        return Ok(Vec::new());
    };
    state::proxy_skip_rules_from_config(&loaded.config.skip)
}

fn auto_transfer_concurrency() -> usize {
    let resources = crate::platform::resources::SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();
    resources.recommended_proxy_download_concurrency(is_ci)
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

    (auto_transfer_concurrency().max(1), false)
}

fn blob_prefetch_concurrency(download_concurrency: usize) -> (usize, bool) {
    if let Some(configured) = parse_positive_usize_env(BLOB_PREFETCH_CONCURRENCY_ENV) {
        return (configured, true);
    }

    (download_concurrency.max(1), false)
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

async fn serve_with_h2c<F>(listener: TcpListener, router: axum::Router, shutdown: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
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
                        async move { router.oneshot(req.map(axum::body::Body::new)).await }
                    });
                    let io = TokioIo::new(stream);
                    if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
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
    fn blob_read_cache_max_bytes_is_fixed() {
        assert_eq!(BLOB_READ_CACHE_MAX_BYTES, 64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn blob_download_concurrency_honors_env_override() {
        let _guard = test_env::lock();
        test_env::set_var(BLOB_DOWNLOAD_CONCURRENCY_ENV, "3");
        assert_eq!(blob_download_concurrency(), (3, true));
        test_env::remove_var(BLOB_DOWNLOAD_CONCURRENCY_ENV);
    }

    #[test]
    fn blob_prefetch_concurrency_defaults_from_download_concurrency() {
        assert_eq!(blob_prefetch_concurrency(8), (8, false));
        assert_eq!(blob_prefetch_concurrency(1), (1, false));
    }

    #[test]
    fn blob_prefetch_concurrency_honors_env_override() {
        let _guard = test_env::lock();
        test_env::set_var(BLOB_PREFETCH_CONCURRENCY_ENV, "3");
        assert_eq!(blob_prefetch_concurrency(8), (3, true));
        test_env::remove_var(BLOB_PREFETCH_CONCURRENCY_ENV);
    }

    #[test]
    fn proxy_startup_labels_go_as_cache_not_oci() {
        let hints = BTreeMap::from([("tool".to_string(), "gocache".to_string())]);

        assert_eq!(cache_tag_label(&hints), "Cache Tags");
        assert_eq!(internal_root_tag_label(&hints), "Internal Cache Root Tag");
        assert_eq!(body_hydration_label(&hints), "Cache body hydration");

        let lines = endpoint_lines(&hints, "127.0.0.1", 4242);
        assert_eq!(
            lines,
            vec![
                "  Go cache object API: http://127.0.0.1:4242/gocache/{action-id}".to_string(),
                "  GOCACHEPROG helper: boringcache go-cacheprog --endpoint http://127.0.0.1:4242"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn proxy_startup_keeps_oci_labels_for_docker_registry_mode() {
        let hints = BTreeMap::from([("tool".to_string(), "oci".to_string())]);

        assert_eq!(cache_tag_label(&hints), "OCI Tags");
        assert_eq!(
            internal_root_tag_label(&hints),
            "Internal Registry Root Tag"
        );
        assert_eq!(body_hydration_label(&hints), "OCI body hydration");
        assert_eq!(
            endpoint_lines(&hints, "127.0.0.1", 4242),
            vec![
                "  OCI registry: --cache-from/--cache-to type=registry,ref=127.0.0.1:4242/CACHE_NAME:TAG"
                    .to_string()
            ]
        );
    }
}
