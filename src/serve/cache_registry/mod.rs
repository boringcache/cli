use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;

use crate::serve::state::{AppState, diagnostics_enabled};

static INFLIGHT_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
const SLOW_REQUEST_WARN_MS: u128 = 2_000;
const PUT_SLOW_WARN_MS: u64 = 2_000;
const ACTION_HEADER: &str = "x-boringcache-action";
const SKIP_RULE_HEADER: &str = "x-boringcache-skip-rule";
tokio::task_local! {
    static REQUEST_SEQ: u64;
}

struct PutProgress {
    scoped_key: String,
    stage: &'static str,
    started_ms: u64,
    last_progress_ms: u64,
    bytes_read: u64,
    bytes_written: u64,
}

static PUT_PROGRESS: OnceLock<DashMap<u64, PutProgress>> = OnceLock::new();

fn put_progress_map() -> &'static DashMap<u64, PutProgress> {
    PUT_PROGRESS.get_or_init(DashMap::new)
}

fn unix_time_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_millis(0))
        .as_millis() as u64
}

fn sccache_request_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(diagnostics_enabled)
}

fn put_probe_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(diagnostics_enabled)
}

pub(crate) struct PutProbeGuard {
    seq: Option<u64>,
}

impl PutProbeGuard {
    pub(crate) fn start(scoped_key: &str) -> Self {
        if !put_probe_enabled() {
            return Self { seq: None };
        }
        let seq = REQUEST_SEQ.try_with(|seq| *seq).ok();
        if let Some(seq) = seq {
            let now_ms = unix_time_ms_now();
            put_progress_map().insert(
                seq,
                PutProgress {
                    scoped_key: scoped_key.to_string(),
                    stage: "begin",
                    started_ms: now_ms,
                    last_progress_ms: now_ms,
                    bytes_read: 0,
                    bytes_written: 0,
                },
            );
        }
        Self { seq }
    }

    pub(crate) fn stage(&self, stage: &'static str) {
        let Some(seq) = self.seq else {
            return;
        };
        let now_ms = unix_time_ms_now();
        if let Some(mut progress) = put_progress_map().get_mut(&seq) {
            progress.stage = stage;
            progress.last_progress_ms = now_ms;
        }
    }

    pub(crate) fn add_read(&self, bytes: u64) {
        let Some(seq) = self.seq else {
            return;
        };
        let now_ms = unix_time_ms_now();
        if let Some(mut progress) = put_progress_map().get_mut(&seq) {
            progress.bytes_read = progress.bytes_read.saturating_add(bytes);
            progress.last_progress_ms = now_ms;
        }
    }

    pub(crate) fn add_written(&self, bytes: u64) {
        let Some(seq) = self.seq else {
            return;
        };
        let now_ms = unix_time_ms_now();
        if let Some(mut progress) = put_progress_map().get_mut(&seq) {
            progress.bytes_written = progress.bytes_written.saturating_add(bytes);
            progress.last_progress_ms = now_ms;
        }
    }
}

impl Drop for PutProbeGuard {
    fn drop(&mut self) {
        if let Some(seq) = self.seq
            && let Some((_, progress)) = put_progress_map().remove(&seq)
        {
            let age_ms = unix_time_ms_now().saturating_sub(progress.started_ms);
            if age_ms >= PUT_SLOW_WARN_MS {
                log::warn!(
                    "slow_kv_put seq={} age_ms={} stage={} bytes_read={} bytes_written={} key={}",
                    seq,
                    age_ms,
                    progress.stage,
                    progress.bytes_read,
                    progress.bytes_written,
                    progress.scoped_key,
                );
            }
        }
    }
}

pub(crate) fn dump_stuck_puts(limit: usize, min_idle_ms: u64) {
    if !put_probe_enabled() {
        return;
    }
    let now_ms = unix_time_ms_now();
    let tracked = put_progress_map().len();
    let mut stuck = Vec::new();
    for item in put_progress_map().iter() {
        let idle_ms = now_ms.saturating_sub(item.last_progress_ms);
        if idle_ms < min_idle_ms {
            continue;
        }
        stuck.push((
            *item.key(),
            item.value().stage,
            idle_ms,
            now_ms.saturating_sub(item.value().started_ms),
            item.value().bytes_read,
            item.value().bytes_written,
            item.value().scoped_key.clone(),
        ));
    }

    stuck.sort_by_key(|(_, _, idle_ms, _, _, _, _)| std::cmp::Reverse(*idle_ms));
    if stuck.is_empty() {
        eprintln!("WATCHDOG PUT none tracked={tracked} min_idle_ms={min_idle_ms}",);
        return;
    }
    for (seq, stage, idle_ms, age_ms, bytes_read, bytes_written, scoped_key) in
        stuck.into_iter().take(limit)
    {
        eprintln!(
            "WATCHDOG PUT seq={seq} stage={stage} idle_ms={idle_ms} age_ms={age_ms} bytes_read={bytes_read} bytes_written={bytes_written} key={scoped_key}"
        );
    }
}

pub(crate) fn request_counters() -> (u64, u64) {
    (
        INFLIGHT_REQUESTS.load(Ordering::Relaxed),
        TOTAL_REQUESTS.load(Ordering::Relaxed),
    )
}

pub mod cache_ops;
mod error;
mod kv;
mod kv_publish;
mod route;
mod tool_routes;

pub use error::RegistryError;
pub(crate) use kv::FlushResult;
pub(crate) use kv::KV_PREFETCH_READINESS_TIMEOUT;
pub(crate) use kv::KvBlobIntegrity;
pub(crate) use kv::KvNamespace;
pub(crate) use kv::KvPutOptions;
pub(crate) use kv::await_startup_prefetch_readiness;
pub(crate) use kv::cleanup_expired_kv_misses;
pub(crate) use kv::count_missing_local_blobs;
pub(crate) use kv::do_download_blob_to_cache;
pub(crate) use kv::enqueue_replication_flush_hint;
pub(crate) use kv::flush_kv_index;
pub(crate) use kv::flush_kv_index_on_shutdown;
pub(crate) use kv::get_or_head_kv_object;
pub(crate) use kv::get_or_head_kv_object_with_integrity;
pub(crate) use kv::kv_publish_tags_visible;
pub(crate) use kv::lookup_published_blob;
pub(crate) use kv::maybe_refresh_published_index_for_lookup;
pub(crate) use kv::poll_tag_version_loop;
pub(crate) use kv::prefetch_manifest_blobs;
pub(crate) use kv::put_kv_object;
pub(crate) use kv::put_kv_object_with_integrity;
pub(crate) use kv::put_kv_object_with_options;
pub(crate) use kv::refresh_kv_index;
pub(crate) use kv::resolve_kv_entries;
pub(crate) use kv::try_schedule_flush;

pub async fn dispatch_root(
    method: Method,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    dispatch_with_path(method, state, String::new(), headers, body).await
}

pub async fn dispatch(
    method: Method,
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    dispatch_with_path(method, state, path, headers, body).await
}

async fn dispatch_with_path(
    method: Method,
    state: AppState,
    path: String,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    let request_method = method.clone();
    let normalized_path = normalize_path(&path);
    let request_path = if normalized_path.is_empty() {
        "/".to_string()
    } else {
        format!("/{normalized_path}")
    };
    let route = route::detect_route(&method, &normalized_path)?;
    let route_tool = tool_for_route(&route);
    let route_instruments_cache_ops = route_instruments_cache_ops(&route);
    if let Some(tool) = route_tool
        && request_matches_skip_rule(&state, tool, &headers)
    {
        let op = op_for_method(&request_method);
        let result = if op == cache_ops::Op::Get {
            cache_ops::OpResult::Miss
        } else {
            cache_ops::OpResult::Hit
        };
        state.skip_rule_metrics.record_match();
        state.cache_ops.record(tool, op, result, false, 0, 0);
        let mut response = best_effort_cache_registry_response(&request_method);
        response.headers_mut().insert(
            SKIP_RULE_HEADER,
            HeaderValue::from_static("boringcache_skip_rule"),
        );
        return Ok(response);
    }
    let is_sccache_connect_route = matches!(route, route::RegistryRoute::SccacheMkcol);
    let is_sccache_route = matches!(
        route,
        route::RegistryRoute::SccacheObject { .. }
            | route::RegistryRoute::SccacheMkcol
            | route::RegistryRoute::SccacheProbe { .. }
    );
    if is_sccache_connect_route {
        state
            .cache_ops
            .record_session_connect(cache_ops::Tool::Sccache);
    }
    let request_start = std::time::Instant::now();
    let inflight = INFLIGHT_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
    let seq = TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    if is_sccache_route && sccache_request_log_enabled() {
        eprintln!("REQ#{seq} {request_method} {request_path} inflight={inflight}");
    }

    let route_state = state.clone();
    let response = REQUEST_SEQ
        .scope(seq, async move {
            match route {
                route::RegistryRoute::BazelAc { digest_hex } => {
                    tool_routes::bazel::handle_ac(&route_state, method, &digest_hex, body).await
                }
                route::RegistryRoute::BazelCas { digest_hex } => {
                    tool_routes::bazel::handle_cas(&route_state, method, &digest_hex, body).await
                }
                route::RegistryRoute::Gradle { cache_key } => {
                    tool_routes::gradle::handle(&route_state, method, &cache_key, body).await
                }
                route::RegistryRoute::Maven { cache_key } => {
                    tool_routes::maven::handle(&route_state, method, &cache_key, body).await
                }
                route::RegistryRoute::NxArtifact { hash } => {
                    tool_routes::nx::handle_artifact(&route_state, method, &headers, &hash, body)
                        .await
                }
                route::RegistryRoute::NxTerminalOutput { hash } => {
                    tool_routes::nx::handle_terminal_output(
                        &route_state,
                        method,
                        &headers,
                        &hash,
                        body,
                    )
                    .await
                }
                route::RegistryRoute::NxQuery => {
                    tool_routes::nx::handle_query(&route_state, method, &headers, body).await
                }
                route::RegistryRoute::TurborepoStatus => {
                    tool_routes::turborepo::handle_status(method, &headers)
                }
                route::RegistryRoute::TurborepoArtifact { hash } => {
                    tool_routes::turborepo::handle_artifact(
                        &route_state,
                        method,
                        &headers,
                        &hash,
                        body,
                    )
                    .await
                }
                route::RegistryRoute::TurborepoQueryArtifacts => {
                    tool_routes::turborepo::handle_query_artifacts(
                        &route_state,
                        method,
                        &headers,
                        body,
                    )
                    .await
                }
                route::RegistryRoute::TurborepoEvents => {
                    tool_routes::turborepo::handle_events(method, &headers, body).await
                }
                route::RegistryRoute::SccacheObject { key_path } => {
                    tool_routes::sccache::handle_object(&route_state, method, &key_path, body).await
                }
                route::RegistryRoute::SccacheProbe { path } => {
                    tool_routes::sccache::handle_probe(method, &path).await
                }
                route::RegistryRoute::SccacheMkcol => tool_routes::sccache::handle_mkcol(method),
                route::RegistryRoute::GoCacheObject { action_hex } => {
                    tool_routes::go_cache::handle_action(&route_state, method, &action_hex, body)
                        .await
                }
            }
        })
        .await;

    INFLIGHT_REQUESTS.fetch_sub(1, Ordering::Relaxed);

    match response {
        Ok(response) => {
            let elapsed_ms = request_start.elapsed().as_millis();
            if elapsed_ms >= SLOW_REQUEST_WARN_MS {
                log::warn!(
                    "slow_cache_registry_request method={} path={} status={} elapsed_ms={} inflight={}",
                    request_method,
                    request_path,
                    response.status(),
                    elapsed_ms,
                    INFLIGHT_REQUESTS.load(Ordering::Relaxed),
                );
            }
            if is_sccache_route && sccache_request_log_enabled() {
                let status = response.status();
                eprintln!("REQ#{seq} {request_method} {request_path} -> {status} ({elapsed_ms}ms)",);
            }
            Ok(response)
        }
        Err(error) => {
            let elapsed_ms = request_start.elapsed().as_millis();
            if elapsed_ms >= SLOW_REQUEST_WARN_MS {
                log::warn!(
                    "slow_cache_registry_request method={} path={} status={} elapsed_ms={} inflight={}",
                    request_method,
                    request_path,
                    error.status,
                    elapsed_ms,
                    INFLIGHT_REQUESTS.load(Ordering::Relaxed),
                );
            }
            if is_sccache_route && sccache_request_log_enabled() {
                if error.status.is_server_error() {
                    let compact = error
                        .message()
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!(
                        "REQ#{seq} {request_method} {request_path} -> {} ({elapsed_ms}ms) msg={compact}",
                        error.status,
                    );
                } else if error.status != StatusCode::NOT_FOUND || elapsed_ms >= 500 {
                    eprintln!(
                        "REQ#{seq} {request_method} {request_path} -> {} ({elapsed_ms}ms)",
                        error.status,
                    );
                }
            }
            if state.fail_on_cache_error || !error.status.is_server_error() {
                return Err(error);
            }
            log::warn!(
                "Best-effort cache-registry fallback on {} {} ({})",
                request_method,
                normalized_path,
                error.status
            );
            if let Some(tool) = route_tool.filter(|_| !route_instruments_cache_ops) {
                let op = op_for_method(&request_method);
                state
                    .cache_ops
                    .record(tool, op, cache_ops::OpResult::Error, true, 0, 0);
            }
            Ok(best_effort_cache_registry_response(&request_method))
        }
    }
}

fn request_matches_skip_rule(state: &AppState, tool: cache_ops::Tool, headers: &HeaderMap) -> bool {
    if state.proxy_skip_rules.is_empty() {
        return false;
    }
    let Some(action) = headers
        .get(ACTION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };

    state
        .proxy_skip_rules
        .iter()
        .any(|rule| rule.matches(tool.as_str(), action))
}

fn tool_for_route(route: &route::RegistryRoute) -> Option<cache_ops::Tool> {
    match route {
        route::RegistryRoute::TurborepoArtifact { .. }
        | route::RegistryRoute::TurborepoQueryArtifacts
        | route::RegistryRoute::TurborepoStatus
        | route::RegistryRoute::TurborepoEvents => Some(cache_ops::Tool::Turborepo),
        route::RegistryRoute::NxArtifact { .. }
        | route::RegistryRoute::NxTerminalOutput { .. }
        | route::RegistryRoute::NxQuery => Some(cache_ops::Tool::Nx),
        route::RegistryRoute::BazelAc { .. } | route::RegistryRoute::BazelCas { .. } => {
            Some(cache_ops::Tool::Bazel)
        }
        route::RegistryRoute::Gradle { .. } => Some(cache_ops::Tool::Gradle),
        route::RegistryRoute::Maven { .. } => Some(cache_ops::Tool::Maven),
        route::RegistryRoute::SccacheObject { .. }
        | route::RegistryRoute::SccacheProbe { .. }
        | route::RegistryRoute::SccacheMkcol => Some(cache_ops::Tool::Sccache),
        route::RegistryRoute::GoCacheObject { .. } => Some(cache_ops::Tool::GoCache),
    }
}

fn op_for_method(method: &Method) -> cache_ops::Op {
    if *method == Method::GET || *method == Method::HEAD {
        cache_ops::Op::Get
    } else if *method == Method::PUT {
        cache_ops::Op::Put
    } else {
        cache_ops::Op::Query
    }
}

fn route_instruments_cache_ops(route: &route::RegistryRoute) -> bool {
    matches!(
        route,
        route::RegistryRoute::BazelAc { .. }
            | route::RegistryRoute::BazelCas { .. }
            | route::RegistryRoute::Gradle { .. }
            | route::RegistryRoute::Maven { .. }
            | route::RegistryRoute::NxArtifact { .. }
            | route::RegistryRoute::NxTerminalOutput { .. }
            | route::RegistryRoute::NxQuery
            | route::RegistryRoute::TurborepoArtifact { .. }
            | route::RegistryRoute::TurborepoQueryArtifacts
            | route::RegistryRoute::TurborepoStatus
            | route::RegistryRoute::TurborepoEvents
            | route::RegistryRoute::SccacheObject { .. }
            | route::RegistryRoute::SccacheMkcol
            | route::RegistryRoute::SccacheProbe { .. }
            | route::RegistryRoute::GoCacheObject { .. }
    )
}

fn normalize_path(path: &str) -> String {
    path.trim_matches('/').to_string()
}

fn best_effort_cache_registry_response(method: &Method) -> Response {
    let status = if *method == Method::GET || *method == Method::HEAD {
        StatusCode::NOT_FOUND
    } else if *method == Method::PUT {
        StatusCode::OK
    } else if *method == Method::POST || *method == Method::PATCH {
        StatusCode::ACCEPTED
    } else if *method == Method::DELETE {
        StatusCode::NO_CONTENT
    } else if method.as_str() == "MKCOL" {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    (status, Body::empty()).into_response()
}
