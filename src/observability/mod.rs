mod request_metrics;

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const OBSERVABILITY_QUEUE_CAPACITY_ENV: &str = "BORINGCACHE_OBSERVABILITY_QUEUE_CAPACITY";
const OBSERVABILITY_HUMAN_LOG_ENV: &str = "BORINGCACHE_OBSERVABILITY_HUMAN_LOG";
const MIN_OBSERVABILITY_QUEUE_CAPACITY: usize = 1_024;
const MAX_OBSERVABILITY_QUEUE_CAPACITY: usize = 131_072;
const DEFAULT_OBSERVABILITY_QUEUE_CAPACITY: usize = 16_384;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ObservabilityEvent {
    pub ts_ms: u64,
    pub run_id: Option<String>,
    pub session_id: Option<String>,
    pub trace_id: Option<String>,
    pub request_id: Option<String>,
    pub source: &'static str,
    pub operation: &'static str,
    pub method: &'static str,
    pub path: String,
    pub status: Option<u16>,
    pub status_class: Option<&'static str>,
    pub duration_ms: u64,
    pub request_bytes: Option<u64>,
    pub response_bytes: Option<u64>,
    pub batch_index: Option<u64>,
    pub batch_count: Option<u64>,
    pub batch_size: Option<u64>,
    pub retry_count: Option<u32>,
    pub workspace: Option<String>,
    pub tag: Option<String>,
    pub cache_entry_id: Option<String>,
    pub error: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Clone)]
struct EventContext {
    run_id: Option<String>,
    session_id: Option<String>,
    trace_id: Option<String>,
}

impl Default for EventContext {
    fn default() -> Self {
        Self {
            run_id: env_opt(
                "BORINGCACHE_OBSERVABILITY_RUN_ID",
                &[
                    "BORINGCACHE_RUN_ID",
                    "GITHUB_RUN_ID",
                    "CI_PIPELINE_ID",
                    "BUILD_BUILDID",
                ],
            ),
            session_id: env_opt(
                "BORINGCACHE_OBSERVABILITY_SESSION_ID",
                &["BORINGCACHE_SESSION_ID"],
            ),
            trace_id: env_opt(
                "BORINGCACHE_OBSERVABILITY_TRACE_ID",
                &["BORINGCACHE_TRACE_ID"],
            ),
        }
    }
}

impl ObservabilityEvent {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn success(
        source: &'static str,
        operation: &'static str,
        method: &'static str,
        path: String,
        status: u16,
        duration_ms: u64,
        request_bytes: Option<u64>,
        response_bytes: Option<u64>,
        batch_index: Option<u64>,
        batch_count: Option<u64>,
        batch_size: Option<u64>,
        retry_count: Option<u32>,
    ) -> Self {
        let ctx = default_context();
        Self {
            ts_ms: now_ms(),
            run_id: ctx.run_id.clone(),
            session_id: ctx.session_id.clone(),
            trace_id: ctx.trace_id.clone(),
            request_id: None,
            source,
            operation,
            method,
            path,
            status: Some(status),
            status_class: Some(status_class(status)),
            duration_ms,
            request_bytes,
            response_bytes,
            batch_index,
            batch_count,
            batch_size,
            retry_count,
            workspace: None,
            tag: None,
            cache_entry_id: None,
            error: None,
            details: None,
        }
    }

    pub(crate) fn failure(
        source: &'static str,
        operation: &'static str,
        method: &'static str,
        path: String,
        error: String,
        duration_ms: u64,
        retry_count: Option<u32>,
    ) -> Self {
        let ctx = default_context();
        Self {
            ts_ms: now_ms(),
            run_id: ctx.run_id.clone(),
            session_id: ctx.session_id.clone(),
            trace_id: ctx.trace_id.clone(),
            request_id: None,
            source,
            operation,
            method,
            path,
            status: None,
            status_class: None,
            duration_ms,
            request_bytes: None,
            response_bytes: None,
            batch_index: None,
            batch_count: None,
            batch_size: None,
            retry_count,
            workspace: None,
            tag: None,
            cache_entry_id: None,
            error: Some(error),
            details: None,
        }
    }

    pub(crate) fn event(
        source: &'static str,
        operation: &'static str,
        method: &'static str,
        path: String,
        details: String,
    ) -> Self {
        let ctx = default_context();
        Self {
            ts_ms: now_ms(),
            run_id: ctx.run_id.clone(),
            session_id: ctx.session_id.clone(),
            trace_id: ctx.trace_id.clone(),
            request_id: None,
            source,
            operation,
            method,
            path,
            status: None,
            status_class: None,
            duration_ms: 0,
            request_bytes: None,
            response_bytes: None,
            batch_index: None,
            batch_count: None,
            batch_size: None,
            retry_count: None,
            workspace: None,
            tag: None,
            cache_entry_id: None,
            error: None,
            details: Some(details),
        }
    }

    pub(crate) fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id.and_then(trim_opt_owned);
        self
    }

    pub(crate) fn with_workspace(mut self, workspace: Option<String>) -> Self {
        self.workspace = workspace.and_then(trim_opt_owned);
        self
    }

    pub(crate) fn with_cache_entry_id(mut self, cache_entry_id: Option<String>) -> Self {
        self.cache_entry_id = cache_entry_id.and_then(trim_opt_owned);
        self
    }

    pub(crate) fn with_details(mut self, details: Option<String>) -> Self {
        self.details = details.and_then(trim_opt_owned);
        self
    }
}

pub(crate) fn emit(event: ObservabilityEvent) {
    hub().emit(event);
}

pub(crate) fn queue_depth() -> u64 {
    hub().queue_depth()
}

pub(crate) fn dropped_events_total() -> u64 {
    hub().dropped_events_total()
}

struct Hub {
    tx: Option<Arc<SyncSender<ObservabilityEvent>>>,
    queued: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    human_log_enabled: bool,
}

impl Hub {
    fn new() -> Self {
        let queued = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let human_log_enabled = parse_bool_env(OBSERVABILITY_HUMAN_LOG_ENV);

        let tx = {
            let (tx, rx) = mpsc::sync_channel(observability_queue_capacity());
            let worker_queued = queued.clone();
            let worker_human = human_log_enabled;
            let spawn_result = std::thread::Builder::new()
                .name("observability-worker".to_string())
                .spawn(move || run_worker(rx, worker_queued, worker_human));
            match spawn_result {
                Ok(_) => Some(Arc::new(tx)),
                Err(error) => {
                    log::warn!("Observability worker spawn failed ({error}); using direct mode");
                    None
                }
            }
        };

        Self {
            tx,
            queued,
            dropped,
            human_log_enabled,
        }
    }

    fn emit(&self, event: ObservabilityEvent) {
        let Some(tx) = &self.tx else {
            dispatch_event(&event, self.human_log_enabled);
            return;
        };

        self.queued.fetch_add(1, Ordering::AcqRel);
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                self.note_drop();
            }
            Err(TrySendError::Disconnected(event)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                dispatch_event(&event, self.human_log_enabled);
            }
        }
    }

    fn note_drop(&self) {
        let dropped = self.dropped.fetch_add(1, Ordering::AcqRel) + 1;
        if dropped == 1 || dropped.is_multiple_of(1_000) {
            log::warn!("Observability queue saturated; dropped {dropped} events");
        }
    }

    fn queue_depth(&self) -> u64 {
        self.queued.load(Ordering::Acquire)
    }

    fn dropped_events_total(&self) -> u64 {
        self.dropped.load(Ordering::Acquire)
    }
}

fn run_worker(
    rx: mpsc::Receiver<ObservabilityEvent>,
    queued: Arc<AtomicU64>,
    human_log_enabled: bool,
) {
    while let Ok(event) = rx.recv() {
        dispatch_event(&event, human_log_enabled);
        queued.fetch_sub(1, Ordering::AcqRel);
    }
}

fn dispatch_event(event: &ObservabilityEvent, human_log_enabled: bool) {
    request_metrics::sink_event(event);
    if human_log_enabled {
        emit_human_log(event);
    }
}

fn emit_human_log(event: &ObservabilityEvent) {
    let status = event
        .status
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let workspace = event.workspace.as_deref().unwrap_or("-");
    let request_id = event.request_id.as_deref().unwrap_or("-");
    eprintln!(
        "OBS event source={} op={} method={} path={} status={} duration_ms={} retry_count={} workspace={} request_id={}",
        event.source,
        event.operation,
        event.method,
        event.path,
        status,
        event.duration_ms,
        event.retry_count.unwrap_or(0),
        workspace,
        request_id
    );
}

fn hub() -> &'static Hub {
    static HUB: OnceLock<Hub> = OnceLock::new();
    HUB.get_or_init(Hub::new)
}

fn default_context() -> &'static EventContext {
    static CONTEXT: OnceLock<EventContext> = OnceLock::new();
    CONTEXT.get_or_init(EventContext::default)
}

fn observability_queue_capacity() -> usize {
    parse_positive_usize_env(OBSERVABILITY_QUEUE_CAPACITY_ENV)
        .unwrap_or(DEFAULT_OBSERVABILITY_QUEUE_CAPACITY)
        .clamp(
            MIN_OBSERVABILITY_QUEUE_CAPACITY,
            MAX_OBSERVABILITY_QUEUE_CAPACITY,
        )
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

fn parse_bool_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            let v = raw.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn env_opt(primary: &str, fallbacks: &[&str]) -> Option<String> {
    if let Some(value) = std::env::var(primary).ok().and_then(trim_opt_owned) {
        return Some(value);
    }
    for key in fallbacks {
        if let Some(value) = std::env::var(key).ok().and_then(trim_opt_owned) {
            return Some(value);
        }
    }
    None
}

fn trim_opt_owned(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
