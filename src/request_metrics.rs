use serde::Serialize;
use serde_json::to_string;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
pub(crate) struct RequestMetric {
    pub ts_ms: u64,
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
    pub error: Option<String>,
    pub details: Option<String>,
}

pub(crate) struct SuccessMetric {
    pub source: &'static str,
    pub operation: &'static str,
    pub method: &'static str,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub request_bytes: Option<u64>,
    pub response_bytes: Option<u64>,
    pub batch_index: Option<u64>,
    pub batch_count: Option<u64>,
    pub batch_size: Option<u64>,
    pub retry_count: Option<u32>,
}

impl RequestMetric {
    pub(crate) fn success(params: SuccessMetric) -> Self {
        Self {
            ts_ms: now_ms(),
            source: params.source,
            operation: params.operation,
            method: params.method,
            path: params.path,
            status: Some(params.status),
            status_class: Some(status_class(params.status)),
            duration_ms: params.duration_ms,
            request_bytes: params.request_bytes,
            response_bytes: params.response_bytes,
            batch_index: params.batch_index,
            batch_count: params.batch_count,
            batch_size: params.batch_size,
            retry_count: params.retry_count,
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
        Self {
            ts_ms: now_ms(),
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
        Self {
            ts_ms: now_ms(),
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
            error: None,
            details: Some(details),
        }
    }
}

pub(crate) fn emit(metric: RequestMetric) {
    let Some(path) = output_path() else {
        return;
    };
    if !metrics_enabled() {
        return;
    }

    let line = to_string(&metric).unwrap_or_default();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

fn output_path() -> Option<&'static PathBuf> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        if let Ok(path) = env::var("BORINGCACHE_REQUEST_METRICS_PATH") {
            if let Some(trimmed) = trim_optional_env(path) {
                return Some(PathBuf::from(trimmed));
            }
        }

        if let Ok(path) = env::var("BORINGCACHE_CACHE_METRICS_PATH") {
            if let Some(trimmed) = trim_optional_env(path) {
                return Some(PathBuf::from(trimmed));
            }
        }

        if let Ok(log_dir) = env::var("LOG_DIR") {
            if let Some(trimmed) = trim_optional_env(log_dir) {
                return Some(PathBuf::from(trimmed).join("cache-registry-request-metrics.jsonl"));
            }
        }

        None
    })
    .as_ref()
}

fn metrics_enabled() -> bool {
    match env::var("BORINGCACHE_METRICS_FORMAT") {
        Ok(raw) => raw.trim().is_empty() || raw.trim().eq_ignore_ascii_case("json"),
        Err(_) => true,
    }
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

fn trim_optional_env(value: String) -> Option<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
