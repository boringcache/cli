use crate::observability::ObservabilityEvent;
use serde_json::to_string;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const OBSERVABILITY_JSONL_PATH_ENV: &str = "BORINGCACHE_OBSERVABILITY_JSONL_PATH";
const OBSERVABILITY_ARCHIVE_DIR_ENV: &str = "BORINGCACHE_OBSERVABILITY_ARCHIVE_DIR";
const OBSERVABILITY_ARCHIVE_WORKSPACE_ENV: &str = "BORINGCACHE_OBSERVABILITY_ARCHIVE_WORKSPACE";
const INTERNAL_LOG_DIR_NAME: &str = ".boringcache";
const INTERNAL_LOG_SUBDIR_NAME: &str = "logs";
const DEFAULT_OBSERVABILITY_JSONL_FILE: &str = "cache-registry-request-metrics.jsonl";

#[derive(Default)]
struct RequestMetrics {
    operations: BTreeMap<String, OperationMetrics>,
}

#[derive(Default)]
struct OperationMetrics {
    request_count: u64,
    error_count: u64,
    retry_count: u64,
    durations_ms: Vec<u64>,
}

pub(crate) fn record_event(event: &ObservabilityEvent) {
    if !rails_api_request_event(event) {
        return;
    }

    if let Ok(mut metrics) = request_metrics().lock() {
        metrics.record(event);
    }
}

pub(crate) fn rails_summary() -> Value {
    request_metrics()
        .lock()
        .map(|metrics| metrics.to_json())
        .unwrap_or_else(|_| RequestMetrics::default().to_json())
}

fn request_metrics() -> &'static Mutex<RequestMetrics> {
    static METRICS: OnceLock<Mutex<RequestMetrics>> = OnceLock::new();
    METRICS.get_or_init(|| Mutex::new(RequestMetrics::default()))
}

fn rails_api_request_event(event: &ObservabilityEvent) -> bool {
    event.source == "cli" && event.path.starts_with("/v2/")
}

impl RequestMetrics {
    fn record(&mut self, event: &ObservabilityEvent) {
        let metrics = self
            .operations
            .entry(event.operation.to_string())
            .or_default();
        metrics.request_count = metrics.request_count.saturating_add(1);
        metrics.retry_count = metrics
            .retry_count
            .saturating_add(event.retry_count.unwrap_or(0).into());
        if event.error.is_some() || event.status.is_some_and(|status| status >= 400) {
            metrics.error_count = metrics.error_count.saturating_add(1);
        }
        metrics.durations_ms.push(event.duration_ms);
    }

    fn to_json(&self) -> Value {
        let mut request_count_by_operation = BTreeMap::new();
        let mut p50_ms_by_operation = BTreeMap::new();
        let mut p95_ms_by_operation = BTreeMap::new();
        let mut error_count_by_operation = BTreeMap::new();
        let mut retry_count_by_operation = BTreeMap::new();
        let mut total_request_count = 0u64;
        let mut total_error_count = 0u64;
        let mut total_retry_count = 0u64;

        for (operation, metrics) in &self.operations {
            request_count_by_operation.insert(operation.clone(), metrics.request_count);
            p50_ms_by_operation.insert(operation.clone(), percentile(&metrics.durations_ms, 50));
            p95_ms_by_operation.insert(operation.clone(), percentile(&metrics.durations_ms, 95));
            error_count_by_operation.insert(operation.clone(), metrics.error_count);
            retry_count_by_operation.insert(operation.clone(), metrics.retry_count);
            total_request_count = total_request_count.saturating_add(metrics.request_count);
            total_error_count = total_error_count.saturating_add(metrics.error_count);
            total_retry_count = total_retry_count.saturating_add(metrics.retry_count);
        }

        json!({
            "request_count_by_operation": request_count_by_operation,
            "p50_ms_by_operation": p50_ms_by_operation,
            "p95_ms_by_operation": p95_ms_by_operation,
            "error_count_by_operation": error_count_by_operation,
            "retry_count_by_operation": retry_count_by_operation,
            "total_request_count": total_request_count,
            "total_error_count": total_error_count,
            "total_retry_count": total_retry_count,
        })
    }
}

fn percentile(values: &[u64], percentile: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = percentile.saturating_mul(sorted.len() as u64).div_ceil(100);
    let index = rank.saturating_sub(1).min((sorted.len() - 1) as u64) as usize;
    sorted[index]
}

pub(crate) fn sink_event(event: &ObservabilityEvent) {
    if !metrics_enabled() {
        return;
    }

    let line = to_string(event).unwrap_or_default();
    if line.is_empty() {
        return;
    }

    let primary = primary_output_path().cloned();
    if let Some(path) = primary.as_ref() {
        append_line(path, &line);
    }

    if let Some(archive_path) = archive_output_path(event) {
        let duplicate_primary = primary
            .as_ref()
            .map(|p| p == &archive_path)
            .unwrap_or(false);
        if !duplicate_primary {
            append_line(&archive_path, &line);
        }
    }
}

fn primary_output_path() -> Option<&'static PathBuf> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        if let Ok(path) = env::var(OBSERVABILITY_JSONL_PATH_ENV)
            && let Some(trimmed) = trim_optional_env(path)
        {
            return Some(PathBuf::from(trimmed));
        }

        if let Ok(path) = env::var("BORINGCACHE_REQUEST_METRICS_PATH")
            && let Some(trimmed) = trim_optional_env(path)
        {
            return Some(PathBuf::from(trimmed));
        }

        if let Ok(path) = env::var("BORINGCACHE_CACHE_METRICS_PATH")
            && let Some(trimmed) = trim_optional_env(path)
        {
            return Some(PathBuf::from(trimmed));
        }

        if let Ok(log_dir) = env::var("LOG_DIR")
            && let Some(trimmed) = trim_optional_env(log_dir)
        {
            return Some(PathBuf::from(trimmed).join("cache-registry-request-metrics.jsonl"));
        }

        if let Some(default_logs_dir) = default_internal_logs_dir() {
            return Some(default_logs_dir.join(DEFAULT_OBSERVABILITY_JSONL_FILE));
        }

        None
    })
    .as_ref()
}

fn archive_output_path(event: &ObservabilityEvent) -> Option<PathBuf> {
    let root = env::var(OBSERVABILITY_ARCHIVE_DIR_ENV)
        .ok()
        .and_then(trim_optional_env)
        .map(PathBuf::from)?;

    let workspace = archive_workspace(event)?;
    let mut path = root;
    for segment in workspace.split('/') {
        let sanitized = sanitize_segment(segment);
        if !sanitized.is_empty() {
            path.push(sanitized);
        }
    }

    let run_id = event
        .run_id
        .as_deref()
        .map(sanitize_segment)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "adhoc".to_string());
    path.push(format!("run-{run_id}.jsonl"));
    Some(path)
}

fn archive_workspace(event: &ObservabilityEvent) -> Option<String> {
    if let Ok(value) = env::var(OBSERVABILITY_ARCHIVE_WORKSPACE_ENV)
        && let Some(trimmed) = trim_optional_env(value)
    {
        return Some(trimmed);
    }

    event.workspace.clone().and_then(trim_optional_env)
}

fn append_line(path: &Path, line: &str) {
    if let Some(parent) = path.parent() {
        let _ = create_dir_all(parent);
    }

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

fn metrics_enabled() -> bool {
    match env::var("BORINGCACHE_METRICS_FORMAT") {
        Ok(raw) => raw.trim().is_empty() || raw.trim().eq_ignore_ascii_case("json"),
        Err(_) => true,
    }
}

fn trim_optional_env(value: String) -> Option<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

fn sanitize_segment(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn default_internal_logs_dir() -> Option<PathBuf> {
    crate::config::Config::home_dir().ok().map(|home| {
        home.join(INTERNAL_LOG_DIR_NAME)
            .join(INTERNAL_LOG_SUBDIR_NAME)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_event(
        operation: &'static str,
        status: u16,
        duration_ms: u64,
        retry_count: Option<u32>,
    ) -> ObservabilityEvent {
        ObservabilityEvent::success(
            "cli",
            operation,
            "POST",
            "/v2/workspaces/org/repo/caches/blobs/check".to_string(),
            status,
            duration_ms,
            None,
            None,
            None,
            None,
            None,
            retry_count,
        )
    }

    #[test]
    fn request_metrics_summary_groups_api_requests_by_operation() {
        let mut metrics = RequestMetrics::default();
        metrics.record(&api_event("cache_blobs_check", 200, 10, Some(0)));
        metrics.record(&api_event("cache_blobs_check", 200, 30, Some(2)));
        metrics.record(&api_event("cache_blobs_check", 500, 50, Some(1)));
        metrics.record(&api_event("cache_finalize_publish", 200, 90, Some(0)));

        let summary = metrics.to_json();

        assert_eq!(
            summary["request_count_by_operation"]["cache_blobs_check"],
            json!(3)
        );
        assert_eq!(
            summary["p50_ms_by_operation"]["cache_blobs_check"],
            json!(30)
        );
        assert_eq!(
            summary["p95_ms_by_operation"]["cache_blobs_check"],
            json!(50)
        );
        assert_eq!(
            summary["error_count_by_operation"]["cache_blobs_check"],
            json!(1)
        );
        assert_eq!(
            summary["retry_count_by_operation"]["cache_blobs_check"],
            json!(3)
        );
        assert_eq!(summary["total_request_count"], json!(4));
        assert_eq!(summary["total_error_count"], json!(1));
        assert_eq!(summary["total_retry_count"], json!(3));
    }

    #[test]
    fn request_metrics_summary_starts_empty() {
        let summary = RequestMetrics::default().to_json();

        assert_eq!(summary["request_count_by_operation"], json!({}));
        assert_eq!(summary["total_request_count"], json!(0));
        assert_eq!(summary["total_error_count"], json!(0));
        assert_eq!(summary["total_retry_count"], json!(0));
    }
}
