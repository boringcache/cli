use crate::observability::ObservabilityEvent;
use serde_json::to_string;
use std::env;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const OBSERVABILITY_JSONL_PATH_ENV: &str = "BORINGCACHE_OBSERVABILITY_JSONL_PATH";
const OBSERVABILITY_ARCHIVE_DIR_ENV: &str = "BORINGCACHE_OBSERVABILITY_ARCHIVE_DIR";
const OBSERVABILITY_ARCHIVE_WORKSPACE_ENV: &str = "BORINGCACHE_OBSERVABILITY_ARCHIVE_WORKSPACE";
const INTERNAL_LOG_DIR_NAME: &str = ".boringcache";
const INTERNAL_LOG_SUBDIR_NAME: &str = "logs";
const DEFAULT_OBSERVABILITY_JSONL_FILE: &str = "cache-registry-request-metrics.jsonl";

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
