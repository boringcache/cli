use crate::observability;
use crate::serve::state::{AppState, diagnostics_enabled};
use std::sync::OnceLock;

use super::{BlobReadSource, KvNamespace};

pub(crate) const SERVE_METRIC_SOURCE: &str = "serve";
pub(crate) const SERVE_PRELOAD_INDEX_OPERATION: &str = "cache_preload_index_fetch";
pub(crate) const SERVE_PREFETCH_OPERATION: &str = "blob_prefetch_cycle";
pub(crate) const SERVE_PRELOAD_INDEX_PATH: &str = "/serve/cache_registry/preload-index";
pub(crate) const SERVE_PREFETCH_PATH: &str = "/serve/cache_registry/prefetch";
pub(crate) const SERVE_BLOB_READ_OPERATION: &str = "cache_blob_read";
pub(crate) const SERVE_BLOB_READ_PATH: &str = "/serve/cache_registry/blob-read";

pub(crate) fn kv_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(diagnostics_enabled)
}

pub(crate) fn kv_trace(namespace: KvNamespace, scoped_key: &str, stage: &str) {
    if !kv_trace_enabled() || !matches!(namespace, KvNamespace::Sccache) {
        return;
    }
    let truncated = scoped_key.get(..96).unwrap_or(scoped_key);
    eprintln!("KV TRACE stage={stage} key={truncated}");
}

pub(crate) fn emit_serve_event(
    workspace: Option<&str>,
    operation: &'static str,
    path: &'static str,
    details: String,
) {
    observability::emit(
        observability::ObservabilityEvent::event(
            SERVE_METRIC_SOURCE,
            operation,
            "EVENT",
            path.to_string(),
            details,
        )
        .with_workspace(workspace.map(|value| value.to_string())),
    );
}

pub(crate) fn emit_serve_phase_metric(
    workspace: Option<&str>,
    cache_entry_id: Option<&str>,
    operation: &'static str,
    path: &'static str,
    status: u16,
    duration_ms: u64,
    batch_size: Option<u64>,
) {
    observability::emit(
        observability::ObservabilityEvent::success(
            SERVE_METRIC_SOURCE,
            operation,
            "PHASE",
            path.to_string(),
            status,
            duration_ms,
            None,
            None,
            None,
            None,
            batch_size,
            None,
        )
        .with_workspace(workspace.map(|value| value.to_string()))
        .with_cache_entry_id(cache_entry_id.map(|value| value.to_string())),
    );
}

pub(crate) fn emit_blob_read_metric(
    state: &AppState,
    cache_entry_id: &str,
    source: BlobReadSource,
    bytes: u64,
    duration_ms: u64,
) {
    match source {
        BlobReadSource::LocalCache => state.blob_read_metrics.record_local(bytes, duration_ms),
        BlobReadSource::RemoteFetch => state.blob_read_metrics.record_remote(bytes, duration_ms),
    }
    observability::emit(
        observability::ObservabilityEvent::success(
            SERVE_METRIC_SOURCE,
            SERVE_BLOB_READ_OPERATION,
            "GET",
            SERVE_BLOB_READ_PATH.to_string(),
            200,
            duration_ms,
            None,
            Some(bytes),
            None,
            None,
            None,
            None,
        )
        .with_workspace(Some(state.workspace.clone()))
        .with_cache_entry_id(Some(cache_entry_id.to_string()))
        .with_details(Some(format!("source={}", source.as_str()))),
    );
}
