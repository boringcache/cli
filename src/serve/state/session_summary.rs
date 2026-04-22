use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct CacheSessionSummarySnapshot {
    pub schema: &'static str,
    pub mode: &'static str,
    pub adapter: &'static str,
    pub workspace: String,
    pub duration_ms: u64,
    pub proxy: Value,
    pub rails: Value,
    pub storage: Value,
    pub oci: Value,
    pub singleflight: Value,
    pub local_cache: Value,
    pub buildkit: Value,
}

pub fn build_cache_session_summary(state: &AppState) -> CacheSessionSummarySnapshot {
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let oci_body = state.oci_body_metrics.metadata_hints();
    let oci_engine = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    let oci_negative = state.oci_negative_cache.metadata_hints();
    let singleflight = state.singleflight_metrics.metadata_hints();

    let proxy = json!({
        "hydration_policy": state.oci_hydration_policy.as_str(),
        "duration_ms": duration_ms,
        "read_only": state.read_only,
        "fail_on_cache_error": state.fail_on_cache_error,
        "blob_download_max_concurrency": state.blob_download_max_concurrency,
        "oci_alias_promotion_refs": &state.oci_alias_promotion_refs,
    });
    let rails = json!({
        "request_metrics": "see_jsonl",
    });
    let storage = map_to_json(select_metric_prefixes(
        &oci_engine,
        &[
            "oci_engine_storage_",
            "oci_engine_local_spool_",
            "oci_engine_digest_verify_",
            "oci_engine_cache_promotion_",
        ],
    ));
    let mut oci = merged_maps_to_json(&[oci_body.clone(), oci_engine, oci_negative]);
    if let Some(object) = oci.as_object_mut() {
        object.insert(
            "buildkit_enrichment".to_string(),
            Value::String("unknown".to_string()),
        );
    }
    let local_cache = json!({
        "blob_read_cache_bytes": state.blob_read_cache.total_bytes(),
        "blob_read_cache_max_bytes": state.blob_read_cache.max_bytes(),
        "oci_body": map_to_json(oci_body),
        "blob_read": map_to_json(state.blob_read_metrics.metadata_hints()),
    });
    let buildkit = json!({
        "run_classification": "unknown",
    });

    CacheSessionSummarySnapshot {
        schema: "cache-session-v1",
        mode: "docker-registry",
        adapter: "oci",
        workspace: state.workspace.clone(),
        duration_ms,
        proxy,
        rails,
        storage,
        oci,
        singleflight: map_to_json(singleflight),
        local_cache,
        buildkit,
    }
}

fn merged_maps_to_json(maps: &[BTreeMap<String, String>]) -> Value {
    let mut object = serde_json::Map::new();
    for map in maps {
        for (key, value) in map {
            object.insert(key.clone(), json_metric_value(value));
        }
    }
    Value::Object(object)
}

fn map_to_json(map: BTreeMap<String, String>) -> Value {
    let mut object = serde_json::Map::new();
    for (key, value) in map {
        object.insert(key, json_metric_value(&value));
    }
    Value::Object(object)
}

fn select_metric_prefixes(
    map: &BTreeMap<String, String>,
    prefixes: &[&str],
) -> BTreeMap<String, String> {
    map.iter()
        .filter(|(key, _)| prefixes.iter().any(|prefix| key.starts_with(prefix)))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn json_metric_value(value: &str) -> Value {
    value
        .parse::<u64>()
        .map(Value::from)
        .unwrap_or_else(|_| Value::String(value.to_string()))
}
