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
    pub startup_prefetch: Value,
    pub kv_upload: Value,
    pub singleflight: Value,
    pub local_cache: Value,
    pub buildkit: Value,
}

pub fn build_cache_session_summary(state: &AppState) -> CacheSessionSummarySnapshot {
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let classification = classify_cache_session(state);
    let oci_body = state.oci_body_metrics.metadata_hints();
    let oci_engine = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    let oci_negative = state.oci_negative_cache.metadata_hints();
    let singleflight = state.singleflight_metrics.metadata_hints();

    let proxy = json!({
        "mode": classification.mode,
        "adapter": classification.adapter,
        "hydration_policy": state.oci_hydration_policy.as_str(),
        "duration_ms": duration_ms,
        "read_only": state.read_only,
        "fail_on_cache_error": state.fail_on_cache_error,
        "blob_download_max_concurrency": state.blob_download_max_concurrency,
        "blob_prefetch_max_concurrency": state.blob_prefetch_max_concurrency,
        "blob_prefetch_concurrency_source": if state.blob_prefetch_concurrency_from_env { "env" } else { "auto" },
        "oci_alias_promotion_refs": &state.oci_alias_promotion_refs,
    });
    let startup_prefetch = map_to_json(state.prefetch_metrics.metadata_hints());
    let kv_upload = map_to_json(state.kv_blob_upload_metrics.metadata_hints());
    let rails = crate::observability::rails_request_summary();
    let storage = storage_summary(&oci_engine);
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
        "run_classification": if classification.adapter == "oci" {
            "unknown"
        } else {
            "not_applicable"
        },
    });

    CacheSessionSummarySnapshot {
        schema: "cache-session-v2",
        mode: classification.mode,
        adapter: classification.adapter,
        workspace: state.workspace.clone(),
        duration_ms,
        proxy,
        rails,
        storage,
        oci,
        startup_prefetch,
        kv_upload,
        singleflight: map_to_json(singleflight),
        local_cache,
        buildkit,
    }
}

fn storage_summary(oci_engine: &BTreeMap<String, String>) -> Value {
    let raw = select_metric_prefixes(
        oci_engine,
        &[
            "oci_engine_storage_",
            "oci_engine_local_spool_",
            "oci_engine_digest_verify_",
            "oci_engine_cache_promotion_",
        ],
    );
    let mut object = serde_json::Map::new();

    let request_count = metric_u64(oci_engine, "oci_engine_storage_get_count").unwrap_or(0);
    let bytes = metric_u64(oci_engine, "oci_engine_storage_get_bytes").unwrap_or(0);
    let ttfb_ms_sum = metric_u64(oci_engine, "oci_engine_storage_get_ttfb_ms").unwrap_or(0);
    let body_duration_ms_sum =
        metric_u64(oci_engine, "oci_engine_storage_get_body_duration_ms").unwrap_or(0);
    let retry_count = metric_u64(oci_engine, "oci_engine_storage_get_retry_count").unwrap_or(0);
    let error_count = metric_u64(oci_engine, "oci_engine_storage_get_error_count").unwrap_or(0);
    let timeout_count = metric_u64(oci_engine, "oci_engine_storage_get_timeout_count").unwrap_or(0);

    if request_count > 0 || bytes > 0 || retry_count > 0 || error_count > 0 {
        object.insert(
            "direction".to_string(),
            Value::String("download".to_string()),
        );
        object.insert(
            "object_kind".to_string(),
            Value::String("oci_blob".to_string()),
        );
        object.insert("request_count".to_string(), Value::from(request_count));
        object.insert("bytes".to_string(), Value::from(bytes));
        object.insert("retry_count".to_string(), Value::from(retry_count));
        object.insert("error_count".to_string(), Value::from(error_count));
        object.insert("timeout_count".to_string(), Value::from(timeout_count));

        if request_count > 0 {
            object.insert(
                "ttfb_ms".to_string(),
                Value::from(ttfb_ms_sum / request_count),
            );
            object.insert(
                "body_duration_ms".to_string(),
                Value::from(body_duration_ms_sum / request_count),
            );
        }
        object.insert("ttfb_ms_sum".to_string(), Value::from(ttfb_ms_sum));
        object.insert(
            "body_duration_ms_sum".to_string(),
            Value::from(body_duration_ms_sum),
        );

        if let Some(throughput) = throughput_mbps(bytes, body_duration_ms_sum) {
            object.insert("throughput_mbps".to_string(), json!(throughput));
        }
        for (source_key, target_key) in [
            ("oci_engine_storage_region", "region"),
            ("oci_engine_storage_cache_status", "cache_status"),
            ("oci_engine_storage_block_location", "block_location"),
        ] {
            if let Some(value) = oci_engine.get(source_key)
                && !value.trim().is_empty()
            {
                object.insert(target_key.to_string(), Value::String(value.clone()));
            }
        }
    }

    for (key, value) in raw {
        object
            .entry(key)
            .or_insert_with(|| json_metric_value(&value));
    }

    Value::Object(object)
}

struct CacheSessionClassification {
    mode: &'static str,
    adapter: &'static str,
}

fn classify_cache_session(state: &AppState) -> CacheSessionClassification {
    if let Some(tool) = state.proxy_metadata_hint("tool")
        && let Some(classification) = classify_tool_hint(&tool)
    {
        return classification;
    }

    if state.proxy_metadata_hint("docker_cache_ref_tag").is_some()
        || !state.oci_alias_promotion_refs.is_empty()
    {
        return CacheSessionClassification {
            mode: "docker-registry",
            adapter: "oci",
        };
    }

    CacheSessionClassification {
        mode: "cache-registry",
        adapter: "runtime",
    }
}

fn classify_tool_hint(tool: &str) -> Option<CacheSessionClassification> {
    let classification = match tool {
        "docker" | "buildkit" | "oci" => CacheSessionClassification {
            mode: "docker-registry",
            adapter: "oci",
        },
        "turbo" | "turborepo" => CacheSessionClassification {
            mode: "cache-registry",
            adapter: "turborepo",
        },
        "nx" => CacheSessionClassification {
            mode: "cache-registry",
            adapter: "nx",
        },
        "bazel" => CacheSessionClassification {
            mode: "cache-registry",
            adapter: "bazel",
        },
        "gradle" => CacheSessionClassification {
            mode: "cache-registry",
            adapter: "gradle",
        },
        "maven" => CacheSessionClassification {
            mode: "cache-registry",
            adapter: "maven",
        },
        "sccache" => CacheSessionClassification {
            mode: "cache-registry",
            adapter: "sccache",
        },
        "go" | "gocache" | "go-cache" => CacheSessionClassification {
            mode: "cache-registry",
            adapter: "gocache",
        },
        _ => return None,
    };
    Some(classification)
}

#[cfg(test)]
fn canonical_cache_registry_tools() -> &'static [&'static str] {
    &[
        "turborepo",
        "nx",
        "bazel",
        "gradle",
        "maven",
        "sccache",
        "gocache",
    ]
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

fn metric_u64(map: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    map.get(key).and_then(|value| value.parse::<u64>().ok())
}

fn throughput_mbps(bytes: u64, body_duration_ms: u64) -> Option<f64> {
    if bytes == 0 || body_duration_ms == 0 {
        return None;
    }
    let mbps = (bytes as f64 * 8.0) / (body_duration_ms as f64 / 1000.0) / 1_000_000.0;
    Some((mbps * 100.0).round() / 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tool_hint_keeps_kv_adapters_out_of_oci_mode() {
        for tool in canonical_cache_registry_tools() {
            let classification = classify_tool_hint(tool).expect("known tool");
            assert_eq!(classification.mode, "cache-registry");
            assert_eq!(classification.adapter, *tool);
        }
    }

    #[test]
    fn classify_tool_hint_accepts_legacy_command_aliases() {
        for (tool, expected_adapter) in [
            ("turbo", "turborepo"),
            ("go", "gocache"),
            ("go-cache", "gocache"),
        ] {
            let classification = classify_tool_hint(tool).expect("known tool");
            assert_eq!(classification.mode, "cache-registry");
            assert_eq!(classification.adapter, expected_adapter);
        }
    }

    #[test]
    fn classify_tool_hint_keeps_docker_on_oci_mode() {
        let classification = classify_tool_hint("docker").expect("docker tool");
        assert_eq!(classification.mode, "docker-registry");
        assert_eq!(classification.adapter, "oci");
    }

    #[test]
    fn cache_registry_fallback_uses_valid_runtime_tool() {
        let classification = CacheSessionClassification {
            mode: "cache-registry",
            adapter: "runtime",
        };
        assert_eq!(classification.mode, "cache-registry");
        assert_eq!(classification.adapter, "runtime");
    }

    #[test]
    fn storage_summary_combines_normalized_fields_with_raw_proxy_counters() {
        let summary = storage_summary(&BTreeMap::from([
            ("oci_engine_storage_get_count".to_string(), "2".to_string()),
            (
                "oci_engine_storage_get_bytes".to_string(),
                "50000000".to_string(),
            ),
            (
                "oci_engine_storage_get_ttfb_ms".to_string(),
                "400".to_string(),
            ),
            (
                "oci_engine_storage_get_body_duration_ms".to_string(),
                "2000".to_string(),
            ),
            (
                "oci_engine_storage_get_retry_count".to_string(),
                "1".to_string(),
            ),
            ("oci_engine_storage_region".to_string(), "iad".to_string()),
            (
                "oci_engine_storage_cache_status".to_string(),
                "hit".to_string(),
            ),
            (
                "oci_engine_storage_block_location".to_string(),
                "remote".to_string(),
            ),
        ]));

        assert_eq!(summary["direction"], "download");
        assert_eq!(summary["object_kind"], "oci_blob");
        assert_eq!(summary["request_count"], 2);
        assert_eq!(summary["bytes"], 50_000_000);
        assert_eq!(summary["ttfb_ms"], 200);
        assert_eq!(summary["ttfb_ms_sum"], 400);
        assert_eq!(summary["body_duration_ms"], 1000);
        assert_eq!(summary["body_duration_ms_sum"], 2000);
        assert_eq!(summary["throughput_mbps"], 200.0);
        assert_eq!(summary["retry_count"], 1);
        assert_eq!(summary["error_count"], 0);
        assert_eq!(summary["region"], "iad");
        assert_eq!(summary["cache_status"], "hit");
        assert_eq!(summary["block_location"], "remote");
        assert_eq!(summary["oci_engine_storage_get_ttfb_ms"], 400);
    }
}
