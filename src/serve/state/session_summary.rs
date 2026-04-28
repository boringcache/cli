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
        "run_classification": if classification.adapter == "oci" {
            "unknown"
        } else {
            "not_applicable"
        },
    });

    CacheSessionSummarySnapshot {
        schema: "cache-session-v1",
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
}
