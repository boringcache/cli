use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::ci_detection::CiSourceRefType;

use super::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct CacheSessionSummarySnapshot {
    pub schema: &'static str,
    pub mode: &'static str,
    pub adapter: &'static str,
    pub workspace: String,
    pub duration_ms: u64,
    pub identity: Value,
    pub proxy: Value,
    pub backend_api: Value,
    pub rails: Value,
    pub storage: Value,
    pub lifecycle: Value,
    pub oci: Value,
    pub startup_prefetch: Value,
    pub kv_upload: Value,
    pub singleflight: Value,
    pub local_cache: Value,
    pub buildkit: Value,
    pub classification: Value,
}

pub fn build_cache_session_summary(state: &AppState) -> CacheSessionSummarySnapshot {
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let session_kind = classify_cache_session(state);
    let oci_body = state.oci_body_metrics.metadata_hints();
    let oci_engine = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    let oci_negative = state.oci_negative_cache.metadata_hints();
    let singleflight_hints = state.singleflight_metrics.metadata_hints();
    let startup_prefetch_hints = state.prefetch_metrics.metadata_hints();
    let kv_upload_hints = state.kv_blob_upload_metrics.metadata_hints();
    let skip_rule_match_count = state.skip_rule_metrics.matched_count();
    let identity = cache_session_identity(state);

    let proxy = json!({
        "mode": session_kind.mode,
        "adapter": session_kind.adapter,
        "hydration_policy": state.oci_hydration_policy.as_str(),
        "duration_ms": duration_ms,
        "read_only": state.read_only,
        "fail_on_cache_error": state.fail_on_cache_error,
        "blob_download_max_concurrency": state.blob_download_max_concurrency,
        "blob_prefetch_max_concurrency": state.blob_prefetch_max_concurrency,
        "blob_prefetch_concurrency_source": if state.blob_prefetch_concurrency_from_env { "env" } else { "auto" },
        "oci_alias_promotion_refs": &state.oci_alias_promotion_refs,
    });
    let rails = crate::observability::rails_request_summary();
    let backend_api = rails.clone();
    let storage = storage_summary(&oci_engine);
    let lifecycle = lifecycle_summary(
        &oci_engine,
        &startup_prefetch_hints,
        &kv_upload_hints,
        &singleflight_hints,
        skip_rule_match_count,
    );
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
        "run_classification": if session_kind.adapter == "oci" {
            "unknown"
        } else {
            "not_applicable"
        },
    });
    let classification = json!({
        "issue_candidates": []
    });

    CacheSessionSummarySnapshot {
        schema: "cache-session-v2",
        mode: session_kind.mode,
        adapter: session_kind.adapter,
        workspace: state.workspace.clone(),
        duration_ms,
        identity,
        proxy,
        backend_api,
        rails,
        storage,
        lifecycle,
        oci,
        startup_prefetch: map_to_json(startup_prefetch_hints),
        kv_upload: map_to_json(kv_upload_hints),
        singleflight: map_to_json(singleflight_hints),
        local_cache,
        buildkit,
        classification,
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

pub fn cache_session_identity(state: &AppState) -> Value {
    let mut object = serde_json::Map::new();

    if let Some(context) = &state.proxy_ci_run_context {
        let run_repository = context
            .repository
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&state.workspace);
        let uid = format!(
            "{}:{}:{}",
            context.provider, run_repository, context.run_uid
        );

        insert_string(&mut object, "kind", "ci");
        insert_string(&mut object, "uid", uid);
        insert_string(&mut object, "provider", context.provider.clone());
        insert_string(&mut object, "provider_run_uid", context.run_uid.clone());
        insert_optional_string(&mut object, "attempt", context.run_attempt.clone());
        insert_optional_string(&mut object, "repository", context.repository.clone());
        insert_string(
            &mut object,
            "source_ref_type",
            ci_ref_type_name(context.source_ref_type),
        );
        insert_optional_string(
            &mut object,
            "source_ref_name",
            context.source_ref_name.clone(),
        );
        if let Some(number) = context.pull_request_number {
            insert_string(&mut object, "change_number", number.to_string());
            insert_string(&mut object, "pull_request_number", number.to_string());
        }
        insert_optional_string(&mut object, "commit_sha", context.commit_sha.clone());
        insert_optional_string(
            &mut object,
            "run_started_at",
            context.run_started_at.clone(),
        );
        insert_string(
            &mut object,
            "summary_session_id",
            state.cache_session_summary_id.clone(),
        );

        return Value::Object(object);
    }

    let uid = format!(
        "local:{}:{}",
        state.workspace, state.cache_session_summary_id
    );
    insert_string(&mut object, "kind", "local");
    insert_string(&mut object, "uid", uid);
    insert_string(&mut object, "provider", "local");
    insert_string(
        &mut object,
        "provider_run_uid",
        state.cache_session_summary_id.clone(),
    );
    insert_string(&mut object, "source_ref_type", "local");
    insert_string(
        &mut object,
        "summary_session_id",
        state.cache_session_summary_id.clone(),
    );

    Value::Object(object)
}

fn lifecycle_summary(
    oci_engine: &BTreeMap<String, String>,
    startup_prefetch: &BTreeMap<String, String>,
    kv_upload: &BTreeMap<String, String>,
    singleflight: &BTreeMap<String, String>,
    skip_rule_match_count: u64,
) -> Value {
    let mut object = serde_json::Map::new();
    let mut miss_reason_counts = serde_json::Map::new();
    let mut degradation_reason_counts = serde_json::Map::new();
    let mut product_behavior_reason_counts = serde_json::Map::new();

    let entry_missing_count = sum_metric_keys(
        oci_engine,
        &[
            "oci_engine_miss_manifest",
            "oci_engine_miss_blob_locator",
            "oci_engine_miss_download_url",
            "oci_engine_miss_remote_blob",
        ],
    );
    insert_positive_count(
        &mut miss_reason_counts,
        "entry_missing",
        entry_missing_count,
    );
    insert_positive_count(
        &mut miss_reason_counts,
        "boringcache_skip_rule",
        skip_rule_match_count,
    );
    insert_positive_count(
        &mut product_behavior_reason_counts,
        "boringcache_skip_rule",
        skip_rule_match_count,
    );

    let storage_check_failed_count = sum_metric_keys(
        oci_engine,
        &[
            "oci_engine_remote_blob_check_errors",
            "oci_engine_storage_get_error_count",
            "oci_engine_storage_get_timeout_count",
        ],
    );
    insert_positive_count(
        &mut degradation_reason_counts,
        "storage_check_failed",
        storage_check_failed_count,
    );

    let negative_cache_hit_count = sum_metric_keys(
        oci_engine,
        &[
            "oci_engine_negative_cache_hit_manifest_ref",
            "oci_engine_negative_cache_hit_blob_locator",
            "oci_engine_negative_cache_hit_download_url",
            "oci_engine_negative_cache_hit_remote_blob",
        ],
    );
    insert_positive_count(
        &mut degradation_reason_counts,
        "negative_cache_hit",
        negative_cache_hit_count,
    );

    if metric_bool(startup_prefetch, "startup_prefetch_timed_out") {
        insert_positive_count(
            &mut degradation_reason_counts,
            "startup_prefetch_timeout",
            1,
        );
    }

    insert_positive_count(
        &mut degradation_reason_counts,
        "singleflight_timeout",
        sum_metric_suffix(singleflight, "_follower_timeouts"),
    );

    insert_positive_count(
        &mut degradation_reason_counts,
        "receipt_commit_failed",
        metric_u64(kv_upload, "kv_upload_failed_blobs").unwrap_or(0),
    );

    insert_count_map(&mut object, "miss_reason_counts", miss_reason_counts);
    insert_count_map(
        &mut object,
        "product_behavior_reason_counts",
        product_behavior_reason_counts,
    );
    let degraded_miss_count = sum_json_counts(&degradation_reason_counts);
    insert_count_map(
        &mut object,
        "degradation_reason_counts",
        degradation_reason_counts,
    );
    insert_positive_count(&mut object, "degraded_miss_count", degraded_miss_count);

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

fn insert_string(object: &mut serde_json::Map<String, Value>, key: &str, value: impl Into<String>) {
    let value = value.into();
    if !value.trim().is_empty() {
        object.insert(key.to_string(), Value::String(value));
    }
}

fn insert_optional_string(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<String>,
) {
    if let Some(value) = value {
        insert_string(object, key, value);
    }
}

fn ci_ref_type_name(ref_type: CiSourceRefType) -> &'static str {
    match ref_type {
        CiSourceRefType::Branch => "branch",
        CiSourceRefType::Tag => "tag",
        CiSourceRefType::PullRequest => "pull_request",
        CiSourceRefType::Other => "other",
    }
}

fn metric_u64(map: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    map.get(key).and_then(|value| value.parse::<u64>().ok())
}

fn metric_bool(map: &BTreeMap<String, String>, key: &str) -> bool {
    matches!(map.get(key).map(String::as_str), Some("true" | "1" | "yes"))
}

fn sum_metric_keys(map: &BTreeMap<String, String>, keys: &[&str]) -> u64 {
    keys.iter().filter_map(|key| metric_u64(map, key)).sum()
}

fn sum_metric_suffix(map: &BTreeMap<String, String>, suffix: &str) -> u64 {
    map.iter()
        .filter(|(key, _)| key.ends_with(suffix))
        .filter_map(|(_, value)| value.parse::<u64>().ok())
        .sum()
}

fn insert_positive_count(object: &mut serde_json::Map<String, Value>, key: &str, count: u64) {
    if count > 0 {
        object.insert(key.to_string(), Value::from(count));
    }
}

fn insert_count_map(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
    counts: serde_json::Map<String, Value>,
) {
    if !counts.is_empty() {
        object.insert(key.to_string(), Value::Object(counts));
    }
}

fn sum_json_counts(counts: &serde_json::Map<String, Value>) -> u64 {
    counts.values().filter_map(Value::as_u64).sum()
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

    #[test]
    fn lifecycle_summary_rolls_up_proxy_health_counters() {
        let summary = lifecycle_summary(
            &BTreeMap::from([
                ("oci_engine_miss_manifest".to_string(), "2".to_string()),
                ("oci_engine_miss_remote_blob".to_string(), "3".to_string()),
                (
                    "oci_engine_remote_blob_check_errors".to_string(),
                    "1".to_string(),
                ),
                (
                    "oci_engine_storage_get_error_count".to_string(),
                    "2".to_string(),
                ),
                (
                    "oci_engine_storage_get_timeout_count".to_string(),
                    "1".to_string(),
                ),
                (
                    "oci_engine_negative_cache_hit_manifest_ref".to_string(),
                    "4".to_string(),
                ),
                (
                    "oci_engine_negative_cache_hit_remote_blob".to_string(),
                    "5".to_string(),
                ),
            ]),
            &BTreeMap::from([("startup_prefetch_timed_out".to_string(), "true".to_string())]),
            &BTreeMap::from([("kv_upload_failed_blobs".to_string(), "2".to_string())]),
            &BTreeMap::from([(
                "singleflight_kv_lookup_follower_timeouts".to_string(),
                "6".to_string(),
            )]),
            7,
        );

        assert_eq!(summary["miss_reason_counts"]["entry_missing"], 5);
        assert_eq!(summary["miss_reason_counts"]["boringcache_skip_rule"], 7);
        assert_eq!(
            summary["product_behavior_reason_counts"]["boringcache_skip_rule"],
            7
        );
        assert_eq!(
            summary["degradation_reason_counts"]["storage_check_failed"],
            4
        );
        assert_eq!(
            summary["degradation_reason_counts"]["negative_cache_hit"],
            9
        );
        assert_eq!(
            summary["degradation_reason_counts"]["startup_prefetch_timeout"],
            1
        );
        assert_eq!(
            summary["degradation_reason_counts"]["singleflight_timeout"],
            6
        );
        assert_eq!(
            summary["degradation_reason_counts"]["receipt_commit_failed"],
            2
        );
        assert_eq!(summary["degraded_miss_count"], 22);
    }
}
