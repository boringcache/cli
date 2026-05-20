use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::serve::cache_registry::cache_ops::ToolOperationSummary;

const SLOW_PROXY_SESSION_MS: u64 = 60_000;
const SLOW_STARTUP_PREFETCH_MS: u64 = 30_000;
const SLOW_STORAGE_BODY_MS: u64 = 30_000;
const MEANINGFUL_STORAGE_BYTES: u64 = 50 * 1024 * 1024;

pub(super) fn bottleneck_summary(
    adapter: &str,
    operation_summary: &ToolOperationSummary,
    lifecycle: &Value,
    storage: &Value,
    startup_prefetch: &BTreeMap<String, String>,
    duration_ms: u64,
) -> Value {
    let counters = &operation_summary.totals;
    let reads = counters
        .cache_read_hit_count
        .saturating_add(counters.cache_read_miss_count);
    let hit_rate = hit_rate(
        counters.cache_read_hit_count,
        counters.cache_read_miss_count,
    );

    let mut candidates = Vec::new();

    let startup_prefetch_timed_out = metric_bool(startup_prefetch, "startup_prefetch_timed_out");
    let startup_prefetch_duration_ms =
        map_u64(startup_prefetch, "startup_prefetch_duration_ms").unwrap_or(0);
    if startup_prefetch_timed_out || startup_prefetch_duration_ms >= SLOW_STARTUP_PREFETCH_MS {
        candidates.push(candidate(
            "setup_overhead",
            if startup_prefetch_timed_out {
                "high"
            } else {
                "medium"
            },
            "Cache startup warmup took long enough to matter before the wrapped tool ran.",
            json!({
                "startup_prefetch_timed_out": startup_prefetch_timed_out,
                "startup_prefetch_duration_ms": startup_prefetch_duration_ms,
                "target_blobs": map_u64(startup_prefetch, "startup_prefetch_target_blobs"),
                "inserted_blobs": map_u64(startup_prefetch, "startup_prefetch_inserted"),
                "failed_blobs": map_u64(startup_prefetch, "startup_prefetch_failures"),
            }),
        ));
    }

    let receipt_commit_failed = lifecycle_count(
        lifecycle,
        "degradation_reason_counts",
        "receipt_commit_failed",
    );
    if counters.cache_write_error_count > 0 || receipt_commit_failed > 0 {
        candidates.push(candidate(
            "save_export",
            "high",
            "Cache writes or publish/flush work failed on the save path.",
            json!({
                "write_count": counters.cache_write_count,
                "write_errors": counters.cache_write_error_count,
                "receipt_commit_failed": receipt_commit_failed,
                "bytes_written": counters.cache_write_bytes,
            }),
        ));
    }

    let storage_check_failed = lifecycle_count(
        lifecycle,
        "degradation_reason_counts",
        "storage_check_failed",
    );
    let singleflight_timeout = lifecycle_count(
        lifecycle,
        "degradation_reason_counts",
        "singleflight_timeout",
    );
    let storage_errors = value_u64(storage, "error_count");
    let storage_timeouts = value_u64(storage, "timeout_count");
    if counters.cache_read_error_count > 0
        || storage_check_failed > 0
        || singleflight_timeout > 0
        || storage_errors > 0
        || storage_timeouts > 0
    {
        candidates.push(candidate(
            "cache_transport",
            "high",
            "Cache reads hit service, storage, or singleflight degradation.",
            json!({
                "read_errors": counters.cache_read_error_count,
                "storage_check_failed": storage_check_failed,
                "singleflight_timeout": singleflight_timeout,
                "storage_errors": storage_errors,
                "storage_timeouts": storage_timeouts,
            }),
        ));
    }

    let storage_body_ms =
        value_u64(storage, "body_duration_ms_sum").max(value_u64(storage, "body_duration_ms"));
    let storage_bytes = value_u64(storage, "bytes");
    if storage_body_ms >= SLOW_STORAGE_BODY_MS && storage_bytes >= MEANINGFUL_STORAGE_BYTES {
        candidates.push(candidate(
            "cache_transport",
            "medium",
            "Cache storage body transfer consumed meaningful time.",
            json!({
                "storage_body_duration_ms": storage_body_ms,
                "storage_bytes": storage_bytes,
                "storage_request_count": value_u64(storage, "request_count"),
                "storage_retry_count": value_u64(storage, "retry_count"),
            }),
        ));
    }

    if counters.cache_read_miss_count > 0 {
        candidates.push(candidate(
            "cache_miss_quality",
            if counters.cache_read_hit_count == 0 || hit_rate < 50.0 {
                "high"
            } else if hit_rate < 90.0 {
                "medium"
            } else {
                "low"
            },
            "The wrapped tool asked for cache keys that were not available in the warmed cache.",
            json!({
                "hits": counters.cache_read_hit_count,
                "misses": counters.cache_read_miss_count,
                "hit_rate": hit_rate,
                "bytes_read": counters.cache_read_bytes,
            }),
        ));
    }

    if candidates.is_empty() && reads > 0 && duration_ms >= SLOW_PROXY_SESSION_MS {
        candidates.push(candidate(
            "needs_native_diagnostics",
            "low",
            "Cache-side reads were hot; remaining time likely sits in the native tool or runner.",
            json!({
                "duration_ms": duration_ms,
                "hits": counters.cache_read_hit_count,
                "misses": counters.cache_read_miss_count,
                "hit_rate": hit_rate,
            }),
        ));
    }

    let primary_bottleneck = candidates
        .first()
        .and_then(|candidate| candidate.get("kind"))
        .cloned()
        .unwrap_or(Value::Null);
    let state = if candidates.is_empty() {
        if reads == 0 {
            "no_cache_reads"
        } else {
            "cache_side_clear"
        }
    } else {
        "bottleneck_detected"
    };

    json!({
        "state": state,
        "adapter": adapter,
        "primary_bottleneck": primary_bottleneck,
        "candidates": candidates,
        "evidence": {
            "duration_ms": duration_ms,
            "hits": counters.cache_read_hit_count,
            "misses": counters.cache_read_miss_count,
            "errors": counters.cache_read_error_count,
            "writes": counters.cache_write_count,
            "write_errors": counters.cache_write_error_count,
            "hit_rate": hit_rate,
        }
    })
}

fn candidate(kind: &str, confidence: &str, summary: &str, evidence: Value) -> Value {
    json!({
        "kind": kind,
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
    })
}

fn hit_rate(hits: u64, misses: u64) -> f64 {
    let reads = hits.saturating_add(misses);
    if reads == 0 {
        0.0
    } else {
        ((hits as f64 / reads as f64) * 1000.0).round() / 10.0
    }
}

fn lifecycle_count(lifecycle: &Value, group: &str, key: &str) -> u64 {
    lifecycle
        .get(group)
        .and_then(Value::as_object)
        .and_then(|counts| counts.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn value_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn map_u64(map: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    map.get(key).and_then(|value| value.parse().ok())
}

fn metric_bool(map: &BTreeMap<String, String>, key: &str) -> bool {
    map.get(key)
        .is_some_and(|value| value == "true" || value == "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serve::cache_registry::cache_ops::{OperationCounters, ToolOperationSummary};

    #[test]
    fn bottleneck_summary_classifies_miss_quality() {
        let summary = bottleneck_summary(
            "gradle",
            &ToolOperationSummary {
                totals: OperationCounters {
                    cache_read_hit_count: 20,
                    cache_read_miss_count: 10,
                    ..OperationCounters::default()
                },
                ..ToolOperationSummary::default()
            },
            &json!({}),
            &json!({}),
            &BTreeMap::new(),
            10_000,
        );

        assert_eq!(summary["primary_bottleneck"], "cache_miss_quality");
        assert_eq!(summary["candidates"][0]["confidence"], "medium");
        assert_eq!(summary["evidence"]["hit_rate"], 66.7);
    }

    #[test]
    fn bottleneck_summary_prefers_startup_overhead_when_prefetch_times_out() {
        let startup_prefetch = BTreeMap::from([
            ("startup_prefetch_timed_out".to_string(), "true".to_string()),
            (
                "startup_prefetch_duration_ms".to_string(),
                "45000".to_string(),
            ),
        ]);

        let summary = bottleneck_summary(
            "bazel",
            &ToolOperationSummary::default(),
            &json!({}),
            &json!({}),
            &startup_prefetch,
            45_000,
        );

        assert_eq!(summary["primary_bottleneck"], "setup_overhead");
        assert_eq!(summary["candidates"][0]["confidence"], "high");
    }

    #[test]
    fn bottleneck_summary_classifies_cache_transport_degradation() {
        let summary = bottleneck_summary(
            "oci",
            &ToolOperationSummary {
                totals: OperationCounters {
                    cache_read_error_count: 2,
                    ..OperationCounters::default()
                },
                ..ToolOperationSummary::default()
            },
            &json!({
                "degradation_reason_counts": {
                    "singleflight_timeout": 1
                }
            }),
            &json!({
                "error_count": 1,
                "timeout_count": 1,
            }),
            &BTreeMap::new(),
            20_000,
        );

        assert_eq!(summary["primary_bottleneck"], "cache_transport");
        assert_eq!(summary["candidates"][0]["confidence"], "high");
    }

    #[test]
    fn bottleneck_summary_classifies_write_failures_as_save_export() {
        let summary = bottleneck_summary(
            "turborepo",
            &ToolOperationSummary {
                totals: OperationCounters {
                    cache_write_count: 4,
                    cache_write_error_count: 1,
                    cache_write_bytes: 1024,
                    ..OperationCounters::default()
                },
                ..ToolOperationSummary::default()
            },
            &json!({}),
            &json!({}),
            &BTreeMap::new(),
            5_000,
        );

        assert_eq!(summary["primary_bottleneck"], "save_export");
    }

    #[test]
    fn bottleneck_summary_marks_long_hot_cache_run_for_native_diagnostics() {
        let summary = bottleneck_summary(
            "sccache",
            &ToolOperationSummary {
                totals: OperationCounters {
                    cache_read_hit_count: 10,
                    ..OperationCounters::default()
                },
                ..ToolOperationSummary::default()
            },
            &json!({}),
            &json!({}),
            &BTreeMap::new(),
            120_000,
        );

        assert_eq!(summary["primary_bottleneck"], "needs_native_diagnostics");
        assert_eq!(summary["candidates"][0]["confidence"], "low");
    }

    #[test]
    fn bottleneck_summary_stays_quiet_for_short_hot_cache_runs() {
        let summary = bottleneck_summary(
            "nx",
            &ToolOperationSummary {
                totals: OperationCounters {
                    cache_read_hit_count: 10,
                    ..OperationCounters::default()
                },
                ..ToolOperationSummary::default()
            },
            &json!({}),
            &json!({}),
            &BTreeMap::new(),
            5_000,
        );

        assert_eq!(summary["state"], "cache_side_clear");
        assert!(summary["primary_bottleneck"].is_null());
        assert_eq!(summary["candidates"].as_array().unwrap().len(), 0);
    }
}
