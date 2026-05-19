use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::serve::cache_registry::cache_ops::{OperationCounters, ToolOperationSummary};

const BAZEL_ACTION_KEY_NEXT_STEP: &str = "BoringCache pins Bazel's action and repository-rule PATH for its adapter path. If these misses persist, compare source changes first, then pin project-specific host toolchain inputs with repository-owned --repo_env values or an explicit Bazel toolchain.";

pub(super) fn cache_key_lookup_summary(
    adapter: &str,
    operation_summary: &ToolOperationSummary,
    kv_lookup: &BTreeMap<String, String>,
) -> Value {
    if adapter != "bazel" {
        return json!({
            "state": "not_applicable",
        });
    }

    let action_cache = operation_summary
        .scoped
        .get("bazel_action_cache")
        .cloned()
        .unwrap_or_default();
    let cas = operation_summary
        .scoped
        .get("bazel_cas")
        .cloned()
        .unwrap_or_default();
    let mut summary = action_cache_lookup_summary(&action_cache, kv_lookup);
    if let Value::Object(ref mut object) = summary {
        object.insert(
            "cas".to_string(),
            cas_lookup_summary(&cas, kv_lookup, action_cache.cache_read_hit_count),
        );
    }
    summary
}

fn action_cache_lookup_summary(
    action_cache: &OperationCounters,
    kv_lookup: &BTreeMap<String, String>,
) -> Value {
    let requests = action_cache
        .cache_read_hit_count
        .saturating_add(action_cache.cache_read_miss_count)
        .saturating_add(action_cache.cache_read_error_count);
    let published_fast_hits =
        metric_u64(kv_lookup, "kv_lookup_bazel_ac_published_fast_hit").unwrap_or(0);
    let published_fast_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_ac_published_fast_miss").unwrap_or(0);
    let after_refresh_hits =
        metric_u64(kv_lookup, "kv_lookup_bazel_ac_after_refresh_hit").unwrap_or(0);
    let after_refresh_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_ac_after_refresh_miss").unwrap_or(0);
    let post_flight_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_ac_post_flight_miss").unwrap_or(0);
    let recent_misses = metric_u64(kv_lookup, "kv_lookup_bazel_ac_recent_miss").unwrap_or(0);
    let leader_recent_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_ac_leader_recent_miss").unwrap_or(0);
    let integrity_misses = metric_u64(
        kv_lookup,
        "kv_lookup_bazel_ac_published_fast_integrity_miss",
    )
    .unwrap_or(0);
    let absent_from_warmed_cache = action_cache_absent_from_warmed_cache_count(kv_lookup)
        .min(action_cache.cache_read_miss_count);
    let state = action_cache_lookup_state(
        action_cache,
        requests,
        absent_from_warmed_cache,
        after_refresh_hits,
        integrity_misses,
    );

    json!({
        "tool": "bazel",
        "scope": "action_cache",
        "state": state,
        "diagnosis": action_cache_lookup_diagnosis(state),
        "owner": action_cache_lookup_owner(state),
        "customer_action_required": action_cache_lookup_customer_action_required(state),
        "next_step": action_cache_lookup_next_step(state),
        "confidence": action_cache_lookup_confidence(state, action_cache, absent_from_warmed_cache),
        "requests": requests,
        "hits": action_cache.cache_read_hit_count,
        "misses": action_cache.cache_read_miss_count,
        "errors": action_cache.cache_read_error_count,
        "evidence": {
            "warmed_cache_hits": published_fast_hits,
            "warmed_cache_misses_before_refresh": published_fast_misses,
            "warmed_cache_refresh_hits": after_refresh_hits,
            "warmed_cache_refresh_misses": after_refresh_misses,
            "shared_lookup_wait_misses": post_flight_misses,
            "recent_negative_cache_misses": recent_misses.saturating_add(leader_recent_misses),
            "integrity_misses": integrity_misses,
            "absent_from_warmed_cache": absent_from_warmed_cache,
        }
    })
}

fn action_cache_lookup_state(
    action_cache: &OperationCounters,
    requests: u64,
    absent_from_warmed_cache: u64,
    after_refresh_hits: u64,
    integrity_misses: u64,
) -> &'static str {
    if requests == 0 {
        return "no_action_cache_requests";
    }
    if action_cache.cache_read_error_count > 0 {
        return "action_cache_request_errors";
    }
    if integrity_misses > 0 {
        return "warmed_cache_integrity_mismatch";
    }
    if action_cache.cache_read_miss_count == 0 && after_refresh_hits > 0 {
        return "warmed_cache_refresh_recovered_action_cache_lookup";
    }
    if action_cache.cache_read_miss_count == 0 {
        return "action_cache_hot";
    }
    if absent_from_warmed_cache >= action_cache.cache_read_miss_count
        && action_cache.cache_read_hit_count == 0
    {
        return "requested_keys_absent_from_warmed_cache";
    }
    if absent_from_warmed_cache > 0 {
        return "some_requested_keys_absent_from_warmed_cache";
    }
    if after_refresh_hits > 0 {
        return "mixed_action_cache_after_warmed_cache_refresh";
    }

    "action_cache_miss_unclassified"
}

fn action_cache_lookup_diagnosis(state: &str) -> &'static str {
    match state {
        "no_action_cache_requests" => "No Bazel action-cache lookups were observed.",
        "action_cache_request_errors" => "Bazel action-cache lookups returned errors.",
        "warmed_cache_integrity_mismatch" => {
            "Bazel asked for action-cache keys that existed in the warmed cache entry, but BoringCache rejected the entries because their integrity did not match the request."
        }
        "warmed_cache_refresh_recovered_action_cache_lookup" => {
            "Bazel asked for action-cache keys that were missing from the warmed cache entry view, and BoringCache recovered them by refreshing that entry."
        }
        "action_cache_hot" => "Bazel action-cache lookups hit the warmed cache.",
        "requested_keys_absent_from_warmed_cache" => {
            "Bazel asked for action-cache keys that were not present in the warmed cache entry, even after BoringCache refreshed that entry."
        }
        "some_requested_keys_absent_from_warmed_cache" => {
            "Some Bazel action-cache keys were present in the warmed cache entry and some were absent, even after BoringCache refreshed that entry."
        }
        "mixed_action_cache_after_warmed_cache_refresh" => {
            "Bazel action-cache lookups were mixed after refreshing the warmed cache entry."
        }
        _ => "Bazel action-cache lookups missed, but the proxy did not classify the cause.",
    }
}

fn action_cache_lookup_owner(state: &str) -> &'static str {
    match state {
        "action_cache_request_errors"
        | "warmed_cache_integrity_mismatch"
        | "warmed_cache_refresh_recovered_action_cache_lookup" => "boringcache",
        "requested_keys_absent_from_warmed_cache"
        | "some_requested_keys_absent_from_warmed_cache"
        | "mixed_action_cache_after_warmed_cache_refresh" => "shared",
        "action_cache_hot" | "no_action_cache_requests" => "none",
        _ => "unknown",
    }
}

fn action_cache_lookup_customer_action_required(state: &str) -> bool {
    matches!(
        state,
        "requested_keys_absent_from_warmed_cache"
            | "some_requested_keys_absent_from_warmed_cache"
            | "mixed_action_cache_after_warmed_cache_refresh"
            | "action_cache_miss_unclassified"
    )
}

fn action_cache_lookup_next_step(state: &str) -> &'static str {
    match state {
        "no_action_cache_requests" => "No action needed.",
        "action_cache_request_errors" => {
            "Inspect BoringCache service and proxy errors for the same run."
        }
        "warmed_cache_integrity_mismatch" => {
            "Treat this as a BoringCache cache-entry integrity bug and inspect the saved entry for the reported cache run."
        }
        "warmed_cache_refresh_recovered_action_cache_lookup" => {
            "No workflow change is needed; inspect why the warmed cache entry view was stale if this repeats."
        }
        "action_cache_hot" => "No action needed.",
        "requested_keys_absent_from_warmed_cache" => BAZEL_ACTION_KEY_NEXT_STEP,
        "some_requested_keys_absent_from_warmed_cache" => {
            "Compare the missed Bazel actions against changed inputs; this usually means partial new work or action-key churn. If source did not change, pin project-specific host toolchain inputs with repository-owned --repo_env values or an explicit Bazel toolchain."
        }
        "mixed_action_cache_after_warmed_cache_refresh" => {
            "Compare Bazel action inputs first, then inspect BoringCache warmed-entry refresh evidence if the same keys later hit."
        }
        _ => "Inspect raw kv_lookup evidence for the run.",
    }
}

fn action_cache_lookup_confidence(
    state: &str,
    action_cache: &OperationCounters,
    absent_from_warmed_cache: u64,
) -> &'static str {
    match state {
        "requested_keys_absent_from_warmed_cache"
            if absent_from_warmed_cache >= action_cache.cache_read_miss_count
                && action_cache.cache_read_miss_count > 0 =>
        {
            "high"
        }
        "action_cache_hot"
        | "warmed_cache_integrity_mismatch"
        | "warmed_cache_refresh_recovered_action_cache_lookup" => "high",
        "some_requested_keys_absent_from_warmed_cache"
        | "mixed_action_cache_after_warmed_cache_refresh" => "medium",
        "no_action_cache_requests" => "high",
        _ => "low",
    }
}

pub(super) fn issue_candidates_summary(
    adapter: &str,
    operation_summary: &ToolOperationSummary,
    kv_lookup: &BTreeMap<String, String>,
) -> Value {
    let mut issues = Vec::new();

    if adapter == "bazel" {
        let action_cache = operation_summary
            .scoped
            .get("bazel_action_cache")
            .cloned()
            .unwrap_or_default();
        let absent_count = action_cache_absent_from_warmed_cache_count(kv_lookup)
            .min(action_cache.cache_read_miss_count);
        if absent_count > 0 {
            issues.push(json!({
                "kind": "bazel_action_cache_key_mismatch",
                "summary": "Bazel requested action-cache keys that were not present in the warmed cache entry.",
                "owner": "shared",
                "surface": "json",
                "severity": "actionable",
                "confidence": 0.85,
                "customer_action_required": true,
                "next_step": BAZEL_ACTION_KEY_NEXT_STEP,
                "evidence_refs": [
                    "classification.cache_key_lookup",
                    "kv_lookup"
                ],
                "evidence": {
                    "action_cache_misses": action_cache.cache_read_miss_count,
                    "absent_from_warmed_cache": absent_count,
                    "warmed_cache_misses_before_refresh": metric_u64(kv_lookup, "kv_lookup_bazel_ac_published_fast_miss").unwrap_or(0),
                    "after_refresh_misses": metric_u64(kv_lookup, "kv_lookup_bazel_ac_after_refresh_miss").unwrap_or(0),
                    "shared_lookup_wait_misses": metric_u64(kv_lookup, "kv_lookup_bazel_ac_post_flight_miss").unwrap_or(0),
                }
            }));
        }

        let refresh_hits =
            metric_u64(kv_lookup, "kv_lookup_bazel_ac_after_refresh_hit").unwrap_or(0);
        if refresh_hits > 0 {
            issues.push(json!({
                "kind": "bazel_action_cache_warmed_cache_refresh_recovered_lookup",
                "summary": "BoringCache had to refresh the warmed cache entry before Bazel action-cache keys became visible.",
                "owner": "boringcache",
                "customer_action_required": false,
                "next_step": "No workflow change is needed; inspect warmed-entry refresh evidence if this repeats.",
                "evidence_refs": [
                    "classification.cache_key_lookup",
                    "kv_lookup"
                ],
                "evidence": {
                    "warmed_cache_refresh_hits": refresh_hits
                }
            }));
        }

        let integrity_misses = metric_u64(
            kv_lookup,
            "kv_lookup_bazel_ac_published_fast_integrity_miss",
        )
        .unwrap_or(0);
        if integrity_misses > 0 {
            issues.push(json!({
                "kind": "bazel_action_cache_entry_integrity_mismatch",
                "summary": "A warmed Bazel action-cache entry did not match the requested key integrity.",
                "owner": "boringcache",
                "customer_action_required": false,
                "next_step": "Treat this as a BoringCache cache-entry integrity bug and inspect the saved entry for the reported cache run.",
                "evidence_refs": [
                    "classification.cache_key_lookup",
                    "kv_lookup"
                ],
                "evidence": {
                    "integrity_misses": integrity_misses
                }
            }));
        }
    }

    Value::Array(issues)
}

fn cas_lookup_summary(
    cas: &OperationCounters,
    kv_lookup: &BTreeMap<String, String>,
    action_cache_hits: u64,
) -> Value {
    let requests = cas
        .cache_read_hit_count
        .saturating_add(cas.cache_read_miss_count)
        .saturating_add(cas.cache_read_error_count);
    let published_fast_hits =
        metric_u64(kv_lookup, "kv_lookup_bazel_cas_published_fast_hit").unwrap_or(0);
    let published_fast_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_cas_published_fast_miss").unwrap_or(0);
    let after_refresh_hits =
        metric_u64(kv_lookup, "kv_lookup_bazel_cas_after_refresh_hit").unwrap_or(0);
    let after_refresh_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_cas_after_refresh_miss").unwrap_or(0);
    let post_flight_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_cas_post_flight_miss").unwrap_or(0);
    let recent_misses = metric_u64(kv_lookup, "kv_lookup_bazel_cas_recent_miss").unwrap_or(0);
    let leader_recent_misses =
        metric_u64(kv_lookup, "kv_lookup_bazel_cas_leader_recent_miss").unwrap_or(0);
    let integrity_misses = metric_u64(
        kv_lookup,
        "kv_lookup_bazel_cas_published_fast_integrity_miss",
    )
    .unwrap_or(0);
    let absent_from_warmed_cache =
        cas_absent_from_warmed_cache_count(kv_lookup).min(cas.cache_read_miss_count);
    let state = cas_lookup_state(
        cas,
        requests,
        absent_from_warmed_cache,
        after_refresh_hits,
        integrity_misses,
        action_cache_hits,
    );

    json!({
        "scope": "cas",
        "state": state,
        "owner": cas_lookup_owner(state),
        "customer_action_required": cas_lookup_customer_action_required(state),
        "requests": requests,
        "hits": cas.cache_read_hit_count,
        "misses": cas.cache_read_miss_count,
        "errors": cas.cache_read_error_count,
        "evidence": {
            "warmed_cache_hits": published_fast_hits,
            "warmed_cache_misses_before_refresh": published_fast_misses,
            "warmed_cache_refresh_hits": after_refresh_hits,
            "warmed_cache_refresh_misses": after_refresh_misses,
            "shared_lookup_wait_misses": post_flight_misses,
            "recent_negative_cache_misses": recent_misses.saturating_add(leader_recent_misses),
            "integrity_misses": integrity_misses,
            "absent_from_warmed_cache": absent_from_warmed_cache,
            "action_cache_hits": action_cache_hits,
        }
    })
}

fn cas_lookup_state(
    cas: &OperationCounters,
    requests: u64,
    absent_from_warmed_cache: u64,
    after_refresh_hits: u64,
    integrity_misses: u64,
    action_cache_hits: u64,
) -> &'static str {
    if requests == 0 {
        return "no_cas_requests";
    }
    if cas.cache_read_error_count > 0 {
        return "cas_request_errors";
    }
    if integrity_misses > 0 {
        return "cas_integrity_mismatch";
    }
    if cas.cache_read_miss_count == 0 && after_refresh_hits > 0 {
        return "cas_refresh_recovered_lookup";
    }
    if cas.cache_read_miss_count == 0 {
        return "cas_hot";
    }
    if action_cache_hits > 0 && absent_from_warmed_cache > 0 {
        return "cas_missing_for_action_cache_hits";
    }
    if absent_from_warmed_cache > 0 {
        return "cas_keys_absent_from_warmed_cache";
    }
    if after_refresh_hits > 0 {
        return "mixed_cas_after_warmed_cache_refresh";
    }

    "cas_miss_unclassified"
}

fn cas_lookup_owner(state: &str) -> &'static str {
    match state {
        "cas_request_errors"
        | "cas_integrity_mismatch"
        | "cas_refresh_recovered_lookup"
        | "cas_missing_for_action_cache_hits" => "boringcache",
        "cas_keys_absent_from_warmed_cache" | "mixed_cas_after_warmed_cache_refresh" => "shared",
        "cas_hot" | "no_cas_requests" => "none",
        _ => "unknown",
    }
}

fn cas_lookup_customer_action_required(state: &str) -> bool {
    matches!(
        state,
        "cas_keys_absent_from_warmed_cache"
            | "mixed_cas_after_warmed_cache_refresh"
            | "cas_miss_unclassified"
    )
}

pub(super) fn action_cache_absent_from_warmed_cache_count(
    kv_lookup: &BTreeMap<String, String>,
) -> u64 {
    sum_metric_keys(
        kv_lookup,
        &[
            "kv_lookup_bazel_ac_after_refresh_miss",
            "kv_lookup_bazel_ac_post_flight_miss",
            "kv_lookup_bazel_ac_recent_miss",
            "kv_lookup_bazel_ac_leader_recent_miss",
        ],
    )
}

fn cas_absent_from_warmed_cache_count(kv_lookup: &BTreeMap<String, String>) -> u64 {
    sum_metric_keys(
        kv_lookup,
        &[
            "kv_lookup_bazel_cas_after_refresh_miss",
            "kv_lookup_bazel_cas_post_flight_miss",
            "kv_lookup_bazel_cas_recent_miss",
            "kv_lookup_bazel_cas_leader_recent_miss",
        ],
    )
}

fn metric_u64(map: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    map.get(key).and_then(|value| value.parse::<u64>().ok())
}

fn sum_metric_keys(map: &BTreeMap<String, String>, keys: &[&str]) -> u64 {
    keys.iter().filter_map(|key| metric_u64(map, key)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_cache_lookup_summary_productizes_key_mismatches() {
        let action_cache = OperationCounters {
            cache_read_miss_count: 3,
            ..OperationCounters::default()
        };
        let lookup = BTreeMap::from([
            (
                "kv_lookup_bazel_ac_published_fast_miss".to_string(),
                "3".to_string(),
            ),
            (
                "kv_lookup_bazel_ac_after_refresh_miss".to_string(),
                "3".to_string(),
            ),
        ]);

        let summary = action_cache_lookup_summary(&action_cache, &lookup);

        assert_eq!(summary["state"], "requested_keys_absent_from_warmed_cache");
        assert_eq!(summary["owner"], "shared");
        assert_eq!(summary["customer_action_required"], true);
        assert_eq!(summary["confidence"], "high");
        assert_eq!(summary["evidence"]["absent_from_warmed_cache"], 3);
    }

    #[test]
    fn issue_candidates_promote_key_mismatch_to_one_answer() {
        let operation_summary = ToolOperationSummary {
            scoped: BTreeMap::from([(
                "bazel_action_cache".to_string(),
                OperationCounters {
                    cache_read_miss_count: 2,
                    ..OperationCounters::default()
                },
            )]),
            ..Default::default()
        };
        let lookup = BTreeMap::from([(
            "kv_lookup_bazel_ac_after_refresh_miss".to_string(),
            "2".to_string(),
        )]);

        let issues = issue_candidates_summary("bazel", &operation_summary, &lookup);
        let issues = issues.as_array().expect("issue array");

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0]["kind"], "bazel_action_cache_key_mismatch");
        assert_eq!(issues[0]["owner"], "shared");
        assert_eq!(issues[0]["severity"], "actionable");
        assert_eq!(issues[0]["customer_action_required"], true);
        assert_eq!(issues[0]["evidence"]["absent_from_warmed_cache"], 2);
        assert_eq!(issues[0]["next_step"], BAZEL_ACTION_KEY_NEXT_STEP);
    }

    #[test]
    fn cache_key_lookup_summary_includes_cas_signal() {
        let operation_summary = ToolOperationSummary {
            scoped: BTreeMap::from([
                (
                    "bazel_action_cache".to_string(),
                    OperationCounters {
                        cache_read_hit_count: 2,
                        ..OperationCounters::default()
                    },
                ),
                (
                    "bazel_cas".to_string(),
                    OperationCounters {
                        cache_read_miss_count: 1,
                        ..OperationCounters::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let lookup = BTreeMap::from([(
            "kv_lookup_bazel_cas_after_refresh_miss".to_string(),
            "1".to_string(),
        )]);

        let summary = cache_key_lookup_summary("bazel", &operation_summary, &lookup);

        assert_eq!(summary["cas"]["scope"], "cas");
        assert_eq!(summary["cas"]["state"], "cas_missing_for_action_cache_hits");
        assert_eq!(summary["cas"]["owner"], "boringcache");
        assert_eq!(summary["cas"]["customer_action_required"], false);
        assert_eq!(summary["cas"]["evidence"]["action_cache_hits"], 2);
        assert_eq!(summary["cas"]["evidence"]["absent_from_warmed_cache"], 1);
    }
}
