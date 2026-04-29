#!/usr/bin/env python3
import json
import math
from pathlib import Path
import sys


STATUS_NUMERIC_SECTIONS = (
    "startup_prefetch",
    "oci_body",
    "oci_engine",
    "oci_negative_cache",
    "singleflight",
)
STATUS_POLICY_FIELDS = (
    ("startup_prefetch", "startup_prefetch_oci_hydration"),
    ("oci_engine", "oci_engine_hydration_policy"),
)
STATUS_SNAPSHOT_PATTERNS = ("proxy-status-*.json", "status-*.json")
STATUS_SNAPSHOT_KEYS = (
    "startup_prefetch_oci_total_unique_blobs",
    "startup_prefetch_oci_body_inserted",
    "startup_prefetch_oci_body_failures",
    "startup_prefetch_oci_body_cold_blobs",
    "startup_prefetch_oci_body_duration_ms",
    "oci_body_local_hits",
    "oci_body_remote_fetches",
    "oci_body_local_bytes",
    "oci_body_remote_bytes",
    "oci_body_local_duration_ms",
    "oci_body_remote_duration_ms",
    "oci_engine_proof_total",
    "oci_engine_proof_bytes",
    "oci_engine_proof_upload_session",
    "oci_engine_proof_mounted_session",
    "oci_engine_proof_manifest_reference_session",
    "oci_engine_proof_local_body_cache",
    "oci_engine_proof_remote_storage",
    "oci_engine_blob_local_reads",
    "oci_engine_blob_remote_reads",
    "oci_engine_blob_served_bytes",
    "oci_engine_blob_remote_fetched_bytes",
    "oci_engine_blob_read_throughs",
    "oci_engine_range_requests",
    "oci_engine_range_partial_responses",
    "oci_engine_range_invalid_responses",
    "oci_engine_graph_expansions",
    "oci_engine_graph_child_manifests",
    "oci_engine_graph_descriptors",
    "oci_engine_publish_total_count",
    "oci_engine_publish_total_duration_ms",
    "oci_engine_publish_save_count",
    "oci_engine_publish_save_duration_ms",
    "oci_engine_publish_blobs_count",
    "oci_engine_publish_blobs_duration_ms",
    "oci_engine_publish_pointer_count",
    "oci_engine_publish_pointer_duration_ms",
    "oci_engine_publish_confirm_count",
    "oci_engine_publish_confirm_duration_ms",
    "oci_engine_publish_alias_count",
    "oci_engine_publish_alias_duration_ms",
    "oci_engine_publish_referrers_count",
    "oci_engine_publish_referrers_duration_ms",
    "oci_engine_miss_blob_locator",
    "oci_engine_miss_remote_blob",
    "oci_engine_miss_manifest",
    "oci_engine_miss_download_url",
    "oci_engine_negative_cache_hit_manifest_ref",
    "oci_engine_negative_cache_hit_blob_locator",
    "oci_engine_negative_cache_hit_download_url",
    "oci_engine_negative_cache_hit_remote_blob",
    "oci_engine_negative_cache_insert_manifest_ref",
    "oci_engine_negative_cache_insert_blob_locator",
    "oci_engine_negative_cache_insert_download_url",
    "oci_engine_negative_cache_insert_remote_blob",
    "oci_engine_storage_get_count",
    "oci_engine_storage_get_bytes",
    "oci_engine_storage_get_ttfb_ms",
    "oci_engine_storage_get_body_duration_ms",
    "oci_engine_storage_get_retry_count",
    "oci_engine_storage_get_error_count",
    "oci_engine_storage_get_timeout_count",
    "oci_engine_local_spool_bytes",
    "oci_engine_local_spool_write_duration_ms",
    "oci_engine_digest_verify_duration_ms",
    "oci_engine_digest_verify_failures",
    "oci_engine_cache_promotion_count",
    "oci_engine_cache_promotion_duration_ms",
    "oci_engine_cache_promotion_failures",
    "oci_engine_upload_session_materialization_count",
    "oci_engine_upload_session_materialization_bytes",
    "oci_engine_upload_session_materialization_copy_duration_ms",
    "oci_engine_upload_session_materialization_sync_duration_ms",
    "oci_engine_borrowed_upload_session_count",
    "oci_engine_borrowed_upload_session_bytes",
    "oci_engine_stream_through_count",
    "oci_engine_stream_through_bytes",
    "oci_engine_stream_through_verify_duration_ms",
    "oci_engine_stream_through_verify_failures",
    "oci_engine_stream_through_cache_promotion_failures",
    "oci_engine_alias_promotion_promoted",
    "oci_engine_alias_promotion_unchanged",
    "oci_engine_alias_promotion_ignored_stale",
    "oci_engine_alias_promotion_failed",
    "oci_negative_manifest_ref_entries",
    "oci_negative_blob_locator_entries",
    "oci_negative_download_url_entries",
    "oci_negative_remote_blob_entries",
    "oci_negative_generation",
    "singleflight_oci_blob_leaders",
    "singleflight_oci_blob_followers",
    "singleflight_oci_blob_follower_timeouts",
    "singleflight_oci_blob_takeovers",
    "singleflight_oci_blob_post_flight_local_hits",
    "singleflight_oci_blob_post_flight_retry_misses",
    "singleflight_oci_blob_follower_wait_p50_ms",
    "singleflight_oci_blob_follower_wait_p95_ms",
    "singleflight_oci_manifest_leaders",
    "singleflight_oci_manifest_followers",
    "singleflight_oci_manifest_follower_timeouts",
    "singleflight_oci_manifest_takeovers",
    "singleflight_oci_manifest_post_flight_local_hits",
    "singleflight_oci_manifest_post_flight_retry_misses",
    "singleflight_oci_manifest_follower_wait_p50_ms",
    "singleflight_oci_manifest_follower_wait_p95_ms",
    "singleflight_kv_lookup_leaders",
    "singleflight_kv_lookup_followers",
    "singleflight_kv_lookup_follower_timeouts",
    "singleflight_kv_lookup_takeovers",
    "singleflight_kv_lookup_post_flight_local_hits",
    "singleflight_kv_lookup_post_flight_retry_misses",
    "singleflight_kv_lookup_follower_wait_p50_ms",
    "singleflight_kv_lookup_follower_wait_p95_ms",
    "singleflight_kv_download_leaders",
    "singleflight_kv_download_followers",
    "singleflight_kv_download_follower_timeouts",
    "singleflight_kv_download_takeovers",
    "singleflight_kv_download_post_flight_local_hits",
    "singleflight_kv_download_post_flight_retry_misses",
    "singleflight_kv_download_follower_wait_p50_ms",
    "singleflight_kv_download_follower_wait_p95_ms",
    "singleflight_kv_url_leaders",
    "singleflight_kv_url_followers",
    "singleflight_kv_url_follower_timeouts",
    "singleflight_kv_url_takeovers",
    "singleflight_kv_url_post_flight_local_hits",
    "singleflight_kv_url_post_flight_retry_misses",
    "singleflight_kv_url_follower_wait_p50_ms",
    "singleflight_kv_url_follower_wait_p95_ms",
    "singleflight_kv_size_leaders",
    "singleflight_kv_size_followers",
    "singleflight_kv_size_follower_timeouts",
    "singleflight_kv_size_takeovers",
    "singleflight_kv_size_post_flight_local_hits",
    "singleflight_kv_size_post_flight_retry_misses",
    "singleflight_kv_size_follower_wait_p50_ms",
    "singleflight_kv_size_follower_wait_p95_ms",
)
OCI_ENGINE_SUMMARY_KEYS = tuple(
    key for key in STATUS_SNAPSHOT_KEYS if key.startswith("oci_engine_")
)


def parse_details(details):
    if not isinstance(details, str) or not details.strip():
        return {}
    parsed = {}
    for token in details.strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        parsed[key.strip()] = value.strip().rstrip(",")
    return parsed


def percentile(values, pct):
    if not values:
        return 0
    values = sorted(values)
    idx = max(0, min(len(values) - 1, math.ceil((pct / 100.0) * len(values)) - 1))
    return int(values[idx])


def env_slug(value):
    return "".join(ch if ch.isalnum() else "_" for ch in value.strip().lower()).strip("_")


def by_operation(records, operation):
    return [
        int(item.get("duration_ms", 0))
        for item in records
        if item.get("operation") == operation and isinstance(item.get("duration_ms"), (int, float))
    ]


def flatten_summary(prefix, value, out):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                continue
            child_prefix = f"{prefix}_{env_slug(key)}" if prefix else env_slug(key)
            flatten_summary(child_prefix, child, out)
        return
    parsed = parse_u64(value)
    if parsed is not None:
        out[prefix] = str(parsed)
    elif isinstance(value, str) and value.strip():
        out[prefix] = env_slug(value) or "unknown"


def parse_u64(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(value))
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def find_status_paths(metrics_path, explicit_paths):
    paths = []
    seen = set()

    def add(path):
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            return
        seen.add(resolved)
        paths.append(path)

    candidates = explicit_paths
    if not candidates:
        parent = metrics_path.parent if metrics_path.parent != Path("") else Path(".")
        candidates = [parent]

    for raw_path in candidates:
        path = Path(raw_path)
        if path.is_dir():
            for pattern in STATUS_SNAPSHOT_PATTERNS:
                for candidate in sorted(path.rglob(pattern)):
                    add(candidate)
        elif path.is_file():
            add(path)

    return paths


def status_snapshot_label(path, count):
    stem = path.stem
    for prefix in ("proxy-status-", "status-"):
        if stem.startswith(prefix):
            stem = stem[len(prefix) :]
            break
    return env_slug(stem) or f"snapshot_{count}"


def collect_status_snapshots(metrics_path, status_args):
    numeric_max = {}
    policies = set()
    snapshots = []
    session_summaries = []
    count = 0

    for path in find_status_paths(metrics_path, status_args):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue

        if isinstance(payload.get("session_summary"), dict):
            session_summaries.append(payload["session_summary"])

        count += 1
        snapshot = {
            "label": status_snapshot_label(path, count),
            "policy": "unknown",
            "values": {},
        }

        for section, policy_key in STATUS_POLICY_FIELDS:
            status_section = payload.get(section)
            if not isinstance(status_section, dict):
                continue
            policy = status_section.get(policy_key)
            if isinstance(policy, str) and policy.strip():
                policy = policy.strip()
                policies.add(policy)
                if snapshot["policy"] == "unknown":
                    snapshot["policy"] = env_slug(policy) or "unknown"

        for section in STATUS_NUMERIC_SECTIONS:
            status_section = payload.get(section)
            if not isinstance(status_section, dict):
                continue
            for key, value in status_section.items():
                if not isinstance(key, str):
                    continue
                parsed = parse_u64(value)
                if parsed is not None:
                    numeric_max[key] = max(parsed, numeric_max.get(key, 0))
                    snapshot["values"][key] = parsed
        snapshots.append(snapshot)

    return {
        "count": count,
        "numeric_max": numeric_max,
        "policies": sorted(policies),
        "snapshots": snapshots,
        "session_summaries": session_summaries,
    }


def print_status_snapshot(prefix, snapshot):
    values = snapshot["values"]
    print(f"{prefix}_oci_hydration={snapshot['policy']}")
    for key in STATUS_SNAPSHOT_KEYS:
        print(f"{prefix}_{key}={values.get(key, 0)}")


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: request-metrics-summary.py <metrics-jsonl> [proxy-status-json-or-dir ...]",
            file=sys.stderr,
        )
        return 2

    path = sys.argv[1]
    metrics_path = Path(path)
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                continue

    failures = 0
    retries = 0
    prefetch_cycles = 0
    cache_ops_records_total = 0
    cache_ops_by_tool = {}
    cache_ops_get_by_tool = {}
    blob_read_by_source = {
        "local_cache": {"count": 0, "bytes": 0, "durations": []},
        "remote_fetch": {"count": 0, "bytes": 0, "durations": []},
    }
    oci_upload_plan = {
        "events": 0,
        "requested_blobs": 0,
        "upload_urls": 0,
        "already_present": 0,
        "requested_bytes": 0,
        "new_blob_count": 0,
        "derived_new_blob_count": 0,
        "mismatches": 0,
    }
    latest_oci_upload_plan = {
        "requested_blobs": 0,
        "upload_urls": 0,
        "already_present": 0,
        "requested_bytes": 0,
        "new_blob_count": 0,
        "derived_new_blob_count": 0,
    }
    session_summaries = []
    for item in records:
        status = item.get("status")
        if item.get("error") is not None:
            failures += 1
        elif isinstance(status, int) and status >= 500:
            failures += 1

        retry_count = item.get("retry_count")
        if isinstance(retry_count, int) and retry_count > 0:
            retries += 1

        if item.get("operation") == "blob_prefetch_cycle":
            prefetch_cycles += 1

        if item.get("operation") == "cache_session_summary":
            session_summaries.append(item)

        if item.get("operation") == "oci_blob_upload_plan":
            details = parse_details(item.get("details"))
            requested_blobs = parse_u64(details.get("requested_blobs")) or 0
            upload_urls = parse_u64(details.get("upload_urls")) or 0
            already_present = parse_u64(details.get("already_present")) or 0
            requested_bytes = parse_u64(details.get("requested_bytes")) or 0
            derived_new_blob_count = max(0, requested_blobs - already_present)

            oci_upload_plan["events"] += 1
            oci_upload_plan["requested_blobs"] += requested_blobs
            oci_upload_plan["upload_urls"] += upload_urls
            oci_upload_plan["already_present"] += already_present
            oci_upload_plan["requested_bytes"] += requested_bytes
            oci_upload_plan["new_blob_count"] += upload_urls
            oci_upload_plan["derived_new_blob_count"] += derived_new_blob_count
            if upload_urls != derived_new_blob_count:
                oci_upload_plan["mismatches"] += 1

            latest_oci_upload_plan["requested_blobs"] = requested_blobs
            latest_oci_upload_plan["upload_urls"] = upload_urls
            latest_oci_upload_plan["already_present"] = already_present
            latest_oci_upload_plan["requested_bytes"] = requested_bytes
            latest_oci_upload_plan["new_blob_count"] = upload_urls
            latest_oci_upload_plan["derived_new_blob_count"] = derived_new_blob_count

        if item.get("operation") == "cache_ops_record":
            cache_ops_records_total += 1
            details = parse_details(item.get("details"))
            tool = details.get("tool", "").strip().lower()
            op = details.get("op", "").strip().lower()
            result = details.get("result", "").strip().lower()
            if tool:
                bucket = cache_ops_by_tool.setdefault(
                    tool, {"hit": 0, "miss": 0, "error": 0}
                )
                if result in bucket:
                    bucket[result] += 1
                    if op == "get":
                        get_bucket = cache_ops_get_by_tool.setdefault(
                            tool, {"hit": 0, "miss": 0, "error": 0}
                        )
                        get_bucket[result] += 1

        if item.get("operation") == "cache_blob_read":
            details = parse_details(item.get("details"))
            source = details.get("source", "").strip().lower()
            if source in blob_read_by_source:
                bucket = blob_read_by_source[source]
                bucket["count"] += 1
                response_bytes = item.get("response_bytes")
                if isinstance(response_bytes, (int, float)):
                    bucket["bytes"] += int(response_bytes)
                duration_ms = item.get("duration_ms")
                if isinstance(duration_ms, (int, float)):
                    bucket["durations"].append(int(duration_ms))

    blob_read_total = sum(bucket["count"] for bucket in blob_read_by_source.values())
    local_blob_reads = blob_read_by_source["local_cache"]
    remote_blob_reads = blob_read_by_source["remote_fetch"]
    local_blob_read_hit_ratio = (
        100.0 if blob_read_total == 0 else (100.0 * local_blob_reads["count"] / blob_read_total)
    )
    status_snapshots = collect_status_snapshots(metrics_path, sys.argv[2:])
    status_session_summaries = status_snapshots["session_summaries"]
    summaries_for_output = session_summaries or status_session_summaries
    status_values = status_snapshots["numeric_max"]
    oci_body_local_hits = status_values.get("oci_body_local_hits", 0)
    oci_body_remote_fetches = status_values.get("oci_body_remote_fetches", 0)
    oci_body_total_reads = oci_body_local_hits + oci_body_remote_fetches
    oci_body_local_hit_ratio = (
        100.0 if oci_body_total_reads == 0 else (100.0 * oci_body_local_hits / oci_body_total_reads)
    )
    oci_engine_blob_local_reads = status_values.get("oci_engine_blob_local_reads", 0)
    oci_engine_blob_remote_reads = status_values.get("oci_engine_blob_remote_reads", 0)
    oci_engine_blob_reads_total = oci_engine_blob_local_reads + oci_engine_blob_remote_reads
    oci_engine_blob_local_hit_ratio = (
        100.0
        if oci_engine_blob_reads_total == 0
        else (100.0 * oci_engine_blob_local_reads / oci_engine_blob_reads_total)
    )

    print(f"request_metrics_total={len(records)}")
    print(f"request_metrics_failures={failures}")
    print(f"request_metrics_retry_events={retries}")
    print(f"request_metrics_check_p95_ms={percentile(by_operation(records, 'cache_blobs_check'), 95)}")
    print(
        f"request_metrics_download_p95_ms={percentile(by_operation(records, 'cache_blobs_download_urls'), 95)}"
    )
    print(
        f"request_metrics_preload_index_p95_ms={percentile(by_operation(records, 'cache_preload_index_fetch'), 95)}"
    )
    print(f"request_metrics_save_p95_ms={percentile(by_operation(records, 'cache_flush_upload'), 95)}")
    print(
        f"request_metrics_publish_p95_ms={percentile(by_operation(records, 'cache_finalize_publish'), 95)}"
    )
    print(f"request_metrics_prefetch_cycles={prefetch_cycles}")
    print(f"request_metrics_cache_session_summaries={len(summaries_for_output)}")
    print(f"request_metrics_status_session_summaries={len(status_session_summaries)}")
    print(f"request_metrics_oci_upload_plan_events={oci_upload_plan['events']}")
    print(f"request_metrics_oci_upload_requested_blobs={oci_upload_plan['requested_blobs']}")
    print(f"request_metrics_oci_upload_upload_urls={oci_upload_plan['upload_urls']}")
    print(f"request_metrics_oci_upload_already_present={oci_upload_plan['already_present']}")
    print(f"request_metrics_oci_upload_requested_bytes={oci_upload_plan['requested_bytes']}")
    print(f"request_metrics_oci_new_blob_count={oci_upload_plan['new_blob_count']}")
    print(
        "request_metrics_oci_derived_new_blob_count="
        f"{oci_upload_plan['derived_new_blob_count']}"
    )
    print(f"request_metrics_oci_upload_plan_mismatches={oci_upload_plan['mismatches']}")
    print(
        "request_metrics_oci_latest_upload_requested_blobs="
        f"{latest_oci_upload_plan['requested_blobs']}"
    )
    print(
        "request_metrics_oci_latest_upload_upload_urls="
        f"{latest_oci_upload_plan['upload_urls']}"
    )
    print(
        "request_metrics_oci_latest_upload_already_present="
        f"{latest_oci_upload_plan['already_present']}"
    )
    print(
        "request_metrics_oci_latest_upload_requested_bytes="
        f"{latest_oci_upload_plan['requested_bytes']}"
    )
    print(
        "request_metrics_oci_latest_new_blob_count="
        f"{latest_oci_upload_plan['new_blob_count']}"
    )
    print(
        "request_metrics_oci_latest_derived_new_blob_count="
        f"{latest_oci_upload_plan['derived_new_blob_count']}"
    )
    if summaries_for_output:
        flattened_summary = {}
        latest_summary = summaries_for_output[-1]
        for section in (
            "schema",
            "mode",
            "adapter",
            "proxy",
            "rails",
            "storage",
            "oci",
            "startup_prefetch",
            "kv_upload",
            "singleflight",
            "local_cache",
            "buildkit",
        ):
            if section in latest_summary:
                flatten_summary(section, latest_summary.get(section), flattened_summary)
        for key in sorted(flattened_summary):
            print(f"request_metrics_cache_session_{key}={flattened_summary[key]}")
    print(
        f"request_metrics_prefetch_cycle_p95_ms={percentile(by_operation(records, 'blob_prefetch_cycle'), 95)}"
    )
    print(f"request_metrics_cache_ops_records_total={cache_ops_records_total}")
    tool_names = sorted(set(cache_ops_by_tool.keys()) | set(cache_ops_get_by_tool.keys()))
    for tool in tool_names:
        slug = env_slug(tool)
        bucket = cache_ops_by_tool.get(tool, {"hit": 0, "miss": 0, "error": 0})
        denom = bucket["hit"] + bucket["miss"]
        hit_rate = 100.0 if denom == 0 else (100.0 * bucket["hit"] / denom)
        get_bucket = cache_ops_get_by_tool.get(tool, {"hit": 0, "miss": 0, "error": 0})
        get_records_total = get_bucket["hit"] + get_bucket["miss"] + get_bucket["error"]
        get_denom = get_bucket["hit"] + get_bucket["miss"]
        get_hit_rate = (
            100.0 if get_denom == 0 else (100.0 * get_bucket["hit"] / get_denom)
        )
        print(f"request_metrics_cache_ops_{slug}_hits={bucket['hit']}")
        print(f"request_metrics_cache_ops_{slug}_misses={bucket['miss']}")
        print(f"request_metrics_cache_ops_{slug}_errors={bucket['error']}")
        print(f"request_metrics_cache_ops_{slug}_hit_rate={hit_rate:.2f}")
        print(f"request_metrics_cache_ops_{slug}_get_records_total={get_records_total}")
        print(f"request_metrics_cache_ops_{slug}_get_hits={get_bucket['hit']}")
        print(f"request_metrics_cache_ops_{slug}_get_misses={get_bucket['miss']}")
        print(f"request_metrics_cache_ops_{slug}_get_errors={get_bucket['error']}")
        print(f"request_metrics_cache_ops_{slug}_get_hit_rate={get_hit_rate:.2f}")
    print(f"request_metrics_blob_read_events_total={blob_read_total}")
    print(f"request_metrics_blob_read_local_count={local_blob_reads['count']}")
    print(f"request_metrics_blob_read_remote_count={remote_blob_reads['count']}")
    print(f"request_metrics_blob_read_local_hit_ratio={local_blob_read_hit_ratio:.2f}")
    print(f"request_metrics_blob_read_local_bytes={local_blob_reads['bytes']}")
    print(f"request_metrics_blob_read_remote_bytes={remote_blob_reads['bytes']}")
    print(
        f"request_metrics_blob_read_local_p50_ms={percentile(local_blob_reads['durations'], 50)}"
    )
    print(
        f"request_metrics_blob_read_local_p95_ms={percentile(local_blob_reads['durations'], 95)}"
    )
    print(
        f"request_metrics_blob_read_remote_p50_ms={percentile(remote_blob_reads['durations'], 50)}"
    )
    print(
        f"request_metrics_blob_read_remote_p95_ms={percentile(remote_blob_reads['durations'], 95)}"
    )
    print(f"request_metrics_status_snapshots_total={status_snapshots['count']}")
    for index, snapshot in enumerate(status_snapshots["snapshots"], start=1):
        print(f"request_metrics_status_snapshot_{index}_label={snapshot['label']}")
        print_status_snapshot(f"request_metrics_status_snapshot_{index}", snapshot)
        print_status_snapshot(f"request_metrics_status_{snapshot['label']}", snapshot)
    print(
        "request_metrics_startup_prefetch_oci_hydration="
        f"{','.join(status_snapshots['policies']) if status_snapshots['policies'] else 'unknown'}"
    )
    print(
        "request_metrics_oci_engine_hydration_policy="
        f"{','.join(status_snapshots['policies']) if status_snapshots['policies'] else 'unknown'}"
    )
    print(
        "request_metrics_startup_prefetch_oci_refs="
        f"{status_values.get('startup_prefetch_oci_refs', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_total_unique_blobs="
        f"{status_values.get('startup_prefetch_oci_total_unique_blobs', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_inserted="
        f"{status_values.get('startup_prefetch_oci_inserted', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_failures="
        f"{status_values.get('startup_prefetch_oci_failures', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_cold_blobs="
        f"{status_values.get('startup_prefetch_oci_cold_blobs', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_duration_ms="
        f"{status_values.get('startup_prefetch_oci_duration_ms', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_body_inserted="
        f"{status_values.get('startup_prefetch_oci_body_inserted', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_body_failures="
        f"{status_values.get('startup_prefetch_oci_body_failures', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_body_cold_blobs="
        f"{status_values.get('startup_prefetch_oci_body_cold_blobs', 0)}"
    )
    print(
        "request_metrics_startup_prefetch_oci_body_duration_ms="
        f"{status_values.get('startup_prefetch_oci_body_duration_ms', 0)}"
    )
    print(f"request_metrics_oci_body_reads_total={oci_body_total_reads}")
    print(f"request_metrics_oci_body_local_hits={oci_body_local_hits}")
    print(f"request_metrics_oci_body_remote_fetches={oci_body_remote_fetches}")
    print(f"request_metrics_oci_body_local_hit_ratio={oci_body_local_hit_ratio:.2f}")
    print(
        "request_metrics_oci_body_local_bytes="
        f"{status_values.get('oci_body_local_bytes', 0)}"
    )
    print(
        "request_metrics_oci_body_remote_bytes="
        f"{status_values.get('oci_body_remote_bytes', 0)}"
    )
    print(
        "request_metrics_oci_body_local_duration_ms="
        f"{status_values.get('oci_body_local_duration_ms', 0)}"
    )
    print(
        "request_metrics_oci_body_remote_duration_ms="
        f"{status_values.get('oci_body_remote_duration_ms', 0)}"
    )
    print(f"request_metrics_oci_engine_blob_reads_total={oci_engine_blob_reads_total}")
    print(f"request_metrics_oci_engine_blob_local_hit_ratio={oci_engine_blob_local_hit_ratio:.2f}")
    for key in OCI_ENGINE_SUMMARY_KEYS:
        print(f"request_metrics_{key}={status_values.get(key, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
