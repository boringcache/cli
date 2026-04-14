#!/usr/bin/env python3
import json
import math
import sys


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


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: request-metrics-summary.py <metrics-jsonl>", file=sys.stderr)
        return 2

    path = sys.argv[1]
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
