#!/usr/bin/env python3
import json
import math
import sys


def percentile(values, pct):
    if not values:
        return 0
    values = sorted(values)
    idx = max(0, min(len(values) - 1, math.ceil((pct / 100.0) * len(values)) - 1))
    return int(values[idx])


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

    print(f"request_metrics_total={len(records)}")
    print(f"request_metrics_failures={failures}")
    print(f"request_metrics_retry_events={retries}")
    print(f"request_metrics_check_p95_ms={percentile(by_operation(records, 'cache_blobs_check'), 95)}")
    print(
        f"request_metrics_download_p95_ms={percentile(by_operation(records, 'cache_blobs_download_urls'), 95)}"
    )
    print(f"request_metrics_save_p95_ms={percentile(by_operation(records, 'cache_flush_upload'), 95)}")
    print(
        f"request_metrics_publish_p95_ms={percentile(by_operation(records, 'cache_finalize_publish'), 95)}"
    )
    print(f"request_metrics_prefetch_cycles={prefetch_cycles}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
