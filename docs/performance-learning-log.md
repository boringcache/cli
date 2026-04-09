# Performance Learning Log

This log captures regressions, root causes, and guardrails for cache-registry performance/correctness.

## 2026-04-09 - sccache startup hydration and adapter profile split

- Symptom:
  - Warm `sccache` paths were spending too much time on remote reads even with high cache-hit rates.
  - Startup preload resolved too many download URLs up front and warmed too little useful data before the build began.
- Root cause:
  - Startup prefetch selection stopped at the first blob that exceeded the remaining budget, leaving usable prefetch budget idle.
  - Startup path resolved all download URLs before warming the startup slice, so control-plane latency was paid before useful local hydration.
  - Generic blob-cache and prefetch defaults were too conservative for `sccache` compared with its warm-path read shape.
- Product-side changes:
  - Skip oversized blobs during startup selection instead of aborting the remainder of the slice.
  - Add a `sccache` tuning profile with more aggressive blob-cache sizing, download concurrency, and prefetch concurrency.
  - Add a `bazel` tuning profile that prioritizes `bazel_ac` and small `bazel_cas` blobs on startup instead of treating the whole tag as generic kv traffic.
  - Resolve startup-slice download URLs first, warm that slice first, then resolve the rest in the background.
  - Emit blob-read observability for `local_cache` vs `remote_fetch`.
- Harness guardrails:
  - Add `BORINGCACHE_BLOB_READ_CACHE_DIR` so restart tests can force a truly fresh local blob cache instead of silently reusing `/tmp/boringcache-blob-cache`.
  - Fix `scripts/e2e-prefetch-readiness-test.sh` to work on local macOS shells by shortening `xargs` worker invocations and separating seed/restart blob-cache directories.
- Guardrail:
  - Adapter behavior is not one-size-fits-all. Use `docs/adapter-cache-profiles.md` when changing prefetch or read-path defaults.

## 2026-04-08 - Shutdown publish visibility regression (Turbo/sccache)

- Symptom:
  - Warm tool runs showed local hits, but cross-process remote tag checks failed (`hits=0, misses=1`).
  - Proxy was often force-killed before publish/tag convergence completed.
- Failure shape:
  - `cache_finalize_publish` returned pending (`423`) and remote tag never became visible before teardown.
- Product-side changes:
  - Keep shutdown publish polling robust for server-owned pending states.
  - Increase pending-publish poll timeout in CLI client to `180s`.
  - Poll pending publish status more aggressively (sub-second capable interval clamp).
  - Add adaptive small-batch flush behavior in cache-registry so tiny pending sets are flushed sooner during active runs instead of being deferred to shutdown.
- Harness guardrails (CLI repo e2e scripts):
  - Centralized proxy graceful-stop default to `210s`.
  - Enforce a minimum graceful-stop budget of `210s` even if lower env values are set.
  - Remove per-tool hardcoded remote-tag verify timings (`30/2`), use shared defaults.

## 2026-04-08 - OCI publish confirm timed out before pending publish settled (Hugo/Turbo)

- Symptom:
  - OCI tool e2e legs failed with remote tag not published after cold save.
  - Proxy logs showed `Best-effort OCI manifest publish fallback ... (500 Internal Server Error)`.
- Root cause:
  - OCI manifest put wrapped `api_client.confirm(...)` in a hard `30s` handler timeout.
  - Confirm supports server-owned pending publish and may legitimately take longer than `30s`.
  - On timeout, the request degraded/fell back before publish completed, so tag checks observed misses.
- Secondary pressure signal:
  - Pending publish status polls hit `429 Too Many Requests` under concurrent CI load.
  - Poll path used generic request retries (`3` attempts), amplifying each poll cycle.
- Product-side changes:
  - Remove the extra `30s` wrapper around OCI confirm in `serve/handlers.rs`; rely on confirm’s publish lifecycle.
  - Use single-attempt status GETs for pending publish poll path.
  - Add explicit poll backoff on `429` (rate-limit aware) to reduce retry storms.
- Guardrail:
  - Do not add short outer timeouts around publish confirm paths; use one authoritative publish lifecycle.

## Merge Checklist For Cache-Registry Changes

Before merging changes touching `src/serve/cache_registry/*`, `src/serve/mod.rs`, or publish/confirm client paths:

1. Run targeted correctness tests:
   - `cargo test pending_publish_completion -- --nocapture`
   - `cargo test should_flush_pending_values -- --nocapture`
2. Validate at least one tool e2e path that relies on remote tag visibility across process restarts.
3. Confirm no workflow-only tuning is required for correctness.
4. Record any new latency/correctness tradeoff in this log.
