# Performance Learning Log

This log captures regressions, root causes, and guardrails for cache-registry performance/correctness.

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
