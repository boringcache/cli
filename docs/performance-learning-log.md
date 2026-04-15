# Performance Learning Log

This log captures regressions, root causes, and guardrails for cache-registry performance/correctness.

## 2026-04-15 - warm-first proxy startup

- Product direction:
  - `cache-registry` is the warm-first standalone proxy surface.
  - `boringcache <tool>` and `boringcache run --proxy` temporarily start that same proxy for one command and inherit the same warm-first startup behavior.
  - `--on-demand` is the explicit expert override when a caller wants immediate startup instead of startup warming.
- Guardrail:
  - Keep warm as the default user path. Treat on-demand as an advanced escape hatch, not the main story.
- Contract:
  - `/_boringcache/status` remains the machine-readable lifecycle contract underneath both modes.
  - `docs/contracts/readiness.md` is the written contract for readiness and publish-settlement semantics.

## 2026-04-14 - first-class proxy lifecycle status

- Symptom:
  - E2E scripts were still inferring readiness and publish settlement from `/v2/`, fixed sleeps, or proxy log output.
  - That kept harness logic coupled to implementation details instead of the product surface.
- Product-side changes:
  - Add `/_boringcache/status` as the proxy lifecycle endpoint.
  - Report `warming`, `ready`, and `draining` plus `publish_settled` for fresh readers.
  - Base publish settlement on real tag visibility, not just empty local queues.
- Harness cleanup:
  - Move shared proxy readiness checks to `/_boringcache/status`.
  - Move prefetch-settlement checks to `publish_settled` instead of log scraping.
  - Update standalone E2E scripts and proxy-mode smoke checks to use the status endpoint.
- Guardrail:
  - `/v2/` is the protocol surface. `/_boringcache/status` is the operator and harness lifecycle surface.

## 2026-04-15 - CLI-managed proxy readiness waits

- Symptom:
  - `boringcache <tool>` and `boringcache run --proxy` could start the wrapped command while the proxy still reported `warming`.
  - Downstream callers added their own readiness waits on top of the CLI-managed lifecycle.
- Product-side changes:
  - Make CLI-managed background proxy startup poll `/_boringcache/status` until `phase=ready`.
  - Probe readiness through the local bind host, not the child-facing endpoint override, so container-facing hostnames do not break local startup waits.
- Guardrail:
  - CLI-managed proxy lifecycle should consume the same `/_boringcache/status` contract that external harnesses use.

## 2026-04-09 - startup hydration and generic machine governor

- Symptom:
  - Warm `sccache` paths were spending too much time on remote reads even with high cache-hit rates.
  - Startup preload resolved too many download URLs up front and warmed too little useful data before the build began.
- Root cause:
  - Startup prefetch selection stopped at the first blob that exceeded the remaining budget, leaving usable prefetch budget idle.
  - Startup path resolved all download URLs before warming the startup slice, so control-plane latency was paid before useful local hydration.
  - Tool-detected defaults were pushing the design toward special-case tuning instead of one generic machine-safe scheduler.
- Product-side changes:
  - Skip oversized blobs during startup selection instead of aborting the remainder of the slice.
  - Use one automatic machine governor for blob-cache sizing, download concurrency, and startup work.
  - Keep startup selection generic and cache-state driven instead of routing behavior through tool profiles.
  - Resolve startup-slice download URLs first, warm that slice first, then resolve the rest in the background.
  - Emit blob-read observability for `local_cache` vs `remote_fetch`.
- Harness guardrails:
  - Add `BORINGCACHE_BLOB_READ_CACHE_DIR` so restart tests can force a truly fresh local blob cache instead of silently reusing `/tmp/boringcache-blob-cache`.
  - Fix `ci/e2e/extended/e2e-prefetch-readiness-test.sh` to work on local macOS shells by shortening `xargs` worker invocations and separating seed/restart blob-cache directories.
- Guardrail:
  - Adapters define protocol and correctness boundaries. Prefetch and read-path defaults should stay generic unless real protocol traffic proves a broader product change.

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
