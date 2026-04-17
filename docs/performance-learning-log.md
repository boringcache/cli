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
  - Make CLI-managed background proxy startup wait on the shared in-process readiness state instead of reimplementing local HTTP polling.
  - Add a hidden ready-file handoff so detached orchestrators can block on the same readiness signal without scraping logs or duplicating `/_boringcache/status` polling.
- Guardrail:
  - Keep one readiness model. User-facing CLI flows stay warm-by-default, detached internal orchestrators consume the CLI-owned readiness signal, and `/_boringcache/status` remains the HTTP lifecycle and publish-settlement surface.

## 2026-04-14 - full-tag hydration as the disk-cache contract

- Symptom:
  - Startup warming still behaved like a slice-based scheduler even though the product direction had moved to cache-first hydration.
  - Hidden startup and background byte budgets made the proxy look simple in small cases but degrade into partial warming under pressure.
- Root cause:
  - Prefetch kept separate startup blob/byte limits and a background inflight byte cap.
  - The blob read cache already had its own size ceiling and eviction path, so the extra prefetch budgets were policy duplication.
- Product-side changes:
  - Hydrate the full active tag by default during startup and continue best-effort in the background if readiness times out.
  - Remove startup selection budgets and background inflight byte budgets from cache-registry hydration.
  - Treat the fixed blob-read-cache ceiling and blob-cache eviction as the authoritative disk safety boundary.
- Guardrail:
  - For disk-backed cache-registry paths, warm selection should not invent a second capacity policy. If we add a RAM cache later, memory budgets belong there instead.

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
  - Tag publish had not converged before teardown, so remote readers observed the old tag state.
- Product-side changes:
  - Keep shutdown flush and tag-visibility polling bounded but long enough for real storage/API convergence.
  - Add adaptive small-batch flush behavior in cache-registry so tiny pending sets are flushed sooner during active runs instead of being deferred to shutdown.
- Harness guardrails (CLI repo e2e scripts):
  - Centralized proxy graceful-stop default to `210s`.
  - Enforce a minimum graceful-stop budget of `210s` even if lower env values are set.
  - Remove per-tool hardcoded remote-tag verify timings (`30/2`), use shared defaults.

## 2026-04-08 - OCI publish confirm timed out before tag settled (Hugo/Turbo)

- Symptom:
  - OCI tool e2e legs failed with remote tag not published after cold save.
  - Proxy logs showed `Best-effort OCI manifest publish fallback ... (500 Internal Server Error)`.
- Root cause:
  - OCI manifest put wrapped `api_client.confirm(...)` in a hard `30s` handler timeout.
  - Confirm can legitimately take longer than `30s` when upload receipts, storage visibility, and pointer publish are all in flight.
  - On timeout, the request degraded/fell back before publish completed, so tag checks observed misses.
- Secondary pressure signal:
  - Generic request retries under concurrent CI load amplified backend pressure.
- Product-side changes:
  - Remove the extra `30s` wrapper around OCI confirm in `serve/handlers.rs`; rely on the shared confirm path.
  - Add explicit poll backoff on `429` (rate-limit aware) to reduce retry storms.
- Guardrail:
  - Do not add short outer timeouts around publish confirm paths; use one authoritative confirm/retry lifecycle.

## 2026-04-16 - OCI proxy parity and warm-path backlog

- Completed:
  - Added explicit startup OCI prewarm via `--oci-prefetch-ref` for selected `repo@ref` pairs, which seeds both manifest and blob locator state during startup when not using `--on-demand`.

- Spec cross-check:
- Distribution manifest pushes should fail with `400 MANIFEST_BLOB_UNKNOWN` when referenced blobs are missing.
  - Distribution resumable blob uploads should reject stale or out-of-order chunk offsets with `416 Requested Range Not Satisfiable`.
  - OCI 1.1 subject-aware manifest pushes should return `OCI-Subject` when the registry supports referrers processing.
- Current gaps:
  - OCI startup policy still does not decide whether selected-ref blob-byte hydration should happen eagerly or only after measured read locality proves it worthwhile.
  - Track the new OCI manifest-contract E2E leg alongside the existing BuildKit registry-cache leg so subject/referrers and restart behavior stay covered as proxy changes land.
  - Measure whether the new OCI inflight dedupe meaningfully reduces restore, pointer, download-url, and blob-fetch fan-out under concurrent reader load.
  - Add an E2E BuildKit OCI-spec mirror that covers manifest PUT validation, resumable upload edge cases, warm restart behavior, and cache import/export parity.

## 2026-04-16 - shutdown flush stall and session cleanup race

- Symptom:
  - Proxy runs with writes occasionally took 180s to shut down instead of the expected 10–15s.
  - `cleanup_blob_sessions` used global `find_by_digest`, which could remove upload sessions belonging to a different OCI repository during concurrent multi-repo manifest pushes.
- Root cause (shutdown):
  - After a Conflict or transient Error during `flush_pending_on_shutdown`, the normal-mode backoff gate (`kv_next_flush_at`) was inherited by the shutdown loop, causing up to 10s sleep per retry iteration.
  - The replication worker did not check `shutdown_requested` and could hold `kv_flush_lock` during a slow network flush while the shutdown path waited for the lock.
  - The sweep task continued enqueuing new flush hints after shutdown was requested.
- Root cause (session cleanup):
  - `cleanup_blob_sessions` called `find_by_digest` (global) instead of `find_by_name_and_digest`, so a completed manifest push for repo A could remove the staged session for repo B if they shared a blob digest.
- Product-side changes:
  - Clear `kv_next_flush_at` on Conflict/Error during shutdown flush loop so retries happen immediately.
  - Use a fixed 1s retry interval during shutdown instead of reading the normal-mode backoff gate.
  - Skip replication worker flush processing and sweep task enqueuing once `shutdown_requested` is set.
  - Scope `cleanup_blob_sessions` by repository name using `find_by_name_and_digest`.
- Guardrail:
  - Shutdown flush path should never inherit normal-mode backoff timing. Background maintenance tasks must check `shutdown_requested` before acquiring `kv_flush_lock`.
  - Upload session lookups should always be scoped by repository name. Global `find_by_digest` is only safe for read-only queries where cross-repo hits are acceptable.

## 2026-04-16 - OCI manifest confirm lock as best-effort error

- Symptom:
  - OCI manifest PUT failed when the backend returned `423` during confirm.
- Root cause:
  - OCI path used plain `confirm()` and treated `423` as a hard error.
- Product-side changes:
  - Switch OCI manifest confirm and alias bind to `confirm_with_retry`, which uses the shared optimistic confirm path.
  - Treat an unresolved lock as an internal error (`500`) that triggers best-effort degraded fallback when `fail_on_cache_error` is false.
  - Check for `prefetch_error` after `Notify` wakeup in `await_startup_prefetch_readiness` to avoid an unnecessary loop iteration on error.
- Guardrail:
  - OCI confirm paths should use the same optimistic confirm helper as archive and KV flush paths.

## Merge Checklist For Cache-Registry Changes

Before merging changes touching `src/serve/cache_registry/*`, `src/serve/mod.rs`, or publish/confirm client paths:

1. Run targeted correctness tests:
   - `cargo test confirm_retry_reason_retries_transient_server_errors -- --nocapture`
   - `cargo test should_flush_pending_values -- --nocapture`
2. Validate at least one tool e2e path that relies on remote tag visibility across process restarts.
3. Confirm no workflow-only tuning is required for correctness.
4. Record any new latency/correctness tradeoff in this log.
