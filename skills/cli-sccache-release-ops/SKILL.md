---
name: cli-sccache-release-ops
description: Use for BoringCache CLI sccache and cache-registry performance debugging, CI benchmark workflow hardening, and release execution (version bumps, tagging, and validation).
---

# CLI SCCache + Release Ops

Use this skill when work touches any of the following:
- sccache proxy hit-rate regressions
- cache-registry request floods or miss storms
- stable-tag vs run-scoped-tag behavior
- benchmark workflow validity and regression tracking
- CLI release cutovers (`v*` tags, artifact availability, install fallback)

## Key Invariants

- Keep normal CI on stable root tags. Do not use run-scoped tags for default CI restore/save paths.
- Run-scoped tags are only for isolated perf or protocol E2E runs.
- Blob deduplication alone is not enough for hits. Hits require key-to-digest mapping in the active tag pointer index.
- Restore candidate behavior is single effective tag, not a fallback chain.
- Cache misses are warn-only unless explicitly running with fail-on-miss behavior.

## API v2 Migration Memory (2026-02-23)

- Keep `BORINGCACHE_API_URL` clean and unversioned by default (`https://api.boringcache.com`).
- `ApiClient` should derive both base URLs (`/v1` and `/v2`) from config, but treat `/v2` as the default runtime base.
- Keep capability negotiation explicit via `/v2/capabilities` (with fallback probes if needed), but do not force users to configure versioned URLs.
- CLI-visible endpoints for `auth`, `workspaces`, `ls`, `check`, `read`, `save`, `restore`, and metrics should hit `/v2/...` paths.
- For capability-off compatibility, stay on v2 wrapper routes (for example `/v2/.../caches`, `/v2/.../caches/blobs/upload-urls`, `/v2/.../caches/:id`) rather than dropping back to `/v1`.
- For capability-on fast path:
  - blob stage: `POST /v2/workspaces/:ns/:ws/caches/blobs/stage`
  - CAS publish: `PUT /v2/workspaces/:ns/:ws/caches/tags/:tag/publish` with `If-Match`
  - optional pointer read: `GET /v2/workspaces/:ns/:ws/caches/tags/:tag/pointer`
- Guard against dead capability branches (`if/else` blocks calling the same method). `cargo clippy -- -D warnings` should stay green.
- Migration verification gate:
  - `cargo fmt --all`
  - `cargo clippy -- -D warnings`
  - `cargo test`

## Performance Triage Flow

1. Confirm tag strategy first.
2. Run paired cold and warm benchmarks for local vs proxy.
3. Compare hit rate, average cache read hit latency, and 429/conflict counts.
4. Inspect proxy logs for resolve-miss patterns and URL refresh churn.
5. Inspect backend endpoint shape for hot paths (`cache_entries#index`, `cache_blobs#download_urls`, `cache_blobs#upload_urls`).

## Benchmark Commands

Use the repository benchmark script for deterministic paired runs.

```bash
SCCACHE_BACKEND=local RUN_SCOPED_TAGS=0 PARALLEL_JOBS=2 scripts/e2e-sccache-test.sh
SCCACHE_BACKEND=proxy RUN_SCOPED_TAGS=0 PARALLEL_JOBS=2 scripts/e2e-sccache-test.sh
```

To quantify run-scoped penalty on the same machine:

```bash
SCCACHE_BACKEND=proxy RUN_SCOPED_TAGS=1 PARALLEL_JOBS=2 scripts/e2e-sccache-test.sh
```

## Regression Signals and Fixes

- Symptom: warm run stays near cold time.
- Likely cause: run-scoped tags in default CI path.
- Fix: stable deterministic root tag in CI and release workflows.

- Symptom: backend request storms on misses.
- Likely cause: repeated miss lookups without dedupe.
- Fix: short miss cache keyed by effective tag plus scoped key and singleflight lookup lock.

- Symptom: repeated flush contention.
- Likely cause: overlapping poller and threshold flushes.
- Fix: atomic flush scheduling guard with guaranteed reset on completion.

- Symptom: accepted data not eventually published after transient backend errors.
- Likely cause: flush error classification too coarse.
- Fix: classify errors into conflict, transient, permanent with backoff and pending restoration on transient/conflict paths.

- Symptom: restore path repeatedly calls blob download URL endpoint.
- Likely cause: URL cache only primed at preload.
- Fix: cache URLs on both preload and resolve paths and invalidate on 403 or entry-id change.

## Proxy Correctness for Multi-Writer Tags

- Keep synchronous preload if startup correctness is preferred over startup latency.
- Add periodic refresh (default around 60s) for long-running processes.
- Apply a simple fence when refreshing published index state (entry identity or pointer identity) to avoid stale overwrite during race windows.

## Workflow Rules

- `sccache-benchmark.yml` should run on:
- push to `main` (optionally path-filtered)
- scheduled cron (`25 5 * * *`)
- manual dispatch

- Do not use job-level `if` with matrix context in this workflow.
- Gate matrix legs using an early step output and apply step-level `if` conditions.

## GitHub Workflows and Tag Conventions

- `/.github/workflows/ci.yml`
- Use stable, deterministic cache-registry tags for normal CI.
- Keep tags scoped by toolchain and runner type, not by run id or attempt.
- Acceptable shape: `rust-<rust_version>-sccache-<target_scope>`.

- `/.github/workflows/release.yml`
- Trigger is tag-driven release (`push` on `v*`).
- Release tag must be semantic with `v` prefix (example: `v1.5.0`).
- Keep release build sccache tags stable per matrix target and rust version.
- Verify release assets include generic Linux aliases:
- `boringcache-linux-amd64`
- `boringcache-linux-arm64`

- `/.github/workflows/sccache-benchmark.yml`
- Run both local and proxy backends.
- Stable tags for normal comparison (`RUN_SCOPED_TAGS=0`).
- Proxy leg may be skipped if `BORINGCACHE_API_TOKEN` is not configured.
- Include summary metrics:
- cold seconds
- warm seconds
- rust hit rate
- average cache read hit latency
- proxy 429 count
- proxy tag conflict count

- `/.github/workflows/serve-registry-e2e.yml`
- Run-scoped tags are acceptable here because this is isolation-focused protocol E2E.
- Keep run-scoped behavior out of default CI and release workflows.

## Tag Naming Rules

- Stable CI and release tags:
- include rust version
- include platform or matrix scope
- exclude run id and run attempt

- Run-scoped tags:
- include run id and run attempt
- use only for isolated E2E, stress, or one-off benchmarking

- Human-facing root tag:
- one deterministic root per workload (for cache reuse)
- avoid per-run churn in normal build pipelines

## Release Runbook

1. Update CLI version (`Cargo.toml` and package entry in `Cargo.lock`).
2. Update install fallback version in `install.sh` and `install-web/install.sh`.
3. Run quality gates:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

4. Commit release payload.
5. Create annotated tag `vX.Y.Z`.
6. Push `main` and tag.
7. Verify release workflow publishes expected assets, including `boringcache-linux-amd64`.

## Pre-Release Checklist

- Stable tag behavior validated in CI/proxy paths
- Local vs proxy benchmark artifacts captured
- 429 count is zero in warm runs
- Tag conflicts are zero for normal CI path
- Warm hit rate and average read latency reported in workflow summary
- Release tag resolves download URL for primary install binary
