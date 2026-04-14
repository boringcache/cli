# Adapter Cache Notes

This note records how each cache-registry adapter behaves, what the client already caches locally, and which generic proxy optimizations are worth doing.

It is based on:

- Local harnesses in `ci/e2e/required/e2e-tool-*.sh` and `ci/e2e/required/e2e-docker-buildkit-registry-test.sh`
- Local mock-backed route checks via `cargo test --manifest-path Cargo.toml round_trip -- --nocapture`
- Official docs:
  - sccache WebDAV: <https://github.com/mozilla/sccache/blob/main/docs/Webdav.md>
  - Gradle build cache: <https://docs.gradle.org/current/userguide/build_cache.html>
  - Maven build cache extension: <https://maven.apache.org/extensions/maven-build-cache-extension/remote-cache.html>
  - Turborepo remote cache: <https://turborepo.dev/docs/core-concepts/remote-caching>
  - Turborepo remote cache API: <https://turborepo.dev/docs/openapi>
  - Nx self-hosted cache: <https://nx.dev/docs/guides/tasks--caching/self-hosted-caching>
  - Docker BuildKit external cache: <https://docs.docker.com/build/cache/optimize/>
  - Bazel remote caching overview: <https://bazel.build/remote/caching>

## Current proxy changes

- Startup prefetch no longer stops on the first oversized blob.
- Blob-read cache sizing and restore/prefetch concurrency now come from one automatic machine governor.
- Startup warming now resolves URLs for the startup slice first, warms that slice first, and resolves the rest in the background.
- Read-path metrics now record `local_cache` vs `remote_fetch`, so we can measure hit ratio and latency instead of guessing.

## Tuning surface

Keep the normal operator surface small:

- Public expert knobs:
  - `BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY`
  - `BORINGCACHE_BLOB_READ_CACHE_MAX_BYTES`
- Internal/debug knobs:
  - startup slice blob and byte caps
  - prefetch batch sizes
  - download-url batch sizes
  - inflight byte budgets
  - raw prefetch concurrency overrides

The intent is that one machine governor and one generic startup path pick the right defaults for almost every workload.
If a benchmark needs lower-level overrides, treat those as engineering controls, not product defaults.

## Adapter matrix

| Adapter | Client protocol | What the client already keeps local | Remote object shape | Best proxy strategy | Avoid |
| --- | --- | --- | --- | --- | --- |
| `sccache` | WebDAV `MKCOL`/`GET`/`HEAD`/`PUT` | `SCCACHE_DIR` plus local server process | Many small compiler result blobs keyed by path-like keys | Keep GET/HEAD cheap, batch URL resolution, and let generic startup warming fill what fits budget | Per-hit URL resolution and low steady-state read concurrency |
| `bazel` | Remote cache over HTTP for `ac/` and `cas/` | Local output base and local disk cache | Split `AC` metadata and `CAS` blobs; can be many objects, sometimes large | Preserve `ac/` and `cas/` correctness, keep startup selection generic, and avoid overcommitting RAM to large CAS graphs | Tool-detected hydrate-first rules or treating large CAS graphs like tiny kv objects |
| `gradle` | Remote HTTP build cache | Local build cache directory; Gradle stores remote hits locally after fetch | One cache object per cacheable task output | Keep GET/PUT path cheap, batch nothing unnecessary, rely on local cache after first restore | Heavy startup hydration by default |
| `maven` | Maven build-cache HTTP or DAV remote | Local Maven repo and local build-cache extension state | Keyed module/project-state artifacts, often many small modules | Keep metadata cheap, preserve portability checks, and rely on local reuse after restore | Ignoring portability/config mismatches or assuming cross-env reuse is always safe |
| `turborepo` | Remote cache API: `GET`/`HEAD`/`PUT`/`POST` | `.turbo/cache` on local disk | One artifact archive per task hash plus query/events calls | Keep query and artifact fetch cheap; warm opportunistically from observed cache state, not tool guesses | Full-tag hydration by default for large monorepos |
| `nx` | Custom remote cache API: `PUT`/`GET`/`HEAD` and query | Local Nx cache folder | Tar archives per task hash plus optional terminal output objects | Same as Turborepo: low-overhead fetch path and opportunistic warming from observed cache state | Blanket hydration of all cached task hashes |
| `docker` | BuildKit registry cache via OCI registry manifests and blobs | Builder local content store and layer cache | OCI manifests plus blob layers; `mode=max` exports more cache state | Optimize manifest/index reuse, URL batching, and local content-store reuse | Treating OCI cache like filesystem kv objects or forcing generic blob hydration into temp disk by default |
| `go-cache` | Simple object API `GET`/`HEAD`/`PUT` | Go local build cache | One object per action/result key | Fast kv path, cheap metadata, local reuse after first fetch | Overengineering it with heavy startup hydration |

## Working rules

- Adapters define protocol, key layout, and cache contents.
- BoringCache owns storage, transfer, verification, and machine-safe scheduling.
- Startup warming should stay opportunistic and budget-bound; tool detection should not grant special RAM or CPU behavior by default.
- Query-aware or protocol-aware optimizations should come from real request shape, not adapter-name guesses.
- `docker` should stay OCI-native. BuildKit already understands manifests, layers, and local content reuse.

## Local measurement plan

When credentials are available, run the per-adapter harnesses and capture:

- `ci/e2e/required/e2e-tool-sccache-test.sh`
- `ci/e2e/required/e2e-tool-bazel-test.sh`
- `ci/e2e/required/e2e-tool-gradle-test.sh`
- `ci/e2e/required/e2e-tool-maven-test.sh`
- `ci/e2e/required/e2e-tool-turbo-test.sh`
- `ci/e2e/required/e2e-docker-buildkit-registry-test.sh`

After each run, summarize `cache-registry-request-metrics.jsonl` with `ci/e2e/request-metrics-summary.py` and compare:

- local blob-read hit ratio
- local vs remote bytes served
- local vs remote p50/p95 read latency
- preload-index p95
- prefetch-cycle p95

For restart-path measurements, force a distinct local blob-cache directory with `BORINGCACHE_BLOB_READ_CACHE_DIR` so the run is not polluted by an older temp-cache from a previous proxy process.

## Immediate next tuning targets

1. Validate that generic startup warming shifts a meaningful share of reads from `remote_fetch` to `local_cache`.
2. Measure object-size distributions and read locality before changing startup ordering.
3. Add request-shaped warming only where real protocol traffic proves it helps.
4. Inspect OCI blob and manifest fetch counts before changing any registry behavior.
