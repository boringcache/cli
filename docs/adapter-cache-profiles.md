# Adapter Cache Profiles

This note records how each cache-registry adapter behaves, what the client already caches locally, and which proxy optimizations are worth doing.

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
- `sccache` now gets a dedicated tuning profile with more aggressive blob-cache sizing and read concurrency.
- `bazel` now gets a dedicated tuning profile that prioritizes `bazel_ac` and small `bazel_cas` blobs ahead of larger CAS payloads during startup.
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

The intent is that adapter profiles pick the right defaults for almost every workload.
If a benchmark needs lower-level overrides, treat those as engineering controls, not product defaults.

## Adapter matrix

| Adapter | Client protocol | What the client already keeps local | Remote object shape | Best proxy strategy | Avoid |
| --- | --- | --- | --- | --- | --- |
| `sccache` | WebDAV `MKCOL`/`GET`/`HEAD`/`PUT` | `SCCACHE_DIR` plus local server process | Many small compiler result blobs keyed by path-like keys | Whole-tag or large-slice hydration when the published tag fits budget; keep hot blob metadata in memory; high read concurrency | Per-hit URL resolution and conservative startup prefetch on warm CI paths |
| `bazel` | Remote cache over HTTP for `ac/` and `cas/` | Local output base and local disk cache | Split `AC` metadata and `CAS` blobs; can be many objects, sometimes large | Treat `AC` and `small CAS` as hydrate-first; keep large `CAS` lazy unless the full tag is small enough to fit budget | Treating all CAS blobs like tiny kv objects or fully hydrating very large CAS graphs by default |
| `gradle` | Remote HTTP build cache | Local build cache directory; Gradle stores remote hits locally after fetch | One cache object per cacheable task output | Keep GET/PUT path cheap, batch nothing unnecessary, rely on local cache after first restore | `sccache`-style whole-tag hydration by default |
| `maven` | Maven build-cache HTTP or DAV remote | Local Maven repo and local build-cache extension state | Keyed module/project-state artifacts, often many small modules | Keep metadata cheap, preserve portability checks, optionally prewarm hot module outputs after manifest load | Ignoring portability/config mismatches or assuming cross-env reuse is always safe |
| `turborepo` | Remote cache API: `GET`/`HEAD`/`PUT`/`POST` | `.turbo/cache` on local disk | One artifact archive per task hash plus query/events calls | Query-aware warming: cache metadata and only hydrate queried or recently hot task artifacts | Full-tag hydration by default for large monorepos |
| `nx` | Custom remote cache API: `PUT`/`GET`/`HEAD` and query | Local Nx cache folder | Tar archives per task hash plus optional terminal output objects | Same profile as Turborepo: query-aware warming and hot artifact locality | Blanket hydration of all cached task hashes |
| `docker` | BuildKit registry cache via OCI registry manifests and blobs | Builder local content store and layer cache | OCI manifests plus blob layers; `mode=max` exports more cache state | Optimize manifest/index reuse, URL batching, and local content-store reuse | Treating OCI cache like filesystem kv objects or forcing generic blob hydration into temp disk by default |
| `go-cache` | Simple object API `GET`/`HEAD`/`PUT` | Go local build cache | One object per action/result key | Fast kv path, cheap metadata, local reuse after first fetch | Overengineering it with heavy startup hydration |

## Working rules

- `sccache` is the strongest candidate for archive-like behavior through the proxy.
  - The client can issue many small reads on warm builds.
  - If the tag is under a sane byte budget, hydrating it locally at startup is better than paying repeated remote round trips.

- `bazel` needs a split strategy.
  - `AC` is metadata and cheap to hydrate.
  - `CAS` can range from tiny to huge. Hydrate small hot blobs first and make full-tag hydration conditional on total size and object count.

- `turborepo` and `nx` are archive-per-task systems, not tiny-blob systems.
  - The main win is keeping query results and hot artifacts local.
  - Full-tag hydration only makes sense for unusually small task sets.

- `gradle`, `maven`, and `go-cache` are better treated as low-latency kv/object adapters.
  - The client already has a local cache story.
  - The proxy should focus on low control-plane overhead and fast steady-state reads, not eager full-tag hydration.

- `docker` should stay OCI-native.
  - BuildKit already understands manifests, layers, and local content reuse.
  - We should optimize OCI-specific fetch/publish behavior instead of trying to emulate archive-mode at the proxy layer.

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

1. `sccache`: validate that startup hydration shifts a meaningful share of reads from `remote_fetch` to `local_cache`.
2. `bazel`: validate startup metrics on real benchmark runs and tune the `small CAS` cutoff using observed blob-size distributions instead of the current conservative default.
3. `turborepo` and `nx`: add query-aware hot-artifact warming instead of generic manifest-wide warming.
4. `docker`: inspect OCI blob and manifest fetch counts before changing any hydration behavior.
