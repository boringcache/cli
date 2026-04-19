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

- Startup warming hydrates the full active tag by default.
- Blob-read cache sizing and restore/prefetch concurrency now come from one automatic machine governor.
- Startup warming now resolves URLs for the full active tag first, hydrates that tag first, and lets the blob read cache evict over budget.
- Read-path metrics now record `local_cache` vs `remote_fetch`, so we can measure hit ratio and latency instead of guessing.

## Tuning surface

Keep the normal operator surface small:

- Public expert knobs:
  - `BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY`
- Internal batching stays fixed in code.

The intent is that one machine governor and one generic startup path pick the right defaults for almost every workload.
If a benchmark needs lower-level overrides, treat those as engineering controls, not product defaults.

## Adapter matrix

| Adapter | Client protocol | What the client already keeps local | Remote object format | Best proxy strategy | Avoid |
| --- | --- | --- | --- | --- | --- |
| `sccache` | WebDAV `MKCOL`/`GET`/`HEAD`/`PUT` | `SCCACHE_DIR` plus local server process | Many small compiler result blobs keyed by path-like keys | Keep GET/HEAD cheap, batch URL resolution, and hydrate the active tag into disk cache by default | Per-hit URL resolution and low steady-state read concurrency |
| `bazel` | Remote cache over HTTP for `ac/` and `cas/` | Local output base and local disk cache | Split `AC` metadata and `CAS` blobs; can be many objects, sometimes large | Preserve `ac/` and `cas/` correctness, hydrate the active tag generically, and let disk-cache eviction enforce capacity | Tool-detected hydrate-first rules or treating large CAS graphs like tiny kv objects |
| `gradle` | Remote HTTP build cache | Local build cache directory; Gradle stores remote hits locally after fetch | One cache object per cacheable task output | Keep GET/PUT path cheap, batch nothing unnecessary, rely on local cache after first restore | Heavy startup hydration by default |
| `maven` | Maven build-cache HTTP or DAV remote | Local Maven repo and local build-cache extension state | Keyed module/project-state artifacts, often many small modules | Keep metadata cheap, preserve portability checks, and rely on local reuse after restore | Ignoring portability/config mismatches or assuming cross-env reuse is always safe |
| `turborepo` | Remote cache API: `GET`/`HEAD`/`PUT`/`POST` | `.turbo/cache` on local disk | One artifact archive per task hash plus query/events calls | Keep query and artifact fetch cheap; warm opportunistically from observed cache state, not tool guesses | Full-tag hydration by default for large monorepos |
| `nx` | Custom remote cache API: `PUT`/`GET`/`HEAD` and query | Local Nx cache folder | Tar archives per task hash plus optional terminal output objects | Same as Turborepo: low-overhead fetch path and opportunistic warming from observed cache state | Blanket hydration of all cached task hashes |
| `docker` | BuildKit registry cache via OCI registry manifests and blobs | Builder local content store and layer cache | OCI manifests plus blob layers; `mode=max` exports more cache state | Optimize manifest/index reuse, URL batching, explicit OCI body hydration, and local content-store reuse | Treating OCI cache like filesystem kv objects or blindly forcing blob hydration for every user |
| `go-cache` | Simple object API `GET`/`HEAD`/`PUT` | Go local build cache | One object per action/result key | Fast kv path, cheap metadata, local reuse after first fetch | Overengineering it with heavy startup hydration |

## Working rules

- Adapters define protocol, key layout, and cache contents.
- BoringCache owns storage, transfer, verification, and machine-safe scheduling.
- Generic KV startup warming should hydrate the full active tag by default on disk-backed cache-registry paths. Capacity control belongs in the blob read cache size and eviction policy, not a separate startup selection budget.
- Query-aware or protocol-aware optimizations should come from real request patterns, not adapter-name guesses.
- `docker` should stay OCI-native. BuildKit already understands manifests, layers, and local content reuse. Use the OCI hydration policy to choose metadata-only read-through, bodies-before-ready, or background body hydration for selected refs.

## Local measurement plan

When credentials are available, run the per-adapter harnesses and capture:

- `ci/e2e/required/e2e-tool-sccache-test.sh`
- `ci/e2e/required/e2e-tool-bazel-test.sh`
- `ci/e2e/required/e2e-tool-gradle-test.sh`
- `ci/e2e/required/e2e-tool-maven-test.sh`
- `ci/e2e/required/e2e-tool-turbo-test.sh`
- `ci/e2e/required/e2e-docker-buildkit-registry-test.sh`

For local Docker-on-macOS/Colima replay, set `REGISTRY_HOST=host.docker.internal`,
`PROXY_HOST=0.0.0.0`, and `PROXY_STATUS_HOST=127.0.0.1`. The Docker E2E harness
generates a BuildKit daemon config for non-localhost registry refs so BuildKit uses
HTTP instead of trying HTTPS against the local proxy.

After each run, summarize `cache-registry-request-metrics.jsonl` with `ci/e2e/request-metrics-summary.py` and compare:

- local blob-read hit ratio
- local vs remote bytes served
- local vs remote p50/p95 read latency
- preload-index p95
- prefetch-cycle p95

For OCI body-plane measurements, prefer a non-compressible payload (`E2E_PAYLOAD_MODE=random`) so blob bytes represent real transfer pressure instead of `/dev/zero` compression artifacts.

For restart-path measurements, use `E2E_BLOB_CACHE_SCOPE=per-proxy` in the Docker E2E harness or force a distinct local blob-cache directory with `BORINGCACHE_BLOB_READ_CACHE_DIR` so the run is not polluted by an older blob cache from a previous proxy process.

## Immediate next tuning targets

1. Validate that full-tag startup hydration shifts a meaningful share of reads from `remote_fetch` to `local_cache`.
2. Measure object-size distributions and read locality before changing hydration ordering.
3. Add request-shaped warming only where real protocol traffic proves it helps.
4. Inspect OCI blob and manifest fetch counts before changing any registry behavior.
5. For OCI manifest PUT, validate referenced config and layer blobs before publish so missing content returns `400 MANIFEST_BLOB_UNKNOWN` instead of degrading into an internal publish failure.
6. Tighten OCI resumable upload offset handling to match Distribution-spec `416 Requested Range Not Satisfiable` behavior for stale or out-of-order chunk ranges.
7. Add OCI startup warming for selected refs into `oci_manifest_cache` and `blob_locator`, with optional blob-byte hydration through the shared `blob_read_cache` only when measurements justify it.
8. Measure the new OCI manifest and blob inflight dedupe under concurrent BuildKit and direct-OCI read load before changing blob-download semaphore policy.
9. Keep the OCI manifest-contract and BuildKit registry-cache E2E legs covering spec-sensitive manifest, referrers, blob-upload, and warm-start behavior as OCI proxy changes land.
