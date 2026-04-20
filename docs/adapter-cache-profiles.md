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
| `docker` | BuildKit registry cache via OCI registry manifests and blobs | Builder local content store and layer cache | OCI manifests plus blob layers; `mode=max` exports more cache state | Optimize manifest/index reuse, URL batching, on-demand blob read-through, and local content-store reuse | Treating OCI cache like filesystem kv objects or forcing full blob hydration before BuildKit starts |
| `go-cache` | Simple object API `GET`/`HEAD`/`PUT` | Go local build cache | One object per action/result key | Fast kv path, cheap metadata, local reuse after first fetch | Overengineering it with heavy startup hydration |

## Working rules

- Adapters define protocol, key layout, and cache contents.
- BoringCache owns storage, transfer, verification, and machine-safe scheduling.
- Generic KV startup warming should hydrate the full active tag by default on disk-backed cache-registry paths. Capacity control belongs in the blob read cache size and eviction policy, not a separate startup selection budget.
- Query-aware or protocol-aware optimizations should come from real request patterns, not adapter-name guesses.
- `docker` should stay OCI-native. BuildKit already understands manifests, layers, and local content reuse. The product default resolves selected refs and serves blob bodies on demand (`metadata-only`); `bodies-background` and `bodies-before-ready` stay internal benchmark/diagnostic modes.

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
- OCI engine local vs remote blob reads
- OCI proof source counts and miss causes
- OCI range request, partial response, and invalid range counts
- OCI publish phase counts and durations
- preload-index p95
- prefetch-cycle p95

When a run captures multiple proxy status snapshots, prefer the labeled
`request_metrics_status_<phase>_*` values for pass/fail checks. For example, the
strict restart gate should read
`request_metrics_status_phase2_restart_warm_oci_body_remote_fetches`, not the
top-level `request_metrics_oci_body_remote_fetches`, because the top-level value
is the max across all snapshots and can include intentional cold-path reads.

For OCI body-plane measurements, prefer a non-compressible payload (`E2E_PAYLOAD_MODE=random`) so blob bytes represent real transfer pressure instead of `/dev/zero` compression artifacts.

For restart-path measurements, use `E2E_BLOB_CACHE_SCOPE=per-proxy` in the Docker E2E harness or force a distinct local blob-cache directory with `BORINGCACHE_BLOB_READ_CACHE_DIR` so the run is not polluted by an older blob cache from a previous proxy process.

## Current OCI tuning targets

1. Use the default metadata-only/on-demand body path for real project and GitHub Actions adapter rollout.
2. Keep hidden `bodies-background` and `bodies-before-ready` controls only for targeted readiness/read-through comparisons.
3. Use `E2E_PAYLOAD_MODE=random` when validating byte movement so digest/size verification and range behavior see real transfer pressure.
4. Compare labeled restart-path `request_metrics_status_<phase>_*` locality values plus top-level `request_metrics_oci_engine_blob_remote_fetched_bytes`, range counts, proof sources, miss causes, and publish phase durations before changing registry behavior.
5. Measure object-size distributions and read locality before changing any non-OCI adapter hydration ordering.
6. Keep the OCI manifest-contract and BuildKit registry-cache E2E legs covering spec-sensitive manifest, referrers, blob-upload, and warm-start behavior as OCI proxy changes land. Release gating must keep those legs present and successful, and benchmark/ad hoc runs must preserve the OCI status artifacts used to explain body-plane behavior.
