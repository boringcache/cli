# Remote Cache Transfer Profiles

This is the product rule for proxy startup warmup. It should be driven by the cache entry shape, not by benchmark names.

## Why This Exists

Native remote-cache tools do not all wait on storage the same way.

- Bazel asks for thousands of CAS/action-cache objects. The gRPC benchmark's rolling cache on 2026-05-07 had 26,217 blobs, 997.5 MiB, and an average blob size of 39 KiB. Bringing those blobs local before Bazel starts is useful, but only if the transfer fan-out is high enough.
- Zed/sccache asks for fewer, much larger compiler objects. The same day's rolling cache had 3,583 blobs, 4.0 GiB, and an average blob size of 1.2 MiB. Local hydration helps avoid compiler-time stalls, but the safe concurrency is governed by bytes in flight, not object count.
- Docker/BuildKit does not need full body hydration before ready. BuildKit can lazily import registry cache metadata and fetch layers as needed, so Docker stays on metadata-first body-on-demand unless a diagnostic mode asks for full hydration.
- Turbo, Nx, Gradle, and Maven remote cache entries are usually task/module artifacts. They benefit from read-through plus enough startup hydration to avoid request latency, but not from unbounded fan-out.

## Current Data Shape

Recent `boringcache/benchmarks` entries, sampled from the live workspace on 2026-05-07:

| Tool shape | Example tag | Size | Objects | Average object |
| --- | --- | ---: | ---: | ---: |
| Bazel remote CAS | `grpc-bazel-remote-cache-rolling-main` | 997.5 MiB | 26,217 | 39 KiB |
| sccache compiler objects | `zed-sccache-rolling-main-sccache-rust1.95` | 4.0 GiB | 3,583 | 1.2 MiB |
| Gradle remote build cache | `otel-gradle-rolling-main-gradle-remote` | 44.9 MiB | 762 | 60 KiB |
| Maven remote build cache | `spring-ai-maven-rolling-main-maven-remote` | 531.7 MiB | 1,656 | 337 KiB |
| Turbo task cache | `n8n-rolling-main-turbo-ubuntu-24-x86_64` | 308.3 MiB | 450 | 701 KiB |
| Nx task cache | `storybook-rolling-nx2-main-nx` | 100.5 MiB | 230 | 447 KiB |
| Docker/OCI layer cache | `posthog-run-rolling-main-ubuntu-24-x86_64` | 5.9 GiB | 87 | 69.4 MiB |

## Product Algorithm

The proxy selects a startup transfer profile from the restored entry:

1. Count unique blobs and total bytes.
2. Compute average blob size.
3. Pick a profile:
   - `many_small_blobs_rtt_bound`: at least 1,000 blobs and average <= 64 KiB.
   - `many_small_blobs_io_bound`: at least 1,000 blobs and average < 1 MiB.
   - `medium_blobs`: average >= 1 MiB and < 8 MiB.
   - `large_blobs`: average >= 8 MiB.
   - `machine_governor`: smaller tags, still capped by bytes in flight.
4. Cap concurrency by object profile. For larger blobs, also cap by the normal bytes-in-flight target. For RTT-bound many-tiny CAS blobs, object latency is the bottleneck, so the profile uses a larger small-object burst budget and can reach the full small-object ceiling.
5. Start many-tiny RTT-bound profiles at their selected ceiling; start larger adaptive profiles below the ceiling and only climb when throughput improves.
6. Treat final failures, rate limits, and material retry pressure as backoff signals.

The normal target is 64 MiB in flight. The many-tiny RTT-bound profile gets a 128 MiB small-object burst budget because 1,000-2,000 tiny reads still carry modest bytes in flight, while avoiding thousands of serialized object round trips. That gives the intended behavior:

| Shape | Expected profile | Typical cap |
| --- | --- | ---: |
| Bazel tiny CAS blobs | `many_small_blobs_rtt_bound` | up to 2,000 |
| Gradle tiny task artifacts | `machine_governor` or `many_small_blobs_rtt_bound` | up to the tag size/count |
| Maven/Turbo/Nx medium-small artifacts | `machine_governor` or `many_small_blobs_io_bound` | byte-budgeted |
| Zed/sccache compiler outputs | `medium_blobs` | about 32-64 |
| Docker/OCI layer bodies | metadata-first, body-on-demand | no full startup body hydration |

## Reading Benchmark Gaps

When actions/cache wins, classify why before changing a benchmark:

- If AC is faster because it restored a local directory and the tool performs many local reads during the build, BoringCache should consider startup hydration or a packed acceleration artifact.
- If AC is faster only in setup but the native build is equal, the product issue is transfer/setup overhead.
- If AC is faster because BoringCache intentionally does not archive local state, the benchmark is not apples-to-apples and should be labelled as remote-cache-only.
- If Docker AC is faster, check import readiness and promoted OCI refs first; full body prewarm is usually the wrong fix.

## External Contracts

- Bazel remote cache is AC metadata plus CAS blobs; Bazel checks local outputs, then remote cache, then executes misses. See https://bazel.build/remote/caching.
- Docker BuildKit registry cache is explicitly imported/exported and supports importing multiple refs, which is why alias readiness matters more than full body prewarm. See https://docs.docker.com/build/cache/backends/.
- Gradle has separate local and remote build caches. See https://docs.gradle.org/current/userguide/build_cache.html.
- Maven build cache keys outputs from source/dependency/effective-POM state and can use remote storage. See https://maven.apache.org/extensions/maven-build-cache-extension/remote-cache.html.
- Turbo and Nx remote caches replay task artifacts by hash; local cache helps, but remote cache is the shared source. See https://turborepo.com/docs/core-concepts/remote-caching and https://canary.nx.dev/docs/features/ci-features/remote-cache.
- sccache is a compiler wrapper with local disk or remote storage backends. See https://github.com/mozilla/sccache.
