# ADR 0003: Runner Proxy Optimization Roadmap

Status: accepted roadmap; sub-ADR rollout remains proof-gated
Date: 2026-04-20

## Context

Two recent reviews converged on the same high-level direction but differed in how much of the current CLI they assumed already existed.

The first review correctly favored a runner-local data-plane proxy over an on-demand edge fleet, and correctly deprioritized eager Docker blob prefetch. The second review corrected the premise: the CLI already has the runner proxy, adapter wrappers, OCI engine modules, selected-ref metadata hydration, local blob read cache, request coalescing, range support, upload sessions, digest verification, pooled transfer clients, and useful diagnostics.

The current optimization problem is therefore not "build a runner proxy". It is "make the existing runner proxy cheaper on the Docker/OCI hot path and better instrumented before introducing more infrastructure".

Current code evidence:

- `cache-registry` is the runner-local proxy and the Docker adapter starts it for BuildKit.
- Docker's product default is OCI `metadata-only`: resolve selected manifest/index state and locator URLs, then let BuildKit request bodies on demand.
- The default OCI blob GET path still hydrates then serves for ordinary misses, but the hidden ADR 0004 stream-through prototype can serve eligible full-body misses while teeing, hashing, and promoting verified bytes.
- Local body-cache and blob-cache-backed mount proof sessions now borrow verified `BlobReadCache` handles with leases; mutable upload-session reuse still materializes owned temp files.
- The proxy emits status snapshots, JSONL request metrics, and a `cache_session_summary` event with proxy, storage, OCI, singleflight, local-cache, and BuildKit sections. Rails percentile rollups, action enrichment, and operator reporting remain follow-up work.

## Source Grounding

The roadmap is grounded in OCI and BuildKit behavior, not only current BoringCache internals.

Primary sources:

- OCI Distribution Spec: https://github.com/opencontainers/distribution-spec/blob/main/spec.md
- OCI Image Spec descriptors: https://github.com/opencontainers/image-spec/blob/main/descriptor.md
- Docker cache backends: https://docs.docker.com/build/cache/backends/
- Docker registry cache backend: https://docs.docker.com/build/cache/backends/registry/
- BuildKit README cache section: https://github.com/moby/buildkit#export-cache
- BuildKit registry remote-cache source: https://github.com/moby/buildkit/blob/v0.25.0/cache/remotecache/registry/registry.go
- BuildKit GitHub Actions remote-cache source: https://github.com/moby/buildkit/blob/v0.25.0/cache/remotecache/gha/gha.go

Relevant source facts:

- OCI pull is manifest plus blobs, and content may be retrieved in any order. That supports metadata-first behavior while keeping body availability as a separate measured plane.
- OCI blob responses are digest-addressed and clients are expected to verify requested digests. That makes stream-through viable for OCI blobs if BoringCache verifies before storing.
- OCI registries should support Range for blobs, and `HEAD`/`404` have explicit existence semantics. That grounds range handling and short-lived negative caching for confirmed misses.
- OCI push uploads blobs first and manifest last; registries may reject manifests whose non-subject descriptors are missing. That grounds `PresentBlob` proof and borrowed upload-session work.
- Docker registry cache is a separate cache image location, requires explicit import/export, supports `mode=max`, and can import multiple remote caches. That grounds multiple `--cache-from` aliases and immutable run refs.
- Docker warns that writing the same cache location twice overwrites previous cache data. That grounds atomic alias promotion instead of same-tag destructive writes.
- BuildKit registry cache uses normal registry resolver/fetcher/pusher plumbing. BoringCache should therefore keep behaving like an OCI registry/proxy instead of inventing a Docker-specific side protocol.
- BuildKit GitHub Actions cache has scope, index, timeout, and branch-like behavior. That is useful comparison evidence for session trace fields and alias/run-scope metadata, even though BoringCache should not copy the GHA backend shape directly.

## Decision

Optimize the existing runner-local proxy first. Do not build an on-demand edge server, custom global proxy fleet, or mandatory daemon before the runner proxy proves where the remaining tail latency is.

The roadmap lands in this order:

1. Add a per-session cache trace, singleflight metrics, and OCI negative-cache behavior. First CLI slice done; backend/action enrichment pending.
2. Design immutable Docker run refs and atomic alias promotion across CLI/action/Rails. Hidden CLI/Rails slice and CI-side derivation done; backend same-alias E2E/action rollout pending.
3. Remove avoidable local copy/sync when cached blobs are reused for OCI publish. Borrowed cache-body sessions done; cache-policy proof pending.
4. Prototype large OCI blob stream-through with tee-to-cache and end-of-stream verification. Hidden threshold prototype done; benchmark proof pending.
5. Tune blob-cache admission and eviction using measured reuse by object size.
6. Add adaptive transfer control only after the metrics show fixed concurrency is a real bottleneck.

The user-facing Docker default remains `metadata-only`. Hidden `bodies-background` and `bodies-before-ready` stay diagnostic controls, not ordinary product choices.

## ADR Map

This roadmap is implemented through narrower ADRs:

- ADR 0004 owns large OCI blob stream-through.
- ADR 0005 owns borrowed upload-session bodies and blob-cache policy.
- ADR 0006 owns the per-session cache trace, OCI negative cache, and singleflight/coalescing metrics.
- ADR 0007 owns Docker immutable run refs and atomic alias promotion across CLI/action/Rails.

ADR 0002 remains the source-backed OCI protocol contract. ADR 0003 does not replace it; it defines the next optimization sequence after the first OCI engine extraction.

Web/API control-plane decisions implied by this roadmap are canonical in the web repo ADR:

- `web/docs/adr/0001-cache-control-plane-roots-aliases-and-session-insight.md`

This CLI ADR owns runner/proxy ordering. The web ADR owns Rails schema, API, state-machine, session-ingestion, and operator insight decisions.

## Current Alignment

As of 2026-04-21, this roadmap is documentation-aligned for hidden/internal implementation. It is not benchmark-proof-complete.

- ADR 0006 is the first-party insight spine: session trace, singleflight counters, negative cache, and later backend/action enrichment.
- ADR 0007 is the correctness and control-plane spine: immutable run refs, alias promotion, and stale-writer visibility.
- ADR 0005 is the local disk-efficiency spine: borrowed upload-session bodies, cache leases, and later admission policy.
- ADR 0004 is the large-body latency spine: stream-through for eligible OCI blob GET misses, default-off until benchmarked.

Testing and proof work may be deferred, but it must stay explicit. A sub-ADR is doc-ready when it names implementation progress, remaining rollout gates, and the artifacts needed before user-visible defaults change.

Current release proof gap: the required registry E2E must be green without verifier-side publish-readiness polling. The intended product contract is receipt-strict publish when Rails returns an upload session: completed blob and manifest receipts make a root safe to expose, and receipt failures or backend "blob not yet verified" confirm responses fail publish/export instead of relying on a post-publish blob download-url convergence loop. Normal API/storage retries for timeouts and transient network or URL failures are still valid retry behavior.

## Required Metrics Before Behavior Claims

Add metrics that can distinguish storage, proxy, and BuildKit wait:

- remote blob client wait before first response byte;
- upstream storage TTFB;
- upstream storage body duration and bytes;
- digest verification duration and failure count;
- local spool bytes and duration;
- local reread duration for the existing hydrate-then-serve path;
- singleflight leader and follower counts;
- follower wait duration and timeout count;
- local cache hit bytes and miss bytes;
- bytes written to local cache;
- bytes evicted before reuse;
- upload-session materialization bytes, copy duration, and sync duration;
- BuildKit cache import/export wall time where the harness can observe it;
- Rails API request count, p50/p95 duration, retry count, and status class.

The first implementation step may add only the subset needed to compare the current OCI path with the stream-through prototype. Do not block the first prototype on a perfect global trace schema.

## Implementation Sequence

### Phase 1: Session Trace, Singleflight Metrics, And OCI Negative Cache

Add the trace and cache behavior from ADR 0006. The first metrics should cover the existing hydrate-then-serve path:

- URL resolve start/end;
- upstream GET send, first body chunk, EOF;
- temp file write bytes and duration;
- digest/size verification result;
- cache promotion result;
- local response open and first byte served.

Also add OCI miss suppression for confirmed short-lived misses and expose leader/follower/wait counts for the existing flight helpers. This creates a baseline before changing behavior and prevents repeated concurrent BuildKit probes from doing duplicate backend work.

### Phase 2: Immutable Run Refs And Alias Promotion

Implement the design in ADR 0007. Parallel same-tag writes remain a correctness and benchmark-noise issue. Handle them with immutable roots and atomic alias promotion, not by locking the whole BuildKit run in the CLI.

This phase can begin as a design/API contract track while Phase 1 instrumentation lands. Rails owns alias policy and atomicity; CLI/action owns valid OCI ref planning, `--cache-to` run refs, selected `--cache-from` aliases, and diagnostics.

### Phase 3: Borrowed Upload-Session Bodies

Avoid copying verified local body-cache blobs into new upload-session temp files when they can be safely referenced by path, offset, size, and digest.

This should land before or beside stream-through because it is a clear local waste and does not change what BuildKit receives.

### Phase 4: Large Blob Stream-Through

For large OCI full-body GETs, stream the upstream body to BuildKit while teeing it to a temp file and hashing it. Promote only after digest and size validation.

Keep the current hydrate-then-serve path for:

- small blobs below the configured threshold;
- `HEAD`;
- invalid or unsupported range requests;
- range requests in the first implementation unless ADR 0004 explicitly extends the prototype;
- any storage response that cannot be safely streamed.

### Phase 5: Cache Policy Tuning

Use measured local reuse to tune admission and eviction. Do not make Docker-aware cache policy clever before proving the waste.

Candidate policy after measurement:

- manifests, indexes, and config-like small blobs remain cheap to cache;
- small and medium blobs are admitted normally;
- very large blobs can be stream-through-only, admitted only when reuse is observed, or admitted under a size budget;
- pinned entries used by borrowed upload sessions must not be evicted while a session or upload job references them.

### Phase 6: Adaptive Transfer Control

Only after the trace shows fixed concurrency is a bottleneck, add a small feedback controller over separate pools:

- metadata/Rails;
- small blob URL and HEAD-style work;
- large blob downloads;
- uploads;
- background prefetch.

The controller should react to latency, retry/error rate, and throughput. It should not be introduced at the same time as stream-through, because that would make benchmark interpretation harder.

## Acceptance Gates

Before claiming an optimization win:

- current metadata-only Docker E2E remains green;
- OCI manifest-contract tests remain green;
- range `206`/`416`, digest `ETag`, upload resume, empty finalize reuse, and mount semantics remain covered;
- PostHog or equivalent real-project benchmark classifies runs as steady, reseed, or fresh before comparing wall time;
- artifacts include proxy status snapshots and request metrics summary;
- the comparison separates BuildKit rebuild/export time from proxy remote body wait.

Before exposing any new user-facing flag:

- hidden/internal controls have been benchmarked;
- default metadata-only remains best or neutral for normal Docker workflows;
- docs explain when the flag helps without making ordinary users choose a hydration policy.

## Rejected Options

Do not build an on-demand edge server per workspace/build now. Cold start, locality detection, TLS/auth/routing, lifecycle, and cache eviction are all extra product and operational complexity before the runner proxy has exhausted cheaper wins.

Do not make eager Docker body hydration the default. BuildKit registry cache already has a sound import/export graph, and large Docker layers should stay on-demand unless telemetry proves repeated reads.

Do not rewrite Docker through snapshot-v2. Docker/OCI wins come from protocol-native manifest/blob behavior, not a generic filesystem engine.

Do not add adaptive concurrency before adding metrics that prove it is the bottleneck.
