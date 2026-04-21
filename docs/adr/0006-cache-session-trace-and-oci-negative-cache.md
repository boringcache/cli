# ADR 0006: Cache Session Trace And OCI Negative Cache

Status: accepted as first-party insight baseline; backend/action enrichment pending
Date: 2026-04-20

## Context

The proxy already emits useful request metrics and `/_boringcache/status` snapshots. Those are enough for targeted debugging, but they do not yet produce one cache-session summary that answers the main performance question without log archaeology:

```text
Was this run Rails-bound, storage-TTFB-bound, storage-throughput-bound,
duplicate-request-bound, local-disk-bound, or BuildKit-cache-miss-bound?
```

The proxy also already has singleflight-style request coalescing for OCI manifest/blob lookup and KV download/lookup paths. We do not expose enough leader/follower/wait metrics to prove how much duplicate work is avoided.

Finally, the KV path has a short recent-miss cache. OCI has miss counters, but no equivalent explicit negative cache for repeated concurrent BuildKit probes. Parallel `HEAD`/`GET`/manifest requests for known-missing OCI objects can still hit the locator/API/storage path repeatedly.

## Source Grounding

This ADR depends on these source-backed properties:

- OCI defines `HEAD` as the existence check for manifests and blobs, with `200 OK` for present objects and `404 Not Found` for missing ones.
- OCI blob `GET` for a missing blob is also `404`. Short-lived negative cache entries are therefore valid only for confirmed miss responses, not for transport or backend failures.
- OCI manifest publish can reject references to missing descriptors. Miss reasons in the trace must distinguish manifest, blob-locator, verified-download-url, and remote-blob misses.
- Docker and BuildKit require explicit cache import/export; external cache is important in CI because runners often lack persistence. Session traces must therefore separate cache import, body transfer, and export/publish costs.
- BuildKit registry cache importer resolves a ref and fetches content through a registry content provider. BoringCache trace fields should explain normal registry pull/push behavior rather than relying only on total build wall time.
- BuildKit's GHA backend models scope, timeout, blob keys, and a mutable index. This reinforces the need to capture scope/run metadata and timeout/retry behavior, while still keeping BoringCache's registry path OCI-native.

Source URLs are listed in ADR 0003.

## Decision

Add a per-session cache trace and OCI negative-cache behavior before adaptive transfer control.

The trace is a single structured summary emitted at proxy shutdown or run finalization. It should be backed by incremental counters and histograms during the session, then written into the existing JSONL observability path and surfaced in E2E summaries.

OCI negative caching should cache only confirmed misses for a short TTL and must be invalidated by local writes or published index changes. It should not hide infrastructure failures.

## Session Trace Shape

The trace should be one JSON object with stable top-level sections:

```json
{
  "schema": "cache-session-v1",
  "workspace": "namespace/workspace",
  "mode": "docker-registry",
  "adapter": "oci",
  "run_id": "github-run-or-adhoc",
  "proxy": {
    "hydration_policy": "metadata-only",
    "started_at": "...",
    "duration_ms": 0
  },
  "rails": {},
  "storage": {},
  "oci": {},
  "singleflight": {},
  "local_cache": {},
  "buildkit": {}
}
```

Exact field names may follow current `request_metrics_summary` naming, but the shape must keep these categories separate.

## First-Party Insight Contract

This ADR is not only a performance trace. It is the first-party insight spine for platform decisions, support, cost control, and default rollout choices.

Every session summary should preserve correlation fields whenever the runner, action, or backend knows them:

- workspace and cache entry identity;
- adapter and mode;
- session id;
- CLI version and release ref when known;
- CI provider, provider run uid, attempt, branch/ref, PR number, commit SHA, and run timestamps when known;
- immutable run ref, import aliases, promotion aliases, and promotion result when ADR 0007 is active;
- storage provider/mode and object-store region when known;
- benchmark run id, scenario, and classification when the harness enriches the trace.

Facts that affect product defaults should be backend-visible eventually, not only local JSONL. The CLI can emit the first summary, but Rails/action/benchmark enrichment should make it possible to answer: which cache plane was slow, which alias/root was used, which blobs were reused, what it cost, and whether the run was fresh, reseed, steady, or unknown.

The canonical web/API decision for session-summary ingestion, backend persistence, rollups, and operator insight lives in:

- `web/docs/adr/0001-cache-control-plane-roots-aliases-and-session-insight.md`

This CLI ADR owns emitted runner/proxy fields and local negative-cache behavior. The web ADR owns backend storage, reporting, API shape, and product/operator visibility.

## Required Fields

### Rails/API

Record by operation:

- request count;
- success/error count;
- retry count;
- p50 and p95 duration;
- status-class counts;
- request bytes and response bytes where known.

Operations should include at least:

- save entry;
- blob check;
- blob upload URL plan;
- blob download URL plan;
- blob receipt commit;
- manifest receipt commit;
- confirm/publish;
- tag pointer read.

### Storage/Object Transfer

For transfer URLs, record:

- GET/PUT count;
- upstream time to first byte for GET;
- body duration;
- bytes transferred;
- p50/p95 throughput;
- retry count;
- timeout count;
- 429/5xx count;
- digest/size verification duration and failures.

Use provider-neutral names in the CLI such as `storage_get_ttfb_ms`. Benchmark analysis may label the provider as Tigris when the environment is known.

### OCI/BuildKit Proxy

Record:

- manifest GET/HEAD/PUT count;
- blob GET/HEAD count;
- remote blob client first-byte wait;
- hydrate-then-serve count and wait duration;
- stream-through count and bytes when ADR 0004 is implemented;
- range request count;
- partial/invalid range count;
- proof source counts;
- miss cause counts.

### Singleflight

Record by flight kind:

- leader count;
- follower count;
- follower wait p50/p95;
- follower timeout count;
- takeover count;
- post-flight local hit count;
- post-flight retry/miss count.

Initial flight kinds:

- `oci-blob`;
- `oci-manifest`;
- `oci-download-url`;
- `kv-lookup`;
- `kv-download`;
- `kv-url`;
- `kv-size`.

### Local Cache

Record:

- hit count and bytes;
- miss count and bytes;
- bytes written;
- bytes evicted;
- bytes evicted before reuse when known;
- pinned bytes and pin duration once ADR 0005 lands;
- materialization copy/sync bytes and duration until ADR 0005 removes the main copy path.

### BuildKit

Where available from the action, Docker wrapper, or benchmark harness, attach:

- cache import wall time;
- cache export wall time;
- cached step count;
- new blob count;
- new blob bytes;
- seed/build wall time;
- run classification: `steady`, `reseed`, `fresh`, or `unknown`.

Do not make the CLI depend on fragile BuildKit log parsing for ordinary local use. It is acceptable for the GitHub Action and benchmark harness to enrich the session trace when they can observe these values.

## OCI Negative Cache

Add short-lived negative cache entries for confirmed OCI misses.

Initial miss classes:

- manifest ref missing after restore candidates are checked;
- blob locator missing for `(registry_root_tag, name, digest)`;
- verified download URL API reports digest missing for a known cache entry;
- remote blob existence check confirms missing.

Do not negative-cache:

- 5xx responses;
- 429 responses;
- network timeouts;
- auth failures;
- digest mismatch;
- any error hidden by `fail_on_cache_error=false` unless the backend explicitly returned a miss.

In other words, negative cache is for OCI miss semantics, not for infrastructure failure suppression.

Suggested TTL:

- 5 seconds for blob-locator and manifest misses;
- 15 seconds for verified download URL missing;
- configurable only by hidden engineering env if needed.

Negative cache keys must include enough scope to avoid cross-ref pollution:

- workspace;
- registry root tag;
- OCI repository name;
- reference or digest;
- cache entry id where relevant;
- miss generation.

Invalidate negative cache entries when:

- a blob upload finalizes locally for the digest;
- a manifest PUT succeeds;
- startup prefetch or on-demand restore populates the locator;
- the registry root tag generation changes;
- cache-registry publish/flush refreshes local index state.

## Implementation Plan

1. Add singleflight counters and wait timings to the existing flight helpers.
2. Add OCI negative-cache storage to `AppState`, mirroring the KV recent-miss pattern but with OCI-specific keys and reasons.
3. Use the negative cache in OCI manifest/blob/download-url miss paths.
4. Add invalidation calls in upload finalize, manifest publish, locator seeding, and startup/on-demand restore.
5. Add current-path session trace counters for Rails, storage GET/PUT, hydrate-then-serve, local cache, and materialization.
6. Emit a `cache_session_summary` observability event at proxy shutdown and, where applicable, action/harness finalization.
7. Teach `ci/e2e/request-metrics-summary.py` to promote the session summary fields into artifacts.
8. Only then evaluate adaptive concurrency.

## Implementation Progress

The first CLI baseline is implemented:

- shared singleflight metrics record leaders, followers, follower wait percentiles, timeouts, takeovers, and post-flight local-hit/retry-miss counts for OCI and KV lookup/download helpers;
- `AppState` owns a short-lived OCI negative cache for manifest-ref, blob-locator, download-url, and remote-blob misses;
- confirmed OCI miss paths insert negative-cache entries, and locator population, upload finalize, mount reuse, and manifest publish invalidate relevant entries;
- OCI blob hydrate-then-serve records storage GET bytes, first body wait, body duration, local spool write duration, digest verification duration/failure, and cache-promotion timing/failure;
- proxy shutdown emits a `cache_session_summary` JSONL event with proxy, storage, OCI, singleflight, local-cache, and BuildKit sections;
- `ci/e2e/request-metrics-summary.py` promotes session summary fields, OCI upload-plan reuse counts, and new status snapshot keys into artifact env output;
- the OCI protocol tests cover the PostHog-shaped transition where a blob `HEAD` miss is followed by local upload, manifest publish, negative-cache invalidation, and a later successful `HEAD`.
- Docker adapter planning now carries provider-neutral CI run metadata into dry-run JSON and proxy metadata hints, including provider, run uid/attempt, ref type/name, default branch, PR number, commit SHA, immutable run ref, import refs, and promotion aliases when ADR 0007 derivation is active.
- startup prefetch download-url preload now has a startup-readiness retry policy while ordinary callers remain one-shot; focused tests cover the startup-only policy selection.

Remaining trace depth belongs in later passes: Rails p50/p95 rollups from request metrics, richer BuildKit enrichment from the action/harness, and release-path Docker E2E artifact validation.

## Proof Status

Documentation and the first CLI baseline are aligned as of 2026-04-21. The trace is accepted as the platform insight spine; backend persistence, Rails percentile rollups, action enrichment, benchmark artifact validation, and operator reporting remain follow-up work.

Focused CLI tests now cover negative-cache invalidation after local writes.

Release proof is partially updated. The 2026-04-21 `1.12.42` release-prep push at CLI commit `14c1dc2` exercised the then-current `origin/main` CLI path and passed CLI CI, but required registry E2E failed in `Registry / Docker BuildKit`, `Registry / Prefetch Smoke`, and `Cache Registry / Cross-Runner Verify`. The failure shape was consistent: published manifests/indices were visible, but verified blob download URL coverage was `0/N`, and downstream BuildKit/CAS reads returned missing blobs or `404`.

Follow-up commits changed that status:

- `6fa1a52` promotes successfully published owned upload-session bodies into the local blob cache for same-proxy readers.
- `c28a7c1` makes the cross-runner verifier wait through backend visibility lag.
- On the `c28a7c1` remote run, CLI CI passed and E2E proved `Registry / Docker BuildKit` plus `Cache Registry / Cross-Runner Verify`.

The remaining failed E2E leg is `Registry / Prefetch Smoke`. It stopped after the remote tag hit check because the tag-pointer helper did not expose a `cache_entry_id` for the published tag. Current CLI work adds startup download-url retry behavior, but that is not release evidence until the Prefetch Smoke harness reaches the convergence and fresh-cache prefetch phases and returns a green artifact.

The later proof bundle must attach:

- a metadata-only Docker E2E artifact containing `cache_session_summary`;
- promoted upload-plan fields including `request_metrics_oci_new_blob_count` and `request_metrics_oci_latest_new_blob_count`;
- status snapshots plus request metrics for phase-level debugging;
- a backend-visible or artifact-promoted summary that keeps Rails, storage, OCI, singleflight, local cache, and BuildKit sections distinct;
- evidence that confirmed OCI misses are cached briefly and invalidated by local writes/publish;
- examples where unknown BuildKit fields stay `unknown` instead of guessed.

## Incident Tracking: OCI `blob unknown` After Export-Time Misses

On 2026-04-21, a PostHog Docker benchmark using `boringcache/one@v1` failed during BuildKit cache export. BuildKit reached manifest commit, then the local registry proxy returned:

```text
PUT /v2/cache/manifests/buildcache -> 400 Bad Request
unknown: blob unknown to registry
```

The proxy log shape matters:

- startup used `OCI hydration: metadata-only`;
- startup indexed the selected `cache@buildcache` manifest and locators, but did not hydrate bodies eagerly;
- during export, BuildKit issued many `HEAD /v2/cache/blobs/<digest>` requests that returned `404 Not Found`;
- the final session summary showed OCI reads but `bytes_written=0 B`;
- manifest commit failed after the export-time `HEAD` misses instead of proving the referenced blobs through upload sessions, local body cache, or backend receipts.

This is a correctness issue until a clean local reproduction proves otherwise. The main suspected failure mode for ADR 0006 is a stale OCI negative-cache entry or locator miss surviving a local write/mount/publish transition:

```text
HEAD blob -> confirmed miss -> negative cache insert
same digest becomes locally present through upload or mounted/present blob proof
manifest PUT validates descriptors
validation still observes the stale miss
registry returns blob unknown
```

Release status as observed after follow-up work:

- `boringcache/one@v1` pointed at action release `v1.12.59`;
- `v1.12.59` pinned CLI release `v1.12.41`;
- CLI `origin/main` now includes OCI negative-cache tracing, invalidation work, borrowed upload-session bodies, owned upload-session body promotion into `BlobReadCache`, and fresh-runner backend visibility waiting;
- current local work adds startup download-url retry and Docker CI-derived run refs, but neither is represented by a CLI tag or released action until the next signed release;
- therefore the failed benchmark did not exercise the follow-up OCI fixes, and the incident is not cleared by any released path.

The required proof is a focused OCI protocol E2E plus release-path registry E2E, not a benchmark-only assertion:

1. create an OCI blob miss through `HEAD`;
2. make that same digest present through a proxy upload, mount, or present-blob proof;
3. publish a manifest referencing the digest;
4. assert manifest publish succeeds and the negative cache is invalidated;
5. assert diagnostics record the miss, invalidation source, upload proof source, and final manifest status.

The concurrent variant should run two same-tag writers against one proxy/backend root and prove that one writer's export-time `HEAD` miss cannot poison the other writer's later upload or manifest publish.

Do not classify this as runner noise. Until the protocol E2E, Prefetch Smoke, and release check are green, benchmark failures with `blob unknown` after export-time `HEAD` misses should be treated as OCI publish correctness failures.

## Acceptance Gates

Before claiming trace coverage:

- a metadata-only Docker E2E artifact contains the session summary;
- the summary distinguishes Rails p95, storage GET TTFB, storage body throughput, local cache hit bytes, and hydrate-then-serve wait;
- labeled proxy status snapshots remain available for phase-specific debugging;
- missing BuildKit enrichment is represented as `unknown`, not guessed.

Before enabling OCI negative cache by default:

- confirmed manifest/blob miss tests prove repeated concurrent probes avoid repeated backend work;
- upload finalize and manifest publish invalidate relevant misses;
- server errors and timeouts are not cached as misses;
- `fail_on_cache_error=true` behavior remains strict;
- cache miss diagnostics still report the original miss cause.

## Rejected Options

Do not replace detailed request metrics with only a session summary. The summary is for orientation; per-request JSONL remains the audit trail.

Do not cache OCI misses for long periods. BuildKit probes can race with writes in the same job, so negative cache TTLs must stay short and invalidation must be explicit.

Do not add adaptive concurrency before the session trace can say which pool is actually saturated.
