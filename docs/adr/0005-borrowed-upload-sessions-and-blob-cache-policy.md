# ADR 0005: Borrowed Upload Sessions And Blob Cache Policy

Status: accepted for hidden implementation; cache-policy rollout pending benchmark proof
Date: 2026-04-20

## Context

The OCI engine now proves manifest descriptors through named sources:

- upload session;
- mounted session;
- manifest-reference session;
- local body cache;
- remote storage.

When a descriptor is proven by the local blob read cache, the current implementation materializes that `BlobReadHandle` into a new upload-session temp file before publish can upload it. Mounted blob reuse follows the same pattern when the source is an existing cached body. Both paths copy bytes and call `sync_data`.

This is safe but can be expensive for large Docker layers, especially because `BlobReadCache` can store data as an offset inside a segment file. Copying a segment slice into another temp file loses the value of the segment cache and adds disk traffic before upload planning even knows whether Rails/Tigris needs that blob uploaded.

## Source Grounding

This ADR depends on these source-backed properties:

- OCI push uploads blob content before manifest publish, and a registry may reject a manifest when referenced non-subject descriptors are missing.
- OCI upload sessions are explicit: clients start an upload, optionally append chunks, then close with a digest for the whole blob. Out-of-order chunks must be rejected with `416`.
- OCI cross-repository mount may complete with `201` or fall back to `202` so the client uploads. That maps cleanly to proof sessions that either have local bytes or require upload.
- OCI monolithic blob upload requires the digest and content length to match the actual payload. Borrowed bodies must therefore carry digest, offset, and size explicitly.
- BuildKit registry cache export uses normal registry push/pusher plumbing. If Rails asks the proxy to upload a blob, the upload source can be a verified local cache handle as long as the bytes streamed to storage match the descriptor.

Source URLs are listed in ADR 0003.

## Decision

Teach upload sessions and publish upload jobs to reference verified cached blob bodies without copying them.

Introduce an upload-session body model:

```rust
enum UploadSessionBody {
    OwnedTempFile {
        path: PathBuf,
    },
    BorrowedBlobRead {
        lease: BlobReadLease,
        digest: String,
        size_bytes: u64,
    },
}
```

The exact type names can change, but the behavior must be explicit:

- owned temp sessions are mutable and cleaned up by deleting their temp file;
- borrowed blob-read sessions are finalized, read-only proof sessions;
- cleanup of a borrowed session releases the cache lease and does not delete the borrowed cache file;
- upload jobs can stream from `path + offset + size`, not only from a standalone temp file.

## Scope

The first implementation should borrow only from `BlobReadCache` handles. Keep ordinary client upload sessions as owned temp files.

Do not borrow from one mutable client upload session into another session in the first pass. That requires shared ownership and cleanup semantics that are not needed to remove the current large local body-cache copy.

Internal sessions that may become borrowed:

- `oci-local-body-*` sessions created for local body-cache proofs;
- `oci-mount-*` sessions when the mount source is a `BlobReadCache` handle;
- future manifest-reference sessions if they prove a cached body and need local bytes.

## Web API Ownership

This ADR owns CLI/proxy local body-source behavior. If Rails later accepts "already verified/present" proofs, idempotent upload intents, richer blob states, or object-store conditional-write policy, the canonical API decision lives in:

- `web/docs/adr/0001-cache-control-plane-roots-aliases-and-session-insight.md`

Do not let this CLI ADR become the source of truth for Rails upload-session schema or blob state transitions.

## Cache Lease Requirement

A borrowed body must not point at data that can be evicted before upload finishes.

Add a lease or pin API to `BlobReadCache`:

```rust
struct BlobReadLease {
    handle: BlobReadHandle,
}
```

While a lease exists:

- legacy-file entries for that digest are not removed;
- segment files containing that digest are not removed;
- eviction can skip pinned entries or pinned segments;
- cleanup releases the pin.

If this is too much for the first patch, do not borrow. A borrowed path without eviction protection is not acceptable.

## Upload Job Changes

`TrackedBlobUploadJob` should carry a body source instead of only a temp path:

```rust
enum BlobUploadSource {
    File {
        path: PathBuf,
        offset: u64,
        size_bytes: u64,
    },
}
```

The upload transport should read only `size_bytes` from `offset`. This preserves support for segment-backed cached blobs.

The publish path must continue to reject upload requests when the proof source has no local bytes. A `remote-storage` proof can satisfy manifest publish, but if Rails later requests an upload URL for that digest, that proof is insufficient unless local bytes are available.

## Metrics

Before and after the behavior change, record:

- upload-session materialization count;
- upload-session materialization bytes;
- materialization copy duration;
- materialization sync duration;
- borrowed upload-session count;
- borrowed upload-session bytes;
- borrowed lease wait/failure count;
- upload bytes read from owned temp file;
- upload bytes read from borrowed cache handle.

These metrics should make it clear whether the change removes material local disk traffic in Docker warm/reseed runs.

## Blob Cache Policy

Do not combine borrowed sessions with a major cache admission rewrite in the same patch. First remove the avoidable copy while preserving current cache behavior.

After metrics exist, tune cache policy by object class:

- manifest/index/config-sized objects should stay cheap to cache;
- small and medium blobs can keep default admission;
- large blobs should be admitted only when the local-cache hit rate or same-job reuse justifies the disk write;
- stream-through reads from ADR 0004 may choose to delete the temp file after serving if policy says not to admit;
- pinned entries used by borrowed sessions must outlive the upload job even if they exceed ordinary eviction budget.

Required policy metrics:

- local cache hit bytes;
- local cache miss bytes;
- bytes written to local cache;
- bytes evicted before reuse;
- large blob local hit count and bytes;
- large blob write bytes;
- pinned bytes and pin duration.

## Implementation Plan

1. Add materialization metrics to the existing copy paths.
2. Add `UploadSessionBody` while keeping existing owned-temp behavior.
3. Add `BlobReadCache` lease/pin support and eviction tests.
4. Convert local body-cache proof sessions to borrowed read handles.
5. Convert mount reuse from `BlobReadCache` handles to borrowed read handles.
6. Change upload job selection and upload transport to read from offset-limited sources.
7. Keep remote-storage proof behavior unchanged.
8. Add cache policy metrics.
9. Tune large-blob admission only after benchmark data shows the right threshold.

## Implementation Progress

The first borrowed-session slice is implemented.

Current behavior:

- `UploadSession` now has an explicit body source: owned temp file or borrowed `BlobReadCache` lease;
- local body-cache proof sessions borrow verified blob-cache handles instead of copying into a fresh temp upload file;
- cross-repository mount reuse borrows from `BlobReadCache` when the source is a verified cached body;
- mount reuse from an existing mutable upload session still materializes a separate owned temp file;
- borrowed cleanup drops the lease and does not delete the cache file;
- owned cleanup still deletes the owned temp file;
- after a successful OCI manifest publish, owned upload-session bodies are promoted into `BlobReadCache` before session cleanup, so immediate same-proxy BuildKit readers can use local digest-verified bodies without waiting for backend download-url verification;
- `BlobReadCache` leases pin legacy files and segment files against eviction while borrowed sessions or upload jobs reference them;
- tracked blob upload jobs now read from `path + offset + size`, so segment-backed cache bodies can upload without materializing a standalone file;
- the single-URL upload transport can seek to an offset and stream exactly the requested byte count;
- materialization count, byte, copy-duration, sync-duration, borrowed-session count, and borrowed-session byte metrics are exposed through `OciEngineDiagnostics`.

Intentionally not changed yet:

- mutable upload sessions are not borrowed into other sessions;
- large-blob admission and eviction policy are not tuned;
- borrowed-session behavior does not assume a specific storage provider or CI provider.

## Proof Status

Documentation and the first borrowed-session implementation slice are aligned as of 2026-04-21. The borrowed proof-session model is accepted; cache admission and eviction policy changes remain proof-gated.

Evidence now available:

- unit tests cover borrowed cleanup, segment-backed offset upload sources, and lease-protected eviction;
- `published_owned_upload_session_is_promoted_to_body_cache` proves successful owned upload-session bodies move into `BlobReadCache` during manifest-publish cleanup, so same-proxy readers can use local digest-verified bodies while backend download URLs settle;
- the Rails-backed local Docker BuildKit E2E passed against a managed workspace provisioned through Rails/Tigris;
- that E2E recorded borrowed upload-session counters in status snapshots and session summaries, including `oci_engine_borrowed_upload_session_count=9` and `oci_engine_borrowed_upload_session_bytes=6430` by the alias-warm status snapshot.

Release-path proof is partially complete. The 2026-04-21 `1.12.42` push at CLI commit `14c1dc2` passed CLI CI but failed required registry E2E legs with manifests/indices visible before all referenced blobs had verified download URLs. Follow-up commit `6fa1a52` promoted owned upload-session bodies into the local blob cache for same-proxy readers.

The follow-up direction is not to add publish-readiness polling. Rails is meant to trust completed upload-session receipts on the hot path: blob receipt commit marks blobs storage-verified, manifest receipt commit links attested blobs and marks the CAS entry storage-verified, and tag publish stays optimistic. If receipt commit fails, the proxy should fail the publish/export instead of publishing a root that depends on the async verifier before fresh readers can fetch bodies. Retries for request timeouts, transient network failures, or stale download URLs remain normal read/transport retry behavior; they are not server-side publish-readiness polling.

Current remote evidence after `c28a7c1`:

- CLI CI passed.
- `Registry / Docker BuildKit` passed, so the same-proxy Docker half now has release-path E2E evidence.
- `Cache Registry / Cross-Runner Verify` passed, but the verifier-level blob URL convergence loop from that commit is not the product contract and is being removed.
- The overall E2E workflow still failed in `Registry / Prefetch Smoke`: `boringcache check` reported the tag hit, but the tag-pointer helper did not expose a `cache_entry_id` before the added convergence check. The real gate is a fresh-cache prefetch/read proof without a post-publish blob URL readiness sleep.

That means the borrowed-session fix has meaningful same-proxy evidence, but full registry release proof remains blocked until the required E2E workflow is green without publish-readiness polling.

Benchmark proof and policy proof are still pending before cache admission changes. The later proof bundle must attach:

- Docker registry publish evidence that borrowed sessions remove materialization copy/sync bytes for cached bodies on a large-layer workload;
- eviction/pin evidence showing borrowed legacy-file and segment-backed cache bodies cannot disappear while referenced;
- tracked upload evidence showing `path + offset + size` reads the exact descriptor bytes;
- session summary fields for materialization count/bytes/duration, borrowed count/bytes, pinned bytes, and upload bytes by source;
- before/after artifacts that keep stream-through effects separate from cache-admission effects.

## Acceptance Gates

Before merging borrowed sessions:

- upload start, PATCH, final PUT, empty finalize reuse, mount, manifest publish, and tracked blob upload tests pass;
- borrowed cached blobs cannot be evicted while referenced;
- cleanup deletes owned temp files and does not delete borrowed cache files;
- upload transport reads the correct offset and byte count from segment-backed handles;
- digest and size checks remain enforced before upload jobs are created;
- Docker BuildKit E2E remains green.

Before changing cache admission:

- traces show large-blob cache write cost and reuse rate;
- stream-through behavior from ADR 0004, if enabled, is measured separately from cache admission changes;
- cache-policy changes do not hide cold remote reads in benchmark artifacts.

## Rejected Options

Do not keep copying large cached blobs into upload sessions as the long-term model. It is correct but wasteful.

Do not borrow cache files without a pin or lease. Eviction safety matters more than avoiding the copy.

Do not make the first implementation borrow arbitrary mutable upload temp files. Start with verified, finalized blob-read-cache handles.

Do not tune Docker large-blob cache admission before the metrics can prove whether large blobs are reused inside one job.
