# ADR 0004: OCI Large Blob Stream-Through

Status: proposed
Date: 2026-04-20

## Context

The current OCI blob GET path is correct but pessimistic for large remote blobs.

When BuildKit asks for a blob that is not already local, the proxy:

1. resolves or refreshes a verified download URL;
2. downloads the full upstream body;
3. writes the body to a temp file;
4. hashes the full body;
5. validates digest and size;
6. promotes the temp file into `BlobReadCache`;
7. opens the cached handle;
8. serves the local file to BuildKit.

That gives a strong storage correctness story, but BuildKit does not receive the first byte until after the full remote download, local write, hash, promotion, and local reopen. For large Docker layers this can turn the proxy into a full pre-response hydration step even under the `metadata-only` product default.

OCI blobs are content-addressed. Clients such as BuildKit already expect blob digests to be verifiable. The proxy must still verify before storing anything locally, but it does not have to wait for verification before forwarding bytes to a client that requested a digest-addressed blob.

## Source Grounding

This ADR depends on these source-backed properties:

- OCI Distribution Spec says pulling centers on manifests plus blobs, and a successful blob `GET` returns the expected blob for `/v2/<name>/blobs/<digest>`.
- OCI blob responses include `Docker-Content-Digest`; if that header is used it must match the body, and clients should verify that the response body matches the requested digest.
- OCI registries should support `Range` requests for blobs, which is why the first stream-through pass must explicitly avoid changing existing partial-range semantics.
- OCI `HEAD` on a blob or manifest reports existence and size through `200 OK`, `Docker-Content-Digest`, and `Content-Length`, while a missing object is `404`.
- BuildKit's registry cache importer resolves a registry ref, creates a registry fetcher, and wraps that as a content provider. That means BoringCache's proxy should optimize normal OCI content delivery, not add a BuildKit-only transport.
- Docker documents registry cache as explicit `--cache-from` / `--cache-to` over a registry ref. Stream-through must remain compatible with ordinary registry clients, not just the benchmark harness.

Source URLs are listed in ADR 0003.

## Decision

Prototype a stream-through path for large OCI full-body `GET` requests.

For eligible blobs:

```text
Tigris/object storage -> proxy stream
                     -> BuildKit response body
                     -> temp file + SHA-256 hasher
```

At EOF:

```text
if digest and size match:
  promote temp file into BlobReadCache
  record stream-through success
else:
  delete temp file
  record verification failure
  fail the response stream before the final buffered chunk is delivered when possible
```

This is only for OCI digest-addressed blob bodies. It must not be reused for generic KV adapters whose object identity is not a cryptographic digest.

## Eligibility

The first implementation should be conservative.

Use stream-through only when all are true:

- method is `GET`;
- request is for an OCI blob digest;
- no local upload session or blob-read-cache hit exists;
- selected range is full-body, not partial;
- blob size is above a hidden threshold, initially around 32 MiB;
- stream-through is enabled by hidden engineering control or default-on only after benchmark proof;
- the proxy has a download URL or can resolve one before sending headers.

Keep the existing hydrate-then-serve path for:

- `HEAD`;
- small blobs;
- unsupported or invalid ranges;
- partial range requests in the first pass, because OCI Range support is a client-visible contract;
- cases where the upstream response cannot provide the expected body.

## Stream Semantics

Once response headers and body bytes are sent, the proxy cannot turn a digest mismatch into a clean OCI JSON error. To preserve a failure signal, the stream implementation should hold one chunk behind:

1. read chunk `N`;
2. write/hash chunk `N`;
3. yield previously buffered chunk `N - 1`;
4. after EOF, validate digest/size;
5. yield the final buffered chunk only if validation succeeds.

For large blobs this still gives early client TTFB while allowing digest mismatch to fail before a complete payload reaches the client. For very small blobs this one-chunk delay is not worth it, which is why stream-through is thresholded.

If an upstream transfer fails mid-stream, delete the temp file and fail the response stream. Do not retry mid-response on the same request after bytes have been sent. Let BuildKit retry the blob request.

If the upstream fails before any body chunk is emitted, the proxy may follow the existing retry policy before returning a response.

## Local Cache Promotion

Stream-through must never insert unverified bytes into `BlobReadCache`.

Promotion happens only after:

- actual digest equals requested digest;
- actual byte count equals descriptor size;
- temp file flush succeeds.

If promotion fails after a valid stream, the client response can still succeed, but the proxy records a cache-promotion failure and future requests may fetch remotely again.

## Singleflight Behavior

The first implementation does not need multi-cast streaming.

When a large remote blob is already being streamed by a leader request:

- the leader streams through to its client and spools/verifies;
- followers wait on the existing in-flight key;
- after leader promotion, followers serve from local cache;
- if leader fails, a follower may clear the flight and retry using existing takeover behavior.

Multi-cast streaming can be revisited only if follower wait metrics prove it matters.

## Metrics

Add enough metrics to compare the current path and stream-through path:

- `oci_blob_remote_ttfb_ms`;
- `oci_blob_client_first_byte_wait_ms`;
- `oci_blob_remote_body_ms`;
- `oci_blob_stream_through_count`;
- `oci_blob_stream_through_bytes`;
- `oci_blob_stream_verify_ms`;
- `oci_blob_stream_verify_failures`;
- `oci_blob_stream_cache_promote_failures`;
- `oci_blob_hydrate_then_serve_count`;
- `oci_blob_hydrate_then_serve_wait_ms`;
- `oci_blob_followers_wait_ms`;
- `oci_blob_singleflight_leaders`;
- `oci_blob_singleflight_followers`.

Exact names can change to match the current `OciEngineDiagnostics` style, but the dimensions must survive into status snapshots and E2E summaries.

## Implementation Plan

1. Add current-path metrics around `download_oci_blob_to_cache` and local reread.
2. Add a hidden threshold control, for example `BORINGCACHE_OCI_STREAM_THROUGH_MIN_BYTES`.
3. Add an internal stream helper in `serve::engines::oci::blobs` that owns upstream response streaming, tee-to-temp, hashing, verification, and promotion.
4. Wire only eligible full-body GET misses through the helper.
5. Preserve existing response headers: `Docker-Content-Digest`, digest `ETag`, `Content-Type`, `Content-Length`, `Accept-Ranges`, and distribution API version.
6. Add unit tests for threshold selection, final-chunk verification failure, temp cleanup, and non-eligible fallback.
7. Add an integration/E2E comparison for metadata-only Docker warm/reseed behavior.

## Acceptance Gates

Before enabling by default:

- existing OCI blob GET, HEAD, range, invalid range, digest mismatch, and retry tests pass;
- BuildKit registry E2E passes under default metadata-only behavior;
- stream-through artifacts show lower client first-byte wait for large remote blobs;
- digest mismatch does not populate local cache;
- mid-stream upstream failure does not populate local cache;
- follower requests remain correct under concurrent same-digest GETs;
- real-project benchmark separates BuildKit rebuild/export time from proxy body wait.

## Non-Goals

Do not implement an edge cache or remote proxy fleet.

Do not change manifest publish semantics.

Do not stream-through non-OCI KV adapter objects.

Do not implement partial-range upstream streaming in the first pass. Full-object stream-through is enough to prove or reject the main hypothesis.
