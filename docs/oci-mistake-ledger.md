# OCI Mistake Ledger

This ledger captures recent OCI/BuildKit failure classes as implementation guardrails. The source column is the authority; local incidents only explain why the guardrail exists.

| Failure class | False assumption | Source-backed invariant | Owning layer | Guardrail test | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Manifest hit without blob-body locality | A manifest/index hit is enough for BuildKit to be warm | OCI pull is manifest plus blobs; Docker registry cache can include intermediate layers in `mode=max` | OCI engine blob/read-through and hydration policy | Cold/warm/restart BuildKit E2E separates manifest hit, local body hit, and remote body fetch | Remote storage latency can still make first read slow under metadata-only |
| Manifest publish with unproven descriptors | If the manifest JSON is valid, publish can proceed | OCI push uploads blobs before manifest; registries may reject manifests whose non-subject descriptors are missing | OCI present-blob proof before publish | Unit test refuses manifest PUT when descriptor is neither uploaded, locally staged, locally cached, nor remote-visible | Backend `check_blobs_verified` must mean storage-visible, not merely staged |
| Cross-repo mount treated as a no-op | `201 Created` for `mount=` does not need a local publish session | OCI mount success means the blob is usable in the target repo; BoringCache still needs upload/receipt state if backend lacks it | OCI uploads/mount handling | Mount from local/prefetched blob creates a finalized target upload session | Remote-only mount still depends on backend visibility proof during manifest PUT |
| Empty finalize accepted blindly | Empty closing PUT can mean the client already uploaded the blob elsewhere | Closing PUT digest is the digest of the whole blob; empty body is valid only if the digest is already present through another source | OCI uploads/finalize | Empty finalize reuses local/remote source or returns digest error | Concurrent client behavior can race; retry window must remain bounded |
| Child manifests treated as ordinary blobs | Every `manifests[]` descriptor is a layer blob | OCI image index points at child manifests; non-manifest descriptors can appear in BuildKit cache indexes | OCI manifest descriptor traversal | Child manifest descriptors are loaded and expanded; non-manifest entries are not recursively parsed | Unknown BuildKit media types should stay non-fatal unless descriptor graph is impossible |
| Referrers inferred from tags only | Subject relationships can be represented only by mutable tags | OCI 1.1 defines referrers for subject relationships; `subject` can be pushed before the subject exists | OCI referrers handling | Subject manifest PUT updates referrers index and `GET /referrers/<digest>` returns an index response | Concurrency can lose referrers without optimistic merge on backend aliases |
| Startup hydration as generic readiness | All adapters need full body hydration before proxy readiness | OCI body hydration is specific to registry cache behavior; other adapters have their own read path | Runtime readiness plus OciEngine diagnostics | Readiness endpoint reports metadata-only vs body hydration policy and cold body counts | Large caches may still choose metadata-only for startup latency |

## Next Ledger Updates

Add one row for every future OCI fix before or with the code change. A row should name the official source, the corrected invariant, the test that prevents regression, and whether the risk is CLI, web, action, or user workflow.

## Research Sources For Active OCI Work

Use the official sources for every OCI engine change:

- OCI Distribution Spec for registry endpoints, push/pull order, upload sessions, mount semantics, error codes, HEAD behavior, and referrers fallback.
- OCI Image Spec for descriptor graph shape, config descriptors, layer descriptors, image indexes, artifact manifests, and subject relationships.
- Docker BuildKit registry cache docs for the product path: `--cache-to type=registry`, `--cache-from type=registry`, `mode=min|max`, OCI media types, image manifest/index output, and cache refs separated from final image refs.

Do not treat the existing handler layout as an authority. It is only evidence of current behavior.
