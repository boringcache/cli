# ADR 0002: Proxy Engine Plan B From Adapter Sources

Status: proposed
Date: 2026-04-20

## Context

ADR 0001 accepted an engine boundary before any snapshot-v2 rewrite. This plan is the fallback plan if the current proxy shape proves too tangled to evolve safely in place.

The rule for this plan is stricter than "trust the current proxy": trust the adapter's own protocol source first, then use BoringCache code and incidents only as evidence of where the product currently violates or obscures that source.

Primary sources:

- OCI Distribution Spec: https://github.com/opencontainers/distribution-spec/blob/main/spec.md
- OCI Image Manifest Spec: https://github.com/opencontainers/image-spec/blob/main/manifest.md
- Docker registry cache backend: https://docs.docker.com/build/cache/backends/registry/
- Bazel remote caching: https://bazel.build/remote/caching
- Gradle HTTP build cache: https://docs.gradle.org/current/userguide/build_cache.html
- Apache Maven Build Cache Extension remote cache: https://maven.apache.org/extensions/maven-build-cache-extension/remote-cache.html
- Turborepo Remote Cache API: https://turborepo.dev/docs/openapi
- Nx custom remote cache OpenAPI: https://nx.dev/docs/guides/tasks--caching/self-hosted-caching
- Go GOCACHEPROG source protocol: https://tip.golang.org/src/cmd/go/internal/cacheprog/cacheprog.go
- sccache WebDAV configuration: https://docs.rs/crate/sccache/latest/source/docs/Configuration.md

## Decision

Keep public UX stable and rewrite internally adapter by adapter behind an explicit engine boundary.

Do not start from the existing proxy as the contract. Start from each adapter's source protocol and make the implementation prove these questions:

- What is the protocol root, object, alias, session, and receipt?
- Which request methods are legal?
- What does a hit mean?
- What does a miss mean?
- Which writes are allowed under read-only or restore-only product modes?
- What local client retry/cache behavior must BoringCache tolerate?
- Which diagnostics prove the adapter behaved according to its own source?

The proxy route layer should parse HTTP or subprocess requests and call an engine. It should not decide protocol correctness, publish safety, or alias visibility.

## Adapter Order

1. OCI/BuildKit registry cache.
2. sccache/WebDAV.
3. Bazel AC/CAS.
4. Gradle and Maven HTTP object caches.
5. Turborepo and Nx remote cache APIs.
6. Go GOCACHEPROG.
7. Generic filesystem snapshot-v2 only after native adapter behavior is boring.

OCI goes first because it is the only current adapter where manifest graphs, blob bodies, local read-through, upload sessions, backend receipt state, and mutable aliases all meet in one request path.

## OCI First-Principles Contract

From the OCI Distribution Spec:

- Pull is manifest plus blobs.
- Push uploads blobs first and manifest last.
- A registry may reject a manifest whose non-subject descriptors reference missing blobs or manifests, and the rejection is `MANIFEST_BLOB_UNKNOWN`.
- Blob upload is session-shaped: start, append or monolithic body, close with the whole-blob digest.
- Out-of-order chunk writes are `416`.
- Cross-repository mount is optional: `201` means mounted; `202` means the client should upload.
- Referrers are a first-class content-discovery endpoint in OCI 1.1.

From the OCI Image Spec:

- `config`, `layers`, and index `manifests` entries are descriptors.
- `subject` is a weak association for referrers, not proof that the subject already exists.
- Unknown media types are not a reason by themselves to reject a descriptor graph.

From Docker/BuildKit docs:

- Registry cache is separate from the final image.
- Import/export are explicit through `--cache-from` and `--cache-to`.
- `mode=max` can include intermediate-stage cache records, so a warm hit must prove body availability, not only top-level manifest visibility.

## OCI Implementation Shape

Create an `OciEngine` in increments rather than one branch:

- `route`: parse registry paths into typed requests.
- `uploads`: upload sessions, offsets, digest finalize, mount result semantics.
- `present_blobs`: descriptor availability proof before manifest publish.
- `manifests`: content type, digest, descriptor traversal, manifest cache.
- `blobs`: local body cache, read-through, HEAD/GET semantics.
- `publish`: BoringCache save, blob upload receipts, pointer upload, confirm, aliases.
- `referrers`: subject descriptor index and filter response.
- `diagnostics`: source proof, miss cause, publish timing, hydration policy, local vs remote body bytes.

The first implementation invariant is:

> No manifest publish unless every non-subject descriptor is present through a named source.

Allowed sources:

- finalized upload session for this repository/ref transaction;
- successful local mount session;
- staged child manifest session;
- local body cache materialized into an upload session;
- backend-confirmed storage-visible blob.

If a descriptor is not proven through one of those sources, the engine must return an OCI-shaped missing-blob error and not call BoringCache publish.

## Web Contract

Rails remains the source of backend truth. The CLI can stage, upload, and diagnose, but it must not infer successful publish from a generic 500, 422, or tag UI row.

The web API must remain able to answer these states for OCI publish:

- save entry created;
- upload session opened;
- blob upload URL issued;
- blob receipt committed;
- manifest pointer uploaded;
- manifest receipt committed;
- cache entry confirmed;
- alias bound;
- publish abandoned.

This ADR does not require a web API change for the first CLI increment. If a later OCI increment needs finer remote-visible state than `check_blobs_verified`, update the web contract and web comprehension map in the same change.

## Acceptance Gates

Before replacing an adapter path:

- Its row exists in `docs/adapter-contract-matrix.md`.
- Its recent mistakes are captured in `docs/oci-mistake-ledger.md` or an adapter-specific ledger.
- Tests cover the official success and miss status codes.
- Diagnostics include the source of every cache hit and the reason for every important miss.

For OCI specifically:

- Upload start, PATCH, closing PUT, stale range `416`, cross-repo mount `201/202`, HEAD/GET, missing manifest blobs, digest refs, and referrers are covered.
- BuildKit E2E proves cold, warm, restart, metadata-only, bodies-before-ready, bodies-background, and random-body graph behavior.
- Manifest publish refuses descriptors that cannot be traced to a named source.
- Blob body locality is measured separately from manifest/index locality.

## Non-Goals

- Do not replace all adapters with archive mode.
- Do not change `cache-registry`, `boringcache docker`, `one@v1`, token split, or tag naming just to make the internals cleaner.
- Do not add new required user ceremony for OCI cache correctness.
- Do not make snapshot-v2 the answer to protocol-native cache behavior.
