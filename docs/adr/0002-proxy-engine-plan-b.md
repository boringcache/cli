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
- BuildKit registry cache source: https://github.com/moby/buildkit/blob/d787da7fa4a8655ce2aa6657ef65707379710f8f/cache/remotecache/registry/registry.go
- BuildKit GitHub Actions cache source: https://github.com/moby/buildkit/blob/d787da7fa4a8655ce2aa6657ef65707379710f8f/cache/remotecache/gha/gha.go
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

## Research Discipline

Each adapter rewrite starts with the primary source for that adapter, not with the current BoringCache implementation:

1. Read the official protocol or tool documentation and update `docs/adapter-contract-matrix.md`.
2. Capture recent local failure modes in an adapter mistake ledger.
3. Write the engine acceptance list from source-backed success, miss, and error behavior.
4. Only then move code behind the engine boundary.
5. Keep benchmarks and diagnostics tied to the source-backed contract, not to incidental current behavior.

For OCI, the controlling sources are the OCI Distribution Spec, OCI Image Spec, and Docker BuildKit registry cache documentation. BuildKit registry cache is the product path we optimize first, so the registry engine must behave like a real OCI registry for the subset BuildKit uses: manifest graphs, blob bodies, upload sessions, cross-repository mount, referrers, digest references, and cache-image import/export refs.

For later adapters, repeat the same discipline. sccache is WebDAV first, Bazel is AC/CAS first, Gradle and Maven are HTTP object-cache first, Turbo and Nx are their own APIs first, and Go cacheprog is subprocess JSON first.

## Source Examples

Each adapter rewrite must name at least one production-grade open-source or standard industry implementation before moving code. The point is not to copy architecture; it is to catch performance and compatibility expectations that specs often leave implicit.

For OCI, the active comparison set is BuildKit's registry cache backend and GitHub Actions cache backend. The registry backend delegates to containerd distribution resolver, fetcher, pusher, and content-store utilities instead of inventing a custom registry protocol. The GHA backend makes cache existence, mutable indexes, timeouts, and parallel scope loading explicit. BoringCache should preserve the same broad properties: digest-addressed content, resumable upload/session behavior, bounded network waits, pooled transfers, and fast metadata decisions before body movement.

For later adapters, add the concrete comparison in `docs/adapter-contract-matrix.md` before implementation. Candidates include the tool's own server/client source, BuildBuddy-style Bazel AC/CAS behavior, Develocity-style Gradle cache behavior, official Turbo/Nx remote-cache APIs, and sccache's native backend sources.

## Engine Boundary Rule

Move all OCI protocol semantics and hot-path decisions into `src/serve/engines/oci`. Do not move generic runtime plumbing just to make the tree look pure.

Belongs in the OCI engine:

- registry request object model and typed operations;
- upload session state machine, range validation, digest finalize, empty finalize reuse, and mount `201`/`202` semantics;
- manifest content-type rules, descriptor extraction, child manifest traversal, digest-reference validation, referrers index behavior, and missing-descriptor errors;
- blob HEAD/GET locality, body cache, read-through, remote URL refresh, range behavior, and digest/size proof;
- publish plan construction: save, blob upload selection from `PresentBlob`, pointer upload, confirm, alias/referrer publish, and cleanup;
- OCI diagnostics: proof sources, local vs remote body bytes, graph expansion, publish timings, miss causes, and hydration policy.

Stays shared outside the OCI engine:

- auth and token handling;
- server runtime, listener, readiness, shutdown, and maintenance loops;
- tag resolver and registry-root derivation where it is not protocol-specific;
- BoringCache API client DTOs and transport;
- transfer client, upload URL calls, receipt commit helpers, and observability primitives;
- generic HTTP routing glue that turns Axum requests and responses into typed engine calls.

The end state is not "some OCI helpers in an engine". The end state is "handlers are glue; the OCI engine owns OCI truth". The migration stays incremental so every step remains testable.

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

- `route`: parse registry paths into typed requests without deciding protocol truth.
- `uploads`: upload sessions, offsets, digest finalize, empty finalize reuse, mount result semantics.
- `present_blobs`: descriptor availability proof before manifest publish.
- `manifests`: content type, digest, descriptor traversal, child expansion, manifest cache.
- `blobs`: local body cache, read-through, HEAD/GET semantics, range/digest/size proof.
- `publish`: BoringCache save, blob upload selection, blob receipts, pointer upload, confirm, aliases.
- `referrers`: subject descriptor index, fallback tag shape, and filter response.
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

## OCI Step Plan

The OCI pass should land in small commits in this order:

1. Source-proof boundary: `PresentBlob` proves every descriptor and drives upload job selection. Done in the first increment.
2. Upload engine: move start upload, PATCH, close PUT, empty finalize reuse, cross-repository mount, and `416` behavior from handlers into `serve::engines::oci::uploads`. Done in the second increment.
3. OCI/KV path audit: before moving manifests, list every `cache_registry/kv` path touched by OCI and decide whether it is protocol-neutral substrate or OCI manifest-graph behavior that belongs in the engine.
4. Manifest engine: move descriptor extraction, content-type resolution, child manifest expansion, digest references, referrers descriptor construction, and missing-descriptor errors into `serve::engines::oci::manifests`.
5. Blob engine: move HEAD/GET locality, blob body cache reads, remote URL refresh, range handling, and digest/size verification into `serve::engines::oci::blobs`.
6. Publish engine: move save/pointer/confirm/alias/referrer orchestration into `serve::engines::oci::publish`, with handlers only parsing request bodies and returning responses.
7. Diagnostics: add an `OciEngineDiagnostics` value with proof source counts, local vs remote reads, graph expansion count, publish timings, miss causes, and hydration state.
8. BuildKit acceptance: run cold, warm, proxy restart, default strict body hydration, hidden metadata-only/background controls, and random body graph registry E2E.
9. Backend contract check: touch Rails only if the BuildKit E2E proves the CLI needs backend-visible truth stronger than `check_blobs_verified`.

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
- All applicable rows in `docs/adapter-contract-matrix.md#known-rewrite-findings` are closed by tests/code or named as residual risk in the handoff.
- Its recent mistakes are captured in `docs/oci-mistake-ledger.md` or an adapter-specific ledger.
- Tests cover the official success and miss status codes.
- Diagnostics include the source of every cache hit and the reason for every important miss.

For OCI specifically:

- Upload start, PATCH, closing PUT, stale range `416`, cross-repo mount `201/202`, HEAD/GET, missing manifest blobs, digest refs, and referrers are covered.
- Upload range parsing accepts the client spellings BoringCache supports, including Docker-style bare upload ranges and RFC-style `bytes=` byte ranges, while still enforcing exact offsets.
- OCI responses that represent immutable digest-addressed content include digest-valued `ETag` headers.
- Upload digest verification hashes streaming request bodies on one-shot paths and only rereads files when resumable state makes that necessary.
- Transfer clients keep HTTP/2 pooling and adaptive windows on by default; any change to pool sizing or protocol fallback must be benchmarked against BuildKit cache import/export.
- Blob engine extraction must add ranged `GET` acceptance before claiming full blob-path parity.
- BuildKit E2E proves cold, warm, restart, default strict body hydration, hidden metadata-only/background controls, and random-body graph behavior.
- Manifest publish refuses descriptors that cannot be traced to a named source.
- Blob body locality is measured separately from manifest/index locality.
- Generic KV code remains substrate only; OCI manifest graphs, upload sessions, range behavior, referrers, and digest response semantics move into `serve::engines::oci`.

## Non-Goals

- Do not replace all adapters with archive mode.
- Do not change `cache-registry`, `boringcache docker`, `one@v1`, token split, or tag naming just to make the internals cleaner.
- Do not add new required user ceremony for OCI cache correctness.
- Do not make snapshot-v2 the answer to protocol-native cache behavior.
