# ADR 0001: Engine Boundary Before Snapshot V2

Status: accepted; superseded in part by ADR 0002 for native adapter shape
Date: 2026-04-19

2026-04-20 amendment: this ADR still stands for "do not let snapshot-v2 become a product rewrite." It no longer requires a universal engine trait across archive, OCI, Bazel, Turbo, Nx, sccache, and other native adapters. ADR 0002 is the controlling plan for adapter rewrites: keep adapter engines native and standardize the backend/session/data-plane contracts they use.

## Context

BoringCache now has more than one cache shape:

- archive save/restore for ordinary filesystem directories;
- file-CAS and OCI-CAS flows that already use missing-object checks, upload receipts, and pointer publish;
- proxy/native adapters for OCI/BuildKit, Bazel, sccache/WebDAV, Turbo, Nx, Gradle, Maven, and Go;
- `one@v1`, `.boringcache.toml`, split restore/save/admin tokens, and standalone benchmark repos as the public product surface.

Recent Docker work showed that protocol-native behavior matters. A BuildKit registry cache hit is not just a manifest hit: BuildKit also needs blob bodies. `metadata-only`, `bodies-before-ready`, and `bodies-background` are OCI-specific body-plane policies, not generic filesystem snapshot behavior.

The generic archive path still pays full tree scan, full manifest build, tar creation, upload, download, and extraction costs. That is a real roadmap problem for low-churn generic caches, but it is separate from Docker/OCI parity and should not force a product restart.

## Decision

Add an explicit internal engine boundary before any snapshot-v2 rewrite or Rust crate split.

The public product surface stays stable:

- `boringcache run`, `save`, `restore`, `cache-registry`, and adapter commands remain the front doors;
- `one@v1` remains the main GitHub Actions entrypoint;
- repo config and split-token trust semantics remain intact;
- native protocols stay native instead of being routed through archive mode.

The first boundary should model engines around behavior, not storage implementation names:

- `ArchiveV1Engine` for current generic filesystem cache compatibility;
- `SnapshotV2Engine` later for the new generic filesystem engine;
- `OciEngine` for registry/BuildKit manifest and blob graphs;
- `FileCasEngine` for file-CAS layouts;
- `BazelEngine` for AC/CAS semantics;
- `WebdavEngine` for sccache-style object protocols;
- `TurboEngine`, `NxEngine`, `GradleEngine`, `MavenEngine`, and `GoCacheEngine` for their native adapter surfaces where a dedicated engine boundary pays for itself.

Shared model terms:

- object: immutable bytes addressed by digest or protocol key;
- root: immutable snapshot or protocol graph root;
- alias: mutable human tag/ref pointing at a root;
- session: save/restore/proxy transaction state;
- receipt: proof that object, manifest, or pointer work was uploaded and committed;
- pack: future storage format for small-object compaction, not a requirement for the first boundary.

## Required Boundary Shape

The boundary should keep CLI/action orchestration thin without forcing every cache type into archive-shaped `save` and `restore` methods.

The stable boundary is the platform contract:

```text
native adapter engine
    -> shared Rails metadata/session APIs
    -> direct object transfer client
    -> shared telemetry and receipts
```

Each adapter may expose its own native operations internally. OCI speaks registry manifest/blob/upload/referrer operations. Bazel should preserve AC/CAS operations. Turbo and Nx should preserve their HTTP remote-cache APIs. sccache/WebDAV should preserve object-key behavior. Generic directory cache engines can still expose restore/save plans because that is their natural shape.

A thin operational shell can exist for process orchestration:

```rust
trait Mode {
    fn prepare(&self) -> Result<()>;
    fn run(&self) -> Result<()>;
    fn finalize(&self) -> Result<()>;
}
```

That shell must not become the storage abstraction. In particular, do not require native adapters to implement a generic `save(paths)` / `restore(paths)` engine API.

Every engine must report diagnostics that can explain misses and latency:

- input root/ref/tag and effective tag;
- local hit count and remote fetch count;
- bytes read and written locally/remotely;
- request count and retry count;
- publish/finalize/receipt timing;
- protocol-specific import/export wall time where applicable.

For OCI/BuildKit specifically, diagnostics must include:

- manifest/index import time;
- cache export time;
- local body hits;
- remote body fetches;
- remote bytes and remote duration;
- startup OCI bodies inserted, cold, failed, and duration;
- hydration policy used for selected refs.

## Consequences

Snapshot-v2 becomes an incremental engine under the existing product, not a rewrite of the whole CLI.

Archive-v1 remains the compatibility path until snapshot-v2 beats it on measured generic filesystem workloads.

OCI, Bazel, sccache, Turbo, Nx, Gradle, Maven, and Go keep their native protocol identity. Their correctness and performance should be evaluated at their protocol boundary, not by forcing them through a filesystem snapshot abstraction.

The benchmark harnesses remain valid acceptance tests. They should grow better diagnostics and churn scenarios instead of changing shape.

## Migration Plan

1. Keep adapter engines native; do not pause OCI, Bazel, Turbo, Nx, or sccache work for a grand unified engine abstraction.
2. Move duplicated Rails/Tigris/session/publish/receipt code into shared platform helpers only when the behavior is protocol-neutral.
3. For OCI, keep moving registry truth out of HTTP handlers and KV-named helpers into `serve::engines::oci`, following ADR 0002.
4. Add comparable telemetry across adapters: hit type, miss reason, local/remote bytes, upload/download counts, retry counts, and publish/finalize timings.
5. Keep archive-v1 as the generic directory compatibility engine.
6. Build snapshot-v2 as a later generic directory engine only after low-churn benchmarks prove it is worth switching.

## Acceptance Gates

No snapshot-v2 default switch until:

- archive-v1 compatibility tests still pass;
- snapshot-v2 beats archive-v1 on 0%, 1%, and 5% churn generic filesystem workloads;
- native adapter tests prove command injection, route detection, protocol materialization or round-trip behavior, and remote tag visibility;
- Docker/OCI benchmarks show manifest graph hits and blob-body locality separately;
- diagnostics explain every important warm miss without log archaeology.

No crate/workspace split until:

- the engine boundary is merged;
- module ownership is documented in `.comprehension`;
- tests cover each engine at the behavior boundary.

## Rejected Options

Do not rewrite the whole product around snapshot-v2. The current public surface is good, and Docker/OCI issues were protocol/body-plane issues, not proof that every adapter should become a filesystem snapshot.

Do not make archive tarballs the canonical truth with CAS as an optimization. CAS/session/receipt flows already represent the better long-term shape.

Do not force native remote-cache tools through archive mode. Bazel AC/CAS, OCI registry cache, sccache WebDAV, Turbo/Nx remote-cache APIs, Gradle, Maven, and Go cache protocols should preserve their own semantics.

Do not require an always-on daemon. Persistent local metadata and optional protocol proxies are enough for the next phase.
