# ADR 0001: Engine Boundary Before Snapshot V2

Status: accepted
Date: 2026-04-19

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

## Required Interface Shape

The boundary should keep CLI orchestration thin:

```rust
trait CacheEngine {
    fn restore_plan(&self, input: RestoreInput) -> Result<RestorePlan>;
    fn save_plan(&self, input: SaveInput) -> Result<SavePlan>;
    fn diagnostics(&self) -> EngineDiagnostics;
}
```

Protocol engines may expose richer internal operations, but command entrypoints should depend on restore/save/proxy plans rather than duplicating transport and layout rules.

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

1. Define the engine model and diagnostics structs behind the current commands.
2. Wrap current archive behavior as `ArchiveV1Engine` without changing public UX.
3. Wrap existing OCI/file-CAS/proxy paths behind protocol engines where that reduces duplication.
4. Build snapshot-v2 behind an explicit opt-in once the boundary exists.
5. Add small-object packing and range-read support after snapshot roots and aliases are stable.
6. Migrate generic filesystem commands to snapshot-v2 only after low-churn benchmarks prove it.

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
