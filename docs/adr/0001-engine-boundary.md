# ADR 0001: Engine Boundary Before Snapshot V2

Status: accepted as snapshot-v2 guardrail; native adapter guidance superseded by ADR 0002
Date: 2026-04-19

2026-04-20 amendment: this ADR is retained only for one current rule: do not let snapshot-v2 become a product rewrite. The OCI migration moved adapter planning into ADR 0002. Do not use this ADR as an adapter-engine checklist or as a requirement for a universal engine trait.

## Context

BoringCache has more than one cache shape:

- archive save/restore for ordinary filesystem directories;
- file-CAS and OCI-CAS flows that already use missing-object checks, upload receipts, and pointer publish;
- proxy/native adapters for OCI/BuildKit, Bazel, sccache/WebDAV, Turbo, Nx, Gradle, Maven, and Go;
- `one@v1`, `.boringcache.toml`, split restore/save/admin tokens, and standalone benchmark repos as the public product surface.

The OCI migration proved that protocol-native behavior should stay with the native adapter plan in ADR 0002. Snapshot-v2 should solve the generic directory-cache problem without becoming the answer to every protocol-specific cache problem.

The generic archive path still pays full tree scan, full manifest build, tar creation, upload, download, and extraction costs. That is a real roadmap problem for low-churn generic caches, but it is separate from Docker/OCI parity and should not force a product restart.

## Decision

Add an explicit internal boundary before any snapshot-v2 rewrite or Rust crate split.

The public product surface stays stable:

- `boringcache run`, `save`, `restore`, `cache-registry`, and adapter commands remain the front doors;
- `one@v1` remains the main GitHub Actions entrypoint;
- repo config and split-token trust semantics remain intact;
- native protocols stay native instead of being routed through archive mode.

The surviving decision is narrow: `ArchiveV1` remains the generic filesystem compatibility path, and `SnapshotV2` must be introduced as an incremental generic-directory engine only after benchmarks justify it. Adapter rewrites are outside this ADR's active scope and follow ADR 0002.

## Required Boundary Shape

The boundary should keep CLI/action orchestration thin without forcing snapshot-v2 work to redesign every cache type.

Generic directory cache engines can expose restore/save plans because that is their natural shape. Native adapters should not be forced into archive-shaped `save(paths)` / `restore(paths)` APIs; ADR 0002 owns that adapter rule.

A thin operational shell can exist for process orchestration:

```rust
trait Mode {
    fn prepare(&self) -> Result<()>;
    fn run(&self) -> Result<()>;
    fn finalize(&self) -> Result<()>;
}
```

That shell must not become the storage abstraction. In particular, do not require native adapters to implement a generic `save(paths)` / `restore(paths)` engine API.

Generic directory engines must report diagnostics that can explain misses and latency:

- input root/ref/tag and effective tag;
- local hit count and remote fetch count;
- bytes read and written locally/remotely;
- request count and retry count;
- publish/finalize/receipt timing;
- save/restore planning and materialization timing.

## Consequences

Snapshot-v2 becomes an incremental engine under the existing product, not a rewrite of the whole CLI.

Archive-v1 remains the compatibility path until snapshot-v2 beats it on measured generic filesystem workloads.

OCI, Bazel, sccache, Turbo, Nx, Gradle, Maven, and Go keep their native protocol identity. Their correctness and performance should be evaluated at their protocol boundary, not by forcing them through a filesystem snapshot abstraction.

The benchmark harnesses remain valid acceptance tests. They should grow better diagnostics and churn scenarios instead of changing shape.

## Migration Plan

1. Follow ADR 0002 for native adapter work.
2. Keep archive-v1 as the generic directory compatibility engine.
3. Move duplicated Rails/Tigris/session/publish/receipt code into shared platform helpers only when the behavior is protocol-neutral.
4. Add snapshot-v2 as a later generic directory engine only after low-churn benchmarks prove it is worth switching.

## Acceptance Gates

No snapshot-v2 default switch until:

- archive-v1 compatibility tests still pass;
- snapshot-v2 beats archive-v1 on 0%, 1%, and 5% churn generic filesystem workloads;
- diagnostics explain every important warm miss without log archaeology.

No crate/workspace split for snapshot-v2 until:

- the engine boundary is merged;
- module ownership is documented in `.comprehension`;
- tests cover each engine at the behavior boundary.

## Rejected Options

Do not rewrite the whole product around snapshot-v2. The current public surface is good, and Docker/OCI issues were protocol/body-plane issues, not proof that every adapter should become a filesystem snapshot.

Do not make archive tarballs the canonical truth with CAS as an optimization. CAS/session/receipt flows already represent the better long-term shape.

Do not force native remote-cache tools through archive mode. Bazel AC/CAS, OCI registry cache, sccache WebDAV, Turbo/Nx remote-cache APIs, Gradle, Maven, and Go cache protocols should preserve their own semantics.

Do not require an always-on daemon. Persistent local metadata and optional protocol proxies are enough for the next phase.
