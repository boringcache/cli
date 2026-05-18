# ADR 0010: Package Manager CAS Layout

Status: accepted for Bundler-first implementation
Date: 2026-05-18

## Context

Archive cache entries are intentionally simple, but dependency install trees are
poor archive workloads. A one-package change in `vendor/bundle`, `node_modules`,
or a Python environment often forces a whole new tar/zstd payload even when most
installed packages are unchanged.

Existing BoringCache CAS plumbing already supports workspace-scoped blobs,
receipt-strict uploads, manifest pointers, restore verification, and
materialization. The missing product shape is a package-manager-aware layout
that groups installed files by package instead of by whole archive or by every
individual file.

The highest-pain targets are not merely the largest ecosystems. They are where
the package manager spends visible CI time doing work a remote build proxy does
not cover:

- Bundler: native extension compilation, git gems, and Rails CI install pain.
- npm/Yarn: very large `node_modules` trees, lifecycle scripts, bin shims, and
  native `node-gyp` packages.
- Python: virtualenv/site-packages materialization, compiled wheels, source
  builds, and console scripts.

Proxy adapters remain the better BoringCache surface for native build cache
protocols such as Bazel remote AC/CAS, Gradle/Maven build cache, Go
`GOCACHEPROG`, sccache, Turborepo, Nx, and Docker/BuildKit OCI layer cache.
Package-manager CAS should not duplicate those build-cache protocols.

## Decision

Add a `pkg-v1` CAS layout in the CLI, with no web/API schema change.

`pkg-v1` stores the materialized package closure:

1. the installed package files after the package manager has extracted,
   compiled, linked, and generated metadata;
2. any small residual state needed for the package manager to recognize the
   restored tree;
3. a pointer manifest that maps packages to workspace-scoped CAS blobs.

The backend continues to see:

- `storage_mode = "cas"`;
- `cas_layout = "pkg-v1"`;
- existing blob descriptors, upload URLs, manifest upload, receipts, confirm,
  quota, garbage collection, and restore endpoints.

The CLI owns detection, scanning, package grouping, materialization, and
compatibility checks. The package manager remains the final verifier and repair
tool. BoringCache should reject obvious runtime mismatches, restore compatible
materialized packages, and then let normal commands such as `bundle install`
repair anything incomplete.

## First Implementation Slice

Ship the primitive behind the existing `save` and `restore` commands, starting
with Bundler only.

Bundler v1 scope:

- detect `vendor/bundle` or a configured Bundler install root;
- group installed gem closures under the current Ruby ABI directory;
- include installed gem files, gemspecs, native extension directories,
  `build_info`, and relevant git gem directories when present;
- record a simple compatibility fingerprint:
  - Ruby engine;
  - Ruby ABI directory such as `ruby/3.4.0`;
  - OS/architecture platform;
  - lockfile digest when available;
- skip `pkg-v1` restore on obvious fingerprint mismatch;
- rely on the user's following `bundle install` or `bundle check` to verify and
  repair the bundle.

Do not inspect linked system libraries in v1. OpenSSL, libyaml, libpq, zlib, and
similar dependencies can drift, but deep `ldd`/`otool` fingerprinting is not
the first product shape. Platform scope plus Ruby ABI guards are enough for the
hidden Bundler proof.

npm is the second proof target after Bundler validates the primitive. npm should
prove large-tree and partial-reuse behavior for `node_modules`.

## Non-Goals

- No global or cross-workspace blob sharing.
- No Rails schema or API change.
- No new top-level command.
- No broad package-manager matrix in the first implementation.
- No package-manager lockfile parser zoo before the Bundler proof.
- No native system-library dependency scanner in v1.
- No replacement for Bazel, Gradle, Maven, Go, sccache, Docker, Turborepo, or
  Nx proxy adapters.

## Safety Model

`pkg-v1` restore is optimistic but bounded:

- pointer and blob digests must verify through the existing CAS restore path;
- materialized paths must pass the same safe-join and symlink escape checks as
  file CAS;
- runtime fingerprints reject obvious wrong restores;
- detection or materialization failure falls back to archive behavior on save
  and skip/ignore behavior on restore;
- package managers remain responsible for final semantic validation.

For Bundler, the intended workflow is:

```sh
boringcache restore <workspace> bundler:vendor/bundle
bundle install
boringcache save <workspace> bundler:vendor/bundle
```

or the equivalent `boringcache run -- bundle install` flow once planner support
selects `pkg-v1`.

## Proof Gates

Before claiming `pkg-v1` broadly or adding more package-manager adapters:

- focused unit tests for pointer parsing, deterministic package archives,
  safe materialization, and Bundler grouping;
- mock API integration tests proving `storage_mode: "cas"` and
  `cas_layout: "pkg-v1"` reuse the existing CAS upload/restore flow;
- local Bundler smoke on a Rails app with native extensions;
- benchmark comparison against archive mode:
  - cold save;
  - warm save with no dependency changes;
  - warm save after changing one gem;
  - restore plus `bundle install`;
  - uploaded bytes, downloaded bytes, package blob reuse, wall time.

Rollout remains proof-gated until the benchmark shows meaningful savings over
archive mode and no spooky restore behavior.

## Implementation Notes

The CLI should add focused modules rather than growing archive/file CAS code:

- `src/cache/cas_pkg/**` for pointer, deterministic package archive, scan, and
  materialization helpers;
- `src/pkg_adapters/**` for Bundler and later package-manager adapters;
- `src/commands/cache/save/pkg.rs` and `restore/pkg.rs` for command glue over
  the existing CAS publish/restore orchestration.

The generic CAS transport, receipts, upload sessions, and server signatures
remain in their current modules.

## Status Notes

2026-05-18: Accepted for a Bundler-first implementation. npm, Python,
Composer, and Yarn are intentionally deferred until the Bundler primitive has
evidence.

2026-05-18 implementation slice: CLI now has `pkg-v1` adapter dispatch, package
pointer parsing, deterministic package tar blobs, residual file/symlink
materialization, Bundler `vendor/bundle` detection, package save glue, and
package restore glue. This is still intentionally dumb: the Bundler adapter
derives package blobs from the installed `vendor/bundle/ruby/<abi>` layout
rather than parsing Bundler's dependency graph, and save falls back to archive
when encryption, excludes, or an unrecognized layout are present. The mock API
save proof is in place. Remaining proof gates are real Bundler/Rails smoke and
archive-vs-package benchmark evidence before claiming or broadening the
behavior.

2026-05-18 npm slice: added a conservative npm adapter for package-lock v2/v3
`node_modules` trees. It only reads the `packages` map, packages installed
directories, captures residual `.bin`/state files through the generic pkg-CAS
scanner, and rejects linked/workspace, symlinked, pnpm, or unparseable layouts
so archive mode remains the safe fallback. npm still needs real-repo smoke on a
large but low-risk app such as n8n before treating the adapter as proven.
