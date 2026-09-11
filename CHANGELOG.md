# Changelog

All notable changes to BoringCache CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [1.30.4] - 2026-09-10

### Fixed

- Reuse archive graph decoder threads and zstd contexts across chunks to reduce
  large archive restore materialization time.

## [1.30.3] - 2026-09-10

### Fixed

- Align BuildKit smoke and end-to-end test defaults with the managed
  `v0.33.0-bc.2` image.

## [1.30.2] - 2026-09-10

### Changed

- Update the managed Docker builder to BuildKit `v0.33.0-bc.2`. Cache-mount
  archives use stable, readable mount names across workers. Archives saved
  under older mount names remain stored but are not selected by the new names.
- Update mise in the runtime and build base images to `2026.9.4`.
- Adapt automatic download and prefetch admission to live OS memory and I/O
  pressure, including when fewer requests are needed than at startup. Range
  downloads share the same admission policy.
- Overlap archive verification and decoding with extraction. Adapt decoder
  admission to measured delivery, live memory and I/O pressure within the CPU
  and operator limits; join workers before cleanup when extraction stops.

- Reuse Cargo target tags across package version, manifest, and lockfile changes.
  Target tags retain the configured Git/platform scope; Cargo rebuilds affected
  crates when their inputs or compiler change. Existing remote snapshots
  with a graph suffix remain under their old tags and are not selected by the
  new key. Populated local targets remain usable. No automatic target rotation
  or pruning is added.
- Honor `CARGO_INCREMENTAL=1` for Cargo target entries and preserve incremental
  directories in archive saves when enabled. The default remains `0`; use
  `compiler-cache = "none"` for incremental compilation. The rustc query cache
  and obsolete BoringCache artifact receipt remain excluded.

### Fixed

- Use retained byte progress to adapt shared download admission after a slow-body
  probe retries. A probe no longer independently halves capacity for unrelated
  objects; transport failures and native resource pressure retain their backoff.

- Use the same download recovery for archive chunks and proxy files. Retry
  stalled response headers within bounded budgets, honor bounded server retry
  delays, and refresh rejected cached URLs without restarting the retry budget.
  Keep startup prefetch within that budget and use actual retries to adapt its
  concurrency. After recovery opens a fresh connection, subsequent downloads
  use its replacement pool. Print terminal transport causes without signed
  storage URLs.

- Retry slow archive and OCI chunk downloads even when the chunk or resumed
  remainder is small. Check throughput within two seconds of collecting bytes,
  keep completed downloads, and report recovered download retries accurately.
- Recover slow live OCI reads and proxy file downloads, including slow resumed
  tails and sequential fallback after range rescue fails. Use the shared
  progress policy after every reopen and avoid repeating a failed range fan-out.
  Preserve byte progress and let the final attempt finish while its idle
  deadline and integrity checks remain active.

- Preserve changed source timestamps after successful Cargo commands so repeated
  `--skip-save` builds can reuse their local artifacts.
- Compress and stage identical chunks only once within each archive save.
- Use Action 1.30.1 in generated GitHub Actions workflows and workflow diagnostics.

## [1.30.1] - 2026-09-09

### Added

- Configure managed Docker and BuildKit workers with a native `buildkitd.toml`.
  The CLI discovers the nearest file within the project; `--buildkitd-config`
  or an adapter's `buildkitd-config` repo setting selects another file.
  Workers are recreated when settings or referenced registry certificates change.
- Limit the managed BuildKit worker's CPU quota and CPU affinity with
  `BORINGCACHE_MANAGED_BUILDKIT_CPUS` and
  `BORINGCACHE_MANAGED_BUILDKIT_CPUSET_CPUS`.

### Fixed

- Use Action 1.30.0 in generated GitHub Actions workflows and workflow diagnostics.


## [1.30.0] - 2026-09-09

### Changed

- Update the managed Docker builder to BuildKit 0.33.0 with the BoringCache
  backend, retaining an immutable image digest and existing cache behavior.

### Fixed

- Use Action 1.21.0 in generated GitHub Actions workflows.

## [1.21.0] - 2026-09-08

### Added

- Configure archive exclusions with `exclude` in `.boringcache.toml` entries,
  or add patterns with `--exclude-pattern` when an adapter such as Cargo saves
  archive entries.

### Fixed

- Publish Artifacts from OIDC jobs using authenticated workload provenance,
  including providers whose job identity differs from the job name.
- Report missing Docker cache references without implying the entire build has
  no cache, and explain cache startup waits and retries in plain language.
- Refresh OIDC credentials inside Docker cache-mount workers throughout long
  builds, preserving restore-only permissions and normal cache publication.
- Refresh product credentials on HTTP retries and use Registry-scoped OIDC
  credentials for Docker image publication.
- Share compiler cache Git and platform scoping between Cargo and sccache while
  keeping Cargo archive scoping independent.
- Bound captured-output draining after a command exits, so background processes
  retaining its output pipes cannot leave the cache lifecycle waiting forever.
- Update the embedded zstd library to 0.14.0 while retaining the existing
  archive format and canonical cache identity.
- Keep archive and CAS restore download concurrency steady across overlapping
  transfers, while retaining immediate backoff when a transfer fails.
- Record archive save and restore phase timings and available resource counters
  so slow local processing can be distinguished from network transfer time.

## [1.20.5] - 2026-09-07

### Fixed

- Keep native CI cache startup reliable across normal control-plane and broker
  response latency by clamping each workload capability to the remaining
  parent session lifetime.

## [1.20.4] - 2026-09-06

### Fixed

- Accept server-issued workload capabilities across normal request latency by
  clamping their local lifetime to the remaining parent session lifetime.
- Start the Actions compatibility service in restore-only mode whenever the
  brokered workload session is restore-only, so Workspace publication policy
  narrows a job without failing runner readiness.
- Explain when a valid CI workload is restore-only and direct users to a
  trusted job or the Machine connection publication policy instead of showing
  only a local broker 403 response.

## [1.20.3] - 2026-09-04

### Added

- Enroll native BoringBuild workload identity with
  `boringcache ci connect --oidc-provider boringbuild`, using the job's
  controller-issued renewable assertion and browser-approved Workspace
  selection without a stored BoringCache secret.
- Acquire renewable CircleCI OIDC assertions with `--oidc-provider circleci`
  through the in-job Environment CLI, BoringCache's audience, and CircleCI's
  root issuer, without a CircleCI API token or stored BoringCache secret.
- Use GitLab.com's job-scoped `BORINGCACHE_OIDC_TOKEN` directly with
  `--oidc-provider gitlab`, binding immutable job namespace/project identity
  while keeping merge-request and fork source jobs restore-only.

### Changed

- Keep native GitLab's private broker session for the bounded lifetime of its
  job assertion, up to one hour, while continuing to issue five-minute product
  capabilities and recheck live publication policy on every issuance. This
  lets ordinary GitLab jobs run without exposing or replaying their OIDC token
  and keeps existing providers compatible with released clients.

## [1.20.2] - 2026-09-03

### Changed

- Checkpoint cumulative proxy diagnostics every five minutes while continuing
  to deliver completed cache-operation rollups every 30 seconds, bounding
  retained session state and repeated reporting work in long builds.

### Fixed

- Keep Windows archive monitor requests on bounded blocking connections so a
  partially delivered local observation cannot prematurely stop unchanged-cache
  reuse.
- Route archive monitor failures through the configured diagnostic output so a
  fail-closed reuse decision retains its actionable cause.
- Preserve each cache-operation rollup's idempotency identity across delivery
  retries so a transient reporting failure cannot duplicate its counters.

## [1.20.1] - 2026-09-03

### Added

- Let Docker and BuildKit repo plans own optional native tool-cache and
  cache-mount composition used by local runs and the thin GitHub Action.

### Fixed

- Preserve managed Docker Cargo target reuse when an unchanged source tree is
  materialized with newer mtimes.
- Forward `SCCACHE_IDLE_TIMEOUT` into Docker-native sccache builds so long link
  phases do not let the compiler-cache daemon exit early.

## [1.20.0] - 2026-09-02

### Added

- Publish customer-facing CLI release notes from this changelog as part of every release.
- Add `boringcache system requirements <adapter> --check` so automation can
  fail before cache setup when a required helper is missing or incompatible.
- Let an interactive administrator enroll an exact provider-neutral OIDC
  issuer through `boringcache onboard` without creating a fallback CI token.
- Add `boringcache ci run` to acquire renewable provider OIDC assertions,
  supervise one runner-local workload broker, and run Cache or Artifact
  commands without exposing or falling back to static BoringCache credentials.
- Add `boringcache ci connect` with browser-approved Workspace selection and
  in-memory enrollment for native CI providers, plus explicit stdin enrollment
  for registered issuers and automation. Neither path creates a reusable
  BoringCache credential.
- Acquire renewable Buildkite OIDC assertions with `--oidc-provider buildkite`
  and no hand-written token command, forge connection, or BoringCache secret.
- Acquire renewable GitHub Actions OIDC assertions with
  `--oidc-provider github-actions` and the job's native `id-token: write`
  permission, without a GitHub App or stored BoringCache secret.

### Changed

- Resolve GHA cache workspace from the committed repo plan when `gha-cache`
  receives no explicit workspace, and include that resolved workspace in the
  service ready document consumed by GitHub integrations.
- Name credentials created by the provider-neutral onboarding path for CI
  instead of GitHub Actions.
- Update the managed ccache HTTP storage helper to 0.9.
- Tell users to install adapter prerequisites through their normal project or
  workflow setup instead of claiming that BoringCache One installs them.

### Fixed

- Accept exact version output from tools such as `ccache-storage-http` that
  return a nonzero status for their version probe.

## [1.19.7] - 2026-08-29

### Added

- Allow a workflow job to download artifacts produced by another job in the same workflow run while keeping cross-run access denied.

### Fixed

- Retry temporary cache publication conflicts without misreporting them as permanent tag conflicts.

## [1.19.6] - 2026-08-28

### Changed

- Promote the exact tested CLI candidate bytes into the public release instead of rebuilding platform artifacts during publication.

### Fixed

- Preserve project-selected Maven extension versions when enabling Maven cache support.

[Unreleased]: https://github.com/boringcache/cli/compare/v1.30.4...HEAD
[1.30.4]: https://github.com/boringcache/cli/compare/v1.30.3...v1.30.4
[1.30.3]: https://github.com/boringcache/cli/compare/v1.30.2...v1.30.3
[1.30.2]: https://github.com/boringcache/cli/compare/v1.30.1...v1.30.2
[1.30.1]: https://github.com/boringcache/cli/compare/v1.30.0...v1.30.1
[1.30.0]: https://github.com/boringcache/cli/compare/v1.21.0...v1.30.0
[1.21.0]: https://github.com/boringcache/cli/compare/v1.20.5...v1.21.0
[1.20.5]: https://github.com/boringcache/cli/compare/v1.20.4...v1.20.5
[1.20.4]: https://github.com/boringcache/cli/compare/v1.20.3...v1.20.4
[1.20.3]: https://github.com/boringcache/cli/compare/v1.20.2...v1.20.3
[1.20.2]: https://github.com/boringcache/cli/compare/v1.20.1...v1.20.2
[1.20.1]: https://github.com/boringcache/cli/compare/v1.20.0...v1.20.1
[1.20.0]: https://github.com/boringcache/cli/compare/v1.19.7...v1.20.0
[1.19.7]: https://github.com/boringcache/cli/releases/tag/v1.19.7
[1.19.6]: https://github.com/boringcache/cli/releases/tag/v1.19.6
