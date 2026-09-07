# Changelog

All notable changes to BoringCache CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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

[Unreleased]: https://github.com/boringcache/cli/compare/v1.20.5...HEAD
[1.20.5]: https://github.com/boringcache/cli/compare/v1.20.4...v1.20.5
[1.20.4]: https://github.com/boringcache/cli/compare/v1.20.3...v1.20.4
[1.20.3]: https://github.com/boringcache/cli/compare/v1.20.2...v1.20.3
[1.20.2]: https://github.com/boringcache/cli/compare/v1.20.1...v1.20.2
[1.20.1]: https://github.com/boringcache/cli/compare/v1.20.0...v1.20.1
[1.20.0]: https://github.com/boringcache/cli/compare/v1.19.7...v1.20.0
[1.19.7]: https://github.com/boringcache/cli/releases/tag/v1.19.7
[1.19.6]: https://github.com/boringcache/cli/releases/tag/v1.19.6
