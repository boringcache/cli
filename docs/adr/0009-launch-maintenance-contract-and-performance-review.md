# ADR 0009: Launch Maintenance Contract And Performance Review

Status: accepted launch-readiness review
Date: 2026-04-23

## Context

ADR 0008 makes `.boringcache.toml` the durable repo cache plan and the CLI the
owner of local planning. This review records the launch checks around long-term
maintenance, cross-platform behavior, action/web contract boundaries, legacy
surfaces, and performance risks.

The external pain pattern is consistent across CI providers and build tools:

- GitHub Actions cache depends on key/version/branch scope, restore-key order,
  retention, and repository cache budget behavior.
- GitLab and CircleCI both expose fallback keys and manual key/cache clearing
  as normal maintenance tools.
- Docker BuildKit external cache requires explicit import/export wiring, and
  bind-mounted Dockerfile inputs participate in cache invalidation.
- Native build caches model inputs, outputs, command, environment, and action
  identity.
- Empirical studies of GitHub Actions and Travis CI caching report frequent
  cache-related workflow changes and repeated cache maintenance activities:
  https://arxiv.org/abs/2604.13129 and https://arxiv.org/abs/2601.19146

The CLI should turn that pain into one lifecycle instead of another pile of
manual cache keys.

## Decision

The launch maintenance contract is:

1. `boringcache onboard` creates the first useful repo plan.
2. `.boringcache.toml` remains the single durable local/CI cache intent file.
3. `boringcache run`, adapter commands, and `boringcache/one` execute CLI plans.
4. `doctor --json` checks workspace/token/API health.
5. `audit --json` and `audit --write` are the current rescan/update path when
   build config changes.
6. Any future `lint`, `rescan`, or `repair` command must wrap the same planner,
   audit, and doctor machinery.

Do not create a second config format, a second key derivation stack, or an
action-only cache planner.

Launch reporting must also be useful on first use:

- CI-backed proxy sessions should group automatically by low-cardinality
  `project` metadata when repository context is available;
- seed/prewarm exclusion should depend on explicit low-cardinality labels such
  as `phase=seed` or `phase=prewarm`, not heuristics that quietly reclassify
  user traffic;
- human-readable `status` and `misses` output should separate actionable misses
  from excluded seed traffic so users can tell whether they have a cache
  quality problem or a benchmark wiring problem.

## Cross-Platform Contract

Platform suffixing stays on by default. Local/CI cache identity includes OS and
architecture unless the user or config explicitly marks an entry portable.

Launch copy should avoid promising cross-OS archive reuse by default. If
copy/docs mention portable entries, the CLI needs audit warnings that help
users spot suspicious settings:

- text/source-only entries that still pay platform suffix cost;
- binary/toolchain entries that opt out of platform suffixing;
- Windows archive portability cases that depend on tar/zstd availability.

## Docker Contract

The CLI must not replace the old action Dockerfile helper path.

The maintained Docker path is outside the Dockerfile through BuildKit registry
cache refs:

- `boringcache docker`;
- `boringcache/one` Docker mode;
- advanced/manual `cache-registry` proxy use.

Do not put the CLI binary, BoringCache commands, token mounts, helper binaries,
build args, or secret mounts inside the user's Docker build graph. A CLI
release must not become a Docker cache input.

## Action And Web Boundaries

The action may validate inputs, install the CLI, collect provider metadata, and
invoke dry-run plans. It should not derive `.boringcache.toml`, Docker refs,
tag suffixes, or Rails policy independently.

Rails owns durable workspace, token, upload, receipt, publish, restore,
session, storage, billing, and plan gates. The CLI may request and consume
those contracts, but should not compensate for weak server state with hidden
polling on normal publish/restore paths.

## Performance Guardrails

The launch UX should be automatic, but not expensive by default.

- Prefer one dry-run plan per logical action step.
- Do not invoke the CLI once per raw archive entry when one repo-config plan can
  describe the whole step.
- Keep `doctor` and `audit` cheap enough to run in CI as drift checks.
- Keep manual cache busting as an escape hatch, not the routine maintenance
  story.
- Do not add normal post-publish sleeps or restore polling.
- Keep hidden diagnostic modes hidden until benchmark evidence justifies a
  default.

## Legacy Surface Review

Active product surfaces:

- `onboard`, `run`, `save`, `restore`, `mount`, `check`, `inspect`, `ls`,
  `tags`, `delete`;
- `doctor`, `audit`, `dashboard`, `status`, `sessions`, `misses`;
- adapters for Docker, Turbo, Nx, Bazel, Gradle, Maven, sccache, Go, and
  `go-cacheprog`;
- `cache-registry` as the explicit raw proxy.

Do not advertise inactive aliases such as `serve` or `docker-registry`.
Internal module names or durable observability labels may still contain those
words; renaming them is a schema/history decision, not launch copy cleanup.

Thin or advanced surfaces such as `go-cacheprog`, hidden Docker immutable-ref
flags, and proxy hydration modes should remain documented as advanced plumbing
or diagnostics, not as the first-run UX.

## Open Work

- Version the machine-readable schemas for dry-run plans, `doctor`, `audit`,
  `onboard`, and adapter JSON outputs.
- Add a first-class drift/lint command only if `audit --json` is not sufficient
  for launch messaging.
- Add cross-platform audit warnings for suspicious platform suffix choices.
- Reduce action archive planning that shells out per raw entry.
- Keep benchmark and CI guidance pushing explicit `phase` labels so shared
  workspaces do not turn recurring misses into product noise.
- Keep performance and stale-promotion claims blocked until released
  CLI/action/web benchmark artifacts contain product refs and diagnostics.
