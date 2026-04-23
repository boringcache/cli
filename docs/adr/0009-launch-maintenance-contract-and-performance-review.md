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

## Consolidated Follow-Ups (2026-04-23)

This ADR is the single launch follow-up ledger across CLI, web, docs, and
benchmark proof. Every item below should either ship, be explicitly deferred,
or have launch copy/docs constrained so users are not promised behavior we have
not yet proven.

| Status | Area | Follow-up | Evidence and current state | Launch expectation |
| --- | --- | --- | --- | --- |
| done | CLI proxy / Go adapter | Allow valid zero-byte blobs in the shared KV blob-read path | A preserved-tag manual Go warm run on 2026-04-23 previously showed `1/179` startup blob prefetch failure and `60` degraded `gocache` GET errors, matching the `sha256:e3b0...` empty digest fanout in the pointer manifest. `BlobReadCache` and KV blob download now preserve zero-byte blobs instead of treating them as corruption. The rerun warmed `179/179` blobs with `0` failures, the manual metrics dropped to `177` GET hits, `1` miss, `0` errors, and the official Go-only harness summary now reports `request_metrics_failures=0`, `request_metrics_cache_ops_gocache_get_hits=177`, `request_metrics_cache_ops_gocache_get_misses=119`, `request_metrics_cache_ops_gocache_get_errors=0`. | Ship the fix and keep Go adapter launch-safe; do not treat the earlier degraded warm run as current product evidence. |
| done | CLI restore UX | Clarify blocked restore targets instead of implying empty directories are unsupported | Live recheck on 2026-04-23 confirmed restore into an already-created empty directory works. The real issue was blocked restores printing a vague warning. The CLI now reports the first conflicting child path and the help text explicitly says existing empty targets are valid. | Ship the clearer warning copy; do not document a nonexistent empty-directory restriction. |
| must-fix | Web dashboard | Fresh cache traffic should update user-visible dashboard numbers quickly enough to be trusted | The local dogfood pass on 2026-04-23 recorded CLI/session values moving to `2` tagged entries, `71.64 MB`, and `417` hits while the signed-in dashboard stats frame still showed `1` entry, `574 Bytes`, and `2` hits. Current dashboard summary caching is keyed only by membership and held for ten minutes. | Either reduce/invalidate that cache before launch or label the dashboard as delayed so users are not comparing stale product UI against live CLI output. |
| must-fix | Docker story | Remove Dockerfile-internal BoringCache examples from dogfood surfaces | CLI/web launch guidance already says BoringCache stays outside Dockerfile `RUN` steps, but the checked-in `web/Dockerfile` still advertises `docker build --secret ...` plus `boringcache run` inside `RUN` layers. | Repo examples, public docs, and product copy must tell one Docker story: external BuildKit registry cache refs only. |
| must-fix | Public docs drift | Sweep stale or contradictory command/docs surfaces before launch | The 2026-04-23 audit found website copy drift against canonical CLI docs: GitHub Actions PR restore guidance, Bazel/Gradle/Maven adapter auto-wiring wording, container host/endpoint guidance, top-level `config` flag wording, and stale local setup instructions in the web README plus `web/bin/setup`. | One docs sweep should align public site, README, and CLI docs/help against the shipped commands and flags. |
| must-fix | Onboard Dockerfile failure UX | Give users an actionable explanation when deterministic Dockerfile conversion is unsupported or the optimization service is unavailable | The local Dockerfile onboarding pass falls through from deterministic rejection into AI assist, and a local auth/config problem surfaces as a generic optimization service configuration error. GitHub Actions rewrite worked, but the Dockerfile step did not explain the product boundary or next step. | If Dockerfile conversion stays unsupported for launch, say that directly and point users to the supported external Docker path instead of emitting a generic service failure. |
| validate | Docker adapter dogfood | Re-run the local Docker adapter path on Colima after freeing space and confirm the launch path end-to-end | Earlier adapter coverage skipped Docker because the daemon was unavailable. Disk cleanup and `cargo clean` recovered space on 2026-04-23, but the Docker leg still needs a fresh local pass with Colima actually running. | Do not claim full local adapter parity until the Docker path is revalidated on the current launch build. |
| validate | Launch proof artifacts | Refresh benchmark and dogfood evidence on the released CLI/action/web pair | Existing ADR evidence still notes gaps around released-path benchmark artifacts, product refs, and operator-facing diagnostics. The 2026-04-23 dogfood pass added local proof for restore UX and Go zero-byte handling, but it is not a release-path benchmark set. | Keep performance, stale-promotion, and benchmark claims gated on fresh released-path artifacts with product refs and diagnostics attached. |

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
- Close or explicitly defer every `must-fix` or `validate` item in the
  consolidated follow-up table above before launch copy treats the behavior as
  complete.
