# ADR 0008: Unified Repo Config And Plan Lifecycle

Status: accepted launch-readiness decision
Date: 2026-04-22

## Context

BoringCache is close enough to launch that cache UX needs to be treated as a product contract, not a collection of shortcuts. The user should be able to set up a repo once, run the same cache plan locally and in CI, and keep that plan healthy when build config changes.

Current CLI reality already points in that direction:

- `.boringcache.toml` is the canonical repo config filename.
- `onboard` authenticates, scans, chooses workspace context, and writes repo config when possible.
- `audit --write` can merge discovered entries and profiles back into repo config.
- `doctor --json`, `run --dry-run --json`, and adapter `--dry-run --json` are machine-readable maintenance and orchestration surfaces.
- `boringcache/one` already asks the CLI for dry-run plans for archive and adapter modes instead of deriving the full plan itself.

External sources reinforce why this must be a lifecycle:

- GitHub Actions cache behavior is key/version/branch scoped, restore-key ordered, and centered on exact and prefix matches rather than a semantic project plan: https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching
- GitHub's 2025 cache-policy update keeps 10 GB as the free default, adds configurable retention/size limits above that, and explicitly names least-recently-used eviction and read-only behavior when budgets are reached: https://github.blog/changelog/2025-11-20-github-actions-cache-size-can-now-exceed-10-gb-per-repository/
- GitLab documents fallback keys and manual cache clearing by changing `cache:key` or clearing runner caches, which shows the same key churn/manual-bust pattern in another CI: https://docs.gitlab.com/ci/caching/
- Docker BuildKit invalidates `RUN --mount=type=bind` cache when file metadata changes, and external cache backends require explicit `--cache-from` and `--cache-to`: https://docs.docker.com/build/cache/invalidation/ and https://docs.docker.com/build/cache/backends/
- Docker's `gha` backend docs describe GitHub cache API throttling risk during BuildKit cache lookups and export timeouts: https://docs.docker.com/build/cache/backends/gha/
- Gradle, Nx, Turborepo, and Bazel all tie cache correctness to declared inputs, outputs, environment, and command shape rather than a human-only key string: https://docs.gradle.org/current/userguide/build_cache.html, https://nx.dev/docs/features/cache-task-results, https://turborepo.dev/docs/crafting-your-repository/caching, https://bazel.build/remote/caching
- Two recent empirical papers report that CI cache configurations evolve repeatedly, stale artifacts happen, and caching requires more maintenance than many teams expect: https://arxiv.org/abs/2604.13129 and https://arxiv.org/abs/2601.19146

## Decision

Treat `.boringcache.toml` as the repo's durable cache plan and the CLI as the only local planner for that plan.

The product lifecycle is:

1. Discover: `boringcache onboard` creates the first useful plan.
2. Execute: `boringcache run`, adapter commands, and `boringcache/one` execute CLI dry-run plans.
3. Maintain: `boringcache doctor --json` and `boringcache audit --json/--write` detect stale config, missing workspace/token state, and drift after build files change.

If future product language introduces `lint` or `rescan`, those commands should wrap the same planner and audit machinery. They should not create a second config format or a second key derivation stack.

## Ownership

- CLI owns repo-config discovery, merge rules, semantic entries/profiles, adapter defaults, dry-run JSON, suffixing, and diagnostics.
- `boringcache/one` owns GitHub Action inputs and orchestration, but should keep asking the CLI for the plan.
- Rails owns workspace, token, storage, publish, restore, session, billing, and API truth.
- Copywriting/docs should describe one setup path first: onboard, commit `.boringcache.toml` when useful, run locally or in CI through the same plan.

## Cross-Platform Rules

Platform suffixing remains on by default. OS/architecture are part of cache identity unless the user or config explicitly marks the artifact portable through `--no-platform` or equivalent config.

Do not promise cross-OS archive reuse by default. Existing ecosystem tools show why: `actions/cache` requires explicit cross-OS archive behavior plus GNU tar/zstd on self-hosted Windows runners, and build tools differ in how they model path sensitivity and environment inputs.

The config should store semantic intent. The planner should derive runner-specific details at execution time:

- OS and architecture suffixes;
- branch/default/PR suffixes;
- CI provider metadata;
- Docker immutable run refs and alias promotion refs;
- endpoint hosts such as `host.docker.internal` when the builder runs in another container.

Implementation note, 2026-04-23: adapter repo config now accepts the same
kebab-case spellings users see in CLI help for repeated proxy fields such as
`no-platform`, `no-git`, `read-only`, `cache-mode`, `cache-ref-tag`, and
`endpoint-host`, with snake_case aliases preserved. This keeps `.boringcache.toml`
as the first-class place to remove repeated flag wiring for both local CLI use
and external helpers that ask the CLI for a plan.

## Docker Rule

The maintained Docker path is BuildKit registry-cache planning:

- `boringcache docker`;
- `boringcache/one` Docker mode;
- direct `cache-registry` only for advanced/manual proxy use.

The CLI should not add a second Docker adoption path. A CLI binary release must not be part of the user's Docker cache graph.

## Performance Guardrails

The plan lifecycle must not add avoidable latency to every CI run.

- Prefer one CLI dry-run per logical action step.
- Avoid action-side loops that invoke the CLI once per raw entry when a single plan can answer the same question.
- Keep hot-path Rails reads DB-trust based; do not add object-storage `HEAD` probes to request paths to compensate for weak publish contracts.
- Treat manual cache busting as an escape hatch, not as the routine maintenance story.
- Keep `audit` and `doctor` usable in CI so teams can fail on config drift before silently wasting minutes.

## Benchmark Evidence Gate

Public performance claims require fresh artifacts gathered with the current CLI/action/web boundary. External docs, papers, and team blogs are market context only.

Each benchmark bundle must record:

- CLI version/ref and action ref;
- web deploy SHA or API revision when Rails is used;
- benchmark repo/ref, upstream project ref, workflow run URL, runner type, and cache mode;
- cold, warm, rolling-reseed, and stale-promotion classification where relevant;
- wall-clock job time, build-tool time, restore/import time, save/export time, and storage transfer bytes when measurable;
- `cache_session_summary`, OCI blob counts/bytes, upload-requested versus already-present blobs, cache-root publish/promotion status, and any BuildKit import/export diagnostics.

Do not reuse artifacts from stale Docker experiments or invalid same-branch reseeds as launch proof.

Evidence note, 2026-04-22: post-fix Docker artifacts prove that benchmark
diagnostics can now retain `cache_session_summary` after the harness flushes
the action-owned proxy before artifact upload. Downloaded BoringCache artifacts
include summaries for PostHog fresh `24795871449`, PostHog rolling
`24795877370`, Hugo fresh `24796205506`, Hugo rolling `24796211023`, Immich
rolling `24796581326`, and Mastodon rolling `24796581317`. The bundle is still
partial launch evidence only: it used `boringcache/one@v1` at
`c7bf06c1b6753a50890a78204e38acbaeec3c2b8` with CLI `v1.12.46`, records cache
mode `max` and OCI hydration `metadata-only`, but does not include web
`APP_REVISION` or `product_refs`; Immich and Mastodon still need post-fix
fresh+warm artifacts.

Additional same-ref rolling reruns on the same artifact shape gave
steady-state evidence for all four Docker workloads: PostHog `24796916333`,
Hugo `24796581263`, Immich `24797097761`, and Mastodon `24797097792` all
classified as `steady_state_candidate=true` with no new OCI blob uploads. This
is useful for cache-behavior analysis, but still not sufficient for launch
claims because the artifacts lack web revision and product-ref fields.

Follow-up implementation on 2026-04-22 adds the launch-proof field shape for
future benchmark artifacts: web `/v2/health` reports nullable `revision`, and
the benchmark artifact contract should emit `product_refs` with CLI, action,
web revision, and API URL fields. This is harness readiness only; the checked
post-fix artifacts still did not contain those fields, and the release/default
claim gate still needs fresh artifacts produced by the intended released
action/CLI path.

## Legacy And Cleanup

`serve` and `docker-registry` are not active command aliases. Tests currently reject both. Public docs and product facts must not advertise them.

Existing internal labels such as `docker-registry` in metrics or historical traces may need a schema migration if they are changed. Do not rename durable observability values casually just to match command help.

The hidden planner flags for `run --dry-run --json` are implementation surface for action/scripts, not user-facing CLI UX.

## Open Work

- Version exact dry-run JSON schemas for `run`, adapters, `doctor`, `audit`, and `onboard`.
- Add a first-class config drift check if `audit --json` is not enough for launch messaging.
- Make action archive planning avoid per-raw-entry CLI dry-run calls when a repo config exists.
- Add cross-platform audit warnings for entries that look portable but still use platform suffixing, and for entries that look binary but opt out of platform suffixing.
- Keep release/default claims blocked until benchmark artifacts show CLI version, action ref, cache mode, immutable run refs, alias promotion status, diagnostics numbers, and `cache_session_summary`.
