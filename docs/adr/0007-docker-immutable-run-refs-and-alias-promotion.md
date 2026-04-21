# ADR 0007: Docker Immutable Run Refs And Alias Promotion

Status: accepted; CI derivation implemented, default rollout pending backend E2E and benchmark proof
Date: 2026-04-20

## Context

Docker BuildKit registry cache writes are tag-shaped. If two jobs write the same cache ref concurrently, one writer can replace the visible tag state from the other. The current CAS publish path uses optimistic tag publish and write scopes, which protects the backend pointer update better than a blind overwrite, but the product model still treats a branch cache ref as both the write destination and the read alias.

That is acceptable for early Docker rollout, but it makes correctness and benchmarks noisier:

- a slower stale job can publish after a newer job;
- same-tag benchmark variants can write into each other's state;
- losing writers may appear as cache corruption even when immutable data is still present;
- branch cache refs mix immutable root identity with mutable alias identity.

The right model is:

```text
immutable root:
  docker-cache/runs/<run-id-or-root-digest>

mutable aliases:
  docker-cache/branch/main
  docker-cache/branch/<branch>
  docker-cache/pr/<number>
  docker-cache/recent
```

BuildKit should write one immutable run ref. Rails should atomically promote aliases after validating the root.

## Source Grounding

This ADR depends on these source-backed properties:

- Docker documents registry cache as a separate cache image location and requires explicit `--cache-to` export plus `--cache-from` import.
- Docker warns that writing a cache location twice overwrites prior cached data. That is the core reason branch aliases should not be the only durable write target.
- Docker documents importing multiple caches, with current branch plus main branch as the common pattern. That grounds multiple `--cache-from` aliases.
- Docker registry cache `mode=max` exports all intermediate-step layers, so the alias/root model must preserve complete cache manifests and blobs, not only final-image layers.
- OCI tag references are constrained to 128 characters and a limited character set. Logical run refs and aliases may need hashing into valid OCI tags.
- BuildKit registry cache source canonicalizes the registry `ref`, obtains a pusher for export, and obtains a resolver/fetcher for import. BoringCache should map immutable roots and aliases onto normal registry refs rather than a side channel invisible to BuildKit.
- OCI referrers fallback notes that simultaneous updates to a tag-shaped index can race, and clients may use conditional requests where supported. That reinforces Rails-side compare-and-swap alias promotion.

Source URLs are listed in ADR 0003.

## Decision

Design Docker registry cache publishing around immutable run refs plus atomic alias promotion.

Do not lock the whole build. Do not let branch aliases be the only durable location for a cache root.

The write path becomes:

1. CLI/action chooses an immutable run ref for `--cache-to`.
2. BuildKit exports to the local proxy using that run ref.
3. Proxy publishes a CAS root for that immutable ref.
4. Rails validates the root and records immutable root metadata.
5. Rails atomically promotes selected aliases to that root if policy allows.
6. A losing or stale promotion leaves the immutable root intact and records an alias conflict.

The read path becomes:

1. CLI/action asks Rails or local planning for candidate aliases.
2. BuildKit imports multiple `--cache-from` refs when supported:
   - current branch alias;
   - default branch alias;
   - PR alias when applicable;
   - recent alias/list when implemented;
   - optional previous run ref for retries.
3. Proxy resolves those aliases to immutable roots through the existing OCI restore machinery.

## Ref Shape

OCI tag constraints are tighter than arbitrary path strings. The final shape must be valid as Docker registry refs.

Suggested local registry ref shape:

```text
cache:<alias-or-run-tag>
```

Suggested logical identities behind the proxy:

```text
docker-cache/runs/<run-id>-<attempt>
docker-cache/branches/<safe-branch>
docker-cache/prs/<number>
docker-cache/default
docker-cache/recent/<n>
```

The CLI can hash long logical identities into OCI-safe tags using the existing scoped ref tag helpers. User-facing inputs should stay simple:

- `--tag` remains the proxy cache tag or logical cache family;
- `--cache-ref-tag` remains the Docker OCI cache tag override;
- action-level run-ref and alias controls start hidden/internal until benchmarked.

## Rails/API Contract

Rails owns alias policy and atomic promotion.

Required backend concepts:

- immutable cache root id;
- root digest and manifest digest;
- provider-neutral source ref/branch/PR metadata;
- CI provider name when known;
- provider run uid and attempt when known;
- explicit client-generated run uid when no CI provider exists;
- commit SHA when available;
- run started/completed timestamps;
- alias pointer version;
- alias conflict or ignored promotion state.

Required API operations:

```text
create_or_confirm_root(workspace, root_ref, root_digest, metadata)
promote_alias(workspace, alias, root_ref, expected_version?, policy_metadata)
resolve_aliases(workspace, aliases[]) -> root refs / manifests / miss reasons
```

This can be represented by new endpoints or by extending the existing tag publish endpoint, but the semantics must be explicit:

- root writes are immutable and idempotent;
- alias promotion is compare-and-swap or equivalent atomic update;
- a promotion conflict does not delete or corrupt the root;
- clients can distinguish promoted, conflicted, ignored, and failed.

The Rails contract must not mention GitHub-specific field names. GitHub Actions is only the first metadata adapter because the action can provide clean run metadata and benchmark artifacts. Other CI systems and local runs use the same contract by passing an explicit provider name plus run uid/attempt/timestamps, or by letting the CLI generate a local run uid when no provider metadata exists.

The canonical Rails/API decision for immutable roots, alias promotion, provider-neutral run metadata, stale promotion visibility, and future schema/API migration work lives in:

- `web/docs/adr/0001-cache-control-plane-roots-aliases-and-session-insight.md`

This CLI ADR owns Docker/BuildKit planning and proxy diagnostics. The web ADR owns API semantics and persistence.

## Promotion Policy

Initial policy should be conservative and easy to explain.

Promote branch alias when:

- the build command exits successfully;
- cache export/publish succeeds;
- the run metadata matches the alias scope;
- Rails accepts the alias version/policy.

Promote default branch alias only from default branch builds.

Promote PR alias only from the PR scope.

Do not promote on failed builds unless explicitly configured for a benchmark.

For out-of-order completions, Rails should avoid obviously stale promotion. Acceptable first policy:

- if alias is empty, promote;
- if alias points to older completed run metadata for the same source scope, promote;
- if alias points to newer run metadata, record ignored-stale promotion;
- if metadata is missing, fall back to CAS version conflict semantics and record ambiguity.

The exact run ordering field should be chosen by Rails. GitHub `run_id` is monotonic enough for GitHub-specific policy, but provider-neutral metadata should use explicit started/completed timestamps where possible.

## CLI And Action Changes

The CLI/action should:

- generate or accept immutable run-ref identity in CI;
- pass immutable run ref as Docker `--cache-to`;
- pass selected aliases as Docker `--cache-from`;
- include alias promotion intent in proxy metadata or publish requests;
- surface alias promotion result in diagnostics;
- keep current same-ref behavior as compatibility fallback during rollout.

For `boringcache docker`, multiple `--cache-from` flags are allowed. The current injection path should grow from one cache-from ref to a planned list when this feature is enabled.

Read-only Docker adapter runs should only inject `--cache-from` refs and must not promote aliases.

The CLI accepts provider-neutral run metadata through `BORINGCACHE_CI_*` environment variables. The GitHub Actions adapter is the first built-in mapper into that contract. Normal local Docker runs do not auto-generate run refs; they keep the existing `buildcache` behavior unless explicit hidden flags or provider-neutral metadata are supplied.

## Session Trace Requirements

ADR 0006 session trace should include:

- immutable run ref;
- aliases requested for import;
- aliases requested for promotion;
- alias promotion result;
- alias conflict/ignored count;
- root digest;
- run classification and cache ref generation.

This is required so benchmark artifacts can explain whether a same-tag race affected the result.

## Rollout Plan

1. Document the API contract in the web repo and update web comprehension.
2. Add CLI/action planning fields behind hidden/internal controls.
3. Teach Docker adapter dry-run JSON to show run ref, cache-from aliases, and promotion aliases.
4. Add Rails root and alias promotion API support.
5. Wire proxy publish metadata through to Rails.
6. Enable in benchmark workflows with policy-suffixed tags first.
7. Enable in `one@v1` Docker mode after benchmark artifacts prove compatibility.
8. Keep old same-ref behavior as fallback for at least one release window.

## Implementation Progress

The first hidden CLI/Rails slice is implemented:

- `boringcache docker` accepts hidden `--cache-run-ref-tag`, repeatable `--cache-from-ref-tag`, and repeatable `--cache-promote-ref-tag`;
- dry-run JSON reports immutable run ref, import refs, and promotion refs;
- Docker command injection can emit multiple `--cache-from` refs and a distinct run-ref `--cache-to`;
- read-only Docker runs still omit `--cache-to` and promotion refs;
- the proxy carries planned OCI alias promotion refs into manifest publish and records alias-promotion counters in session diagnostics;
- Rails tag publish responses now expose `promotion_status`, `promotion_reason`, and `requested_cache_entry_id` so stale/ignored alias promotion is visible without deleting the immutable root.
- focused proxy tests now simulate two immutable run refs requesting promotion to the same provider-neutral alias, proving both run refs remain readable and diagnostics distinguish `promoted` from `ignored_stale`.
- `boringcache docker` now derives immutable run refs, branch/default/PR import aliases, and promotion aliases from provider-neutral `BORINGCACHE_CI_*` metadata, with GitHub Actions `GITHUB_*` metadata as the first built-in mapper;
- CI-derived import refs include the legacy `buildcache` ref as a read fallback during the migration window, while promotion refs stay scoped to branch/default/PR policy;
- explicit hidden run/import/promotion flags still override the derived plan.

Remaining rollout work: add a dedicated backend-backed same-alias writer E2E, wire action benchmark workflows to pass provider-neutral metadata, compare artifacts, and promote the behavior to the default action path only after proof.

The concurrent writer E2E should stay provider-neutral. It should simulate two provider contexts, not GitHub-only environment variables:

```text
run A -> immutable ref A -> promote branch/main
run B -> immutable ref B -> promote branch/main
```

Expected assertions:

- both immutable roots remain readable;
- exactly one root owns `branch/main` according to promotion policy;
- the stale loser reports `ignored_stale` or conflict metadata;
- session trace records the requested aliases, promotion outcome, and immutable root.

## Proof Status

Documentation, hidden CLI/Rails contract fields, automatic CLI-side CI derivation, and focused proxy proof are aligned as of 2026-04-21. Immutable run refs and alias promotion are accepted as the correctness model; backend-backed same-alias E2E proof, action workflow wiring, benchmark artifact comparison, and default rollout remain proof-gated.

Focused evidence now available:

- `test_two_immutable_run_refs_promote_same_alias_without_losing_roots` runs two proxy manifest publishes for immutable refs `run-a` and `run-b`, both promoting `branch-main`;
- both immutable primary refs remain locally readable after the alias updates;
- alias diagnostics record one `promoted`, one `ignored_stale`, and no failed promotion.
- `detects_provider_neutral_run_context` and `detects_github_actions_run_context` cover provider-neutral and GitHub Actions run metadata detection;
- `resolve_docker_plan_derives_branch_aliases_from_ci_run_context` covers default-branch import/promotion alias planning;
- `test_docker_dry_run_json_derives_github_actions_run_refs_and_aliases` proves dry-run JSON and injected Docker flags for a GitHub Actions PR context: immutable run ref, PR/head/default imports, PR promotion, and CI metadata hints.

Benchmark and backend E2E proof are still pending. The later proof bundle must attach:

- a provider-neutral concurrent same-alias writer E2E with two immutable refs;
- API/session evidence that both roots remain readable after one alias winner is selected;
- stale/conflict promotion evidence in both Rails response fields and session trace fields;
- Docker dry-run/action artifacts showing derived run refs, import aliases, and promotion aliases;
- real-project benchmark artifacts that classify alias conflicts separately from cache misses.

The 2026-04-21 `1.12.42` release-prep push at CLI commit `14c1dc2` did not clear this gate. CLI CI passed, but the required registry E2E workflow failed before a release tag because Docker BuildKit and fresh-runner blob reads could observe visible cache roots whose referenced blobs were not yet downloadable. Follow-up `c28a7c1` cleared the Docker BuildKit and Cross-Runner Verify legs, but the overall E2E workflow still failed in Prefetch Smoke before blob download-url and fresh-cache prefetch proof. Immutable-root/promotion default rollout therefore remains pending.

## Incident Tracking: Same-Tag PostHog Writer Overlap

The 2026-04-21 PostHog Docker benchmark also exposed the same-tag risk this ADR is meant to remove. A manual rolling run overlapped with another PostHog writer for the same logical cache tag. The failed BoringCache run reached cache export, then manifest commit returned `400 blob unknown`.

The exact root cause is still tracked under ADR 0006 because the immediate failure is descriptor validation seeing a missing blob after export-time `HEAD` misses. The concurrency relevance is that both writers used the same mutable BuildKit registry ref as the read and write identity. That makes the failure harder to interpret:

- one writer can observe a miss while another writer is still uploading or publishing;
- export-time `HEAD` misses may be cached locally for a digest that becomes present moments later;
- the visible tag can move while another writer is validating its manifest;
- benchmark artifacts can confuse an alias race with a true cache miss or storage failure.

This incident strengthens the rollout requirement for immutable run refs:

```text
cache-to:   immutable run ref for this CI attempt
cache-from: branch/default aliases and optional previous run refs
promote:   branch/default aliases only after successful export
```

Release status matters for incident review:

- the failed benchmark used the released action path, `boringcache/one@v1`;
- that action currently resolves to action `v1.12.59`, which pins CLI `v1.12.41`;
- CLI `origin/main` now includes the first negative-cache and alias-promotion proof commits; `c28a7c1` has green CLI CI, Docker BuildKit E2E, and Cross-Runner Verify evidence, but the full E2E workflow still fails in Prefetch Smoke before release tagging;
- active borrowed-session follow-up work, including owned upload-session body promotion into the local blob cache, is not represented by a released CLI/action path yet;
- no benchmark should be used as release evidence for this incident unless the artifact records the action ref, CLI version, immutable run ref state, promotion status, and session trace.

The tracking proof for this ADR is a provider-neutral E2E:

1. run A writes immutable OCI run ref A and requests promotion to one branch alias;
2. run B writes immutable OCI run ref B and requests promotion to the same branch alias;
3. both roots remain readable by digest/ref regardless of alias winner;
4. one alias promotion wins according to policy and the loser is reported as stale/conflict, not as corruption;
5. no manifest publish returns `blob unknown` because of the other writer's misses or tag movement;
6. diagnostics link each manifest PUT to run ref, import aliases, promotion aliases, CLI version, and action/ref metadata.

Until this E2E exists, concurrent same-tag Docker benchmark runs are useful for finding bugs but should not be used as clean performance comparisons.

## Acceptance Gates

Before enabling in benchmarks:

- two concurrent writes to the same branch alias leave both immutable roots intact;
- exactly one alias pointer wins according to policy;
- losing/ignored promotion is visible in API response and session trace;
- read path can import from branch plus default aliases;
- read-only runs do not promote.

Before making it default:

- Docker BuildKit E2E covers concurrent same-alias writers;
- real-project benchmark uses immutable run refs and classifies alias conflicts separately from cache misses;
- first-party action workflows pass provider-neutral metadata and record the derived plan in artifacts;
- CLI/action docs explain the visible behavior without exposing internal root IDs as ordinary user ceremony;
- Rails and CLI comprehension maps are updated.

## Rejected Options

Do not serialize all builds with a global alias lock. BuildKit runs are long and should not hold a write lock for the duration of a build.

Do not keep branch aliases as the only durable cache root. A failed or losing promotion must not erase the run's immutable output.

Do not make users hand-author run refs for normal GitHub Actions usage. The action should derive them from CI metadata.

Do not solve this only in the CLI. Alias promotion policy and atomicity belong in Rails/API.
