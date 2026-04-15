# Intent And Context Gaps

This file separates:

1. intent that is already clear from the product, docs, or code
2. context that is still missing and is best supplied by a product owner

The goal is to avoid asking for intent where the codebase already answers it.

## What is already clear

These do not need more product input unless you want to change direction.

### Setup and workspace flow

- `onboard` is the default getting-started path.
- `auth --token` is the noninteractive bootstrap path.
- `login` is the interactive terminal sign-in path.
- `workspaces` and `use` establish and persist default workspace context.
- `audit --write` is the migration/import path, not the default onboarding path.

### Cache model

- archive mode is the default simple workflow
- `run` is the primary archive-mode command
- `save` and `restore` are the split lower-level form
- tag suffixing by git and platform is part of cache identity, not presentation
- signature verification is warn-only by default unless explicit strictness is requested
- encryption is workspace-scoped and Age-based when configured

### Proxy and adapter split

- adapter commands are the preferred path for supported remote-cache tools
- `cache-registry` is the lower-level long-lived endpoint path
- `/_boringcache/status` is the operator/harness lifecycle endpoint, not the cache protocol surface
- Bazel, Gradle, and Maven are intentionally thinner wrappers today
- Docker, Turbo, Nx, sccache, and Go own more automatic tool wiring

### Repo-config and planning

- `.boringcache.toml` is the home for repeated command shape, entries, profiles, and adapter setup
- `project_config/**` is intentionally the planner for `run` and adapters
- command inference exists as convenience when repo config and command shape make it possible

## Decisions captured from owner review

These are decisions or strong direction already provided and should be treated as the current intent unless changed explicitly.

### Product surface

- `mount`, `dashboard`, `doctor`, `setup-encryption`, and `go-cacheprog` are intended as real core commands, not hidden support-only tooling.
- `status`, `sessions`, `misses`, and `tags` are intended as first-class operational surfaces.
- The CLI is meant to complement the web UI and TUI, not replace them.

### Machine contracts

- JSON outputs and dry-run plan outputs are intended to be stable contracts because CI and automation rely on them.
- Proxy/runtime readiness is intended to be a machine-consumable contract for CI and automation.

### Auth and failure policy

- Proxy and adapter flows should degrade gracefully when write auth is missing.
- Restore/save/admin token scopes are intended as hard guarantees.
- `delete` is intended to remain admin-only.

### Repo config and adapters

- `.boringcache.toml` is the intended canonical repo-config filename.
- CLI flags should be able to override repo config where needed.
- Archive, CAS, OCI, and file cache layouts are all intended to stay first-class, with archive as the direct save/restore path and CAS/OCI/file backing tool-oriented flows.
- Adapters should stay thin where possible because the CLI should provide cache plumbing rather than tool-specific orchestration.

### Cleanup direction

- Duplicate compatibility surfaces should be reviewed aggressively and removed when they are not serving a clear user need.
- User-visible behavior should stay unsurprising and focused on cache workflows rather than exposing unnecessary internal helpers.
- Dormant scaffolding and compatibility-heavy leftovers are cleanup targets.
- The canonical naming cleanup kept `run`, `dashboard`, `inspect`, `status`, `cache-registry`, `--no-platform`, `.boringcache.toml`, and the token subcommand names `list` and `create-ci`; the broader token admin surface still includes `show`, `create`, `revoke`, and `rotate`.

## Remaining gaps after that review

These are the places where the current product shape is still not fully decided by code/docs plus the owner review above.

## P1: Product-surface decisions

These matter most because they affect docs, naming, maintenance, and what stays first-class.

1. Canonical naming and alias policy
   - Resolved direction:
     - duplicate command aliases should be removed aggressively
     - `cache-registry` remains as the single explicit raw proxy command
     - direct adapter commands still exist for Docker, Turbo, Nx, Bazel, Gradle, Maven, sccache, and Go
   - Implemented cleanup:
     - removed `serve`, `docker-registry`, `exec`, `tui`, `show`, `overview`, `token ls`, `token ci`, `--cross-os`, and hidden `optimize`
     - kept `run`, `dashboard`, `inspect`, `status`, `cache-registry`, `--no-platform`, `.boringcache.toml`, and the canonical token subcommand names `list` and `create-ci`
     - retained the broader token admin surface: `show`, `create`, `revoke`, and `rotate`
   - Remaining compatibility question:
     - legacy release asset aliases such as distro-specific binary names

2. First-class vs advanced surfaces
   - Resolved direction:
     - `mount`, `dashboard`, `doctor`, `setup-encryption`, and `go-cacheprog` are real product commands
     - `status`, `sessions`, `misses`, and `tags` are all first-class operational surfaces
   - Remaining documentation question:
     - how strongly to present each one in docs and onboarding versus keeping some as secondary but supported tools

3. Machine-contract stability
   - Resolved direction:
     - yes, the `--json` outputs and dry-run plans are intended to be stable machine contracts for CI and scripts
   - The main remaining work is to write down and version the exact supported schemas for:
     - `check`
     - `inspect`
     - `ls`
     - `status`
     - `sessions`
     - `misses`
     - `tags`
     - `run --dry-run --json`
     - adapter `--dry-run --json`
     - `doctor`
     - `workspaces`
     - `use`
     - `config`
     - `audit`
     - `onboard`
     - `token * --json`
   - There are also two unrelated status-shaped machine surfaces today:
     - `boringcache status --json` for workspace analytics
     - `/_boringcache/status` for proxy runtime state
   - Remaining decision:
     - whether both should be documented as stable public contracts, and how explicitly they are separated for tooling users

4. Auth and failure policy for proxy/adapter flows
   - Resolved direction:
     - graceful degradation is intended
     - restore/save/admin token access levels are hard guarantees
     - `delete` is permanently admin-only
   - Remaining detail:
     - whether proxy read-only downgrade should remain implicit or become an explicit user-visible mode/message contract

5. Canonical readiness and runtime-state probe
   - Resolved direction:
     - readiness/runtime state is intended as a stable machine contract for CI
   - There are still two probe surfaces with different semantics today:
     - `/v2/` exposes prefetch readiness through headers
     - `/_boringcache/status` exposes runtime phase and publish-settlement state
   - Decide which one external callers should use for:
     - "proxy has started"
     - "proxy is ready for traffic"
     - "publish has settled and tags are visible"
   - Also decide whether backend/cache errors may intentionally degrade into cache misses on read paths, or whether tooling should be able to distinguish infrastructure failure from an expected miss.

## P2: Format and support-strategy decisions

These matter for future refactors and cleanup.

6. Canonical cache-layout strategy
   - Resolved direction:
     - archive, CAS, OCI, and file layouts all remain first-class
     - archive is the direct directory save/restore surface
     - CAS/OCI/file are core tool-facing cache transports, not second-class compatibility leftovers

7. Repo-config discovery and filename policy
   - `.boringcache.toml` is the intended canonical filename.
   - Code reality today:
     - `discover()` accepts only `.boringcache.toml`
     - ancestor search stops at the first matching file
     - nested configs do not merge
   - In this repo, only `.boringcache.toml` currently exists.
   - Remaining decision:
     - whether first-match ancestor shadowing is the intended permanent behavior

8. Built-in repo-config behavior
   - Direction from review:
     - built-ins are acceptable product behavior and the CLI should remain convenient
   - Active code behavior worth locking down explicitly:
     - built-in aliases like `npm` -> `npm-cache` and `node-modules` -> `node_modules`
     - path resolution precedence (`path` -> `path_env` -> `default_path` -> env lookup -> dynamic fallback -> built-in default)
     - env exports such as `BUNDLE_PATH`, `GOMODCACHE`, `GOCACHE`, `COMPOSER_CACHE_DIR`
     - extra env mutation such as `YARN_ENABLE_GLOBAL_CACHE=false`
     - command inference scope, which is currently narrow (`bundle install`, `mise install`, `npm install/ci`, `pnpm install/i`, `yarn install`, `uv sync/pip`)
   - Remaining decision:
     - whether all of the above should be treated as stable product contract versus convenient defaults that may evolve cautiously

9. Adapter defaulting and merge strategy
   - Direction from review:
     - CLI should be able to override config where needed
   - Adapter behavior currently includes:
     - implicit tag fallback from explicit config to `GITHUB_REPOSITORY` basename to adapter name
     - merge rules for config vs CLI entries/profiles/metadata
     - baked-in defaults like Docker `cache_mode=max` and `cache_ref_tag=buildcache`
   - Remaining decision:
     - whether list-like inputs should merge or whether CLI should fully override config in all cases
     - whether Docker compatibility input `--tag proxy-tag:ref-tag` should be kept or retired in favor of `--cache-ref-tag`

10. Thin-adapter strategy
   - Resolved direction:
     - adapters should stay thin where possible because the CLI should provide cache plumbing rather than tool-specific ownership

## P3: Cleanup and dormant-code decisions

These are not blocking for users, but they matter for maintenance clarity.

11. Hidden compatibility surfaces
   - Current direction:
     - review and remove duplicate compatibility surfaces aggressively
   - Surfaces currently in scope:
     - Docker `--tag proxy-tag:ref-tag` compatibility input
     - legacy release asset names
   - Remaining decisions:
     - whether Docker `--tag proxy-tag:ref-tag` should be removed now
     - whether legacy release asset aliases still need a migration window

12. Dormant or weakly connected code
   - Current cleanup target direction:
     - remove dormant scaffolding rather than keeping speculative code around
   - Current state after cleanup:
     - `TelemetryCollector` and related debug exports were removed; the active telemetry surface is the save/restore metrics path
     - `ResumeInfo` / `UploadResumeInfo` were removed; `RetryConfig` remains as the active retry helper used by the HTTP client
   - Caution:
     - capability negotiation and pending-publish acceptance logic are not obviously the same class of dead code; some of it may still be active protocol compatibility rather than removable scaffolding

13. User-visible vs internal helper surfaces
   - Direction from review:
     - avoid surprising users and keep the product focused on cache workflows
   - Remaining decisions:
     - whether `go-cacheprog` should stay explicitly documented as a direct command or be treated as secondary plumbing behind the `go` adapter
     - whether proxy-root deletion during `delete` should remain a documented guarantee or just an implementation detail of "delete removes associated cache data"

## Highest-value remaining answers

If you only want to finish the remaining open questions, these seven decisions cover most of the uncertainty:

1. Which readiness probe is canonical for automation: `/v2/`, `/_boringcache/status`, or both with distinct meanings?
2. Should built-in repo-config aliases/env exports/path precedence/inference be treated as stable product contract or careful convenience behavior?
3. For adapter config, should CLI always fully override config, or should some list-like settings continue to merge?
4. Should Docker compatibility input `--tag proxy-tag:ref-tag` be retired in favor of `--cache-ref-tag`?
5. Which legacy release asset aliases still need a migration window?
6. Which compatibility-heavy adapter inputs or release-name aliases are still worth keeping?
7. Should `go-cacheprog` stay explicitly documented as a direct command or be treated as secondary plumbing behind the `go` adapter?

## Suggested working assumptions until you answer

These are the least risky assumptions for ongoing maintenance:

- keep `onboard`, `run`, adapters, and workspace selection as the main product surface
- treat `mount`, `dashboard`, `doctor`, `setup-encryption`, and `go-cacheprog` as supported core surfaces
- treat `--json` outputs and dry-run plans as stable contracts
- treat `.boringcache.toml` as the only supported repo-config filename
- treat built-in entry aliases, env exports, and inference as active behavior that should be changed cautiously until the product contract is written down
- treat dormant telemetry/resume code as cleanup candidates unless a concrete roadmap depends on them
