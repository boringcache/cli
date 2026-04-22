# Intent And Context Gaps

This file tracks only product intent that is not fully settled by the current code, docs, and owner direction.

## Already Clear

- `onboard` is the default getting-started path.
- `auth --token` is the noninteractive bootstrap path.
- `login` is the interactive terminal sign-in path.
- `workspaces` and `use` establish default workspace context.
- `audit --write` is a migration/import helper, not the default onboarding path.
- Archive mode is the default direct save/restore workflow.
- `run` is the primary archive-mode command; `save` and `restore` are the split lower-level commands.
- Tag suffixing by git and platform is part of cache identity.
- Signature verification is warn-only by default unless explicit strictness is requested.
- Encryption is workspace-scoped and Age-based when configured.
- Adapter commands are the preferred path for supported remote-cache tools.
- `cache-registry` is the explicit raw proxy command.
- `run --proxy` temporarily starts that same proxy for one command.
- `/_boringcache/status` is the operator/harness lifecycle endpoint, not the cache protocol surface.
- `.boringcache.toml` is the canonical repo config filename.
- `project_config/**` is intentionally the planner for `run` and adapters.
- `mount`, `dashboard`, `doctor`, `setup-encryption`, `status`, `sessions`, `misses`, and `tags` are supported product surfaces.
- `go-cacheprog` is supported as advanced plumbing behind the `go` adapter and manual `GOCACHEPROG` setups.
- Archive, CAS, OCI, and file layouts are all first-class cache transports.
- Duplicate compatibility surfaces and dormant scaffolding are cleanup targets unless they serve a clear user need.

## Open Decisions

### 1. ADR Release Proof Gaps

The current ADR set is aligned on implementation direction, and the first receipt-strict registry proof is done: commit `83e547e` cleared Docker BuildKit, Prefetch Smoke, and Cross-Runner Verify without verifier-side blob URL readiness polling. These gates still block release/default claims:

- receipt commit failure, including a backend "blob not yet verified" confirm response, should continue to fail OCI/KV publish instead of waiting for asynchronous storage verification;
- E2E publish/read checks now fail fast by default: remote tag verification has one attempt, local post-save visibility checks do not poll, prefetch seed does not wait for publish-settled before shutdown, Docker registry export retries are opt-in, and any retry must be an explicit diagnostic override rather than a hidden correctness dependency;
- first-party action workflows still need to pass and artifact provider-neutral Docker run metadata;
- backend-backed same-alias writer E2E is the selected ADR 0007 proof gate; the required direct-OCI harness is locally green against Rails with two live writer proxies, immutable refs, stale alias promotion, zero alias-promotion failures, and fresh-proxy reads proven, and CI still needs to carry that evidence;
- stream-through and cache-admission changes remain benchmark-gated before any default threshold or policy change.

### 2. Machine-Readable Output Contracts

`--json` outputs and dry-run plans are intended to be stable machine contracts. The remaining work is to write down and version exact schemas for command outputs such as `check`, `inspect`, `ls`, `status`, `sessions`, `misses`, `tags`, `run --dry-run --json`, adapter dry runs, `doctor`, `workspaces`, `use`, `config`, `audit`, `onboard`, and `token * --json`.

Also decide how explicitly to separate the two status-shaped surfaces:

- `boringcache status --json` for workspace analytics
- `/_boringcache/status` for proxy runtime state

### 3. Proxy Read Failure Semantics

Decide whether backend/cache errors may intentionally degrade into cache misses on read paths, or whether tooling should always be able to distinguish infrastructure failure from an expected miss.

### 4. Repo Config Stability

Decide which built-in repo-config behaviors are stable product contract versus careful convenience behavior:

- built-in aliases such as `npm` -> `npm-cache` and `node-modules` -> `node_modules`
- path resolution precedence
- env exports such as `BUNDLE_PATH`, `GOMODCACHE`, `GOCACHE`, and `COMPOSER_CACHE_DIR`
- extra env mutation such as `YARN_ENABLE_GLOBAL_CACHE=false`
- command inference scope
- first-match ancestor shadowing for nested `.boringcache.toml`

### 5. Adapter Merge Strategy

CLI flags should override config where needed. The remaining question is whether any list-like settings should be additive beyond the current metadata-hint merge behavior.

### 6. Compatibility Alias Retention

The remaining known compatibility question is whether legacy release asset aliases, such as distro-specific binary names, still need a migration window.

### 7. Proxy Delete Contract

Decide whether proxy-root deletion during `delete` should remain a documented guarantee or just an implementation detail of "delete removes associated cache data."

## Working Assumptions

- Keep `onboard`, `run`, adapters, and workspace selection as the main product surface.
- Treat `mount`, `dashboard`, `doctor`, and `setup-encryption` as supported core surfaces.
- Treat `go-cacheprog` as supported advanced helper plumbing, not a headline workflow.
- Treat `--json` outputs and dry-run plans as stable contracts until versioned schemas say otherwise.
- Treat `.boringcache.toml` as the only supported repo-config filename.
- Treat built-in entry aliases, env exports, and inference as active behavior that should change cautiously.
