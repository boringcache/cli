# Feature Map Overview

This is the shortest whole-system view of the CLI.

## Entry flow

1. `src/main.rs` sets panic/logging behavior, preprocesses args, and parses Clap.
2. `src/cli/preprocess.rs` injects default-workspace shorthand before Clap parsing.
3. `src/cli/dispatch.rs` routes every command into `src/commands/**`.
4. `src/commands/**` owns command orchestration.
5. Shared execution logic lives in:
   - `src/cache/**` for archive and CAS lifecycle work
   - `src/proxy/**` and `src/serve/**` for the local cache-registry
   - `src/project_config/**` for `.boringcache.toml` planning
   - `src/api/**` for server transport and models
   - `src/command_support/**` for workspace, spec parsing, concurrency, and save helpers

## Feature families

| Family | What lives here | Primary docs |
| --- | --- | --- |
| Cache lifecycle | `save`, `restore`, `mount`, `run`, plus cache inspection/reporting commands | `feature-map-cache-lifecycle.md` |
| Proxy and adapters | `cache-registry`, tool adapters, serve runtime, advanced helper wiring | `feature-map-proxy-and-adapters.md` |
| Workspace, auth, config | `auth`, `login`, `token`, `doctor`, `dashboard`, `use`, `workspaces`, `onboard`, `audit`, `config`, `setup-encryption` | `feature-map-workspace-auth-config.md` |
| Cross-cutting support | API client, command plumbing, observability, telemetry, retry, platform, progress/UI, reachability notes | `support-and-reachability.md` |

## Public command inventory

| Group | Commands | Notes |
| --- | --- | --- |
| Cache lifecycle | `save`, `restore`, `mount`, `run`, `check`, `rm`, `inspect`, `ls`, `status`, `sessions`, `misses`, `tags` | `run` is the highest-level lifecycle wrapper; `mount` is specialized and thinner on docs |
| Adapters and proxy | `cache-registry`, `turbo`, `nx`, `bazel`, `gradle`, `maven`, `sccache`, `go`, `docker`, `go-cacheprog` | `cache-registry` is the proxy; adapters temporarily start that proxy for one tool run; `go-cacheprog` is a supported advanced helper for manual Go wiring |
| Workspace and account | `auth`, `login`, `token`, `doctor`, `audit`, `dashboard`, `use`, `config`, `setup-encryption`, `workspaces`, `onboard` | `onboard` is the setup funnel |

## Hidden and legacy surfaces

| Surface | Current role | Status |
| --- | --- | --- |
| `delete` | visible alias for `rm` | `legacy-visible-alias` |
| `run --archive-path`, `--archive-tag-prefix`, `--archive-restore-prefix`, `--cache-tag`, `--tool-tag-suffix` | planner-only dry-run surface | `hidden-internal` |
| `cache-registry --ready-file PATH` | detached orchestration readiness handoff | `hidden-internal` |
| `cache-registry --oci-alias-promotion-ref REF` | internal ADR 0007 E2E/proof hook for planned OCI alias promotion refs | `hidden-internal` |

## Current hotspots

These are the biggest orchestration files and usually the first places to revisit when behavior changes:

| Path | Approx. size | Why it matters |
| --- | ---: | --- |
| `src/api/client/mod.rs` | 2089 lines | API transport, capability negotiation, error parsing, publish polling |
| `src/commands/workspace/onboard.rs` | 1468 lines | auth handoff, repo scan, optimization request/review, local edits |
| `src/commands/cache/restore/mod.rs` | 1376 lines | restore preflight, retries, transfer and verification |
| `src/commands/workspace/dashboard.rs` | 1353 lines | TUI orchestration, rendering, polling, status composition |
| `src/serve/cache_registry/kv/mod.rs` | 923 lines | KV env tuning constants, root re-exports, and test scaffolding |
| `src/commands/cache/run.rs` | 1023 lines | `run` planning, proxy integration, dry-run JSON, save/restore orchestration |
| `src/encryption/mod.rs` + `src/encryption/**` | 365 lines across focused modules | lifecycle encryption, identity handling, passphrase flow |

## What is clearly first-class vs thinner

### First-class

- `onboard`
- `save`
- `restore`
- `run`
- `cache-registry`
- adapter commands as a family
- `auth` / `login` / `workspaces`

### Real but thinner or less documented

- `mount`
- `doctor`
- `dashboard`
- `use`
- `config`
- `setup-encryption`
- `inspect`
- `sessions`
- `misses`
- `tags`
- `go-cacheprog` as an advanced helper for manual `GOCACHEPROG` setups

### Present but intentionally hidden or weakly connected

- `run` planner-only flags
- helper-style optimize functions with `allow(dead_code)`
- shape-only API DTO fields marked `allow(dead_code)`
