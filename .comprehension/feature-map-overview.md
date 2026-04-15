# Feature Map Overview

This is the shortest whole-system view of the CLI.

## Entry flow

1. `src/main.rs` sets panic/logging behavior, preprocesses args, and parses Clap.
2. `src/cli/preprocess.rs` injects default-workspace shorthand and compatibility parsing.
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
| Proxy and adapters | `cache-registry`, tool adapters, `go-cacheprog`, serve runtime | `feature-map-proxy-and-adapters.md` |
| Workspace, auth, config | `auth`, `login`, `token`, `doctor`, `dashboard`, `use`, `workspaces`, `onboard`, `audit`, `config`, `setup-encryption` | `feature-map-workspace-auth-config.md` |
| Cross-cutting support | API client, command plumbing, observability, telemetry, retry/resume, platform, progress/UI, reachability notes | `support-and-reachability.md` |

## Public command inventory

| Group | Commands | Notes |
| --- | --- | --- |
| Cache lifecycle | `save`, `restore`, `mount`, `run`, `check`, `rm`, `inspect`, `ls`, `status`, `sessions`, `misses`, `tags` | `run` is the highest-level lifecycle wrapper; `mount` is specialized and thinner on docs |
| Adapters and proxy | `cache-registry`, `turbo`, `nx`, `bazel`, `gradle`, `maven`, `sccache`, `go`, `docker`, `go-cacheprog` | `cache-registry` is the only raw proxy command |
| Workspace and account | `auth`, `login`, `token`, `doctor`, `audit`, `dashboard`, `use`, `config`, `setup-encryption`, `workspaces`, `onboard` | `onboard` is the setup funnel |

## Hidden and legacy surfaces

| Surface | Current role | Status |
| --- | --- | --- |
| `delete` | visible alias for `rm` | `legacy-visible-alias` |
| `run --archive-path`, `--archive-tag-prefix`, `--archive-restore-prefix`, `--cache-tag`, `--tool-tag-suffix` | planner-only dry-run surface | `hidden-internal` |

## Current hotspots

These are the biggest orchestration files and usually the first places to revisit when behavior changes:

| Path | Approx. size | Why it matters |
| --- | ---: | --- |
| `src/api/client/mod.rs` | 2089 lines | API transport, capability negotiation, error parsing, publish polling |
| `src/serve/cache_registry/kv/mod.rs` | 2071 lines | KV proxy policy, refresh/load behavior, blob flow, pending publish handoff |
| `src/commands/workspace/onboard.rs` | 1468 lines | auth handoff, repo scan, optimization request/review, local edits |
| `src/commands/workspace/dashboard.rs` | 1353 lines | TUI orchestration, rendering, polling, status composition |
| `src/commands/cache/restore/mod.rs` | 1376 lines | restore preflight, retries, transfer and verification |
| `src/commands/cache/run.rs` | 1023 lines | `run` planning, proxy integration, dry-run JSON, save/restore orchestration |
| `src/config.rs` | 750 lines | token/env/config resolution and persistence |

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
- `go-cacheprog`

### Present but intentionally hidden or weakly connected

- `run` planner-only flags
- helper-style optimize functions with `allow(dead_code)`
- shape-only API DTO fields marked `allow(dead_code)`
