# Proxy And Adapters

This file covers the local cache-registry, the tool adapters, and the serve/runtime internals behind them.

## Core shape

- `cache-registry` is the standalone operator-facing proxy command.
- Adapter commands either start that proxy in the background or hand off to a small helper.
- `src/serve/**` is the real proxy runtime.
- `src/proxy/**` is the CLI-side wrapper around tag derivation, child command launch, and proxy startup.

## Feature map

| Feature | Entry points | Status | Primary code | Key shared modules | Evidence of use | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Standalone cache proxy | `cache-registry WORKSPACE TAG` with `--port`, `--host`, `--no-platform`, `--no-git`, `--metadata-hint`, `--fail-on-cache-error`, `--read-only` | `public-primary` | `src/cli/proxy.rs`, `src/commands/proxy/cache_registry.rs`, `src/cli.rs` | `tag_utils`, `proxy::tags`, `serve::runtime`, `serve::state`, `serve::cache_registry` | `tests/integration_tests.rs`, `tests/workspace_injection_tests.rs`, `tests/run_proxy_e2e_tests.rs`, `docs/proxy-mode.md`, `README.md` | Single canonical raw proxy command after alias cleanup |
| Proxy runtime and readiness | same proxy command plus runtime status endpoint behavior | `support-primary`, `internal-only` | `src/serve/runtime/mod.rs`, `src/serve/runtime/listener.rs`, `src/serve/runtime/maintenance.rs`, `src/serve/runtime/shutdown.rs`, `src/serve/http/routes.rs`, `src/serve/http/handlers/mod.rs` | `AppState`, `BlobReadCache`, `PrefetchMetrics`, maintenance loop, shutdown handoff | `tests/serve_tests.rs`, `docs/proxy-mode.md`, `docs/performance-learning-log.md` | Backs `/_boringcache/status`, warmup/drain state, and shutdown publish behavior |
| Registry protocol dispatch | proxy-side OCI/Bazel/Gradle/Maven/Nx/Turborepo/sccache/Go protocol handling | `support-primary`, `internal-only` | `src/serve/cache_registry/mod.rs`, `src/serve/cache_registry/route.rs`, `src/serve/cache_registry/bazel.rs`, `gradle.rs`, `maven.rs`, `nx.rs`, `turborepo.rs`, `sccache.rs`, `go_cache.rs` | `cache_ops`, `kv_publish`, `upload_sessions`, `blob_read_cache`, `AppState` | broad protocol coverage in `tests/serve_tests.rs`, context in `docs/adapter-cache-profiles.md` | This is the heart of the proxy feature, but not a separate CLI surface |
| KV proxy core | internal KV registry behavior for lookup, write, publish, refresh, preload, and handoff | `support-primary`, `internal-only` | `src/serve/cache_registry/kv/mod.rs`, `src/serve/cache_registry/kv/blob_read.rs`, `index.rs`, `lookup.rs`, `prefetch.rs`, `write.rs`, `flush.rs`, `refresh.rs`, `flight.rs` | published index state, pending publish handoff, blob read cache, observability, refresh fencing | unit and scenario tests in `src/serve/cache_registry/kv/mod.rs`, `tests/serve_tests.rs`, operational notes in `docs/performance-learning-log.md` | Current worktree shows active extraction into `refresh.rs` and `flight.rs`; keep this section updated as the split settles |
| Adapter command framework | `turbo`, `nx`, `bazel`, `gradle`, `maven`, `sccache`, `go`, `docker` with common adapter flags | `public-primary` | `src/cli/adapters.rs`, `src/commands/adapters/command/mod.rs`, `src/commands/adapters/mod.rs` | `project_config`, `command_support`, `proxy`, `serve`, `save`, `restore`, `tag_utils`, `git` | `tests/integration_tests.rs`, `docs/adapter-commands.md`, `docs/github-actions.md`, `docs/tool-guides.md` | Shared dry-run JSON, repo-config resolution, proxy startup, and command execution |
| Docker adapter | `docker` with `--cache-mode`, `--cache-ref-tag`, shared adapter flags | `public-primary` | `src/commands/adapters/command/docker.rs`, `src/commands/adapters/command/mod.rs` | `ProxyContext`, `cache_registry::start_proxy_background`, `proxy::command`, Docker plan resolver | `src/commands/adapters/command/docker.rs` tests, `tests/run_proxy_e2e_tests.rs`, `docs/tool-guides.md` | Has a compatibility path for embedded `tag:ref-tag`; preferred split is `--tag` plus `--cache-ref-tag` |
| Turbo/Nx/sccache/Go wrapper env wiring | `turbo`, `nx`, `sccache`, `go` | `public-primary` | `src/commands/adapters/command/turbo.rs`, `nx.rs`, `sccache.rs`, `go.rs` | `ProxyContext`, environment injection, `PROXY_AUTH_TOKEN` | `tests/run_proxy_e2e_tests.rs`, per-tool docs in `docs/tool-guides.md` | These are more opinionated than Bazel/Gradle/Maven because they wire more env/protocol details directly |
| Bazel/Gradle/Maven passthrough wrappers | `bazel`, `gradle`, `maven` | `public-primary`, `lightly-used` | `src/commands/adapters/command/bazel.rs`, `gradle.rs`, `maven.rs` | shared adapter lifecycle in `command/mod.rs`, proxy startup | protocol tests in `tests/serve_tests.rs`, tool guides in `docs/tool-guides.md` | Real support, but thinner wrappers because more config stays in the tool or repo |
| Go cacheprog helper | `go-cacheprog --endpoint ... [--token ...]` with env fallbacks | `public-primary`, `lightly-used` | `src/commands/adapters/go_cacheprog.rs`, `src/cli/proxy.rs`, `src/cli.rs` | direct HTTP client path, used by `go` adapter and manual proxy setups | unit tests in `src/commands/adapters/go_cacheprog.rs`, `docs/tool-guides.md`, `docs/proxy-mode.md` | Real feature, but more helper-like than the main adapter framework |
| Tag resolution and registry-root derivation | shared across proxy and adapters via `--no-platform`, `--no-git`, `--tag`, `--endpoint-host` | `support-primary` | `src/tag_utils.rs`, `src/proxy/tags.rs`, `src/serve/http/oci_tags.rs`, parts of `src/commands/proxy/cache_registry.rs` | `platform`, `git`, registry root tag hashing, OCI tag helpers | unit tests in `src/tag_utils.rs`, `src/commands/proxy/cache_registry.rs`, `src/serve/http/handlers/mod.rs` | Public behavior depends on this, but the helpers themselves are internal plumbing |

## Current active internals

These are internal, but they are clearly active, not dead:

- `src/serve/runtime/**`
- `src/serve/http/**`
- `src/serve/cache_registry/**`
- `src/serve/state/**`
- `src/proxy/command.rs`
- `src/proxy/tags.rs`

## Thin or weakly connected surfaces in this family

- `go-cacheprog` is real, but helper-like relative to `cache-registry` and the adapters
- `bazel`, `gradle`, and `maven` are supported, but thinner wrappers than `docker`, `turbo`, `nx`, and `sccache`
- workspace shorthand preprocessing is support glue, not a separate product feature

## Current worktree note

The KV path is currently mid-refactor:

- `src/serve/cache_registry/kv/flush.rs` is modified
- `src/serve/cache_registry/kv/mod.rs` is modified
- `src/serve/cache_registry/kv/flight.rs` is present as a new split
- `src/serve/cache_registry/kv/refresh.rs` is part of the current split

That means this file should be updated again if the KV submodule boundaries settle differently.
