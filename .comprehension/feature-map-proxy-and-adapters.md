# Proxy And Adapters

This file covers the local cache-registry, the tool adapters, and the serve/runtime internals behind them.

## Core shape

- `cache-registry` is the proxy.
- `cache-registry` is the standalone operator-facing proxy command.
- Adapter commands either start that proxy in the background or hand off to a small helper.
- `src/serve/**` is the real proxy runtime.
- `src/proxy/**` is the CLI-side wrapper around tag derivation, child command launch, and proxy startup.

## Feature map

| Feature | Entry points | Status | Primary code | Key shared modules | Evidence of use | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Standalone cache proxy | `cache-registry WORKSPACE TAG` with `--port`, `--host`, `--no-platform`, `--no-git`, `--metadata-hint`, `--oci-prefetch-ref`, `--oci-hydration`, `--on-demand`, `--fail-on-cache-error`, `--read-only` | `public-primary` | `src/cli/proxy.rs`, `src/cli/app.rs`, `src/commands/proxy/cache_registry.rs` | `tag_utils`, `proxy::tags`, `serve::runtime`, `serve::state`, `serve::cache_registry` | `tests/integration_tests.rs`, `tests/workspace_injection_tests.rs`, `tests/run_proxy_e2e_tests.rs`, `docs/proxy-mode.md`, `README.md` | Warm-first raw proxy command; `--on-demand` is the expert cold-start override. `--oci-hydration` is an OCI/BuildKit-only selected-ref policy, not a generic adapter warmup switch. |
| One-shot proxy wrapper | `run --proxy TAG -- COMMAND...` | `public-primary` | `src/commands/cache/run.rs` | `cache_registry::start_proxy_background`, `proxy::spawn_command`, archive `restore`/`save` helpers | `tests/run_proxy_e2e_tests.rs`, `docs/tool-guides.md`, `docs/contracts/readiness.md` | Temporarily starts the same proxy for one command, waits on shared readiness, then shuts it down |
| Proxy runtime and readiness | same proxy command plus runtime status endpoint behavior | `support-primary`, `internal-only` | `src/serve/runtime/mod.rs`, `src/serve/runtime/listener.rs`, `src/serve/runtime/maintenance.rs`, `src/serve/runtime/shutdown.rs`, `src/serve/http/routes.rs`, `src/serve/http/handlers/mod.rs` | `AppState`, `BlobReadCache`, `PrefetchMetrics`, maintenance loop, shutdown handoff | `tests/serve_tests.rs`, `docs/proxy-mode.md`, `docs/contracts/readiness.md`, `docs/performance-learning-log.md` | Backs shared readiness state, the hidden ready-file orchestration handoff, `/_boringcache/status`, on-demand bypass, and shutdown publish behavior. OCI publish fallback warnings include the underlying phase error instead of only the generic status. |
| Registry protocol dispatch | proxy-side OCI/Bazel/Gradle/Maven/Nx/Turborepo/sccache/Go protocol handling | `support-primary`, `internal-only` | `src/serve/cache_registry/mod.rs`, `src/serve/cache_registry/route.rs`, `src/serve/cache_registry/bazel.rs`, `gradle.rs`, `maven.rs`, `nx.rs`, `turborepo.rs`, `sccache.rs`, `go_cache.rs` | `cache_ops`, `kv_publish`, `upload_sessions`, `blob_read_cache`, `AppState` | broad protocol coverage in `tests/serve_tests.rs`, context in `docs/adapter-cache-profiles.md` | This is the heart of the proxy feature, but not a separate CLI surface. OCI selected-ref startup has three body policies: metadata-only, bodies-before-ready, and bodies-background. Non-OCI adapters keep the existing KV proxy behavior. OCI blob upload planning, per-blob upload, and batch upload completion emit JSONL observability events. |
| KV proxy core | internal KV registry behavior for lookup, write, publish, preload, and flush/shutdown settlement | `support-primary`, `internal-only` | `src/serve/cache_registry/kv/mod.rs`, `src/serve/cache_registry/kv/blob_read.rs`, `index.rs`, `lookup.rs`, `prefetch.rs`, `write.rs`, `flush.rs` | published index state, blob read cache, flush/publish coordination, observability | unit and scenario tests in `src/serve/cache_registry/kv/mod.rs`, `tests/serve_tests.rs`, operational notes in `docs/performance-learning-log.md` | The active tree keeps the remaining publish/refresh orchestration in `flush.rs`; update this row if that code is extracted again |
| Adapter command framework | `turbo`, `nx`, `bazel`, `gradle`, `maven`, `sccache`, `go`, `docker` with common adapter flags | `public-primary` | `src/cli/adapters.rs`, `src/commands/adapters/command/mod.rs`, `src/commands/adapters/mod.rs` | `project_config`, `command_support`, `proxy`, `serve`, `save`, `restore`, `tag_utils`, `git` | `tests/integration_tests.rs`, `docs/adapter-commands.md`, `docs/github-actions.md`, `docs/tool-guides.md` | Shared dry-run JSON, repo-config resolution, proxy startup, and command execution |
| Docker adapter | `docker` with `--cache-mode`, `--cache-ref-tag`, `--oci-hydration`, shared adapter flags | `public-primary` | `src/commands/adapters/command/docker.rs`, `src/commands/adapters/command/mod.rs` | `ProxyContext`, `cache_registry::start_proxy_background`, `proxy::command`, Docker plan resolver | `src/commands/adapters/command/docker.rs` tests, `tests/run_command_tests.rs`, `tests/run_proxy_e2e_tests.rs`, `docs/tool-guides.md` | `--tag` is the proxy cache tag; `--cache-ref-tag` is the OCI cache tag. Read-only Docker adapter runs use on-demand proxy startup and do not auto-prefetch the cache ref, so restore-only CI jobs avoid full tag hydration before BuildKit asks for blobs. `--oci-hydration bodies-before-ready` is the strict local-registry edge for selected refs. |
| Turbo/Nx/sccache/Go wrapper env wiring | `turbo`, `nx`, `sccache`, `go` | `public-primary` | `src/commands/adapters/command/turbo.rs`, `nx.rs`, `sccache.rs`, `go.rs` | `ProxyContext`, environment injection, `PROXY_AUTH_TOKEN` | `tests/run_proxy_e2e_tests.rs`, per-tool docs in `docs/tool-guides.md` | These are more opinionated than Bazel/Gradle/Maven because they wire more env/protocol details directly |
| Bazel/Gradle/Maven passthrough wrappers | `bazel`, `gradle`, `maven` | `public-primary`, `lightly-used` | `src/commands/adapters/command/bazel.rs`, `gradle.rs`, `maven.rs` | shared adapter lifecycle in `command/mod.rs`, proxy startup | protocol tests in `tests/serve_tests.rs`, tool guides in `docs/tool-guides.md` | Real support, but thinner wrappers because more config stays in the tool or repo |
| Go cacheprog helper | `go-cacheprog --endpoint ... [--token ...]` with env fallbacks | `lightly-used` | `src/commands/adapters/go_cacheprog.rs`, `src/cli/proxy.rs`, `src/cli/app.rs` | direct HTTP client path, used by `go` adapter and manual proxy setups | unit tests in `src/commands/adapters/go_cacheprog.rs`, `docs/tool-guides.md`, `docs/proxy-mode.md` | Supported advanced helper for manual `GOCACHEPROG` wiring, not a headline adapter workflow |
| Tag resolution and registry-root derivation | shared across proxy and adapters via `--no-platform`, `--no-git`, `--tag`, `--endpoint-host` | `support-primary` | `src/tag_utils.rs`, `src/proxy/tags.rs`, `src/serve/http/oci_tags.rs`, parts of `src/commands/proxy/cache_registry.rs` | `platform`, `git`, registry root tag hashing, OCI tag helpers | unit tests in `src/tag_utils.rs`, `src/commands/proxy/cache_registry.rs`, `src/serve/http/handlers/mod.rs` | OCI manifest refs are scoped under the registry root tag, with legacy unscoped restore fallback, so `cache:buildcache` cannot collide across configured registry proxy tags |

## Current active internals

These are internal, but they are clearly active, not dead:

- `src/serve/runtime/**`
- `src/serve/http/**`
- `src/serve/cache_registry/**`
- `src/serve/state/**`
- `src/proxy/command.rs`
- `src/proxy/tags.rs`

## Thin or weakly connected surfaces in this family

- `go-cacheprog` is supported, but only as an advanced helper behind `go` or manual `GOCACHEPROG` setups
- `bazel`, `gradle`, and `maven` are supported, but thinner wrappers than `docker`, `turbo`, `nx`, and `sccache`
- workspace shorthand preprocessing is support glue, not a separate product feature

## Current tree note

The KV path is active and still concentrated in `src/serve/cache_registry/kv/flush.rs` and `src/serve/cache_registry/kv/mod.rs`. Update this file if those responsibilities split into new helper modules later.
