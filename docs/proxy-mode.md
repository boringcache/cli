# Proxy mode

This page covers the proxy itself: the lower-level local endpoint path for supported native remote-cache tools.

Most teams should read [Adapter commands](adapter-commands.md) first.
Use this page when the repo already has a checked-in local endpoint setup or another process should connect to the same local endpoint.

## `cache-registry`

`cache-registry` is the proxy.
It keeps the local endpoint running as a standalone process:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000
```

That command starts in warm mode by default.
The proxy warms its current internal active tag and shared blob cache state before it reports `ready`.
That warm path improves first reads for disk-backed proxy traffic today; startup does not preseed per-repository OCI manifest refs unless they are listed explicitly with `--oci-prefetch-ref`.
OCI/BuildKit refs use a metadata-only default: selected manifests and blob download URLs are resolved before the proxy reports `ready`, then BuildKit fetches blob bodies on demand through the proxy.
That is the product path for BuildKit performance, because it avoids blocking proxy readiness or competing with large layer graphs while preserving OCI read-through diagnostics.
The lower-level hydration policy flag is hidden and reserved for diagnostics or benchmark work; normal workflows should not set it.

Use `--on-demand` only when you want the proxy to come up immediately and accept colder first reads:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000 --on-demand
```

Use it when:

- the repo already has a checked-in local endpoint setup
- another process should connect to the proxy
- you want to point several commands at the same local endpoint

If you only need the proxy for one wrapped command, use `boringcache run --proxy ...` instead.
That path temporarily starts this same proxy, waits for `ready`, runs one command, then shuts the proxy down.

Supported native protocols:

- OCI registry APIs for BuildKit
- Bazel HTTP remote cache
- Gradle HTTP build cache
- Maven build cache extension
- Nx self-hosted remote cache
- Turborepo remote cache
- sccache
- Go `GOCACHEPROG`

For Go, most teams should use `boringcache go`. Direct `go-cacheprog` wiring is the advanced/manual path when another process is already keeping `cache-registry` alive.

The proxy binds to `127.0.0.1` by default.
Use `--host 0.0.0.0` when the proxy must listen on every interface.
Use `--endpoint-host host.docker.internal` when the wrapped client must reach the proxy through a different hostname than the bind address, for example with `docker buildx build` and a containerized builder.

## Status endpoint

The proxy exposes `/_boringcache/status` for readiness and drain checks.
It reports lifecycle phase (`warming`, `ready`, `error`, `draining`) and whether publish is settled for fresh readers.
CLI-managed proxy paths wait until the proxy is ready before they start the wrapped tool.
Most users do not need to poll it during startup; warm-by-default CLI paths and internal orchestration already handle that.
Use it when an external observer needs machine-readable lifecycle or publish-settlement state.
The exact contract lives in [Proxy readiness contract](contracts/readiness.md).

## Expert tuning

Most users should rely on the default proxy behavior.

The intended expert overrides are:

- `BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY` to cap read/download parallelism
- `BORINGCACHE_PROXY_MIN_FREE_MB` to raise or lower the local free-memory pressure threshold used by adaptive prefetch
- `BORINGCACHE_PROXY_DEBUG=1` to print detailed proxy diagnostics such as prefetch, tag refresh, blob upload, flush, and per-session lines

Startup prefetch uses a separate auto budget so warmup can hydrate many-object tags quickly before the wrapped tool starts. Many-small and machine-governed tags start with a moderate adaptive window and probe upward when goodput improves. Rate limits pause replacement prefetch spawns for `Retry-After`, and resource pressure holds increases. An explicit `BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY` still caps prefetch by default; `BORINGCACHE_BLOB_PREFETCH_CONCURRENCY` exists for benchmark/proof runs that need to tune startup hydration separately.

The proxy keeps normal stderr quiet: one startup line, warnings/errors, and one shutdown summary.
Use global `--verbose`, `BORINGCACHE_PROXY_DEBUG=1`, or debug-level logging when debugging proxy internals.
