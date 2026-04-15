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
The proxy preloads its startup slice and reports `warming` until it is ready for first reads.
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
It reports lifecycle phase (`warming`, `ready`, `draining`) and whether publish is settled for fresh readers.
CLI-managed proxy paths wait for `phase=ready` before they start the wrapped tool.
Long-lived external setups should poll this endpoint directly when they need explicit lifecycle coordination.
The exact contract lives in [Proxy readiness contract](contracts/readiness.md).

## Expert tuning

Most users should rely on the default proxy behavior.

The intended expert overrides are:

- `BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY` to cap read/download parallelism
- `BORINGCACHE_BLOB_READ_CACHE_MAX_BYTES` to grow or shrink the local blob cache
