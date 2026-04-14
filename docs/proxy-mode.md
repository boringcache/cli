# Proxy mode

This page covers the lower-level proxy paths.

Most teams should read [Adapter commands](adapter-commands.md) first.
Use this page when you need one of these two cases:

1. `run --proxy` for an unsupported or custom tool
2. `cache-registry` for a long-lived local endpoint

## `run --proxy`

`run --proxy` starts the same local proxy used by adapter commands, but leaves the tool-specific wiring to you.

```bash
boringcache run --proxy build-cache -- my-custom-tool build
```

Use it when:

- the tool speaks its own remote-cache protocol
- BoringCache does not have a dedicated adapter command yet
- you still want one command to own proxy startup and shutdown

## `cache-registry`

`cache-registry` keeps the proxy running as a standalone local endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000
```

Use it when:

- the repo already has tool-specific remote-cache config checked in
- another process should connect to the proxy
- you want to point several commands at the same local endpoint

Supported native protocols:

- OCI registry APIs for BuildKit
- Bazel HTTP remote cache
- Gradle HTTP build cache
- Maven build cache extension
- Nx self-hosted remote cache
- Turborepo remote cache
- sccache
- Go `GOCACHEPROG`

The proxy binds to `127.0.0.1` by default.
Use `--host 0.0.0.0` when the proxy must listen on every interface.
Use `--endpoint-host host.docker.internal` when the wrapped client must reach the proxy through a different hostname than the bind address, for example with `docker buildx build` and a containerized builder.

## Status endpoint

The proxy exposes `/_boringcache/status` for readiness and drain checks.
It reports lifecycle phase (`warming`, `ready`, `draining`) and whether publish is settled for fresh readers.

## Expert tuning

Most users should rely on the default proxy behavior.

The intended expert overrides are:

- `BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY` to cap read/download parallelism
- `BORINGCACHE_BLOB_READ_CACHE_MAX_BYTES` to grow or shrink the local blob cache
