# Proxy mode

Proxy mode is for build tools that already know how to talk to a remote cache.

Use adapter commands when you want the CLI to start a local cache endpoint around one command and inject only the tool-specific settings that matter:

```bash
boringcache nx --tag build-cache -- nx run-many --target=build
boringcache turbo --tag build-cache -- turbo run build
boringcache sccache --tag rust-cache -- cargo build --release
boringcache go --tag go-cache -- go build ./...
```

Use `cache-registry` when you want a long-lived local endpoint:

```bash
boringcache cache-registry my-org/app build-cache --port 5000
```

Supported native protocols:

- OCI registry APIs for BuildKit
- Bazel HTTP remote cache
- Gradle HTTP build cache
- Maven build cache extension
- Nx self-hosted remote cache
- Turborepo remote cache
- sccache
- Go `GOCACHEPROG`

`run --proxy` still works as the generic escape hatch:

```bash
boringcache run --proxy build-cache -- nx run-many --target=build
```

Examples:

```bash
# Docker buildx
boringcache docker --tag docker-cache -- docker buildx build --push .

# Bazel
boringcache bazel --tag bazel-cache -- bazel build //...

# Go 1.24+
boringcache go --tag go-cache -- go build ./...
```

The proxy binds to `127.0.0.1` by default.
Use `--host 0.0.0.0` when the proxy must listen on every interface.
Use `--endpoint-host host.docker.internal` when the wrapped client must reach the proxy through a different hostname than the bind address, for example with `docker buildx build` and a containerized builder.

Adapter commands accept `--workspace` when you want an explicit workspace in CI, but they also work with a repo-level `.boringcache.toml` and a configured default workspace.

## Expert tuning

Most users should rely on the adapter profile and host-resource auto tuning.

The intended expert overrides are:

- `BORINGCACHE_BLOB_DOWNLOAD_CONCURRENCY` to cap read/download parallelism
- `BORINGCACHE_BLOB_READ_CACHE_MAX_BYTES` to grow or shrink the local blob cache

Other proxy env vars that control prefetch batches, URL batch sizes, startup slice limits, or inflight byte budgets are internal/debug controls.
They are useful for benchmarking and incident response, but they are not the normal operator surface and may change as the profiles improve.
