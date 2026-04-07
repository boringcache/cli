# Proxy mode

Proxy mode is for build tools that already know how to talk to a remote cache.

Use `run --proxy` when you want the CLI to start a local cache endpoint around one command:

```bash
boringcache run --proxy build-cache -- nx run-many --target=build
boringcache run --proxy build-cache -- turbo run build
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

Examples:

```bash
# BuildKit
docker buildx build \
  --cache-from type=registry,ref=localhost:5000/my-cache:main \
  --cache-to type=registry,ref=localhost:5000/my-cache:main,mode=max \
  .

# Bazel
bazel build --remote_cache=http://127.0.0.1:5000 //...

# Go 1.24+
GOCACHEPROG="boringcache go-cacheprog --endpoint http://127.0.0.1:5000" go build ./...
```

The proxy binds to `127.0.0.1` by default.
Use `--host 0.0.0.0` when the client runs in another container.
