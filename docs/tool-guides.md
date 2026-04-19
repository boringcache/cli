# Tool guides

These are the short paths for the adapter commands BoringCache ships today.

The pattern is simple:

1. run `boringcache onboard`
2. put repeated setup in `.boringcache.toml`
3. use `boringcache <tool>`
4. drop to `cache-registry` only when the repo already has a checked-in local endpoint setup or another process should keep the proxy alive

`cache-registry` is the proxy.
`boringcache <tool>` and `boringcache run --proxy` temporarily start that same proxy for one command, wait until it is ready, then hand traffic to the wrapped tool.
`cache-registry` itself is warm by default. Use `--on-demand` only for advanced shared-proxy setups that prefer immediate startup over warmed first reads.

## Docker / BuildKit

```toml
[adapters.docker]
tag = "docker-cache"
command = ["docker", "buildx", "build", "."]
```

```bash
boringcache docker
boringcache docker --tag docker-cache -- docker buildx build .
```

`boringcache docker` injects `--cache-from` and `--cache-to` for you.
Do not pass those flags yourself.
Use `--cache-ref-tag` and `--cache-mode` when you need to override the OCI cache ref or export mode.
By default the Docker path indexes the selected OCI manifest and blob URLs, then lets BuildKit fetch layer bodies on demand through the local proxy.
Use `--oci-hydration bodies-before-ready` when you want the selected registry cache bodies local before BuildKit starts, or `--oci-hydration bodies-background` when you want startup to continue while body hydration runs.

If the builder runs in another container, set `endpoint-host = "host.docker.internal"` in `.boringcache.toml` or pass `--endpoint-host host.docker.internal`.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

docker buildx build \
  --cache-from type=registry,ref=127.0.0.1:5000/my-cache:main \
  --cache-to type=registry,ref=127.0.0.1:5000/my-cache:main,mode=max \
  .
```

## Nx

```toml
[adapters.nx]
tag = "build-cache"
command = ["nx", "run-many", "--target=build"]
```

```bash
boringcache nx
```

Nx gets the local endpoint and access token automatically.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

NX_SELF_HOSTED_REMOTE_CACHE_SERVER=http://127.0.0.1:5000 \
NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN=boringcache \
nx run-many --target=build
```

## Turborepo

```toml
[adapters.turbo]
tag = "turbo-cache"
command = ["pnpm", "turbo", "run", "build"]
```

```bash
boringcache turbo
```

Turborepo gets `TURBO_API`, `TURBO_TOKEN`, and `TURBO_TEAM` automatically.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

TURBO_API=http://127.0.0.1:5000 \
TURBO_TOKEN=boringcache \
TURBO_TEAM=boringcache \
turbo run build
```

## Bazel

```toml
[adapters.bazel]
tag = "bazel-cache"
command = ["bazel", "build", "//..."]
```

```bash
boringcache bazel
```

`boringcache bazel` starts the proxy and runs Bazel.
It injects `--remote_cache=http://127.0.0.1:5000` automatically and keeps upload enabled unless you run the adapter in read-only mode.

If the repo already has Bazel cache flags in `.bazelrc`, those stay in effect and explicit user flags still win.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

bazel build --remote_cache=http://127.0.0.1:5000 //...
```

## Gradle

```toml
[adapters.gradle]
tag = "gradle-cache"
command = ["./gradlew", "build", "--build-cache", "--no-daemon"]
```

```bash
boringcache gradle
```

`boringcache gradle` starts the proxy and runs Gradle.
It injects `--build-cache` and a generated init script that points Gradle remote cache traffic at `http://127.0.0.1:5000/cache/`.
The adapter keeps push enabled unless you run it in read-only mode.

If the repo already has build cache config in `settings.gradle(.kts)`, that still works. The adapter-owned init script just makes the local proxy turnkey for one command.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000
./gradlew build --build-cache --no-daemon
```

## Maven

```toml
[adapters.maven]
tag = "maven-cache"
command = ["mvn", "install", "-DskipTests", "--batch-mode", "-ntp"]
```

```bash
boringcache maven
```

`boringcache maven` starts the proxy and runs Maven.
It injects the `maven.build.cache.remote.url` and `maven.build.cache.remote.save.enabled` properties automatically.
If the repo does not already use the Maven build cache extension, add that first. The adapter owns the endpoint and save mode, but it does not bootstrap the extension itself.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000
mvn install -DskipTests --batch-mode -ntp -Dmaven.build.cache.remote.save.enabled=true
```

## sccache

```toml
[adapters.sccache]
tag = "rust-cache"
command = ["cargo", "build", "--release"]
```

```bash
boringcache sccache
```

The adapter sets `RUSTC_WRAPPER=sccache` and `SCCACHE_WEBDAV_ENDPOINT` automatically.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

RUSTC_WRAPPER=sccache \
SCCACHE_WEBDAV_ENDPOINT=http://127.0.0.1:5000/ \
cargo build --release
```

## Go

```toml
[adapters.go]
tag = "go-cache"
command = ["go", "build", "./..."]
```

```bash
boringcache go
```

Use `boringcache go` for normal Go cache integration. The adapter sets `GOCACHEPROG` automatically for Go 1.24+.

Advanced: manual `GOCACHEPROG` wiring for a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

GOCACHEPROG="boringcache go-cacheprog --endpoint http://127.0.0.1:5000" \
go build ./...
```
