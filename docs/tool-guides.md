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

The snippets below are intended to be copy-pasteable `.boringcache.toml`
starting points. They work for local CLI runs and for `boringcache/one@v1`
because the action asks the CLI for the same repo plan.

Shared defaults for the examples:

- put the stable project label in `[proxy].metadata-hints`
- put the stable tool and lane labels in `[adapters.<tool>].metadata-hints`
- leave `no-platform` and `no-git` unset unless the cache is genuinely portable
- set `read-only = true` only on restore-only lanes
- use `phase=seed` for explicit priming jobs and `phase=ci` or `phase=warm` for normal runs

## Docker / BuildKit

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=app"]

[adapters.docker]
tag = "docker-cache"
command = ["docker", "buildx", "build", "."]
metadata-hints = ["tool=oci", "phase=ci"]
```

```bash
boringcache docker
boringcache docker --tag docker-cache -- docker buildx build .
```

`boringcache docker` injects `--cache-from` and `--cache-to` for you.
Do not pass those flags yourself.
Use `--cache-ref-tag` and `--cache-mode` only when you need to override the OCI cache ref or export mode.

Direct BuildKit runs use the same OCI cache plan:

```toml
[adapters.buildkit]
tag = "docker-cache"
command = ["buildctl", "build", "--frontend", "dockerfile.v0"]
metadata-hints = ["tool=oci", "phase=ci"]
```

```bash
boringcache buildkit
boringcache buildkit --tag docker-cache -- buildctl build --frontend dockerfile.v0
```

`boringcache buildkit` injects `--import-cache` and `--export-cache` for `buildctl build`.
Keep builder installation, daemon lifecycle, QEMU/binfmt, and Docker container networking in the caller's runtime setup.

Docker has two cache tag concepts:

- `--tag docker-cache` selects the BoringCache proxy cache family.
- `--cache-ref-tag buildcache` selects the stable BuildKit OCI ref tag under that family, such as `/cache:buildcache`. You can omit it when you want `buildcache`, because that is the default.

In GitHub Actions or another CI environment that provides BoringCache CI metadata, the adapter derives an immutable run ref plus PR/branch/default cache aliases.
It plans the full BuildKit import fallback chain and injects every planned `--cache-from` ref before the run-scoped `--cache-to` ref:

```text
--cache-from .../cache:pr-3208
--cache-from .../cache:branch-feature-docker-cache
--cache-from .../cache:default
--cache-from .../cache:buildcache
--cache-to   .../cache:run-gha-24771923434-attempt-1
```

Passing `--cache-ref-tag customcache` only changes the final stable fallback from `buildcache` to `customcache`.
On restore-only PR runs, the PR-scoped ref may not exist yet and may return 404. That is expected; BuildKit should continue with the remaining branch, default, and stable fallback refs. Enable PR saves only when you intentionally want PR-scoped writes. PR-context saves promote the PR alias by default; they do not promote the stable fallback unless an explicit promotion ref override asks for it.
Local Docker runs without CI metadata keep the single `buildcache` OCI ref unless provider-neutral CI metadata or expert hidden overrides are supplied.
BoringCache backs the BuildKit registry cache through the Docker and direct BuildKit adapters.
By default the Docker path warms the selected OCI manifest, blob URLs, and blob bodies before BuildKit starts.
That keeps the normal path simple: a warm BuildKit run should read cache bodies through the local proxy instead of discovering remote body reads after the manifest hit.

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
If `nx.json` is still connected to Nx Cloud with `nxCloudId`, `nxCloudAccessToken`,
or an `nx-cloud` task runner, Nx may select its private cloud runner before the
self-hosted cache endpoint. Remove that Nx Cloud binding from the workspace
config before using the BoringCache Nx proxy, or use a prepared disposable
checkout for benchmarks. Do not use `NX_NO_CLOUD` as the BoringCache setup path;
Nx treats it as remote-cache disablement in current releases.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

NX_SELF_HOSTED_REMOTE_CACHE_SERVER=http://127.0.0.1:5000 \
NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN=boringcache \
nx run-many --target=build
```

## Turborepo

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=web"]

[adapters.turbo]
tag = "turbo-cache"
command = ["pnpm", "turbo", "run", "build"]
metadata-hints = ["tool=turborepo", "phase=ci"]
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
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=backend"]

[adapters.bazel]
tag = "bazel-cache"
command = ["bazel", "build", "//..."]
metadata-hints = ["tool=bazel", "phase=ci"]
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
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=backend"]

[adapters.gradle]
tag = "gradle-cache"
command = ["./gradlew", "build", "--no-daemon"]
metadata-hints = ["tool=gradle", "phase=ci"]
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
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=rust"]

[adapters.sccache]
tag = "rust-cache"
command = ["cargo", "build", "--release"]
metadata-hints = ["tool=sccache", "phase=ci"]
# Optional: keep sccache objects under a WebDAV sub-root.
sccache-key-prefix = "rust/ci"
```

```bash
boringcache sccache
```

The adapter sets `RUSTC_WRAPPER=sccache`, `SCCACHE_WEBDAV_ENDPOINT`, `SCCACHE_WEBDAV_KEY_PREFIX`, and `CARGO_INCREMENTAL=0` when the caller has not set it.
After the wrapped command exits, it reads `sccache --show-stats` and prints a concise hit/miss summary when sccache reports one.

For a long-lived endpoint:

```bash
boringcache cache-registry my-org/app registry-cache --port 5000

RUSTC_WRAPPER=sccache \
SCCACHE_WEBDAV_ENDPOINT=http://127.0.0.1:5000/ \
SCCACHE_WEBDAV_KEY_PREFIX=rust/ci \
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
