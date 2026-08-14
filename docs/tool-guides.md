# Tool guides

These are the short paths for the adapter commands BoringCache ships today.

The pattern is simple:

1. run `boringcache onboard`
2. put repeated setup in `.boringcache.toml`
3. use `boringcache <tool>`

The snippets below are intended to be copy-pasteable `.boringcache.toml`
starting points. They work for local CLI runs and for `boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9`
because the action asks the CLI for the same repo plan.

Shared defaults for the examples:

- put the stable project label in `[proxy].metadata-hints`
- put the stable tool and lane labels in `[adapters.<tool>].metadata-hints`
- leave `no-platform` and `no-git` unset unless the cache is genuinely portable
- set `read-only = true` only on restore-only lanes
- do not add cold/warm labels for normal runs; BoringCache derives new-vs-recurring misses from cache target and lifecycle telemetry

## Docker / BuildKit

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=app"]

[adapters.docker]
tag = "docker-cache"
command = ["docker", "buildx", "build", "."]
metadata-hints = ["tool=oci", "lane=ci"]
```

```bash
boringcache docker
boringcache docker --tag docker-cache -- docker buildx build .
```

`boringcache docker` injects `--cache-from` and `--cache-to` for you.
Do not pass those flags yourself.
Use `--cache-mode` only when you need to change the BuildKit export mode.

Direct BuildKit runs use the same managed cache plan:

```toml
[adapters.buildkit]
tag = "docker-cache"
command = ["buildctl", "build", "--frontend", "dockerfile.v0"]
metadata-hints = ["tool=oci", "lane=ci"]
```

```bash
boringcache buildkit
boringcache buildkit --tag docker-cache -- buildctl build --frontend dockerfile.v0
```

`boringcache buildkit` injects `--import-cache` and `--export-cache` for `buildctl build`.
The Docker and BuildKit adapters own the managed BoringCache builder lifecycle and its Docker networking, including selecting a cache endpoint reachable from the builder.

Docker has one BoringCache tag concept:

- `--tag docker-cache` selects the resolved human cache tag, and the CLI uses that same tag for the managed BuildKit cache ref and backend entry.

In GitHub Actions or another CI environment that provides BoringCache CI metadata, the adapter applies the shared branch/default/PR restore ordering as human tags.
It injects the planned human-tag imports and exports the resolved write tag:

```text
--cache-from .../cache:docker-cache-pr-3208-ubuntu-24-x86_64
--cache-from .../cache:docker-cache-main-ubuntu-24-x86_64
--cache-to   .../cache:docker-cache-pr-3208-ubuntu-24-x86_64
```

BoringCache provides the managed BuildKit backend through the Docker and direct BuildKit adapters.
By default the Docker path warms the selected cache metadata before BuildKit starts, then lets BuildKit fetch blob bodies on demand through the local proxy.
Use explicit OCI hydration settings only for evidence-backed read-path experiments; do not assume blob bodies are warmed before every BuildKit run.

## Nx

```toml
[adapters.nx]
tag = "build-cache"
command = ["nx", "run-many", "--target=build"]
```

```bash
boringcache nx
```

Nx gets the local endpoint and a random per-proxy access token automatically;
the proxy rejects a token copied from another wrapped run.
If `nx.json` is still connected to Nx Cloud with `nxCloudId`, `nxCloudAccessToken`,
or an `nx-cloud` task runner, Nx may select its private cloud runner before the
self-hosted cache endpoint. Remove that Nx Cloud binding from the workspace
config before using the BoringCache Nx proxy, or use a prepared disposable
checkout for benchmarks. Do not use `NX_NO_CLOUD` as the BoringCache setup path;
Nx treats it as remote-cache disablement in current releases.

## Turborepo

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=web"]

[adapters.turbo]
tag = "turbo-cache"
command = ["pnpm", "turbo", "run", "build"]
metadata-hints = ["tool=turborepo", "lane=ci"]
```

```bash
boringcache turbo
```

Turborepo gets `TURBO_API`, `TURBO_TOKEN`, and `TURBO_TEAM` automatically. The
wrapped token is random per proxy and is not a multi-tenant authorization model.

## Bazel

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=backend"]

[adapters.bazel]
tag = "bazel-cache"
command = ["bazel", "build", "//..."]
metadata-hints = ["tool=bazel", "lane=ci"]
```

```bash
boringcache bazel
```

`boringcache bazel` starts the local cache process and runs Bazel.
It injects the remote-cache endpoint automatically and keeps upload enabled unless you run the adapter in read-only mode.

If the repo already has Bazel cache flags in `.bazelrc`, those stay in effect and explicit user flags still win.

## Gradle

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=backend"]

[adapters.gradle]
tag = "gradle-cache"
command = ["./gradlew", "build", "--no-daemon"]
metadata-hints = ["tool=gradle", "lane=ci"]
```

```bash
boringcache gradle
```

`boringcache gradle` starts the local cache process and runs Gradle.
It injects `--build-cache` and a generated init script that points Gradle remote cache traffic at the managed local endpoint. The init script is written under the effective Gradle user home, including command-line `-g`/`--gradle-user-home` overrides.
The adapter keeps push enabled unless you run it in read-only mode.

If the repo already has build cache config in `settings.gradle(.kts)`, that still works. The adapter-owned init script just makes the local proxy turnkey for one command.

## Maven

```toml
[adapters.maven]
tag = "maven-cache"
command = ["mvn", "install", "-DskipTests", "--batch-mode", "-ntp"]
```

```bash
boringcache maven
```

`boringcache maven` starts the local cache process and runs Maven.
It injects the `maven.build.cache.remote.url` and `maven.build.cache.remote.save.enabled` properties automatically. When setup is absent, it also creates `.mvn/extensions.xml` for extension 1.2.3 and a marker-owned 1.2.0 build-cache config. Any existing build-cache extension declaration and user-owned cache config are preserved; when a version override is explicit, a mismatch is an error. The adapter refuses to splice into unrelated or unreadable user-owned XML.

## Nix

```toml
[adapters.nix]
tag = "nix-cache"
command = ["nix", "build"]
```

```bash
boringcache nix
boringcache nix -- nix build .#package
```

The adapter exposes the local proxy as a standard Nix HTTP binary cache. It
uses `NIX_CONFIG` for a per-invocation trusted substituter, keeps negative
narinfo caching disabled for the live session, and falls back to local builds
on cache errors by default; `--fail-on-cache-error` disables that fallback. In write mode its post-build hook enqueues store paths to a
background worker; `nix copy` performs closure-aware publication with zstd
parallel compression outside the build loop. A multi-user daemon requires the
runner user or one of its groups in `trusted-users`.

## ccache

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=cpp-app"]

[adapters.ccache]
tag = "cpp-cache"
command = ["cmake", "--build", "build"]
metadata-hints = ["tool=ccache", "lane=ci"]
```

```bash
boringcache ccache
boringcache ccache -- cmake --build build
```

Keep compiler-launcher selection in the project, such as
`CMAKE_C_COMPILER_LAUNCHER=ccache` and
`CMAKE_CXX_COMPILER_LAUNCHER=ccache`. The adapter supplies ccache's remote
storage, remote-only mode, lifecycle, and native statistics; it does not
rewrite `CC` or `CXX`. Use the same adapter name through `mode: ccache` in
`boringcache/one`.

## Xcode

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=ios-app"]

[adapters.xcode]
tag = "xcode-cache"
command = ["xcodebuild", "-workspace", "App.xcworkspace", "-scheme", "App", "build"]
metadata-hints = ["tool=xcode", "lane=ci"]
```

```bash
boringcache xcode
boringcache xcode -- xcodebuild -workspace App.xcworkspace -scheme App build
```

The wrapper requires macOS and a supported Xcode installation. It finds
Apple's toolchain CAS plugin, loads the BoringCache adapter shipped beside the
CLI, creates stable per-tag CAS and DerivedData directories, starts the local
bridge, and injects the compilation-cache settings. Xcode and the plugin never
receive a workspace token.

Xcode 26 reuse is scoped by absolute paths. Keep the checkout at the same real
path across runners; use one explicit canonical checkout path when sharing
between CI providers. Inspect `boringcache xcode --dry-run --json` for the
Xcode build, resolved paths, path strategy, and `path_cohort` before comparing
cache performance across lanes.

## sccache

```toml
workspace = "my-org/my-project"

[proxy]
metadata-hints = ["project=rust"]

[adapters.sccache]
tag = "rust-cache"
command = ["cargo", "build", "--release"]
metadata-hints = ["tool=sccache", "lane=ci"]
# Optional: keep sccache objects under a WebDAV sub-root.
sccache-key-prefix = "rust/ci"
```

```bash
boringcache sccache
```

The adapter sets `RUSTC_WRAPPER=sccache`, the WebDAV endpoint/prefix/read-write mode, and `SCCACHE_MULTILEVEL_CHAIN=webdav`, plus `CARGO_INCREMENTAL=0` when unset. It removes inherited alternate-backend selectors and WebDAV credentials so host or CI configuration cannot bypass the local proxy.
Each invocation uses a dedicated sccache daemon port. After the wrapped command exits, the adapter reads stats on that port, records normalized native-tool evidence when available, and stops the dedicated daemon. Use the reviewed sccache 0.17.0 default; 0.16.0 remains the behavioral floor, and newer releases must pass the adapter compatibility review first.

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
