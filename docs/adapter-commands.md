# Adapter commands

Adapter commands are the preferred path for tools that already speak a remote-cache protocol.

Use them when you want BoringCache to:

- manage one cache adapter for one tool invocation
- inject the tool-specific environment or cache flags
- keep the repeated command short with `.boringcache.toml`

Supported adapter commands today:

- `boringcache docker`
- `boringcache nx`
- `boringcache turbo`
- `boringcache bazel`
- `boringcache gradle`
- `boringcache maven`
- `boringcache ccache`
- `boringcache sccache`
- `boringcache go`
- `boringcache buildkit`
- `boringcache xcode` (macOS)

## Common commands

```bash
# Archive mode (run/save/restore)
boringcache run -- bundle install

# Docker adapter from repo config
boringcache docker

# Other adapters use the same shape
boringcache bazel
boringcache turbo
boringcache sccache

# Xcode compilation cache; the CLI supplies stable CAS and DerivedData paths
boringcache xcode -- xcodebuild -workspace App.xcworkspace -scheme App build
```

Archive mode commands (`run`, `save`, and `restore`) are for explicit directory caches. Adapter commands are for supported remote-cache tools.
`.boringcache.toml` keeps repeated adapter commands and cache identity out of
shell scripts.

For a restore-first laptop workflow, run
`boringcache config set read_only true` once. The setting is machine-local,
applies even when `CI=true` is present, and makes `run` plus adapter commands
skip writes. Add `--write` to one invocation to publish intentionally. See
[Archive mode](archive-mode.md#laptop-read-only-default) for the trust boundary
and GitHub Action behavior.

## Repo config

Put repeated adapter setup in `.boringcache.toml`:

```toml
workspace = "my-org/my-project"

[adapters.docker]
tag = "docker-cache"
command = ["docker", "buildx", "build", "."]
```

Then:

```bash
boringcache docker
```

Useful adapter fields:

- `tag` — cache identity for the adapter
- `command` — command to run when you call `boringcache <adapter>` with no args; accepts an argv array or a shell-style string
- `no-platform`, `no-git`, `read-only` — scope and write-mode defaults you would otherwise keep repeating as flags
- `entries` / `profiles` — optional archive entries to restore before the tool runs
- `metadata-hints` — low-cardinality session metadata
- `port` — an exceptional local coordination override; otherwise every adapter uses `22243`
- `skip-restore`, `skip-save`, `save-on-failure` — archive behavior overrides
- `cache-mode` — Docker/BuildKit cache export mode
- `sccache-key-prefix` — sccache-only WebDAV key prefix/root

## Session hints

Adapter CLI flows can label sessions directly. This is the non-GitHub path
for grouping dashboard sessions and misses by stable labels instead of
anonymous traffic.

Use repo config when the labels are part of the normal adapter contract:

```toml
[adapters.turbo]
tag = "turbo-main"
command = ["pnpm", "turbo", "run", "build"]
metadata-hints = ["tool=turborepo", "lane=ci"]
```

Keep these hints low-cardinality and replayable. Good values are
`project=web`, `benchmark=grpc-bazel`, `tool=gradle`, `lane=ci`, and
`workflow=build`. Avoid commit SHAs, run ids, timestamps, and other per-run
values. Normal sessions do not need `cold` or `warm` labels; BoringCache
derives new-vs-recurring misses from cache target and lifecycle telemetry.
Use the same kebab-case spellings in `.boringcache.toml` that you see in CLI
flags and docs.

`command` is repo config, not a general templating system.
For advanced adapter command templates, BoringCache only substitutes these placeholders inside command arguments:

- `{PORT}` — the advertised local proxy port
- `{ENDPOINT}` — the advertised local endpoint
- `{CACHE_REF}` — the proxy cache ref when the wrapped tool expects a registry-style cache ref

Example:

```toml
[adapters.bazel]
tag = "bazel-cache"
command = ["bazel", "build", "--remote_cache={ENDPOINT}", "//..."]
```
## What gets wired automatically

These adapters inject the tool-specific settings for you:

- `docker`
- `buildkit`
- `nx`
- `turbo`
- `bazel`
- `gradle`
- `maven`
- `ccache`
- `sccache`
- `go`
- `xcode`

For Bazel, the adapter injects the remote-cache flags directly.
For Docker, `--tool-cache TOOL:TAG` starts the selected tool proxy outside the
build and lets managed BuildKit inject its session-only environment and config
into every `RUN` step. BuildKit cannot see through package scripts, aliases,
Makefiles, or compiler wrappers, so command-name matching would silently
disable an explicitly selected cache. Plain
`--tool-cache TOOL` is also accepted when
`[adapters.<tool>].tag` is set in `.boringcache.toml`.
For BuildKit, the adapter injects `--import-cache` and `--export-cache` for `buildctl build`.
For Turbo and Nx, the adapter generates a random per-proxy bearer credential,
injects it only into the wrapped process, and rejects tokens from another proxy.
This isolates local proxy instances; it does not model team or tenant authorization.
Dry-run JSON uses the non-secret `boringcache` preview placeholder because no
proxy instance exists yet; it is never the runtime credential for a wrapped run.
For Gradle, the adapter adds `--build-cache` plus a generated init script in the effective Gradle user home. Command-line `-g`/`--gradle-user-home` wins over `GRADLE_USER_HOME`, just as it does in Gradle.
For Maven, the adapter injects the `maven.build.cache.*` endpoint/save properties and bootstraps extension 1.2.3 plus a marker-owned 1.2.0 cache config when those files are absent. Any existing build-cache extension declaration and user-owned cache config are preserved. Unrelated or unreadable extension XML, and an explicit requested-version mismatch, produce a setup error instead of a rewrite.
For sccache, the adapter injects `RUSTC_WRAPPER`, the WebDAV endpoint/prefix/read-write mode, and `SCCACHE_MULTILEVEL_CHAIN=webdav`, plus `CARGO_INCREMENTAL=0` when unset. It removes inherited alternate-backend selectors and WebDAV credentials, starts the child on a dedicated daemon port, collects best-effort stats on that same port, and stops the daemon afterward. This lifecycle contract requires supported sccache 0.16.0 or a newer version that has passed the adapter review. Leave `sccache-key-prefix` unset unless you need a stable WebDAV sub-root.
For Xcode, the adapter injects native compilation-cache settings, a stable CAS
and DerivedData path, and a credential-free Unix-socket bridge to the normal
BoringCache proxy. A direct `xcodebuild` command gets `-derivedDataPath`
automatically unless it already supplies one. Xcode version, build, path cohort,
compilation actions, CAS objects, bytes, and publication failures are recorded
as native evidence.

If a repo already has a stable checked-in cache config, that still works. Explicit tool flags and checked-in config stay user-owned.

## CLI overrides

Adapter commands accept direct overrides when you need them:

```bash
boringcache turbo \
  --workspace my-org/my-project \
  --tag turbo-cache \
  -- pnpm turbo run build
```

Useful flags:

- `--workspace`
- `--tag`
- `--entry`
- `--profile`
- `--port`
- `--read-only`
- `--write`
- `--fail-on-cache-error`
- `--dry-run`
- `--json`

Leave `--port` unset normally. Set it only when another process must coordinate
on an explicit local port or the product default conflicts on that machine.

Docker and BuildKit also support:

- `--cache-mode`

Docker also supports:

- `--tool-cache turbo:turbo-cache,nx:nx-cache,bazel:bazel-cache,gradle:gradle-cache,maven:maven-cache,sccache:rust-cache,go:go-cache`

Override precedence:

| Input kind | Rule |
| --- | --- |
| Scalars | CLI value wins when provided |
| Lists | CLI list replaces repo config |
| Metadata hints | repo config and CLI merge; CLI wins on duplicate keys |

For Docker and BuildKit, `--tag` is the cache tag all the way through: the proxy session, BuildKit registry ref, backend cache entry, and human-visible tag all use the resolved human tag.
The CLI still applies the shared branch/default/PR restore ordering, but it expresses those candidates as human tags rather than Docker-specific ref aliases.
The direct `buildkit` adapter uses the same OCI plan as Docker, but injects `buildctl build` flags as `--import-cache` and `--export-cache`.
`--tool-cache` is Docker-only. Supported names are `turbo`, `nx`, `bazel`,
`gradle`, `maven`, `sccache`, and `go`. Each requested tool uses the same tag
contract as running that adapter directly: pass
`--tool-cache turbo:turbo-cache`, or set
`[adapters.turbo].tag = "turbo-cache"` and pass `--tool-cache turbo`.
BoringCache starts the Docker/OCI proxy under the Docker tag and one normal
tool proxy for each requested tool tag.

The managed builder applies every selected native contract throughout Docker
build execution:

- Turbo and Nx receive their endpoint and per-proxy credential environment.
- sccache receives its WebDAV/compiler environment, so compiler subprocesses
  do not have to mention `sccache` in the Dockerfile command.
- Bazel receives a read-only generated bazelrc.
- Gradle receives a read-only init script and properties file inside a writable,
  session-only Gradle user-home tmpfs.
- Maven receives `MAVEN_OPTS` and a read-only cache config. The project must
  still declare `maven-build-cache-extension` in `.mvn/extensions.xml` or its
  POM; BoringCache does not overwrite project source during a build.
- Go receives `GOCACHEPROG` plus a standard-library-only helper source file.
  The target image's Go toolchain compiles that helper, avoiding host/container
  architecture mismatch.

Injected values are BuildKit secrets and mounts, not image-layer contents.
They are scoped to build execution. An explicit Dockerfile secret-env entry or
mount at the same destination wins; ordinary image `ENV` values are replaced
because selecting `--tool-cache` makes BoringCache the cache configuration
owner for that build. Session configuration is attached only when an uncached
`RUN` executes and is not added to the layer cache key, so selecting a tool
cache does not invalidate otherwise reusable Docker layers. The file-backed
adapters require a managed BuildKit image with tool-env plan v2 support.

The earlier explicit shell-secret contract remains available for Dockerfiles
that deliberately source it. It is an environment-only compatibility path for
Turbo, Nx, and sccache:

```Dockerfile
RUN --mount=type=secret,id=boringcache-tool-cache-env \
  . /run/secrets/boringcache-tool-cache-env && \
  turbo run build
```

Managed native injection does not require that mount or shell snippet; a normal
`RUN turbo run build`, `RUN ./gradlew build`, or `RUN go build ./...` is enough.

Repeat the flag when that reads better than a comma list:

```bash
boringcache docker \
  --tool-cache sccache:rust-cache \
  --tool-cache turbo:turbo-cache \
  -- docker buildx build .
```

Or keep the tags in repo config and pass only tool names:

```toml
[adapters.docker]
tag = "docker-cache"

[adapters.turbo]
tag = "turbo-cache"

[adapters.sccache]
tag = "rust-cache"
```

```bash
boringcache docker --tool-cache turbo,sccache -- docker buildx build .
```

So the common Docker command can stay short:

```bash
boringcache docker \
  --workspace my-org/my-project \
  --tag docker-cache \
  -- docker buildx build .
```

Use [Tool guides](tool-guides.md) for per-tool examples and local endpoint setup.
