# Adapter commands

Adapter commands are the preferred path for tools that already speak a remote-cache protocol.

Use them when you want BoringCache to:

- start a local proxy for one tool invocation
- inject the tool-specific env vars or cache flags when the adapter supports that
- keep the repeated command short with `.boringcache.toml`

Supported adapter commands today:

- `boringcache docker`
- `boringcache nx`
- `boringcache turbo`
- `boringcache bazel`
- `boringcache gradle`
- `boringcache maven`
- `boringcache sccache`
- `boringcache go`

## Common commands

```bash
# Archive mode (run/save/restore)
boringcache run -- bundle install

# Docker adapter from repo config
boringcache docker

# Same adapter without repo config
boringcache docker --tag docker-cache -- docker buildx build .

# Long-lived local proxy
boringcache cache-registry my-org/app registry-cache --port 5000
```

Archive mode commands (`run`, `save`, and `restore`) are for explicit directory caches. Adapter commands are for supported remote-cache tools. Use `cache-registry` when the repo already has a checked-in local endpoint setup or another process should keep the proxy alive.
When `.boringcache.toml` stores the Docker command, `boringcache docker` is the short form. Use the longer version when you want to pass the Docker command inline.
Proxy-backed adapter commands start in warm mode by default. Use `--on-demand` when a proxy-backed command should skip startup warming and serve colder first reads.

The product split is:

- `cache-registry` is the proxy
- adapter commands temporarily start that proxy for one tool invocation, wait internally until it is ready, and wire the tool to it

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

- `tag` — cache tag for the proxy session
- `command` — command to run when you call `boringcache <adapter>` with no args; accepts an argv array or a shell-style string
- `no-platform`, `no-git`, `read-only` — proxy scope and write-mode defaults you would otherwise keep repeating as flags
- `entries` / `profiles` — optional archive entries to restore before the tool runs
- `metadata-hints` — low-cardinality session metadata
- `host`, `endpoint-host`, `port` — local endpoint settings
- `skip-restore`, `skip-save`, `save-on-failure` — archive behavior overrides
- `cache-mode`, `cache-ref-tag` — Docker-only cache export settings
- `sccache-key-prefix` — sccache-only WebDAV key prefix/root

## Session hints

Proxy-backed CLI flows can label sessions directly. This is the non-GitHub path
for grouping dashboard sessions and misses by stable labels instead of
anonymous traffic.

Use CLI flags when you want one-off labels:

```bash
boringcache run --proxy bazel-main \
  --metadata-hint project=web \
  --metadata-hint tool=bazel \
  --metadata-hint phase=warm \
  -- bazel build //...
```

Use repo config when the labels are part of the normal adapter contract:

```toml
[proxy]
metadata-hints = ["project=web"]

[adapters.turbo]
tag = "turbo-main"
command = ["pnpm", "turbo", "run", "build"]
metadata-hints = ["tool=turborepo", "phase=ci"]
```

Use `BORINGCACHE_PROXY_METADATA_HINTS` when another script or service starts
`cache-registry` and you do not want to repeat `--metadata-hint` flags:

```bash
export BORINGCACHE_PROXY_METADATA_HINTS=project=web,tool=gradle,phase=seed
boringcache cache-registry my-org/my-project gradle-main --port 5000
```

Keep these hints low-cardinality and replayable. Good values are
`project=web`, `benchmark=grpc-bazel`, `tool=gradle`, `phase=seed`, and
`phase=warm`. Avoid commit SHAs, run ids, timestamps, and other per-run values.
Use `phase=prewarm` only for a real standalone priming session.
The normal precedence is repo config first, then
`BORINGCACHE_PROXY_METADATA_HINTS`, then explicit CLI flags.
Use the same kebab-case spellings in `.boringcache.toml` that you see in CLI
flags and docs; the config reader accepts both kebab-case and snake_case for
adapter proxy fields.

`command` is repo config, not a general templating system.
For proxy-backed commands, BoringCache only substitutes these placeholders inside command arguments:

- `{PORT}` — the advertised local proxy port
- `{ENDPOINT}` — the advertised local proxy endpoint, for example `http://127.0.0.1:5000`
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
- `nx`
- `turbo`
- `bazel`
- `gradle`
- `maven`
- `sccache`
- `go`

For Bazel, the adapter injects the remote-cache flags directly.
For Gradle, the adapter adds `--build-cache` plus a generated init script that points the remote cache at the local proxy.
For Maven, the adapter injects the `maven.build.cache.*` remote endpoint properties, but the Maven build cache extension still needs to be present in the repo.
For sccache, the adapter injects `RUSTC_WRAPPER`, `SCCACHE_WEBDAV_ENDPOINT`, and `SCCACHE_WEBDAV_KEY_PREFIX`. Leave `sccache-key-prefix` unset unless you need a stable WebDAV sub-root within the proxy cache.

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
- `--host`
- `--endpoint-host`
- `--port`
- `--read-only`
- `--fail-on-cache-error`
- `--dry-run`
- `--json`

Docker also supports:

- `--cache-mode`
- `--cache-ref-tag`

Override precedence:

| Input kind | Rule |
| --- | --- |
| Scalars | CLI value wins when provided |
| Lists | CLI list replaces repo config |
| Metadata hints | repo config and CLI merge; CLI wins on duplicate keys |

For Docker, `--tag` is always the proxy cache tag. Use `--cache-ref-tag` for the OCI cache tag.
In GitHub Actions, the Docker adapter derives an immutable run ref plus PR/branch/default cache aliases from CI metadata.
The CLI plans the full BuildKit import fallback chain and injects every planned `--cache-from` ref before the run-scoped `--cache-to` ref.
On restore-only PR runs, the PR-scoped ref may not exist yet and may return 404; BuildKit should then continue with branch/default/stable imports. Enable PR saves only when you intentionally want PR-scoped writes. PR-context saves promote the PR alias by default and leave the stable fallback restore-only unless an explicit promotion override is supplied.
Local Docker runs keep the single `buildcache` OCI ref unless provider-neutral CI metadata or expert hidden overrides are supplied.

A Docker cache has two tag concepts:

- `--tag docker-cache` selects the BoringCache proxy cache family.
- `--cache-ref-tag buildcache` selects the stable BuildKit OCI ref tag under that family, such as `/cache:buildcache`. Omit it when you want the default `buildcache` fallback.

So the common Docker command can stay short:

```bash
boringcache docker \
  --workspace my-org/my-project \
  --tag docker-cache \
  -- docker buildx build .
```

Use [Tool guides](tool-guides.md) for per-tool examples and local endpoint setup.
