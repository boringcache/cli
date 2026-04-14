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
# Archive mode
boringcache run -- bundle install

# Adapter command from repo config
boringcache nx

# One-off adapter command
boringcache docker --tag docker-cache -- docker buildx build .

# Fallback for unsupported or custom tools
boringcache run --proxy build-cache -- my-custom-tool build

# Long-lived local endpoint
boringcache cache-registry my-org/app registry-cache --port 5000
```

## Repo config

Put repeated adapter setup in `.boringcache.toml`:

```toml
workspace = "my-org/my-project"

[adapters.nx]
tag = "build-cache"
command = ["nx", "run-many", "--target=build"]
```

Then:

```bash
boringcache nx
```

Useful adapter fields:

- `tag` — cache tag for the proxy session
- `command` — command to run when you call `boringcache <adapter>` with no args; accepts an argv array or a shell-style string
- `entries` / `profiles` — optional archive entries to restore before the tool runs
- `metadata-hints` — low-cardinality session metadata
- `host`, `endpoint-host`, `port` — local endpoint settings
- `skip-restore`, `skip-save`, `save-on-failure` — archive behavior overrides
- `cache-mode`, `cache-ref-tag` — Docker-only cache export settings

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
- `sccache`
- `go`

These adapters start the proxy and run the command, but the tool still needs its own remote-cache config pointing at the local endpoint:

- `bazel`
- `gradle`
- `maven`

That split is intentional.
If the tool already has a stable config file, keep that config in the repo and let the adapter command just own proxy lifecycle.

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

Use [Tool guides](tool-guides.md) for per-tool examples and local endpoint setup.
