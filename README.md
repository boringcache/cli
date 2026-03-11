# BoringCache CLI

BoringCache is a cache service for CI, Docker, and the build tools that keep doing the same work on every run.

The CLI gives you two ways to use it:
- wrap save and restore around a directory such as `node_modules`, `vendor/bundle`, or `dist`
- run a local proxy for tools that already speak a cache protocol, such as BuildKit, Bazel, Gradle, Nx, Turborepo, sccache, or Go `GOCACHEPROG`

If you want the fastest first run, start with `boringcache run`.

## Installation

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
```

You can also download binaries from [GitHub Releases](https://github.com/boringcache/cli/releases).

## When to use the CLI

Reach for the CLI when you want to:
- test BoringCache outside GitHub Actions first
- wire caching into a custom CI setup or local script
- run one command with restore before it and save after it
- expose a local cache endpoint for BuildKit, Bazel, Gradle, Nx, Turborepo, sccache, or Go

If you are already on GitHub Actions and want the workflow wiring done for you, start with the published actions instead.

## Quick start

```bash
# Authenticate once for local use
boringcache auth --token YOUR_SAVE_OR_ADMIN_TOKEN

# Restore, run, and save in one command
boringcache run my-org/app "deps:node_modules" -- npm ci

# Same pattern for Bundler
boringcache run my-org/app "gems:vendor/bundle" -- bundle install

# Proxy mode for native cache clients
boringcache run my-org/app --proxy build-cache -- nx run-many --target=build
```

The `tag:path` pair is the basic unit. In `deps:node_modules`, `deps` is the cache tag and `node_modules` is where the files live locally.

## Trust model

Local CLI use is simplest with `boringcache auth --token ...`.

In CI, prefer split tokens:
- `BORINGCACHE_RESTORE_TOKEN` for restore and other read-only paths
- `BORINGCACHE_SAVE_TOKEN` for trusted jobs that should also publish updates
- `BORINGCACHE_API_TOKEN` only as a legacy fallback for older setups

Restore resolution order:
- `BORINGCACHE_RESTORE_TOKEN`
- `BORINGCACHE_SAVE_TOKEN`
- `BORINGCACHE_API_TOKEN`
- `BORINGCACHE_TOKEN_FILE`
- local config

Save resolution order:
- `BORINGCACHE_SAVE_TOKEN`
- `BORINGCACHE_API_TOKEN`
- `BORINGCACHE_TOKEN_FILE`
- local config

Security defaults:
- save commands fail fast when only a restore token is configured
- `cache-registry` and `run --proxy` downgrade to read-only when only a restore token is available
- set `BORINGCACHE_REQUIRE_SERVER_SIGNATURE=1` or pass `--require-server-signature` to fail restore when the server signature is missing or invalid

## Pick a mode

### `run`

This is the default starting point. It restores, runs your command, then saves again on the way out.

```bash
boringcache run my-org/app "deps:node_modules" -- npm ci
boringcache run my-org/app "deps:node_modules,build:dist" -- npm test
boringcache run my-org/app --proxy build-cache -- turbo run build
```

Use `run` when you want the cache behavior close to the command that benefits from it.

### `cache-registry`

Use this when the build tool already has a remote cache protocol and should keep using it.

```bash
boringcache cache-registry my-org/app build-cache --port 5000
```

That local proxy speaks:
- OCI registry APIs for BuildKit `type=registry`
- Bazel HTTP remote cache
- Gradle HTTP build cache
- Maven build cache extension
- Nx self-hosted remote cache
- Turborepo remote cache
- sccache WebDAV-style paths
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

Aliases: `docker-registry` and `serve`.

### `save` and `restore`

Use these when restore and save need to happen at different points in the job.

```bash
boringcache restore my-org/app "deps:node_modules"
npm ci
boringcache save my-org/app "deps:node_modules"
```

### `mount`

Use `mount` for long-lived local directories that should stay synced.

```bash
boringcache mount my-org/app "dev-cache:./node_modules"
```

It restores on start, syncs in the background, and does a final save on exit.

## How data is stored

You point the CLI at a directory. The CLI picks the storage mode.

- OCI image layouts use blob-level storage by digest
- Bazel disk caches use blob-level storage by digest
- everything else is saved as one compressed archive

You do not need to choose a mode manually for normal use.

## Smaller commands

```bash
# Check whether tags exist without downloading
boringcache check my-org/app "deps,build" --json

# List cache entries
boringcache ls my-org/app --json

# Delete cache entries by tag
boringcache delete my-org/app "deps"

# Inspect or set local config
boringcache config list
boringcache config set default_workspace my-org/app

# Generate an Age keypair and configure workspace encryption
boringcache setup-encryption my-org/app

# Analyze CI config and propose BoringCache migrations
boringcache optimize
```

## Tag behavior

Tags are git-aware by default.

- feature branches save to a branch-suffixed tag
- the default branch uses the base tag
- platform suffixes are added by default

Use `--no-git` to disable git-aware suffixing and `--no-platform` only when the cached directory is genuinely portable across operating systems and architectures.

## Environment variables

- `BORINGCACHE_RESTORE_TOKEN`
- `BORINGCACHE_SAVE_TOKEN`
- `BORINGCACHE_API_TOKEN`
- `BORINGCACHE_REQUIRE_SERVER_SIGNATURE`
- `BORINGCACHE_TOKEN_FILE`
- `BORINGCACHE_DEFAULT_WORKSPACE`
- `BORINGCACHE_API_URL`
- `BORINGCACHE_NO_GIT`

## Learn more

- [Documentation](https://boringcache.com/docs)
- [CLI docs](https://boringcache.com/docs#cli-run)
- [GitHub Actions docs](https://boringcache.com/docs#action)
- [GitHub Actions trust model](https://boringcache.com/docs#actions-auth)
