# BoringCache CLI

**Cache once. Reuse everywhere.**

BoringCache is a universal build artifact cache for CI, Docker, and local development. It stores and restores directories you choose so build outputs, dependencies, and tool caches can be reused across environments.

BoringCache does not run builds and is not tied to any build tool. It works with any language, framework, or workflow by caching directories explicitly selected by the user.

The CLI automatically detects what you're caching and picks the best storage strategy. OCI image layouts and Bazel disk caches get content-addressable storage with blob-level deduplication. Everything else is compressed into a single archive. No flags needed.

This repository contains the BoringCache CLI, which can be used directly in CI pipelines, Docker builds, and local development.

## Installation

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
```

Or download from [GitHub Releases](https://github.com/boringcache/cli/releases) (Linux AMD64/ARM64, macOS ARM64, Windows AMD64).

## Quick start

```bash
# Authenticate
boringcache auth --token your-api-token

# Save cache (tag:path format)
boringcache save my-org/my-workspace "node-deps:node_modules"

# Restore cache
boringcache restore my-org/my-workspace "node-deps:node_modules"

# Multiple caches at once
boringcache save my-org/my-workspace "node-deps:node_modules,build-cache:dist"

# Set default workspace
boringcache config set default_workspace my-org/my-workspace

# Use default workspace
boringcache save "node-deps:node_modules"
boringcache restore "node-deps:node_modules"
```

## Mental model

You choose what to cache and where it should be restored.

- A cache entry is identified by a tag and a path, like `deps:node_modules`.
- BoringCache fingerprints the directory contents and skips uploads when unchanged.
- Platform scoping is enabled by default for safety.

## Content-addressable storage (CAS)

BoringCache automatically detects structured layouts and uses content-addressable storage for efficient caching. No configuration needed — just point `save` at a directory and the CLI handles the rest.

### Supported layouts

| Layout | Detection | Storage |
|--------|-----------|---------|
| OCI image layout | `index.json` + `oci-layout` + `blobs/sha256/` | Each blob stored individually by SHA-256 digest |
| Bazel disk cache | `ac/` + `cas/` directories | Each file stored individually by digest |
| Everything else | Default | Single compressed archive (tar + zstd) |

### How it works

- **Save** scans the directory, identifies blobs already stored remotely, and uploads only new or changed blobs. Unchanged blobs are skipped entirely.
- **Restore** downloads only the blobs missing locally. Large blobs (8MB+) use parallel byte-range downloads for maximum throughput.
- **Mount** detects the layout, restores from remote, watches for local changes, and syncs back — all using the appropriate storage strategy.

Every blob is verified against its SHA-256 digest on download. Sequential downloads hash inline during streaming. Parallel downloads verify after assembly.

### Docker / BuildKit

Cache OCI image layouts produced by BuildKit, Kaniko, or any OCI-compliant tool:

```bash
# Save a BuildKit cache export
boringcache save my-org/ws "buildkit-cache:/path/to/oci-layout"

# Restore before the next build
boringcache restore my-org/ws "buildkit-cache:/path/to/oci-layout"

# Keep it synced with mount
boringcache mount my-org/ws "buildkit-cache:/path/to/oci-layout"
```

BuildKit produces OCI layouts with `index.json`, `oci-layout`, and `blobs/sha256/`. BoringCache detects this automatically and stores each layer as a separate blob. When layers are shared across builds (common with multi-stage Dockerfiles), they are uploaded once and deduplicated across cache entries.

### Bazel

Cache Bazel's disk cache directory:

```bash
# Save Bazel disk cache
boringcache save my-org/ws "bazel-cache:/path/to/bazel-disk-cache"

# Restore before build
boringcache restore my-org/ws "bazel-cache:/path/to/bazel-disk-cache"
```

Bazel disk caches use `ac/` (action cache) and `cas/` (content-addressable storage) directories. BoringCache detects this structure and stores each file individually, deduplicating across saves.

## Commands

### `save <WORKSPACE> <TAG:PATH,...>`
Save cache entries using `tag:path` format.

```bash
boringcache save my-org/ws "deps:node_modules"
boringcache save my-org/ws "deps:node_modules,build:dist" --force
boringcache save my-org/ws "gems:vendor/bundle" --exclude "*.out"
# strict mode: fail command on cache/backend errors
boringcache save my-org/ws "deps:node_modules" --fail-on-cache-error
```

Use `--force` to overwrite existing entries. Use `--exclude` to skip files matching glob patterns.
By default, cache/backend save errors are warn-only (non-fatal). Use `--fail-on-cache-error` for strict behavior.

### `restore <WORKSPACE> <TAG:PATH,...>`
Restore cache entries. Path controls local extraction directory.

```bash
boringcache restore my-org/ws "deps:node_modules"
boringcache restore my-org/ws "deps:./node_modules,build:./dist"
# strict miss handling
boringcache restore my-org/ws "deps:node_modules" --fail-on-cache-miss
# strict backend/cache-error handling
boringcache restore my-org/ws "deps:node_modules" --fail-on-cache-error
```

By default, restore cache/backend errors are warn-only (non-fatal).
Use `--fail-on-cache-miss` to fail on misses and `--fail-on-cache-error` to fail on cache/backend failures.

### `ls [WORKSPACE]`
List cache entries.

### `mount <WORKSPACE> <TAG:PATH>`
Watch a directory and sync changes to remote cache in real-time.

```bash
boringcache mount my-org/ws "dev-cache:./node_modules"
```

Restores from remote on start, syncs periodically, and performs a final sync on Ctrl+C.

### `docker-registry <WORKSPACE> <TAG>`
Run a local cache registry proxy for native integrations:
- OCI registry (`/v2/*`) for BuildKit `type=registry`
- Bazel HTTP cache (`/ac/*`, `/cas/*`)
- Gradle HTTP build cache (`/cache/*`)
- Turborepo remote cache (`/v8/artifacts/*`)
- sccache WebDAV-style paths (`/<prefix>/a/b/c/<key>`)

Aliases: `serve`, `cache-registry`

`TAG` uses this format:
- first tag is the shared registry root tag for Bazel/Gradle/Turborepo/sccache
- optional additional comma-separated tags are OCI human aliases

```bash
boringcache docker-registry my-org/ws registry-cache --port 5000
# same command via compatibility alias
boringcache serve my-org/ws registry-cache --port 5000
# same command via explicit multi-protocol alias
boringcache cache-registry my-org/ws registry-cache --port 5000
# with explicit OCI human aliases
boringcache cache-registry my-org/ws registry-cache,docker-main,docker-stable --port 5000
# when BORINGCACHE_DEFAULT_WORKSPACE is set
boringcache cache-registry registry-cache --port 5000
```

BuildKit connects directly to the proxy as a standard OCI registry:

```bash
docker buildx build \
  --cache-from type=registry,ref=localhost:5000/my-cache:main \
  --cache-to type=registry,ref=localhost:5000/my-cache:main,mode=max \
  .
```

The proxy translates OCI Distribution API calls into BoringCache CAS operations. BuildKit's `type=registry` supports lazy blob resolution — only the manifest is fetched on cache hit, and individual layers are pulled only if needed. This avoids downloading the entire cache upfront, which `type=local` cannot do.

The proxy binds to `127.0.0.1` by default. Use `--host 0.0.0.0` when the BuildKit daemon runs in a separate container (e.g., `docker-container` driver).

`docker-registry` / `serve` / `cache-registry` do not currently have a `--fail-on-cache-error` flag. They are long-running proxy commands, and strictness is enforced by client behavior or e2e assertions.

### `delete <WORKSPACE> <TAGS>`
Delete cache entries by tag.

### `check <WORKSPACE> <TAGS>`
Check if cache entries exist without downloading.

```bash
boringcache check my-org/ws "node-deps"
boringcache check my-org/ws "node-deps,build-cache" --json
```

## Tag resolution (git-aware)

By default, tags are git-aware.

- Save on a feature branch uses a branch-suffixed tag.
- Restore uses one effective tag (branch-suffixed on feature branches, base tag on the default branch).
- Platform suffixes are appended by default; disable with `--no-platform`.
- If a tag already includes an explicit channel (`-branch-`, `-sha-`, `-main`, `-master`), no git suffix is applied.
- Disable this behavior with `--no-git` or `BORINGCACHE_NO_GIT=1`.

### `workspaces`
List available workspaces.

### `config <ACTION>`
Manage configuration: `list`, `get <key>`, `set <key> <value>`

### `setup-encryption [WORKSPACE]`
Generate an Age keypair and configure automatic encryption for a workspace.

```bash
boringcache setup-encryption my-org/ws
```

## Environment variables

- `BORINGCACHE_API_TOKEN` - API token (recommended for CI)
- `BORINGCACHE_DEFAULT_WORKSPACE` - Default workspace
- `BORINGCACHE_API_URL` - Override API URL
- `BORINGCACHE_NO_GIT` - Disable git-aware tag suffixing

## GitHub Actions

Use the official `setup-boringcache` action for version pinning, checksum verification, and tool cache support:

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - uses: boringcache/setup-boringcache@v1
        with:
          token: ${{ secrets.BORINGCACHE_API_TOKEN }}

      - run: boringcache restore my-org/project "node-deps:node_modules"
        continue-on-error: true

      - run: npm ci
      - run: npm test

      - run: boringcache save my-org/project "node-deps:node_modules"
        if: success()
```

### Docker layer caching in GitHub Actions

Using the registry proxy (recommended — BuildKit only downloads layers it needs):

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: boringcache/setup-boringcache@v1
        with:
          token: ${{ secrets.BORINGCACHE_API_TOKEN }}

      - run: boringcache docker-registry my-org/project registry-cache --port 5000 &

      - uses: docker/build-push-action@v6
        with:
          context: .
          cache-from: type=registry,ref=localhost:5000/buildkit-cache:main
          cache-to: type=registry,ref=localhost:5000/buildkit-cache:main,mode=max
```

Using local export (downloads all layers upfront):

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: boringcache/setup-boringcache@v1
        with:
          token: ${{ secrets.BORINGCACHE_API_TOKEN }}

      - run: boringcache restore my-org/project "buildkit-cache:/tmp/buildkit-cache"
        continue-on-error: true

      - uses: docker/build-push-action@v6
        with:
          context: .
          cache-from: type=local,src=/tmp/buildkit-cache
          cache-to: type=local,dest=/tmp/buildkit-cache,mode=max

      - run: boringcache save my-org/project "buildkit-cache:/tmp/buildkit-cache"
        if: always()
```

The action accepts these inputs:
- `token` - BoringCache API token (sets `BORINGCACHE_API_TOKEN` env var)
- `version` - Version to install (default: `v1.1.0`)
- `verify-checksum` - Verify SHA256 checksum (default: `true`)
- `skip-cache` - Skip tool cache, always download fresh (default: `false`)

In GitHub Actions, prefer `BORINGCACHE_API_TOKEN` over running `boringcache auth`.

## When not to cache

Not all directories benefit from caching. Avoid caching:

- Highly non-deterministic outputs (timestamps, random IDs in filenames)
- Directories with machine-specific absolute paths baked in
- Temporary build artifacts that change on every run

If a directory cannot be safely reused, it should not be cached.

## Portability rules

- Same OS + architecture -> safe by default
- Cross-platform reuse requires `--no-platform`
- Binary caches should remain platform-scoped

When in doubt, keep platform scoping enabled.

## Security

### Server-side signing

All cache artifacts are automatically signed by the server using Ed25519. This provides:

- Authenticity: Cryptographic proof the artifact came from your workspace
- Integrity: Tamper detection for cached content
- Zero configuration: No keys to manage, automatic verification

```bash
# Signing happens automatically on save
boringcache save my-org/ws "deps:node_modules"

# Verification happens automatically on restore/mount (warnings if invalid)
boringcache restore my-org/ws "deps:node_modules"
```

The server generates a unique Ed25519 keypair per workspace. Signatures cover `tag:manifest_root_digest` to prevent replay attacks.
Signature verification is warn-only; restores continue, but invalid or missing signatures are reported.
If manifest digest validation fails, the cache is skipped with a warning (no hard failure).

### Client-side encryption (Age)

Optional encryption for sensitive data like database backups. Data is encrypted before leaving your machine.

When encryption is enabled on a CAS layout (OCI or Bazel), the CLI falls back to archive transport since encrypting individual blobs would break deduplication.

Recommended: Workspace-scoped encryption

```bash
# One-time setup per workspace
boringcache setup-encryption my-org/ws
# Generates keypair, saves to ~/.boringcache/age-identity.txt
# Configures workspace for automatic encryption

# From now on, save/restore auto-encrypt/decrypt
boringcache save my-org/ws "db-backup:./dump.sql"
boringcache restore my-org/ws "db-backup:./restored"
```

Manual encryption (ad-hoc)

```bash
# Save with explicit encryption
boringcache save my-org/ws "db-backup:./dump.sql" \
  --recipient age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Restore with explicit decryption
boringcache restore my-org/ws "db-backup:./restored" \
  --identity ~/.boringcache/age-identity.txt

# Mount with encryption (recipient enables encryption; identity is for decryption)
boringcache mount my-org/ws "backup:./data" \
  --recipient age1xxx... \
  --identity ~/.boringcache/age-identity.txt
```

Key management:
- You control your keys - we never see them
- Store identity files securely (they decrypt your data)
- Identity file location: `~/.boringcache/age-identity.txt`
- Passphrase-protected age identities prompt automatically; blank input skips passphrase use

## Performance

- Adaptive concurrency: Scales with CPU cores, memory, and disk type
- Parallel byte-range downloads: Large blobs (8MB+) are split into ranges and downloaded concurrently
- Blob-level deduplication: CAS layouts skip uploading blobs that already exist remotely
- Zstd compression: Fast compression with excellent ratios for archive transport
- Streaming I/O: Memory-efficient with inline SHA-256 verification
- Connection pooling: Reuses HTTP connections across transfers
- Content fingerprinting: Skips redundant uploads via Blake3 hashing

## Development

```bash
cargo build --release
cargo test
cargo fmt && cargo clippy
```
