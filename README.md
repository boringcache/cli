# BoringCache CLI

**Cache once. Reuse everywhere.**

BoringCache is a universal build artifact cache for CI, Docker, and local development. It stores and restores directories you choose so build outputs, dependencies, and tool caches can be reused across environments.

BoringCache does not run builds and is not tied to any build tool. It works with any language, framework, or workflow by caching directories explicitly selected by the user.

Caches are content-addressed and verified before restore. If identical content already exists, uploads are skipped. The same cache can be reused in GitHub Actions, Docker/BuildKit, and on developer machines using the same CLI.

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

## Commands

### `save <WORKSPACE> <TAG:PATH,...>`
Save cache entries using `tag:path` format.

```bash
boringcache save my-org/ws "deps:node_modules"
boringcache save my-org/ws "deps:node_modules,build:dist" --force
boringcache save my-org/ws "gems:vendor/bundle" --exclude "*.out"
```

Use `--force` to overwrite existing entries. Use `--exclude` to skip files matching glob patterns.

### `restore <WORKSPACE> <TAG:PATH,...>`
Restore cache entries. Path controls local extraction directory.

```bash
boringcache restore my-org/ws "deps:node_modules"
boringcache restore my-org/ws "deps:./node_modules,build:./dist"
```

### `ls [WORKSPACE]`
List cache entries.

### `mount <WORKSPACE> <TAG:PATH>`
Watch a directory and sync changes to remote cache in real-time.

```bash
boringcache mount my-org/ws "dev-cache:./node_modules"
```

Restores from remote on start, syncs periodically, and performs a final sync on Ctrl+C.

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
- Restore on a feature branch tries the branch tag first, then falls back to the base tag.
- Restore on the default branch only uses the base tag.
- Platform suffixes are appended by default; disable with `--no-platform`.
- If a tag already includes an explicit channel (`-branch-`, `-sha-`, `-main`, `-master`), no git suffix or fallback is applied.
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

The action accepts these inputs:
- `token` - BoringCache API token (sets `BORINGCACHE_API_TOKEN` env var)
- `version` - Version to install (default: `v1.0.0`)
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

- Parallel transfers: Concurrent uploads/downloads with adaptive concurrency
- Zstd compression: Fast compression with excellent ratios
- Streaming I/O: Memory-efficient for large files
- Connection pooling: Reuses HTTP connections
- Content fingerprinting: Skips redundant uploads
- Blake3 hashing: Fast content-addressable storage

## Development

```bash
cargo build --release
cargo test
cargo fmt && cargo clippy
```
