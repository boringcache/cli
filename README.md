# BoringCache CLI

CLI client for BoringCache, the high-performance cache for CI/CD workflows. Built with Rust.

## Installation

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
```

Or download from [GitHub Releases](https://github.com/boringcache/cli/releases) (Linux AMD64/ARM64, macOS ARM64, Windows AMD64).

## Quick Start

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

## Commands

### `save <WORKSPACE> <TAG:PATH,...> [OPTIONS]`
Save cache entries using `tag:path` format.

```bash
boringcache save my-org/ws "deps:node_modules"
boringcache save my-org/ws "deps:node_modules,build:dist" --force

# Exclude files from cache (useful for non-deterministic build artifacts)
boringcache save my-org/ws "gems:vendor/bundle" --exclude "*.out,*.log"
boringcache save my-org/ws "gems:vendor/bundle" --exclude "*.out" --exclude "*.log"
```

Options:
- `--force` - Force save even if cache entry already exists
- `--no-platform` - Disable platform suffix (for cross-platform caches)
- `--no-git` - Disable git-aware tag suffixing (branch/sha detected from the repo of the path/cwd)
- `--exclude <PATTERNS>` - Exclude files matching glob patterns (comma-separated, can be repeated)
- `--recipient <PUBKEY>` - Enable encryption with the provided Age recipient (age1...)
- `-v, --verbose` - Detailed output

#### Exclude Patterns

The `--exclude` option supports glob-like patterns:

| Pattern | Matches |
|---------|---------|
| `*.out` | All files ending with `.out` |
| `gem_*` | All files starting with `gem_` |
| `gem*.out` | Files like `gem_make.out`, `gem.out` |
| `*make*` | Files containing `make` |
| `ruby/*.out` | `.out` files in the `ruby/` directory |

Common use case: Ruby gem caches contain `gem_make.out` files with non-deterministic build paths. Exclude them for consistent cache hits:

```bash
boringcache save my-org/ws "gems:vendor/bundle" --exclude "*.out"
```

### `restore <WORKSPACE> <TAG:PATH,...> [OPTIONS]`
Restore cache entries. Path controls local extraction directory.

```bash
boringcache restore my-org/ws "deps:node_modules"
boringcache restore my-org/ws "deps:./node_modules,build:./dist"
```

Options:
- `--no-platform` - Disable platform suffix
- `--no-git` - Disable git-aware tag suffixing (branch/sha detected from the repo of the path/cwd)
- `--fail-on-cache-miss` - Warn on cache miss (non-fatal)
- `--lookup-only` - Check if cache exists without downloading
- `--identity <PATH>` - Path to Age identity file for decryption
- `-v, --verbose` - Detailed output

### `ls [WORKSPACE] [OPTIONS]`
List cache entries.

Options:
- `-l, --limit` - Number of entries (default: 20)
- `--page` - Page number

### `mount <WORKSPACE> <TAG:PATH>`
Watch a directory and sync changes to remote cache in real-time.

```bash
boringcache mount my-org/ws "dev-cache:./node_modules"
```

- Restores from remote on start (if exists)
- Syncs after 50 changes or 60s idle
- Final sync on Ctrl+C
- Platform-aware by default

Options:
- `--force` - Allow clearing root, home, or current directory on initial restore
- `--recipient <PUBKEY>` - Enable encryption with the provided Age recipient (age1...)
- `--identity <PATH>` - Path to Age identity file for decryption
- `-v, --verbose` - Detailed output

### `delete <WORKSPACE> <TAGS> [OPTIONS]`
Delete cache entries by tag.

### `check <WORKSPACE> <TAGS> [OPTIONS]`
Check if cache entries exist on the server without downloading.

```bash
# Check single tag
boringcache check my-org/ws "node-deps"

# Check multiple tags
boringcache check my-org/ws "node-deps,build-cache,test-artifacts"

# JSON output for scripting
boringcache check my-org/ws "node-deps" --json

# Warn if any tag is missing (non-fatal)
boringcache check my-org/ws "required-deps" --fail-on-miss
```

Options:
- `--no-platform` - Disable platform suffix
- `--no-git` - Disable git-aware tag suffixing
- `--fail-on-miss` - Warn if any tag is not found (non-fatal)
- `-j, --json` - Output results in JSON format

**Note:** The check command verifies tag existence only, not content integrity. A tag may exist but the underlying cache content could be incomplete or corrupted. Use `restore` for production workflows where you need the actual cached content. The check command is useful for:
- CI/CD workflow decisions (conditional steps based on cache availability)
- Debugging cache key issues
- Quick verification scripts

### `workspaces`
List available workspaces.

### `config <ACTION>`
Manage configuration: `list`, `get <key>`, `set <key> <value>`

### `setup-encryption [WORKSPACE] [OPTIONS]`
Setup encryption for a workspace. Generates an Age keypair and configures auto-encryption.

```bash
# Setup encryption for default workspace
boringcache setup-encryption

# Setup encryption for a specific workspace
boringcache setup-encryption my-org/ws

# Use custom identity file location
boringcache setup-encryption my-org/ws --identity-output ~/.age/mykey.txt
```

After setup, save/restore/mount commands for that workspace will automatically encrypt/decrypt.

## Environment Variables

- `BORINGCACHE_API_TOKEN` - API token (recommended for CI)
- `BORINGCACHE_DEFAULT_WORKSPACE` - Default workspace
- `BORINGCACHE_API_URL` - Override API URL
- `BORINGCACHE_NO_GIT` - Disable git-aware tag suffixing

## GitHub Actions

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_API_TOKEN }}

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: curl -sSL https://install.boringcache.com/install.sh | sh

      - run: boringcache restore my-org/project "node-deps:node_modules"
        continue-on-error: true

      - run: npm ci
      - run: npm test

      - run: boringcache save my-org/project "node-deps:node_modules"
        if: success()
```

## Platform-Aware Caching

By default, platform suffixes are appended to tags for binary isolation:

```bash
# On Ubuntu: deps-ubuntu-22.04-amd64
# On macOS ARM: deps-macos-15-arm64
boringcache save ws "deps:node_modules"

# Cross-platform cache (no suffix)
boringcache save ws "config:settings" --no-platform
```

## Security

### Server-Side Signing

All cache artifacts are automatically signed by the server using Ed25519. This provides:

- **Authenticity** - Cryptographic proof the artifact came from your workspace
- **Integrity** - Tamper detection for cached content
- **Zero configuration** - No keys to manage, automatic verification

```bash
# Signing happens automatically on save
boringcache save my-org/ws "deps:node_modules"

# Verification happens automatically on restore/mount (warnings if invalid)
boringcache restore my-org/ws "deps:node_modules"
```

The server generates a unique Ed25519 keypair per workspace. Signatures cover `tag:manifest_root_digest` to prevent replay attacks.
Signature verification is warn-only; restores continue, but invalid or missing signatures are reported.
If manifest digest validation fails, the cache is skipped with a warning (no hard failure).

### Client-Side Encryption (Age)

Optional encryption for sensitive data like database backups. Data is encrypted before leaving your machine.

**Recommended: Workspace-scoped encryption**

```bash
# One-time setup per workspace
boringcache setup-encryption my-org/ws
# Generates keypair, saves to ~/.boringcache/age-identity.txt
# Configures workspace for automatic encryption

# From now on, save/restore auto-encrypt/decrypt
boringcache save my-org/ws "db-backup:./dump.sql"
boringcache restore my-org/ws "db-backup:./restored"
```

**Manual encryption (ad-hoc)**

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

**Key management:**
- You control your keys - we never see them
- Store identity files securely (they decrypt your data)
- Identity file location: `~/.boringcache/age-identity.txt`
- Passphrase-protected age identities prompt automatically; blank input skips passphrase use

## Performance

- **Parallel transfers** - Concurrent uploads/downloads with adaptive concurrency
- **Zstd compression** - Fast compression with excellent ratios
- **Streaming I/O** - Memory-efficient for large files
- **Connection pooling** - Reuses HTTP connections
- **Content fingerprinting** - Skips redundant uploads
- **Blake3 hashing** - Fast content-addressable storage

## Development

```bash
cargo build --release
cargo test
cargo fmt && cargo clippy
```
