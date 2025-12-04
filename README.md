# BoringCache CLI

High-performance cache management for CI/CD workflows. Built with Rust.

## Installation

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
```

Or download from [GitHub Releases](https://github.com/boringcache/cli/releases) (Linux, macOS, Windows - AMD64/ARM64).

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
```

## Commands

### `save <WORKSPACE> <TAG:PATH,...> [OPTIONS]`
Save cache entries using `tag:path` format.

```bash
boringcache save my-org/ws "deps:node_modules"
boringcache save my-org/ws "deps:node_modules,build:dist" --force
```

Options:
- `--force` - Overwrite existing cache
- `--no-platform` - Disable platform suffix (for cross-platform caches)
- `-v, --verbose` - Detailed output

### `restore <WORKSPACE> <TAG:PATH,...> [OPTIONS]`
Restore cache entries. Path controls local extraction directory.

```bash
boringcache restore my-org/ws "deps:node_modules"
boringcache restore my-org/ws "deps:./node_modules,build:./dist"
```

Options:
- `--no-platform` - Disable platform suffix
- `--fail-on-cache-miss` - Exit with error if cache not found
- `--lookup-only` - Check if cache exists without downloading
- `-v, --verbose` - Detailed output

### `ls [WORKSPACE] [OPTIONS]`
List cache entries.

Options:
- `-l, --limit` - Number of entries (default: 20)
- `--page` - Page number

### `delete <WORKSPACE> <TAGS> [OPTIONS]`
Delete cache entries by tag.

### `workspaces`
List available workspaces.

### `config <ACTION>`
Manage configuration: `list`, `get <key>`, `set <key> <value>`

## Environment Variables

- `BORINGCACHE_API_TOKEN` - API token (recommended for CI)
- `BORINGCACHE_DEFAULT_WORKSPACE` - Default workspace
- `BORINGCACHE_API_URL` - Override API URL

## GitHub Actions

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_TOKEN }}

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

## Performance

- **Parallel transfers** - Concurrent uploads/downloads with adaptive concurrency
- **Zstd compression** - Fast compression with excellent ratios
- **Streaming I/O** - Memory-efficient for large files
- **Connection pooling** - Reuses HTTP connections
- **Content fingerprinting** - Skips redundant uploads
- **SHA256 verification** - Prevents cache poisoning

## Development

```bash
cargo build --release
cargo test
cargo fmt && cargo clippy
```
