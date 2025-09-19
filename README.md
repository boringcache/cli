# BoringCache CLI

High-performance command-line interface for cache management in CI/CD workflows. Built with Rust for maximum performance and reliability.

## 🚀 Installation

### Direct Download
```bash
curl -sSL https://install.boringcache.com/install.sh | sh
```

### Pre-built Binaries
Download the latest release from [GitHub Releases](https://github.com/boringcache/cli/releases):
- **Linux AMD64/ARM64** 
- **macOS Intel/ARM64**
- **Windows AMD64**

### From Source
```bash
git clone https://github.com/boringcache/cli.git
cd cli
cargo install --path .
```

## ⚡ Quick Start

### 1. Authentication
```bash
boringcache auth --token your-api-token
```

### 2. Save & Restore Cache
```bash
# Save cache entries (path:tag pairs) - workspace format: namespace/workspace
boringcache save my-org/my-workspace "node_modules:node-deps,target:build-cache"

# Restore cache entries (tag:path pairs)  
boringcache restore my-org/my-workspace "node-deps:node_modules,build-cache:target"

# Custom compression
boringcache save my-org/my-workspace "target:rust-release" --compression zstd
```

### 3. Manage Caches
```bash
# List cache entries
boringcache ls my-workspace

# Delete cache entries
boringcache delete my-workspace "old-cache-key"

# List workspaces
boringcache workspaces
```

## 📋 Command Reference

### `boringcache auth --token <TOKEN>`
Authenticate with the BoringCache API.

### `boringcache save <WORKSPACE> <PATH_TAG_PAIRS> [OPTIONS]`
Save cache entries. Use `path:tag` format.

**Options:**
- `--compression, -c`: Algorithm (`lz4`, `zstd`) - auto-selected by default
- `--description`: Description for the cache entry
- `--no-platform`: Disable platform info in cache keys
- `--verbose, -v`: Enable detailed output

### `boringcache restore <WORKSPACE> <TAG_PATH_PAIRS> [OPTIONS]`
Restore cache entries. **Path is mandatory** - use `tag:path` format.

**Examples:**
```bash
# Single restore
boringcache restore my-workspace "node-deps:node_modules"

# Multiple restores  
boringcache restore my-workspace "node-deps:node_modules,build-cache:target"
```

**Options:** 
- `--all`: Extract all archived paths to current directory
- `--no-platform`: Disable platform info in cache keys
- `--verbose, -v`: Enable detailed output

### `boringcache ls <WORKSPACE> [OPTIONS]`
List cache entries.

**Options:**
- `--limit, -l`: Number of entries (default: 20)
- `--page`: Page number (default: 1)

### `boringcache delete <WORKSPACE> <KEYS_OR_TAGS> [OPTIONS]`
Delete cache entries.

**Options:**
- `--by-tag`: Delete by tags instead of keys

### `boringcache workspaces`
List all workspaces.

### `boringcache config <ACTION>`
Manage configuration (`list`, `get <key>`, `set <key> <value>`).

## Configuration

### Environment Variables
- `BORINGCACHE_API_URL` - Override API URL
- `BORINGCACHE_API_TOKEN` - API token (useful for CI)  
- `BORINGCACHE_DEFAULT_WORKSPACE` - Set default workspace
- `BORINGCACHE_COMPRESSION` - Force compression (`lz4`, `zstd`)
- `BORINGCACHE_OPTIMIZE_FOR` - Optimize for (`speed`, `size`, `bandwidth`)
- `BORINGCACHE_ZSTD_LEVEL` - Set ZSTD compression level (1-22)
- `BORINGCACHE_DEBUG` - Show compression decision reasoning

**Override Examples:**
```bash
# Force LZ4 for maximum speed
export BORINGCACHE_COMPRESSION=lz4

# Force ZSTD for maximum compression  
export BORINGCACHE_COMPRESSION=zstd

# Optimize for bandwidth in slow networks
export BORINGCACHE_OPTIMIZE_FOR=bandwidth

# Debug compression decisions
export BORINGCACHE_DEBUG=1
```

## Performance Features

### 🚀 Intelligent Compression System

The CLI automatically chooses between LZ4 and ZSTD based on:
- **System resources** (CPU cores, memory, load)
- **File characteristics** (size, file count)
- **Environment context** (CI, containers, platform)

**Selection Logic:**
- **Small files (<50MB)**: LZ4 for speed
- **Large files (>500MB) + powerful system**: ZSTD for compression 
- **CI environments + large packages**: ZSTD for bandwidth savings
- **Resource-constrained systems**: LZ4 regardless of size
- **High CPU load (>95%)**: LZ4 to avoid system stress

**Adaptive Compression Levels:**
- **High-end systems** (16+ cores, 32GB+ RAM): ZSTD Level 6
- **Mid-range systems** (8+ cores, 16GB+ RAM): ZSTD Level 4
- **Standard systems** (4+ cores): ZSTD Level 2
- **Resource-constrained**: ZSTD Level 1 or LZ4

### 🎯 Performance Examples

| Scenario | System | File Size | Choice | Reason |
|----------|---------|-----------|--------|---------|
| CI build cache | 4 cores, 8GB | 500MB | **LZ4** | Fast extraction priority |
| Package distribution | 16 cores, 32GB | 2GB | **ZSTD** | Worth compression time for downloads |
| Container with limits | 2 cores, 4GB | 1GB | **LZ4** | Resource constraints |
| High CPU load | Any | Any | **LZ4** | Avoid additional CPU stress |

### 🛠 Other Optimizations
- **Streaming I/O** - Memory-efficient for large files
- **Content fingerprinting** - Avoids redundant uploads
- **Cross-platform** - Linux, macOS, Windows (AMD64/ARM64)
- **Sub-second startup** - <100ms cold start

## GitHub Actions Integration

```yaml
name: CI with BoringCache
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    env:
      BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_TOKEN }}
    
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      # Restore cache
      - run: boringcache restore my-workspace "node-deps:node_modules"
        continue-on-error: true
      
      - run: npm ci
      - run: npm test
      
      # Save cache  
      - run: boringcache save my-workspace "node_modules:node-deps"
        if: success()
```

## Releases & CI

### 🚀 Automated Releases
Cross-platform binaries are automatically built and released via GitHub Actions:

**Trigger Methods:**
```bash
# 1. Create and push a tag
git tag v1.2.3
git push origin v1.2.3

# 2. Create a GitHub release
# Go to GitHub → Releases → "Draft a new release"

# 3. Manual workflow dispatch
# GitHub → Actions → "Build and Release CLI" → "Run workflow"
```

**Built Platforms:**
- Linux AMD64 + ARM64 
- macOS Intel + ARM64
- Windows AMD64

### 🛠 Local Development
```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check formatting & linting
cargo fmt -- --check
cargo clippy
```

## Architecture

- **Rust** - Maximum performance and safety
- **Intelligent compression** - Auto-selects LZ4/ZSTD based on system capabilities
- **Streaming I/O** - Memory-efficient for large files  
- **Cross-platform** - Linux, macOS, Windows (AMD64/ARM64)
- **No dependencies** - Static binaries with no runtime requirements