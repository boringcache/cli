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
# Save cache entries (tag:path pairs) - workspace format: namespace/workspace
boringcache save my-org/my-workspace "node-deps:node_modules,build-cache:target"

# Restore cache entries (tag:path pairs)  
boringcache restore my-org/my-workspace "node-deps:node_modules,build-cache:target"

# Custom compression
boringcache save my-org/my-workspace "rust-release:target" --compression zstd
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

### `boringcache save <WORKSPACE> <TAG_PATH_PAIRS> [OPTIONS]`
Save cache entries. Use `tag:path` format.

**Options:**
- `--compression, -c`: Algorithm (`lz4`, `zstd`) - auto-selected by default
- `--description`: Description for the cache entry
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

### ⚡ Lightning-Fast Performance
- **Early cache hit detection** - 1ms response for existing caches (vs 15s+ without optimization)
- **Instant UI feedback** - Shows progress immediately before network operations
- **Zero startup delay** - Optimized initialization order eliminates 1-2s hangs
- **Preflight validation** - Checks permissions and disk space before expensive operations
- **Connection pooling** - Reuses HTTP connections for multiple operations

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

### 🔒 Security Features
- **SHA256 content verification** - Prevents cache poisoning attacks
- **Path traversal protection** - Safe archive extraction with path validation
- **Permission safety** - Disables dangerous setuid/setgid permission preservation
- **Resource limits** - Protects against zip bombs and excessive resource usage

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
- **Symlink preservation** - Maintains symbolic links in archives

## GitHub Actions Integration

### 🚀 Basic Integration
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
      
      # Install BoringCache CLI
      - run: curl -sSL https://install.boringcache.com/install.sh | sh
      
      # Restore cache (fails gracefully if not found)
      - run: boringcache restore my-org/my-workspace "node-deps:node_modules"
        continue-on-error: true
      
      - run: npm ci
      - run: npm test
      
      # Save cache on success
      - run: boringcache save my-org/my-workspace "node-deps:node_modules"
        if: success()
```

### 🎯 Advanced Multi-Cache Setup
```yaml
name: Advanced CI with Multiple Caches
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_TOKEN }}
      BORINGCACHE_OPTIMIZE_FOR: bandwidth  # Optimize for CI bandwidth
    
    steps:
      - uses: actions/checkout@v4
      
      # Install CLI
      - run: curl -sSL https://install.boringcache.com/install.sh | sh
      
      # Multi-language setup
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      # Restore multiple caches (lightning fast with early hit detection)
      - run: |
          boringcache restore my-org/project \
            "node-deps:node_modules,python-deps:.venv,build-cache:dist"
        continue-on-error: true
      
      # Build steps
      - run: npm ci && npm run build
      - run: python -m pip install -r requirements.txt
      - run: python -m pytest
      
      # Save all caches atomically
      - run: |
          boringcache save my-org/project \
            "node-deps:node_modules,python-deps:.venv,build-cache:dist" \
            --description "CI build ${{ github.sha }}"
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

## Key Format Changes

### 📋 Tag:Path Format (v0.1.0+)
The CLI now uses a **consistent `tag:path` format** for both save and restore operations:

```bash
# ✅ New format (v0.1.0+) - consistent tag:path
boringcache save workspace "node-deps:node_modules"
boringcache restore workspace "node-deps:node_modules"

# ❌ Old format (deprecated) - inconsistent path:tag vs tag:path  
boringcache save workspace "node_modules:node-deps"    # was path:tag
boringcache restore workspace "node-deps:node_modules" # was tag:path
```

**Benefits:**
- **Consistent API** - Same format for save and restore
- **User control** - No automatic platform suffix appending 
- **Predictable** - What you save is exactly what you restore
- **Cross-platform** - Works identically on all platforms

### 🎯 Migration Guide
If upgrading from earlier versions:

1. **Review your scripts** - Change save format from `path:tag` to `tag:path`
2. **Update CI workflows** - Use consistent `tag:path` format throughout
3. **Test thoroughly** - Verify cache keys match between save and restore

## Architecture

- **Rust** - Maximum performance and safety
- **Security-first design** - SHA256 verification, path traversal protection, resource limits
- **Intelligent compression** - Auto-selects LZ4/ZSTD based on system capabilities
- **Streaming I/O** - Memory-efficient for large files  
- **Early optimization** - Cache hit detection before expensive operations
- **Cross-platform** - Linux, macOS, Windows (AMD64/ARM64)
- **No dependencies** - Static binaries with no runtime requirements