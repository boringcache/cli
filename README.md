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
# Install (force CDN revalidation to avoid stale script)
curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
  https://install.boringcache.com/install.sh | sh

# Save cache entries (tag:path pairs) - workspace format: namespace/workspace
# (only the tag is sent to the API; the path stays local)
boringcache save my-org/my-workspace "node-deps:node_modules,build-cache:target"

# Restore cache entries (tag:path pairs)  
# (remote lookups now use tag-only identifiers)
boringcache restore my-org/my-workspace "node-deps:node_modules,build-cache:target"

# Force overwrite existing cache
boringcache save my-org/my-workspace "build-cache:dist" --force

# Save without platform suffix (cross-platform cache)
boringcache save my-org/my-workspace "platform-agnostic:data" --no-platform

# Set a default workspace so commands can omit the workspace argument
boringcache config set default_workspace my-org/my-workspace
```

### 3. Manage Caches
```bash
# List cache entries
# Uses the configured default workspace (set via env/config)
boringcache ls
# Explicit workspace
boringcache ls my-org/my-workspace

# Delete cache entries
# Delete by tag (automatically appends platform suffix unless --no-platform)
boringcache delete my-org/my-workspace "old-cache-tag"

# List workspaces
boringcache workspaces
```

## 📋 Command Reference

### `boringcache auth --token <TOKEN>`
Authenticate with the BoringCache API.

### `boringcache save <WORKSPACE> <TAG_PATH_PAIRS> [OPTIONS]`
Save cache entries. Use `tag:path` format. Only the tag reaches the
BoringCache API; the path is used locally to locate files before upload.

**Options:**
- `--force`: Force save even if cache entry already exists on server (overwrites existing)
- `--no-platform`: Disable automatic platform suffix (e.g., `-ubuntu-22.04-amd64`)
- `--verbose, -v`: Enable detailed output

### `boringcache restore <WORKSPACE> <TAG_PATH_PAIRS> [OPTIONS]`
Restore cache entries. Use `tag:path` format when you want to control the target
directory; if the path portion is omitted the archive extracts into the current
directory. The CLI always looks up cache entries by tag on the server, while the
path controls local extraction.

**Examples:**
```bash
# Single restore
boringcache restore my-workspace "node-deps:node_modules"

# Multiple restores  
boringcache restore my-workspace "node-deps:node_modules,build-cache:target"
```

**Options:** 
- `--no-platform`: Disable automatic platform suffix (e.g., `-ubuntu-22.04-amd64`)
- `--verbose, -v`: Enable detailed output

### `boringcache ls [WORKSPACE] [OPTIONS]`
List cache entries. Provide the workspace as the first argument or rely on the
configured default (`BORINGCACHE_DEFAULT_WORKSPACE` or `boringcache config`).

**Options:**
- `--limit, -l`: Number of entries (default: 20)
- `--page`: Page number (default: 1)

### `boringcache delete <WORKSPACE> <TAGS> [OPTIONS]`
Delete cache entries by tag. Multiple tags can be provided as a comma-separated
string.

**Options:**
- `--no-platform`: Disable automatic platform suffix when matching tags
- `--verbose, -v`: Show extra diagnostics

### `boringcache workspaces`
List all workspaces.

### `boringcache config <ACTION>`
Manage configuration (`list`, `get <key>`, `set <key> <value>`).

## Configuration

### Environment Variables
- `BORINGCACHE_API_URL` - Override API URL
- `BORINGCACHE_API_TOKEN` - API token (useful for CI)  
- `BORINGCACHE_DEFAULT_WORKSPACE` - Set default workspace

## Performance Features

### ⚡ Lightning-Fast Performance
- **Early cache hit detection** - 1ms response for existing caches (vs 15s+ without optimization)
- **Instant UI feedback** - Shows progress immediately before network operations
- **Zero startup delay** - Optimized initialization order eliminates 1-2s hangs
- **Preflight validation** - Checks permissions and disk space before expensive operations
- **Connection pooling** - Reuses HTTP connections for multiple operations
- **Zstd chunk compression** - Predictable ratios and fast restores across platforms

### 🔒 Security Features
- **SHA256 content verification** - Prevents cache poisoning attacks
- **Path traversal protection** - Safe archive extraction with path validation
- **Permission safety** - Disables dangerous setuid/setgid permission preservation
- **Resource limits** - Protects against zip bombs and excessive resource usage

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

## Platform-Aware Caching

### 🎯 Automatic Platform Suffixes
By default, BoringCache automatically appends platform-specific suffixes to cache tags to ensure platform isolation. This prevents binary incompatibilities when caches are shared across different operating systems and architectures.

**Default Behavior:**
```bash
# Saved on Ubuntu 22.04 AMD64
boringcache save workspace "deps:node_modules"
# Actual tag: deps-ubuntu-22.04-amd64

# Saved on macOS ARM64 
boringcache save workspace "deps:node_modules"
# Actual tag: deps-macos-15-arm64

# Saved on Windows
boringcache save workspace "deps:node_modules"
# Actual tag: deps-windows-2022-amd64
```

**Disabling Platform Suffix:**
Use `--no-platform` when your cache is platform-independent:
```bash
# Platform-agnostic data (configs, documentation, etc.)
boringcache save workspace "config:settings" --no-platform
boringcache restore workspace "config:settings" --no-platform

# Cross-platform JavaScript/TypeScript
boringcache save workspace "js-deps:node_modules" --no-platform
```

**Force Overwriting:**
Use `--force` to overwrite existing cache entries:
```bash
# Update existing cache without checking
boringcache save workspace "build:dist" --force

# Combine with no-platform for cross-platform overwrites
boringcache save workspace "data:files" --force --no-platform
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
- **Privacy** - Only the tag is sent to the API; the path never leaves your machine
- **Cross-platform** - Works identically on all platforms

### 🎯 Migration Guide
If upgrading from earlier versions:

1. **Review your scripts** - Change save format from `path:tag` to `tag:path`
2. **Update CI workflows** - Use consistent `tag:path` format throughout
3. **Test thoroughly** - Verify cache tags match between save and restore

## Architecture

- **Rust** - Maximum performance and safety
- **Security-first design** - SHA256 verification, path traversal protection, resource limits
- **Zstd chunk compression** - Consistent ratios with fast decompression
- **Streaming I/O** - Memory-efficient for large files  
- **Early optimization** - Cache hit detection before expensive operations
- **Cross-platform** - Linux, macOS, Windows (AMD64/ARM64)
- **No dependencies** - Static binaries with no runtime requirements
