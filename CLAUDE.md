# Claude Development Guide - BoringCache CLI

## 🎯 Your Role & Rules

**You are working on a Rust CLI for distributed build caching. Follow these rules STRICTLY:**

### ❌ NEVER DO
- **NO LINE COMMENTS** - Code must be self-documenting via naming
- **NO .unwrap()** - Always use proper error handling
- **NO panicking** - Use `Result<T, E>` patterns
- **NO manual formatting** - Let cargo fmt handle it

### ✅ ALWAYS DO
1. **Run quality checks**: `cargo fmt && cargo clippy -- -D warnings && cargo test`
2. **Use descriptive names** instead of comments
3. **Handle errors properly** with `anyhow::Result` or `BoringCacheError`
4. **Follow Rust conventions**: snake_case, PascalCase, SCREAMING_SNAKE_CASE

## 🏗️ Codebase Architecture

### Critical Files You'll Work With

**Core Logic**:
- `src/platform.rs` - Platform detection & system resources (CPU, memory, disk)
- `src/cache_operations/` - Save/restore workflows and upload logic  
- `src/api.rs` - HTTP client for server communication
- `src/compression.rs` - LZ4/ZSTD compression selection
- `src/tag_utils.rs` - Tag validation and parsing utilities

**Commands**:
- `src/commands/save.rs` - Batch save operations with validation
- `src/commands/restore.rs` - Batch restore with path expansion
- `src/commands/auth.rs` - Token authentication

**CI/CD**:
- `.github/workflows/release.yml` - Multi-platform binary builds
- `install.sh` - Distribution-aware installation script

### Key Data Flow

1. **Save**: `tag:path` → compression → archive → upload
2. **Restore**: `tag:path` → download → verify → extract → place files
3. **Tag handling**: Tags are used exactly as provided by users (no automatic platform suffixing)

## 🔧 Platform Support Matrix

**Architecture Mapping**: `x86_64` → `amd64`, `aarch64` → `arm64`

**Tag Suffixes Generated**:
- Ubuntu: `ubuntu-22.04-amd64`, `ubuntu-24.04-arm64`
- Debian: `debian-bookworm-amd64`, `debian-bullseye-arm64`  
- Alpine: `alpine-amd64` (musl static)
- Arch: `arch-amd64`, `arch-arm64`
- macOS: `macos-13-amd64`, `macos-15-arm64`
- Windows: `windows-2022-amd64`
- Generic: `linux-amd64`, `linux-arm64` (Ubuntu 22.04 base)

**Detection Logic** (`src/platform.rs:90-130`):
- Linux: `/etc/os-release`, `/etc/debian_version`, `/etc/arch-release`, etc.
- macOS: `sw_vers -productVersion`
- Architecture: `std::env::consts::ARCH`

## 🚀 Release & Build System

**Binary Naming Convention**:
```
boringcache-{platform}-{version}-{arch}[.exe]
Examples:
- boringcache-ubuntu-22.04-amd64
- boringcache-macos-15-arm64  
- boringcache-windows-2022-amd64.exe
- boringcache-linux-amd64 (generic, Ubuntu 22.04 base)
```

**Install Script Logic** (`install.sh:99-132`):
1. Detect OS/arch: `uname -s` / `uname -m`
2. Check distro files: `/etc/arch-release`, `/etc/alpine-release`, etc.
3. Select best binary match
4. Fallback to generic `linux-amd64/arm64` for unknown distros

## 🧪 Testing Patterns

**Must test after changes**:
```bash
cargo test platform::tests::test_tag_suffix_generation
cargo test tag_utils::tests::test_basic_tag_validation
cargo test compression::tests::test_intelligent_selection
```

**Error Scenarios to Handle**:
- Missing files in save operations → skip with warning
- Network failures → retry with exponential backoff
- Platform detection failures → fallback to generic
- Invalid tag formats → clear validation errors

## 🔍 Common Debugging Areas

**Tag Validation Issues**:
- Check tag validation in `validate_tag_basic()` in `src/tag_utils.rs`
- Test parsing functions `parse_save_format()` and `parse_restore_format()`
- Verify tag:path format consistency across commands

**CI/CD Build Failures**:
- Docker container setup in `.github/workflows/release.yml:145-173`
- Cross-compilation for ARM64 targets
- Binary naming consistency across platforms

**Install Script Issues**:
- Distribution detection logic
- Binary name mapping to releases
- Fallback mechanisms for unknown platforms

## 🎨 Code Style Specifics

**Error Handling Pattern**:
```rust
// ✅ Good
pub fn operation() -> Result<String> {
    let result = risky_operation()
        .map_err(|e| anyhow!("Failed to perform operation: {}", e))?;
    Ok(result)
}

// ❌ Bad  
pub fn operation() -> String {
    risky_operation().unwrap() // NEVER DO THIS
}
```

**Naming Patterns**:
```rust
// ✅ Good - self-documenting
let platform_specific_tag = generate_platform_tag(user_tag, &platform_info);
let ubuntu_build_binary_name = "boringcache-ubuntu-22.04-amd64";

// ❌ Bad - would need comments
let tag = gen_tag(user_tag, &platform); // What kind of tag?
let binary = "boringcache-ubuntu-22.04-amd64"; // What's this for?
```

## 🚨 Critical Invariants

1. **Platform tags must be deterministic** - same input always produces same tag
2. **Binary names must match install script expectations** - exact string matching
3. **All paths must be expanded** - handle `~` and relative paths consistently  
4. **No secrets in logs** - sanitize URLs and tokens
5. **Graceful degradation** - unknown platforms should fallback, not crash

