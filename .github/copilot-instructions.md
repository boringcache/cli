# Copilot Instructions for BoringCache CLI

## Project Overview

This is a high-performance Rust CLI tool for cache management with chunking, streaming uploads/downloads, and comprehensive error handling.

## Core Development Principles

### 1. Code Quality Standards

#### Rust-Specific Rules

- **Always run `cargo fmt` before committing** - Code must be formatted
- **Pass `cargo clippy --all-targets -- -D warnings`** - Zero clippy warnings allowed
- **Maintain 100% test coverage for critical paths** - All new features need tests
- **Use `anyhow::Result` for error handling** - Provide context with `.context()`
- **Prefer `tokio::spawn` for async tasks** - Manage task lifecycles properly
- **Use structured logging** - `log::debug!`, `log::info!`, `log::warn!`, `log::error!`

#### Memory & Performance

- **Streaming over buffering** - Use streaming chunkers, not in-memory buffers
- **Bounded channels** - Use `tokio::sync::mpsc::channel(capacity)` not unbounded
- **Resource cleanup** - Always `.abort()` spawned tasks in error paths
- **Efficient path handling** - Check `is_file()` vs `is_dir()` to avoid double joins

#### Error Handling

- **Contextual errors** - Use `.with_context(|| format!("...", var))`
- **Specific error types** - Don't swallow errors with generic messages
- **User-facing messages** - Use `ui::error()`, `ui::warn()`, `ui::info()`
- **Enhanced error logging** - Include request IDs, status codes, response bodies
- **Graceful degradation** - Continue processing on non-critical failures

### 2. Testing Requirements

#### Test Categories (125 total tests maintained)

- **Unit tests** - Test individual functions in `#[cfg(test)]` modules
- **Integration tests** - Test CLI workflows with mocked HTTP servers
- **API contract tests** - Verify request/response formats match API
- **Workflow tests** - End-to-end CLI command testing
- **Network tests** - Run with `BORINGCACHE_FORCE_NETWORK_TESTS=1`

#### Testing Standards

- **Mock HTTP with mockito** - Use `mockito::Server` for API mocking
- **Test both success and failure paths** - Don't just test happy paths
- **Verify error messages** - Check actual user-facing error text
- **Test flag combinations** - Verify flags work in any position
- **Include edge cases** - Empty inputs, single files, large batches

#### Critical Test Patterns

```rust
// Always acquire test lock for CLI tests
let _lock = acquire_test_lock().await;

// Check for network availability
if !networking_available() {
    eprintln!("skipping test: networking disabled");
    return;
}

// Use proper API contract (arrays, not wrapped objects)
json!([{ "tag": "...", "status": "..." }])  // ✅ Correct
json!({"results": [...]})                    // ❌ Wrong

// Include platform suffixes in mocks
"tag": "test-tag-macos-15-arm64"  // ✅ Correct
"tag": "test-tag"                  // ❌ Wrong (will fail with real platform)
```

### 3. API Integration Patterns

#### Request Structure

- **Wrap save requests** - `{"cache": { SaveRequest fields }}`
- **Use entries parameter** - `?entries=tag1,tag2` not `?tags=`
- **Platform suffixes** - Tags automatically get `-{os}-{version}-{arch}`
- **Force flag handling** - Client sends, API decides (API as source of truth)

#### Response Handling

- **Check exists field** - `if response.exists { skip_upload }`
- **Respect API decisions** - Don't duplicate server-side logic
- **Handle partial failures** - Process batch entries independently
- **Parse error payloads** - Extract `error`, `message`, `details` fields

### 4. File & Path Handling

#### Critical Path Rules

```rust
// ✅ Correct: Handle single file vs directory
let base_is_file = Path::new(base_path).is_file();
let full_path = if base_is_file && draft.descriptors.len() == 1 {
    PathBuf::from(base_path)  // Use base_path directly
} else {
    Path::new(base_path).join(&desc.path)  // Join for directories
};

// ❌ Wrong: Always joining causes /path/to/file/file
let full_path = Path::new(base_path).join(&desc.path);
```

#### Manifest Building

- **Single file handling** - Use filename as relative path, not full path
- **Directory walking** - Use `WalkDir` with `.follow_links(false)`
- **Path validation** - Expand tildes, check accessibility before processing
- **Metadata handling** - Use `symlink_metadata` to avoid following symlinks

### 5. Progress & UI Patterns

#### Progress System

- **Use ProgressSession** - 8 steps for save, configurable for restore
- **Update step progress** - `.update_progress(percent, detail)`
- **Complete steps** - Always call `.complete()` or `complete_skipped_step()`
- **Abort on errors** - `ticker_handle.abort()` before returning errors

#### User Interface

```rust
// ✅ Use structured UI functions
ui::info("Processing...");
ui::warn("Cache already exists");
ui::error("Failed to upload");

// ✅ Show progress with details
session.start_step("Chunking files".to_string(),
    Some(format!("{} changed file{}", count, if count == 1 { "" } else { "s" })))?;

// ✅ Format output consistently
ui::info(&format!("Saved {}/{} entries", success, total));
```

### 6. Architecture Patterns

#### Command Structure

- **Preflight checks** - Validate inputs before expensive operations
- **Batch processing** - Use `FuturesUnordered` for parallel operations
- **Summary reporting** - Show success/failure counts at the end
- **Clean shutdown** - Wait for all tasks before exiting

#### Module Organization

```
src/
  commands/     - CLI command implementations (save, restore, etc.)
  api/         - API client and models
  chunks/      - Chunking, uploading, downloading
  manifest/    - Manifest building and diffing
  platform/    - OS/arch detection
  progress/    - Progress tracking system
  *.rs         - Utilities (auth, config, error, etc.)
```

### 7. Comments & Documentation

#### When to Comment

- **Complex algorithms** - CDC chunking, path resolution edge cases
- **Non-obvious logic** - Platform suffix handling, force flag behavior
- **Bug fix explanations** - Reference issue or explain the problem
- **API contract notes** - Document expected request/response formats

#### When NOT to Comment

- **Obvious code** - Don't write `// Create client` before `ApiClient::new()`
- **Variable declarations** - Names should be self-explanatory
- **Test descriptions** - Use descriptive test function names instead
- **Redundant info** - Code should speak for itself when possible

#### Documentation Standards

```rust
// ✅ Good: Explains why and provides context
// Check if base_path is a file or directory to avoid double-joining paths.
// When saving a single file, base_path IS the file, not a directory containing it.
let base_is_file = Path::new(base_path).is_file();

// ❌ Bad: States the obvious
// Check if base_path is a file
let base_is_file = Path::new(base_path).is_file();

// ✅ Good: Documents public API with examples
/// Restores cache entries from the specified workspace
///
/// # Arguments
/// * `workspace` - Workspace slug (e.g., "org/project")
/// * `entries` - Tag:path pairs to restore
///
/// # Returns
/// Number of successfully restored entries
```

### 8. Git & Version Control

#### Commit Standards

- **Descriptive messages** - "Fix single file path resolution in chunking" not "Fix bug"
- **Reference issues** - Link to issue numbers when applicable
- **Atomic commits** - One logical change per commit
- **Test before commit** - Run `cargo test` and `cargo clippy`

#### Branch Strategy

- **Feature branches** - Create branches for new features
- **Fix branches** - Separate branches for bug fixes
- **Clean history** - Squash commits before merging if needed

### 9. Dependencies & Versions

#### Dependency Philosophy

- **Prefer well-maintained crates** - Check recent updates and community
- **Minimize dependencies** - Don't add for trivial functionality
- **Pin major versions** - Use semver compatible ranges
- **Audit regularly** - Check for security advisories

#### Key Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
anyhow = "1"
serde = { version = "1", features = ["derive"] }
reqwest = { version = "0.12", features = ["json", "stream"] }
clap = { version = "4", features = ["derive"] }
```

### 10. Performance Considerations

#### Optimization Rules

- **Profile before optimizing** - Don't guess, measure
- **Streaming for large files** - Never load entire files into memory
- **Parallel where beneficial** - Use `tokio::spawn` for I/O bound tasks
- **Bounded parallelism** - Use `determine_chunk_parallelism()` not unlimited
- **Smart buffering** - Use `BufReader`/`BufWriter` with appropriate sizes

#### Resource Management

```rust
// ✅ Bounded channel with proper capacity
let (tx, rx) = mpsc::channel(max_buffered_chunks);

// ✅ Cleanup temporary resources
let _temp_dir = TempDir::new()?;  // Auto-cleanup on drop

// ✅ Abort background tasks
let ticker_handle = spawn_ticker();
// ... work ...
ticker_handle.abort();  // Always cleanup
```

## Quick Checklist Before Committing

- [ ] `cargo fmt` - Code is formatted
- [ ] `cargo clippy --all-targets -- -D warnings` - No clippy warnings
- [ ] `cargo test` - All tests pass
- [ ] `BORINGCACHE_FORCE_NETWORK_TESTS=1 cargo test` - Network tests pass (if applicable)
- [ ] `cargo build --release` - Release build succeeds
- [ ] No trailing whitespace
- [ ] No TODO/FIXME/DEBUG comments without issue tracking
- [ ] Comments are meaningful, not obvious
- [ ] Error messages are user-friendly
- [ ] New features have integration tests
- [ ] API contract changes are tested
- [ ] Platform-specific code is tested on macOS/Linux

## Common Pitfalls to Avoid

1. **Path joining for single files** - Check if path is file before joining
2. **Forgetting platform suffixes** - Mocks must include `-{os}-{version}-{arch}`
3. **Wrong API contract** - Use arrays, not `{"results": [...]}` wrappers
4. **Not aborting background tasks** - Always abort ticker/progress tasks
5. **Swallowing errors** - Always add context with `.context()`
6. **Unbounded channels** - Use bounded channels for backpressure
7. **Missing force flag** - API decides, client respects decision
8. **Hardcoded tags in tests** - Use regex matchers for platform suffixes
9. **Not handling partial failures** - Process batch entries independently
10. **Forgetting to cleanup** - Use RAII patterns for resource management

## Testing Commands Reference

```bash
# Run all tests
cargo test

# Run with network tests enabled
BORINGCACHE_FORCE_NETWORK_TESTS=1 cargo test

# Run specific test
cargo test test_name -- --nocapture

# Run clippy
cargo clippy --all-targets -- -D warnings

# Format code
cargo fmt

# Build release
cargo build --release

# Check without building
cargo check
```

## When to Ask for Review

- Adding new CLI commands or flags
- Changing API contract or request/response formats
- Modifying chunking or streaming logic
- Large refactoring (>500 lines)
- Performance-critical code changes
- Changes to error handling patterns
- New external dependencies
- Breaking changes to configuration or storage formats
