# Agent Guide (BoringCache CLI)

## Overview

CLI client for BoringCache, the CI-first cache tool built with Rust.

## Scope

- CLI is a CI-first cache tool.
- Server-side signing is the supported authenticity model; the CLI does not create signatures.
- Avoid reintroducing legacy fallbacks unless explicitly requested.

## Key Behaviors

**Encryption and signing**
- Server signs payload "{tag}:{manifest_root_digest}" with Ed25519.
- CLI verifies using `workspace_signing_public_key` and `server_signature`.
- Signature verification is warn-only; do not fail on missing/invalid signatures.
- Manifest bytes digest and manifest root digest mismatches warn and skip the cache (no hard failure).
- Encryption uses age: archives are `tar.zst` then age-encrypted; manifests are CBOR, zstd-compressed, then age-encrypted when encryption is on.
- `setup-encryption` stores workspace encryption config and default identity.
- Save and mount auto-enable encryption if workspace config exists; `--recipient` enables encryption and overrides the configured recipient.
- Restore/mount decrypt if `hit.encrypted` or the manifest bytes are age-encrypted.
- Age identity files must be `0600` on unix; fail on insecure perms.
- Passphrase decryption prompts automatically for scrypt-encrypted age files; blank input skips passphrase use.

**Tags and manifests**
- Tag resolution uses `TagResolver` with platform suffix and git suffix when enabled.
- Restore candidates are a single effective tag (no fallback chain).
- Manifest root digest uses SHA-256; file hashes remain BLAKE3.
- Manifest digest is SHA-256 of the uploaded manifest bytes.
- `BORINGCACHE_TEST_MODE=1` disables git suffixing to keep test tags stable.

**Cache miss behavior**
- Cache miss is warn-only by default.
- `--fail-on-cache-miss` turns a miss into a hard error.

## Project Structure

Key paths:
- `src/` Rust source code
- `tests/` CLI tests
- `install.sh` install script
- `install-web/` installation website assets

## Conventions

**Rust code style**
- No inline comments; code must be self-documenting through clear naming.
- Comments only for non-obvious business logic or external constraints.
- Follow Rust conventions strictly.
- Use `snake_case` for functions and variables.
- Use `CamelCase` for types and traits.
- Keep functions focused and under 50 lines when possible.
- Use meaningful variable names that describe purpose.

**Error handling**
- Use `anyhow::Result` for application errors.
- Use `thiserror` for library-level errors.
- Provide context with `.context()` for actionable error messages.
- Never swallow errors silently.

**General**
- Minimal changes only.
- No over-engineering.
- No backwards compatibility hacks.
- Delete unused code completely.
- Performance-first: avoid extra allocations, unnecessary I/O, and blocking calls in async paths.

## Inputs and Configuration

Environment variables:
- `BORINGCACHE_API_TOKEN`
- `BORINGCACHE_DEFAULT_WORKSPACE`
- `BORINGCACHE_API_URL`
- `BORINGCACHE_NO_GIT`

Config locations:
- Config file: `~/.boringcache/config.json`.
- Default identity path: `~/.boringcache/age-identity.txt`.

## Testing

Run before committing:
```
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## Operational Notes

- `mount` is a long-running watch/sync operation.
- `mount` refuses to clear root, home, or current directory unless `--force` is set.

## Skills

This repo does not define local skills. Use the global skill list when applicable.
