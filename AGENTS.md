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
- `.github/workflows/` CI, E2E, release, and image workflows

## Comprehension Map

- Use `.comprehension/README.md` before broad CLI changes.
- Update the relevant `.comprehension` file before handoff when command surface, flags, environment/config behavior, cache lifecycle, proxy/adapters, release workflows, module ownership, support reachability, or file coverage changes.
- If the CLI change changes Rails API contract expectations, also update the relevant web `.comprehension` docs in `/Users/gaurav/boringcache/web/.comprehension`.

## Structure Rules

- Load `/Users/gaurav/boringcache/skills/categories/coding-principles/boringcache-engineering-guide/SKILL.md` before broad code changes.
- Keep command entrypoints thin. Shared transport logic should live in focused helpers, not be duplicated across `save`, `restore`, and `mount`.
- Use `src/commands/cas_publish.rs` for shared CAS publish flow.
- Use `src/commands/cas_restore.rs` for shared CAS restore fetch/verify/download flow.
- Use `src/commands/upload_receipts.rs` for upload-session receipt helpers.
- Keep adapter capability and layout decisions in `src/adapters/mod.rs`; do not re-encode transport/layout rules in command modules.
- Prefer extracting a shared helper or module before introducing a third copy of similar logic.
- Keep archive-specific behavior separate from CAS-specific behavior.
- Keep workflow intent split cleanly:
  - PR validation belongs in validation workflows.
  - publish or deployment behavior belongs in main/tag/release workflows only.

## Conventions

**Rust code style**
- No inline comments; code must be self-documenting through clear naming.
- Comments only for non-obvious business logic or external constraints.
- Follow Rust conventions strictly.
- Write Rust with the same restraint expected from good Ruby: clear names, small public APIs, low ceremony, no abstraction theater, and performance visible in the data path.
- Prefer Rust 2024 idioms supported by the pinned toolchain instead of preserving older 2021-style patterns.
- Use `let ... else`, let-chains, inline format args, and helpers like `is_some_and` or `is_ok_and` when they make control flow clearer.
- New examples, fixtures, and generated Cargo manifests should default to `edition = "2024"`.
- In tests, mutate process environment only through `crate::test_env`; do not call `std::env::set_var` or `std::env::remove_var` directly.
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
- When a file grows large because of orchestration-only code, extract shared helpers instead of adding more branches inline.

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
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTFLAGS='-Wrust-2024-compatibility' cargo check --all-targets
cargo test
```

Run before pushing too. Do not rely on CI to catch a missed local formatting or lint pass.

Recent reminder:
- GitHub Actions run `23025952437` (`Test CLI (BoringCache)`, March 12, 2026) passed build and tests, then failed at `cargo fmt -- --check`.
- Treat `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `RUSTFLAGS='-Wrust-2024-compatibility' cargo check --all-targets`, and `cargo test` as the required local pre-push gate for CLI changes.

## Operational Notes

- `mount` is a long-running watch/sync operation.
- `mount` refuses to clear root, home, or current directory unless `--force` is set.

## Skills

- Prefer global skills for general CLI, API, or repo work.
- Use root `release-paths` (`/Users/gaurav/boringcache/skills/categories/release-operations/release-paths/SKILL.md`) before any CLI release, release tag, base-image publish, action follow-up, or benchmark dispatch.
- Use local `cli-sccache-release-ops` for sccache proxy behavior, workflow tag conventions, benchmark regression checks, and CLI release execution.
