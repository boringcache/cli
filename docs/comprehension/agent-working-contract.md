# Agent Working Contract

Stable CLI rules live here so `AGENTS.md` can stay small. Read this when implementing behavior, changing command flags, or touching cache lifecycle code.

## Product Boundaries

- The CLI is a CI-first cache tool.
- The server owns signing and API policy; the CLI owns local IO, command behavior, proxy behavior, and user-facing diagnostics.
- Do not reintroduce legacy fallback chains unless the task explicitly asks for them.

## Encryption And Signing

- The server signs `{tag}:{manifest_root_digest}` with Ed25519.
- The CLI verifies `workspace_signing_public_key` and server signatures. New responses can carry `server_envelope_signature` plus a canonical server signature payload, signature version, workspace key fingerprint, and signing key id; `server_signature` remains the legacy `tag:root` signature during rollout.
- Signature verification is warn-only unless strict mode is enabled. Missing or invalid signatures must not fail restore by default.
- `BORINGCACHE_TRUSTED_WORKSPACE_KEY_FINGERPRINT` optionally pins strict restores/checks to an expected `ed25519-sha256` workspace signing key fingerprint.
- Manifest bytes digest and manifest root digest mismatches warn and skip the cache.
- Encryption uses age: archives are `tar.zst` then age-encrypted; manifests are CBOR, zstd-compressed, then age-encrypted when encryption is on.
- `setup-encryption` stores workspace encryption config and default identity.
- `save` and `mount` auto-enable encryption if workspace config exists. `--recipient` enables encryption and overrides the configured recipient.
- `restore` and `mount` decrypt if `hit.encrypted` or manifest bytes are age-encrypted.
- Unix age identity files must be `0600`; fail on insecure permissions.
- Passphrase decryption prompts automatically for scrypt-encrypted age files. Blank input skips passphrase use.

## Tags, Manifests, And Misses

- Tag resolution uses `TagResolver` with platform suffix and git suffix when enabled.
- Restore candidates are a single effective tag. There is no fallback chain.
- For the proxy KV flush path, `bc_registry_root_v2_*` remains the OCI URL path. When the server advertises `registry_path_tags` and the primary resolved tag is valid under Rails tag rules, publish the human tag directly and let Rails resolve the root path through `cache_tags.registry_path`; unsupported tag names stay on the legacy root publish path.
- Manifest root digest uses SHA-256. File hashes remain BLAKE3.
- Manifest digest is SHA-256 of the uploaded manifest bytes.
- `BORINGCACHE_TEST_MODE=1` disables git suffixing to keep test tags stable.
- Cache miss is warn-only by default. `--fail-on-cache-miss` turns a miss into a hard error.

## Important Paths

- `src/` Rust source code.
- `tests/` CLI tests.
- `install.sh` install script.
- `install-web/` installation website assets.
- `.github/workflows/` CI, E2E, release, and image workflows.

## Code Style

- Write idiomatic Rust with clear names, small public APIs, low ceremony, and visible performance tradeoffs.
- Prefer Rust 2024 idioms supported by the pinned toolchain.
- Use `let ... else`, let-chains, inline format args, `is_some_and`, and `is_ok_and` when they clarify control flow.
- Use `anyhow::Result` for application errors and `thiserror` for library-level errors.
- Add `.context()` where it makes failures actionable.
- Do not swallow errors silently.
- Avoid extra allocations, unnecessary IO, and blocking calls in async paths.
- Delete unused code completely. Do not leave commented-out dead code.
- Comments are only for non-obvious business logic or external constraints.

## Operational Notes

- Config file: `~/.boringcache/config.json`.
- Default identity path: `~/.boringcache/age-identity.txt`.
- Important environment variables: `BORINGCACHE_API_TOKEN`, `BORINGCACHE_DEFAULT_WORKSPACE`, `BORINGCACHE_API_URL`, `BORINGCACHE_NO_GIT`.
- `mount` is long-running and refuses to clear root, home, or the current directory unless `--force` is set.

## Testing Gates

The exact required gate commands live in `AGENTS.md`. Do not rely on CI to catch a missed local formatting or lint pass.
