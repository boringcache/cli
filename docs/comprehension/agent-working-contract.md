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
- Restore candidates are ordered by the GitHub cache accessibility model: default-branch runs read/write the default tag; trusted non-default branches read branch then default and write branch; PRs read base/default by default; PR save-enabled runs read PR then base/default and write only PR. The complete matrix and action/Rails ownership split lives in `docs/comprehension/cache-scope-model.md`.
- Generated git scope suffixes are sanitized. Explicit user-provided cache tags are not silently rewritten, so workflow authors who interpolate refs such as `github.ref_name` must pass a slugged tag.
- The action may pass GitHub metadata, `BORINGCACHE_SAVE_ON_PULL_REQUEST` for PR save intent, and `BORINGCACHE_RESTORE_PR_CACHE` for PR-first archive reads. The CLI restore path must not infer read scope from the save-side env name, and the action must not become a second branch/default/PR planner for archive, proxy, or Docker behavior.
- Git detection env precedence is explicit. Default branch detection reads `BORINGCACHE_DEFAULT_BRANCH`, then `BORINGCACHE_CI_DEFAULT_BRANCH`, then `GITHUB_DEFAULT_BRANCH`, then `GITHUB_EVENT_PATH` repository JSON. PR base and number overrides are `BORINGCACHE_CI_BASE_REF` and `BORINGCACHE_CI_PR_NUMBER`; GitHub Actions `GITHUB_BASE_REF`, `GITHUB_REF`, `GITHUB_REF_NAME`, and event JSON are fallbacks.
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

## Refactoring Hygiene

- When a change touches a complex module, long file, or confusing test surface, make the touched area easier for the next human or agent to understand.
- Prefer small, reviewable cleanup slices: move tests into sibling modules, split protocol or command concerns by owner, extract repeated setup only when it removes real noise, and keep mechanical moves separate from behavior changes when possible.
- Do not refactor across hot cache, proxy, publish, or restore paths without behavior-boundary tests that prove no regression.
- If cleanup would make the task riskier or too broad, document the deferred cleanup and owner in the relevant `docs/comprehension` file instead of leaving hidden complexity unnamed.
- Do not add abstractions for tidiness alone. A new module or helper should make ownership, data flow, or invariants easier to see.

## Operational Notes

- Config file: `~/.boringcache/config.json`.
- Default identity path: `~/.boringcache/age-identity.txt`.
- Important environment variables: `BORINGCACHE_API_TOKEN`, `BORINGCACHE_DEFAULT_WORKSPACE`, `BORINGCACHE_API_URL`, `BORINGCACHE_NO_GIT`.
- `mount` is long-running and refuses to clear root, home, or the current directory unless `--force` is set.
- CLI releases use a two-step path: prepare the signed version commit, wait for the existing CLI CI and E2E workflow runs on that exact commit to pass, then create the signed tag. `scripts/release.sh tag VERSION [COMMIT]` may target an explicit already-green commit SHA; the release workflow verifies existing runs and does not dispatch prerequisite CI.

## Testing Gates

The exact required gate commands live in `AGENTS.md`. Do not rely on CI to catch a missed local formatting or lint pass.
