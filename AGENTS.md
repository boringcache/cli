# Agent Guide (BoringCache CLI)

Keep this file short. It is loaded often; durable detail belongs in skills and `docs/comprehension`.

## First Reads

- For CLI work, prefer the `cli-expert` skill entrypoint.
- For broad code changes, read `/Users/gaurav/boringcache/skills/categories/coding-principles/boringcache-engineering-guide/SKILL.md`.
- For broad CLI behavior or ownership questions, start at `docs/comprehension/README.md`.
- For implementation rules, read `docs/comprehension/agent-working-contract.md`.

## Non-Negotiables

- CLI is a CI-first Rust cache client.
- Server-side signing is the authenticity model; the CLI does not create signatures.
- Avoid legacy fallbacks unless explicitly requested.

## Structure

- Keep command entrypoints thin; shared transport belongs in focused helpers.
- CAS publish, restore, and receipt flows belong in their existing shared modules under `src/cache/`.
- Adapter capability and layout decisions belong in `src/adapters/mod.rs`.
- Keep archive-specific behavior separate from CAS-specific behavior.
- Split workflow intent cleanly: PR validation belongs in validation workflows; publish/deploy behavior belongs in main, tag, or release workflows.
- When touching a long or hard-to-grok file, treat simplification as part of the task: split by ownership, move tests into focused sibling modules, delete dead paths, or leave a clear note in `docs/comprehension` when deferring the cleanup.

## Required Gates

Run before committing or pushing CLI changes:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTFLAGS='-Wrust-2024-compatibility' cargo check --all-targets
cargo test
```

Use `crate::test_env` for process environment mutation in tests.

## Updates

- Update the relevant `docs/comprehension` file before handoff when command surface, flags, env/config behavior, cache lifecycle, proxy/adapters, release workflows, module ownership, support reachability, or file coverage changes.
- If CLI changes alter Rails API expectations, update `/Users/gaurav/boringcache/web/docs/comprehension` too.
- If CLI work implements, validates, supersedes, or rejects an ADR-tracked decision, update the relevant ADR before handoff with progress, evidence, and remaining gates.
- For release, action tag, base-image, or benchmark dispatch work, load `/Users/gaurav/boringcache/skills/categories/release-operations/release-paths/SKILL.md` first.
