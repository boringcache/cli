# CLI Comprehension Map

This folder is the durable feature map for the CLI.

Use it in this order:

1. `feature-map-overview.md`
2. `feature-map-cache-lifecycle.md`
3. `feature-map-proxy-and-adapters.md`
4. `feature-map-workspace-auth-config.md`
5. `support-and-reachability.md`
6. `intent-and-context-gaps.md`
7. `file-coverage-index.md`
8. `cli-structure.md` for the namespace/tree view

## Status legend

- `public-primary`: direct user-facing feature wired from `src/cli.rs`
- `support-primary`: not a command by itself, but on hot paths for public features
- `internal-only`: compiled and used, but not exposed as a direct CLI feature
- `legacy-visible-alias`: still reachable from the CLI, but mainly compatibility naming
- `hidden-internal`: intentionally hidden from normal help or meant only for machine/planner use
- `lightly-used`: real feature, but docs/tests/usage evidence are thinner than the main flows
- `dormant-or-underused`: code exists and compiles, but current reachability is weak

## How to update this map

When a feature changes:

1. Update the relevant row in the feature-family file.
2. Update `feature-map-overview.md` if the feature moved groups, changed status, or added/removed entrypoints.
3. Update `support-and-reachability.md` if shared plumbing changed reachability.
4. Update `intent-and-context-gaps.md` when product intent becomes clearer or a previously open question is decided.
5. Update `file-coverage-index.md` if files moved, were added, or were deleted.
6. Keep `cli-structure.md` focused on namespace boundaries, not feature intent.

## Scope note

This map is based on the current workspace state, not only on committed files.

At the time of writing, the proxy KV internals are in motion in the worktree:

- `src/serve/cache_registry/kv/mod.rs`
- `src/serve/cache_registry/kv/flush.rs`
- `src/serve/cache_registry/kv/refresh.rs`
- `src/serve/cache_registry/kv/flight.rs`

That refactor is reflected in the proxy/adapters map as the current shape.
