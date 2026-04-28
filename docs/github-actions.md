# GitHub Actions

The preferred path is:

1. install the CLI locally
2. run `boringcache onboard`
3. commit `.boringcache.toml` when it helps
4. use [`boringcache/one@v1`](https://github.com/boringcache/one) in GitHub Actions

That keeps CI and local runs on the same workspace, entries, and cache profiles.

Example:

```yaml
- uses: boringcache/one@v1
  with:
    workspace: my-org/my-project
    cache-profiles: bundle-install
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ secrets.BORINGCACHE_SAVE_TOKEN }}
```

For proxy-backed modes, `boringcache/one@v1` also accepts first-class `metadata-hints` so sessions and misses stay grouped by stable labels instead of per-run noise:

```yaml
- uses: boringcache/one@v1
  with:
    mode: bazel
    workspace: my-org/my-project
    metadata-hints: |
      project=web
      tool=bazel
      phase=ci
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ secrets.BORINGCACHE_SAVE_TOKEN }}
```

Keep those hints low-cardinality. Good values are `project=web`, `benchmark=grpc-bazel`, `tool=gradle`, `phase=seed`, or `phase=warm`. Avoid commit SHAs, run ids, or timestamps.

If the repo already defines `[proxy]` or adapter `metadata-hints` in `.boringcache.toml`, `boringcache/one@v1` inherits them through the CLI dry-run plan. Prefer repo config for durable defaults and use the action input only when the workflow needs an explicit override.
The canonical repo-config starting points in [Tool guides](tool-guides.md) are
meant to be shared between local CLI runs and GitHub Actions for exactly this
reason.

If you are migrating an existing workflow and do not have repo config yet, raw `entries` and `actions/cache`-compatible `path` / `key` / `restore-keys` inputs still work.

If you already manage the tool-specific setup yourself and only want proxy lifecycle plus adapter env injection, the CLI now also supports direct adapter commands:

```yaml
- run: |
    cat > .boringcache.toml <<'EOF'
    workspace = "my-org/my-project"

    [proxy]
    metadata-hints = ["project=web"]

    [adapters.turbo]
    tag = "turbo-main"
    command = ["pnpm", "turbo", "run", "build"]
    metadata-hints = ["tool=turborepo", "phase=ci"]
    EOF

- run: boringcache turbo
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ secrets.BORINGCACHE_SAVE_TOKEN }}
```

You can still override a configured adapter from the workflow when needed:

```yaml
- run: |
    boringcache turbo \
      --workspace my-org/my-project \
      --tag turbo-main \
      -- pnpm turbo run build
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ secrets.BORINGCACHE_SAVE_TOKEN }}
```

Use `boringcache/one@v1` when you want the action to keep owning tool setup such as Bazel rc files, Maven or Gradle cache config, buildx setup, or container networking.
When you run `boringcache docker` directly in GitHub Actions, the CLI derives Docker registry-cache run refs and aliases from GitHub metadata automatically. The action path passes the same provider-neutral metadata so Docker cache artifacts report the immutable run ref, import aliases, and promotion aliases.

For Docker and BuildKit registry caches on pull requests, restore-only is the default.
A PR-scoped ref such as `/cache:pr-3208` may be absent and return 404, but the CLI/action should still import the rest of the planned fallback chain: branch, default, and the stable fallback such as `/cache:buildcache`.
If a workflow intentionally wants PR-scoped Docker writes, give the job a save-capable token and set `save-on-pull-request: true`; do that only when the PR write scope is isolated, not merely to make the PR ref exist. In PR context, the derived write target is the PR alias. The stable fallback remains restore-only unless an explicit promotion override is configured.

Keep the proxy story simple in CI too:

- `cache-registry` is the long-lived proxy when a workflow or service needs to keep one around
- adapter commands and `run --proxy` temporarily start that same proxy for one command and wait internally
- if a detached helper needs to spawn `cache-registry` and continue only after startup readiness, it should consume the CLI-owned readiness handoff instead of reimplementing local HTTP polling
- use `/_boringcache/status` for diagnostics, explicit lifecycle assertions, and publish-settlement checks

Keep the trust model simple:

- every job gets `BORINGCACHE_RESTORE_TOKEN`
- only trusted jobs get `BORINGCACHE_SAVE_TOKEN`
- `pull_request` jobs stay restore-only by default inside `boringcache/one`; set `save-on-pull-request: true` only when the write scope is intentionally isolated
- restore-only PR Docker refs may 404 and should fall through to branch/default/stable imports
- avoid broad legacy `BORINGCACHE_API_TOKEN` use in CI

Read from pull requests.
Write from trusted branches, tags, or manual jobs.
