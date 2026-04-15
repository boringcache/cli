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

If you are migrating an existing workflow and do not have repo config yet, raw `entries` and `actions/cache`-compatible `path` / `key` / `restore-keys` inputs still work.

If you already manage the tool-specific setup yourself and only want proxy lifecycle plus adapter env injection, the CLI now also supports direct adapter commands:

```yaml
- run: |
    cat > .boringcache.toml <<'EOF'
    workspace = "my-org/my-project"

    [adapters.turbo]
    tag = "turbo-main"
    command = ["pnpm", "turbo", "run", "build"]
    metadata-hints = ["tool=turbo", "phase=ci"]
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

Keep the proxy story simple in CI too:

- `cache-registry` is the long-lived proxy when a workflow or service needs to keep one around
- adapter commands and `run --proxy` temporarily start that same proxy for one command and wait internally
- if a detached helper needs to spawn `cache-registry` and continue only after startup readiness, it should consume the CLI-owned readiness handoff instead of reimplementing local HTTP polling
- use `/_boringcache/status` for diagnostics, explicit lifecycle assertions, and publish-settlement checks

Keep the trust model simple:

- every job gets `BORINGCACHE_RESTORE_TOKEN`
- only trusted jobs get `BORINGCACHE_SAVE_TOKEN`
- `pull_request` jobs stay restore-only by default inside `boringcache/one`; set `save-on-pull-request: true` only when the write scope is intentionally isolated
- avoid broad legacy `BORINGCACHE_API_TOKEN` use in CI

Read from pull requests.
Write from trusted branches, tags, or manual jobs.
