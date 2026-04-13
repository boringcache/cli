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
    boringcache turbo \
      --workspace my-org/my-project \
      --tag turbo-main \
      -- pnpm turbo run build
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ secrets.BORINGCACHE_SAVE_TOKEN }}
```

Use `boringcache/one@v1` when you want the action to keep owning tool setup such as Bazel rc files, Maven or Gradle cache config, buildx setup, or container networking.

Keep the trust model simple:

- every job gets `BORINGCACHE_RESTORE_TOKEN`
- only trusted jobs get `BORINGCACHE_SAVE_TOKEN`
- `pull_request` jobs stay restore-only by default inside `boringcache/one`; set `save-on-pull-request: true` only when the write scope is intentionally isolated
- avoid broad legacy `BORINGCACHE_API_TOKEN` use in CI

Read from pull requests.
Write from trusted branches, tags, or manual jobs.
