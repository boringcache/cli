# GitHub Actions

The preferred path is:

1. install the CLI locally
2. run `boringcache onboard`
3. commit `.boringcache.toml` when it helps
4. use [`boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9`](https://github.com/boringcache/one) in GitHub Actions

That keeps CI and local runs on the same workspace, entries, and cache profiles.

Example:

```yaml
- uses: boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9 # v1.19.2
  with:
    trust-policy: auto
    setup: none
    mode: archive
    cache-profiles: bundle-install
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ github.event_name != 'pull_request' && secrets.BORINGCACHE_SAVE_TOKEN || '' }}
```

The immutable ref and its version comment identify the reviewed Action release,
not the CLI binary version. The Action and CLI are released independently; each
Action release installs a default CLI version, and the `cli-version` input is an
explicit override.

For proxy-backed modes, `boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9` also accepts first-class `metadata-hints` so sessions and misses stay grouped by stable labels instead of per-run noise:

```yaml
- uses: boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9 # v1.19.2
  with:
    trust-policy: auto
    setup: none
    mode: bazel
    metadata-hints: |
      project=web
      tool=bazel
      lane=ci
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ github.event_name != 'pull_request' && secrets.BORINGCACHE_SAVE_TOKEN || '' }}
```

Keep those hints low-cardinality. Good values are `project=web`, `benchmark=grpc-bazel`, `tool=gradle`, `lane=ci`, or `workflow=build`. Avoid commit SHAs, run ids, timestamps, and cold/warm labels for normal sessions; BoringCache classifies new and recurring misses from cache target and lifecycle data.

If the repo already defines `[proxy]` or adapter `metadata-hints` in `.boringcache.toml`, `boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9` inherits them through the CLI dry-run plan. Prefer repo config for durable defaults and use the action input only when the workflow needs an explicit override.
The canonical repo-config starting points in [Tool guides](tool-guides.md) are
meant to be shared between local CLI runs and GitHub Actions for exactly this
reason.

Adapter modes use the same names as their CLI commands: `mode: docker`,
`mode: buildkit`, `mode: bazel`, `mode: ccache`, `mode: go`, `mode: gradle`,
`mode: gha`, `mode: maven`, `mode: nix`, `mode: nx`, `mode: sccache`,
`mode: turbo`, and `mode: xcode`.

Existing `actions/cache` users have two deliberate paths:

- Keep existing cache steps, keys, restore keys, and cache-enabled `setup-*`
  behavior by placing a BoringCache One `mode: gha` step before them. The
  Actions client keeps owning its provider identity while BoringCache replaces
  the v2 cache service. This mode is included in the reviewed CLI and Action
  `v1.19.2` release.
- Move to the native BoringCache model by running `boringcache onboard`,
  committing the generated profile, and selecting it with `mode: archive` and
  `cache-profiles`. Do not copy GitHub paths or keys into BoringCache One; the
  CLI plan owns the replacement identity and can be reused locally or in other
  CI systems.

Both paths start a new BoringCache history and do not import GitHub-hosted cache
objects. Compatibility preserves the action-owned tar archive; native profiles
provide BoringCache's semantic per-entry model.

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
    metadata-hints = ["tool=turborepo", "lane=ci"]
    EOF

- run: boringcache turbo
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ github.event_name != 'pull_request' && secrets.BORINGCACHE_SAVE_TOKEN || '' }}
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
    BORINGCACHE_SAVE_TOKEN: ${{ github.event_name != 'pull_request' && secrets.BORINGCACHE_SAVE_TOKEN || '' }}
```

Use `boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9` when you want the action to keep owning tool setup such as Bazel rc files, Maven or Gradle cache config, buildx setup, or container networking.
When you run `boringcache docker` directly in GitHub Actions, the CLI derives the same branch/default/PR human tags from GitHub metadata that archive and proxy flows use. The action path passes provider-neutral metadata so Docker cache artifacts report the resolved human import/export tags and CI context.
For Dockerfile `RUN` steps that invoke native remote-cache tools, use the
Docker-specific action input with inline tags such as
`docker-tool-cache: turbo:turbo-cache,gradle:gradle-cache,go:go-cache`, or pass plain tool
names when `.boringcache.toml` defines `[adapters.<tool>].tag`. The action
delegates those builds to `boringcache docker --tool-cache ...`, so the CLI
owns the session-only BuildKit env/config injection and Docker-visible proxy
endpoints. The supported Docker tool set is Turbo, Nx, Bazel, Gradle, Maven,
sccache, and Go.

For managed Docker and BuildKit caches on pull requests, `trust-policy: auto`
is restore-only. A separately trusted job can use `trust-policy: stage` to
create an immutable candidate. A later trusted solve supplies its exact ID or
digest through `cache-candidates`, imports it beside the current published
manifest, and exports only the fresh published manifest.
`boringcache/one` exposes the authenticated stage receipts as its
`cache-candidates` and `cache-candidate-digests` outputs for direct job-to-job
handoff.

Adapter modes start, wait for, diagnose, and stop their local cache process.
Workflows select the adapter name and should not recreate that lifecycle.

Keep the trust model simple:

- every job gets `BORINGCACHE_RESTORE_TOKEN`
- candidate-producing jobs get `BORINGCACHE_STAGE_TOKEN`
- only trusted jobs get `BORINGCACHE_SAVE_TOKEN`
- `pull_request` jobs stay restore-only under `trust-policy: auto`
- exact candidates are explicit inputs, never ambient PR or Git fallbacks
- use only the purpose-specific restore/stage/save variables

The Action does not use `CI=true` or a self-hosted runner's machine config as a
trust signal. After it evaluates event intent and token capability, every CLI
plan call receives exactly one explicit policy: `--read-only`, `--stage`, or
`--write`. The service still enforces token capability; the CLI flag is
orchestration, not authority.

Read from pull requests.
Write from trusted branches, tags, or manual jobs.
