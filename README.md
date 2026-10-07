<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/images/boringcache-dark.svg">
  <img src=".github/images/boringcache-light.svg" width="240" alt="BoringCache">
</picture>

# BoringCache CLI

Shared build cache for CI, Docker builds, coding agents, and local development.

Reuse dependency downloads, compiler results, task outputs, and Docker layers
across compatible builds. Run BoringCache on your laptop, in CI, or in a coding
agent's environment so each machine can use work already completed elsewhere.

## What you can reuse and keep

| Product | What it does |
|---|---|
| [Cache](https://boringcache.com/build-cache) | Shares directory caches and native build results across CI and local development. Supported tools include Docker, Cargo, Bazel, Gradle, Nx, and Turborepo. |
| [Artifacts](https://boringcache.com/docs/artifacts) | Keeps binaries, test reports, and release packages with retention you choose. Download an exact output by its immutable Artifact ID for testing or deployment. |
| [Registry](https://boringcache.com/registry) | Stores private container images alongside your cache and build outputs. Push and pull with Docker or an OCI client, and pin deployments to an image digest. |

Matching cache content is stored once within a workspace, so related builds can
reuse existing data without uploading another full copy. Native integrations
keep your build tool's rules for deciding which results are reusable.

Trusted builds can publish shared cache. Pull requests and coding agents can
use restore-only access to reuse it while keeping their new outputs local.
Cache, Artifacts, and Registry include managed storage; see
[plans and allowances](https://boringcache.com/pricing).

Explore [recorded builds](https://boringcache.com/demo) to see cache hits and
transfers, or [benchmarks](https://boringcache.com/benchmarks) for build-time and
storage comparisons with their workloads and configurations.

## Install and onboard

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` signs in, selects a workspace, and writes
`.boringcache.toml` when it can. Workflow scanning is an explicit checkpoint:
press Enter to skip it, or run `boringcache onboard --skip-workflows` (`-S`) to
guarantee no workflow scan or write.

Start with the command that matches the cache your build already understands:

```bash
# Explicit directories and dependency archives
boringcache run -- bundle install

# Native BuildKit cache
boringcache docker

# Native Nix binary cache
boringcache nix -- nix build .

# Native Xcode compilation cache
boringcache xcode -- xcodebuild -workspace App.xcworkspace -scheme App build
```

Use archive mode for explicit directories. Use an adapter command when the
tool already has a native remote-cache protocol. Each adapter command reads its
cache tag from `[adapters.<adapter>]` in `.boringcache.toml`, so the commands
stay short and local builds and CI use the same settings. Pass `--tag` to
override the tag for one run.

## GitHub Actions

After onboarding, commit `.boringcache.toml` and pin the Action to a full commit
in CI. Add this step after checkout and project toolchain setup:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: boringcache/one@43cf123ff3236d37e070ee79610189714f2c2c2d # v1.40.1
    with:
      trust-policy: auto
      mode: archive
      cache-profiles: ci
```

After **Connect CI** approves the repository once, the Action starts a
short-lived Machine connection automatically. Pull requests restore by default;
trusted jobs publish when Workspace policy allows. On BoringBuild, the same step
reuses the runner-provided connection. When workload identity is unavailable,
configure scoped restore/save credentials explicitly.

## Guides

Set up BoringCache, choose the cache path for your build, and reuse it in CI:

- [Get started](https://boringcache.com/docs)
- [Adapter commands](https://boringcache.com/docs/adapters)
- [GitHub Actions](https://boringcache.com/docs/github-actions)
- [Installation details](INSTALLATION.md)
- [Release history](CHANGELOG.md)
