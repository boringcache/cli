# BoringCache CLI

**One command between your build and shared cache.**

The BoringCache CLI keeps dependency state, compiler output, Docker build
cache, and other completed work available across CI and local development.
Run the build tools you already use; BoringCache carries their reusable work
between machines.

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
tool already has a native remote-cache protocol. Keep repeated commands, cache
identity, and stable labels in `.boringcache.toml` so local builds and CI use
the same settings.

## GitHub Actions

After onboarding, pin the Action to a full commit in CI:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: boringcache/one@a610ec5a564efd9b360925056dbade04deb5def6 # v1.30.0
    with:
      trust-policy: auto
      mode: archive
      cache-profiles: ci
```

After **Connect CI** approves the repository once, the Action starts a
short-lived Machine connection automatically. Pull requests restore by default;
trusted jobs publish when Workspace policy allows. On BoringBuild, the same step
reuses the runner-provided connection. Scoped restore/save credentials remain an
explicit fallback when workload identity is unavailable.

## Guides

Set up BoringCache, choose the cache path for your build, and reuse it in CI:

- [Get started](https://boringcache.com/docs)
- [Adapter commands](https://boringcache.com/docs/adapters)
- [GitHub Actions](https://boringcache.com/docs/github-actions)
- [Installation details](INSTALLATION.md)
- [Release history](CHANGELOG.md)
