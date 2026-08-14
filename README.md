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
- uses: boringcache/one@71fdb67f0aa0afc1c4ac616c8c57d0d535f15bd9 # v1.19.2
  with:
    trust-policy: auto
    setup: none
    mode: archive
    cache-profiles: ci
  env:
    BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}
    BORINGCACHE_SAVE_TOKEN: ${{ github.event_name != 'pull_request' && secrets.BORINGCACHE_SAVE_TOKEN || '' }}
```

Pull requests restore by default. Trusted jobs with save capability publish.

## Guides

Set up BoringCache, choose the cache path for your build, and reuse it in CI:

- [Get started](https://boringcache.com/docs)
- [Adapter commands](https://boringcache.com/docs/adapters)
- [GitHub Actions](https://boringcache.com/docs/github-actions)
- [Installation details](INSTALLATION.md)
