# BoringCache CLI

BoringCache is a shared build cache for CI, Docker builds, and local development.

If you are new here, start in the terminal:

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` authenticates the CLI, chooses a workspace, writes `.boringcache.toml` when it can, and lines up the same cache names across local runs, Docker builds, and GitHub Actions.

For restore-first laptop use, set `boringcache config set read_only true` once
and add `--write` only when a local command should publish.

If you want to start sign-in from the terminal by email, use `boringcache onboard --email you@example.com`. For a brand-new account, pass `--name` and `--username` too.

Repo config can also keep the repeated command itself under `[adapters.<tool>]`.
`command` accepts either an argv array or a shell-style string.
After that, start with the shortest command that fits the tool:

```bash
# Archive mode (run/save/restore)
boringcache run -- bundle install

# Docker adapter from repo config
boringcache docker
# Native Xcode compilation cache (macOS)
boringcache xcode -- xcodebuild -workspace App.xcworkspace -scheme App build
```

Use archive mode commands (`run`, `save`, and `restore`) when you are caching explicit directories.
Use adapter commands when the build tool already speaks a remote-cache protocol and BoringCache has a dedicated wrapper for it.
`.boringcache.toml` keeps repeated adapter commands and cache identity out of
shell scripts.

Image publication is opt-in and uses the same workspace CAS as the BuildKit
cache. Configure a stable default with `publish-image = "web:latest"` under
`[adapters.docker]`, or pass a dynamic tag with `--publish-image`. To pull from
another machine, use a workspace restore token as the password. The hosted
registry is pull-only in this release; publish through the BoringCache wrapper,
not a direct `docker push`:

```bash
boringcache docker --publish-image web:$GITHUB_SHA

echo "$BORINGCACHE_RESTORE_TOKEN" | docker login registry.boringcache.com \
  --username boringcache --password-stdin
docker pull registry.boringcache.com/my-org/my-workspace/web:latest
```

If you are wiring GitHub Actions, use [`boringcache/one@9721d419d2c78c0780963d297eb3f81f24641a27`](https://github.com/boringcache/one) after onboard so CI can reuse the same repo config and trust model.

## Docs

- [Quick start](docs/quick-start.md)
- [Onboard](docs/onboard.md)
- [Archive mode](docs/archive-mode.md)
- [Adapter commands](docs/adapter-commands.md)
- [Tool guides](docs/tool-guides.md)
- [GitHub Actions](docs/github-actions.md)
- [Development](docs/development.md)
- [Installation setup](INSTALLATION.md)
- [Website docs](https://boringcache.com/docs)
