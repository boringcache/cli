# BoringCache CLI

BoringCache is a shared build cache for CI, Docker builds, and local development.

If you are new here, start in the terminal:

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` authenticates the CLI, chooses a workspace, writes `.boringcache.toml` when it can, and offers an opt-in workflow scan to line up the same cache names across local runs, Docker builds, and GitHub Actions. Press Enter to skip that phase, or use `--skip-workflows` (`-S`) to declare the same boundary up front.

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
# Nix HTTP binary cache
boringcache nix -- nix build
# Native Xcode compilation cache (macOS)
boringcache xcode -- xcodebuild -workspace App.xcworkspace -scheme App build
```

Sequential `boringcache docker` commands automatically reuse one managed
builder for the repository across Buildx, Bake, and Compose. There is no setup
or cleanup command, and every upstream Docker invocation keeps its normal
targets, outputs, service lifecycle, and exit status.

Use archive mode commands (`run`, `save`, and `restore`) when you are caching explicit directories.
Use adapter commands when the build tool already speaks a remote-cache protocol and BoringCache has a dedicated wrapper for it.
`.boringcache.toml` keeps repeated adapter commands and cache identity out of
shell scripts.

Image publication is opt-in and uses separate Registry storage. Configure a
stable build-and-publish default with `publish-image = "web:latest"` under
`[adapters.docker]`, or pass a dynamic tag with `--publish-image`. If the image
already exists locally, publish it without rebuilding through `docker push`.
To pull from another machine, use a workspace restore token as the password.
The hosted registry exposes pull routes; writes go through the verified local
BoringCache proxy:

```bash
boringcache docker --publish-image web:$GITHUB_SHA
boringcache docker push local-image:tag --as web:$GITHUB_SHA

echo "$BORINGCACHE_RESTORE_TOKEN" | docker login registry.boringcache.com \
  --username boringcache --password-stdin
docker pull registry.boringcache.com/my-org/my-workspace/web:latest
```

If you are wiring GitHub Actions, use [`boringcache/one@ab52a39d3d7358c22b359a6ffbf86cf74be9bf56`](https://github.com/boringcache/one) after onboard so CI can reuse the same repo config and trust model.

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
