# BoringCache CLI

BoringCache is a shared build cache for CI, Docker builds, and local development.

If you are new here, start in the terminal:

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` authenticates the CLI, chooses a workspace, writes `.boringcache.toml` when it can, and lines up the same cache names across local runs, Dockerfiles, and GitHub Actions.

If you want to start sign-in from the terminal by email, use `boringcache onboard --email you@example.com`. For a brand-new account, pass `--name` and `--username` too.

After that, pick the mode that matches the repeated work:

```bash
# Archive mode: restore, run, save
boringcache run -- bundle install

# Proxy mode: let the build tool use a native remote-cache protocol
boringcache run --proxy build-cache -- nx run-many --target=build
```

If you are wiring GitHub Actions, use [`boringcache/one@v1`](https://github.com/boringcache/one) after onboard so CI can reuse the same repo config and trust model.

## Docs

- [Quick start](docs/quick-start.md)
- [Onboard](docs/onboard.md)
- [Archive mode](docs/archive-mode.md)
- [Proxy mode](docs/proxy-mode.md)
- [GitHub Actions](docs/github-actions.md)
- [Development](docs/development.md)
- [Installation setup](INSTALLATION.md)
- [Website docs](https://boringcache.com/docs)
