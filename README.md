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

Repo config can also keep the repeated command itself under `[adapters.<tool>]`.
`command` accepts either an argv array or a shell-style string.
This is not general TOML templating: proxy-backed commands only substitute `{PORT}`, `{ENDPOINT}`, and `{CACHE_REF}`.
After that, start with the shortest command that fits the tool:

```bash
# Archive mode
boringcache run -- bundle install

# Adapter commands
boringcache nx
boringcache docker --tag docker-cache -- docker buildx build .

# Fallback for unsupported or custom tools
boringcache run --proxy build-cache -- my-custom-tool build

# Long-lived local endpoint
boringcache cache-registry my-org/app registry-cache --port 5000
```

Use `run` when you are caching directories.
Use adapter commands when the build tool already speaks a remote-cache protocol and BoringCache has a dedicated wrapper for it.
Use `run --proxy` only when you need that same proxy lifecycle for a tool without a dedicated adapter yet.
Use `cache-registry` when the tool already has a checked-in remote-cache config or another process should keep the endpoint alive.

If you are wiring GitHub Actions, use [`boringcache/one@v1`](https://github.com/boringcache/one) after onboard so CI can reuse the same repo config and trust model.

## Docs

- [Quick start](docs/quick-start.md)
- [Onboard](docs/onboard.md)
- [Archive mode](docs/archive-mode.md)
- [Adapter commands](docs/adapter-commands.md)
- [Tool guides](docs/tool-guides.md)
- [Proxy mode](docs/proxy-mode.md)
- [GitHub Actions](docs/github-actions.md)
- [Development](docs/development.md)
- [Installation setup](INSTALLATION.md)
- [Website docs](https://boringcache.com/docs)
