# BoringCache CLI

Shared build cache for CI, Docker builds, and local development.

Start here:

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` authenticates the CLI, chooses a workspace, and writes `.boringcache.toml` when it can.

Common commands:

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

Docs:

- [Quick start](docs/quick-start.md)
- [Onboard](docs/onboard.md)
- [Archive mode](docs/archive-mode.md)
- [Proxy mode](docs/proxy-mode.md)
- [GitHub Actions](docs/github-actions.md)
- [Development](docs/development.md)
- [Website docs](https://boringcache.com/docs)
