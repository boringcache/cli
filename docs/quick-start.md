# Quick start

Start in the terminal.

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` is the default starting point.
It authenticates the CLI, chooses a default workspace, and writes `.boringcache.toml` when it can so local runs, Dockerfiles, and CI can reuse the same cache names.

After onboard, start with the shortest command that fits the tool:

```bash
# Archive mode (run/save/restore)
boringcache run -- bundle install

# Adapter command from repo config
boringcache nx

# One-off adapter command
boringcache docker --tag docker-cache -- docker buildx build .

# Long-lived local proxy
boringcache cache-registry my-org/app registry-cache --port 5000
```

Use archive mode commands (`run`, `save`, and `restore`) when you want to cache an explicit directory such as `vendor/bundle`, `node_modules`, or `dist`.
Use adapter commands when the build tool already knows how to talk to a remote cache and BoringCache has a dedicated wrapper for it.
Use `cache-registry` when the repo already has a checked-in local endpoint setup or another process should keep the proxy alive.

For repeated remote-cache commands, put the adapter setup in `.boringcache.toml` and keep the invocation short:

```toml
workspace = "my-org/my-project"

[adapters.nx]
tag = "build-cache"
command = ["nx", "run-many", "--target=build"]
```

`command` can be an argv array like the example above or a shell-style string such as `command = "nx run-many --target=build"`.
This is not general TOML templating.
When the adapter starts a local proxy, command arguments can use `{PORT}`, `{ENDPOINT}`, and `{CACHE_REF}`.

```bash
boringcache nx
```

The next docs to read are usually [Adapter commands](adapter-commands.md) and [Tool guides](tool-guides.md).

If the repo uses GitHub Actions, the next step is usually [`boringcache/one@v1`](https://github.com/boringcache/one).
See [GitHub Actions](github-actions.md).
