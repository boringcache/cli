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

# Docker adapter from repo config
boringcache docker

# Same adapter without repo config
boringcache docker --tag docker-cache -- docker buildx build .

# Long-lived local proxy
boringcache cache-registry my-org/app registry-cache --port 5000
```

Use archive mode commands (`run`, `save`, and `restore`) when you want to cache an explicit directory such as `vendor/bundle`, `node_modules`, or `dist`.
Use adapter commands when the build tool already knows how to talk to a remote cache and BoringCache has a dedicated wrapper for it.
Use `cache-registry` when the repo already has a checked-in local endpoint setup or another process should keep the proxy alive.
When `.boringcache.toml` stores the Docker command, `boringcache docker` is the short form. Use the longer version when you want to pass the Docker command inline.

For repeated remote-cache commands, put the adapter setup in `.boringcache.toml` and keep the invocation short:

```toml
workspace = "my-org/my-project"

[adapters.docker]
tag = "docker-cache"
command = ["docker", "buildx", "build", "."]
```

`command` can be an argv array like the example above or a shell-style string such as `command = "docker buildx build ."`.
This is not general TOML templating.
When the adapter starts a local proxy, command arguments can use `{PORT}`, `{ENDPOINT}`, and `{CACHE_REF}`.

```bash
boringcache docker
```

The next docs to read are usually [Adapter commands](adapter-commands.md) and [Tool guides](tool-guides.md).

If the repo uses GitHub Actions, the next step is usually [`boringcache/one@v1`](https://github.com/boringcache/one).
See [GitHub Actions](github-actions.md).
