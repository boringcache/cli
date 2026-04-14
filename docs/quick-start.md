# Quick start

Start in the terminal.

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` is the default starting point.
It authenticates the CLI, chooses a default workspace, and writes `.boringcache.toml` when it can so local runs, Dockerfiles, and CI can reuse the same cache names.

After onboard, wrap one repeated step:

```bash
# Archive mode
boringcache run -- bundle install
```

Use archive mode when you want to cache an explicit directory such as `vendor/bundle`, `node_modules`, or `dist`.
Use adapter commands when the build tool already knows how to talk to a remote cache and you want BoringCache to handle proxy lifecycle plus the right env vars or cache flags.

For repeated remote-cache commands, put the adapter setup in `.boringcache.toml` and keep the invocation short:

```toml
workspace = "my-org/my-project"

[adapters.nx]
tag = "build-cache"
command = ["nx", "run-many", "--target=build"]
```

```bash
boringcache nx
```

Use `run --proxy` as the low-level fallback for tools without a dedicated adapter yet.

If the repo uses GitHub Actions, the next step is usually [`boringcache/one@v1`](https://github.com/boringcache/one).
See [GitHub Actions](github-actions.md).
