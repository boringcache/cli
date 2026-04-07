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

# Native remote cache mode
boringcache run --proxy build-cache -- nx run-many --target=build
```

Use archive mode when you want to cache an explicit directory such as `vendor/bundle`, `node_modules`, or `dist`.
Use proxy mode when the build tool already knows how to talk to a remote cache.

If the repo uses GitHub Actions, the next step is usually [`boringcache/one@v1`](https://github.com/boringcache/one).
See [GitHub Actions](github-actions.md).
