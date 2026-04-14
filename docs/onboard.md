# Onboard

`boringcache onboard` is the CLI-first setup path.

Run it once per repo:

```bash
cd your-project
boringcache onboard
```

What it does:

- authenticates the CLI
- helps choose a default workspace
- scans the repo for cacheable workflows and commands
- writes `.boringcache.toml` when it can
- keeps local runs, Docker builds, and CI cache names aligned

Useful variants:

```bash
# Apply detected changes directly
boringcache onboard --apply

# Avoid trying to open a browser automatically
boringcache onboard --manual

# Start sign-in or signup by email from the terminal
boringcache onboard --email you@example.com
boringcache onboard --email you@example.com --name "Jane Doe" --username janedoe
```

If onboard writes `.boringcache.toml`, later commands can stay short and semantic instead of repeating raw `tag:path` pairs:

```toml
workspace = "my-org/app"

[entries.bundler]
tag = "bundler-gems"

[profiles.bundle-install]
entries = ["bundler"]

[adapters.nx]
tag = "build-cache"
command = ["nx", "run-many", "--target=build"]
```

Then:

```bash
# Archive mode
boringcache run --profile bundle-install -- bundle install
boringcache run -- bundle install

# Native remote-cache adapter command
boringcache nx
```

Use `run --proxy` only when the tool does not have a dedicated adapter yet or a wrapper script launches the remote-cache client internally:

```bash
boringcache run --proxy build-cache -- my-custom-tool build
```

If the repo also uses GitHub Actions, the next step is usually [`boringcache/one@v1`](https://github.com/boringcache/one) so CI can reuse the same workspace, cache profiles, and split-token trust model.

If the repo already has a lot of manual `tag:path` usage, you can import that shape into repo config later with `boringcache audit --write`.
That is a migration step, not the default getting-started path.
