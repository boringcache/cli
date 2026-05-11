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
- keeps local, Docker, and CI cache names aligned

Useful variants:

```bash
# Apply detected changes directly
boringcache onboard --apply

# Agent/CI friendly: create or verify the workspace, set split GitHub secrets,
# apply repo edits, and print a machine-readable summary.
boringcache onboard \
  --workspace my-org/app \
  --create-workspace \
  --github-secrets \
  --apply \
  --json

# Avoid trying to open a browser automatically
boringcache onboard --manual

# Start sign-in or signup by email from the terminal
boringcache onboard --email you@example.com
boringcache onboard --email you@example.com --name "Jane Doe" --username janedoe
```

With `--workspace --apply`, onboard writes or verifies the repo `workspace`
setting even when the repo has CI files that do not need optimization.

`--github-secrets` uses the GitHub CLI to set `BORINGCACHE_RESTORE_TOKEN` and
`BORINGCACHE_SAVE_TOKEN` without printing token values. If both secrets already
exist, it leaves them alone; pass `--rotate-ci-tokens` to replace them.

If onboard writes `.boringcache.toml`, later commands can use semantic entries and profiles instead of repeating raw `tag:path` pairs:

```toml
workspace = "my-org/app"

[entries.bundler]
tag = "bundler-gems"

[profiles.bundle-install]
entries = ["bundler"]
```

Then:

```bash
boringcache run --profile bundle-install -- bundle install
boringcache run -- bundle install
```

You can also keep native remote-cache commands short in the same file:

```toml
[adapters.nx]
tag = "build-cache"
command = ["nx", "run-many", "--target=build"]
```

Then:

```bash
boringcache nx
```

If the repo already has a lot of manual `tag:path` usage, you can import that setup into repo config later with `boringcache audit --write`.
That is a migration step, not the default getting-started path.
