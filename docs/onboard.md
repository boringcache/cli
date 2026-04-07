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

# Avoid trying to open a browser automatically
boringcache onboard --manual

# Start sign-in or signup by email from the terminal
boringcache onboard --email you@example.com
boringcache onboard --email you@example.com --name "Jane Doe" --username janedoe
```

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

If the repo already has a lot of manual `tag:path` usage, you can import that shape into repo config later with `boringcache audit --write`.
That is a migration step, not the default getting-started path.
