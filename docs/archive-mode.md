# Archive mode

Archive mode is the simplest path.
You point BoringCache at a directory and it restores first, runs your command, then saves on the way out.

Start with `run`:

```bash
boringcache run my-org/app "deps:node_modules" -- npm ci
boringcache run my-org/app "gems:vendor/bundle" -- bundle install
```

If the repo already has `.boringcache.toml`, prefer entries or profiles:

```bash
boringcache run --entry bundler -- bundle install
boringcache run --profile bundle-install -- bundle install
boringcache run -- bundle install
```

Use lower-level commands only when restore and save need to happen at different points in the job:

```bash
boringcache restore my-org/app "deps:node_modules"
npm ci
boringcache save my-org/app "deps:node_modules"
```

The basic unit is `tag:path`:

- `tag` is the logical cache name
- `path` is the local directory

Tags are git-aware and platform-aware by default.
Use `--no-git` to disable branch suffixing and `--no-platform` only when the cached directory is genuinely portable across operating systems and architectures.
