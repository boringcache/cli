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

## Laptop read-only default

If you want normal laptop commands to reuse shared caches without publishing,
set the machine-local default once:

```bash
boringcache config set read_only true
```

`boringcache run` and every adapter command will still restore, but will skip
archive saves and proxy writes. Use `--write` on one invocation when you
intentionally want to publish the current Git-scoped tag:

```bash
boringcache run --write -- bundle install
boringcache turbo --write
```

The preference lives in `~/.boringcache/config.json`; it is not written to the
repository by onboarding, and a `CI=true` environment does not bypass it.
`boringcache/one` always passes an explicit read-only or write policy based on
its trusted-event and save-token decision, so a self-hosted runner does not
inherit an ambiguous laptop default.

This setting is an accident-prevention guardrail, not an authorization
boundary. A restore-only token is what prevents writes at the service. The
lower-level `boringcache save` command remains an explicit write operation.
