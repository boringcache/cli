# Quick start

Start in the terminal.

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
cd your-project
boringcache onboard
```

`boringcache onboard` is the default starting point.
It authenticates the CLI, chooses a default workspace, and writes `.boringcache.toml` when it can so local runs, Docker builds, and CI can reuse the same cache names.

For restore-first laptop use, opt in with
`boringcache config set read_only true`; add `--write` only to an invocation
that should publish. Onboarding does not choose this policy for you.

After onboard, use the plan it wrote. The command name is the cache adapter:

```bash
# Archive entries inferred from the command or selected by profile
boringcache run -- bundle install

# Native adapters use the same name everywhere
boringcache docker
boringcache turbo
boringcache nx
boringcache bazel
boringcache sccache
```

Use archive mode commands (`run`, `save`, and `restore`) when you want to cache an explicit directory such as `vendor/bundle`, `node_modules`, or `dist`.
Use adapter commands when the build tool already knows how to talk to a remote cache and BoringCache has a dedicated wrapper for it.
`.boringcache.toml` keeps repeated adapter commands and cache identity out of
shell scripts.

For repeated remote-cache commands, put the adapter setup in `.boringcache.toml` and keep the invocation short:

```toml
workspace = "my-org/my-project"

[adapters.docker]
tag = "docker-cache"
command = ["docker", "buildx", "build", "."]
```

`command` can be an argv array like the example above or a shell-style string
such as `command = "docker buildx build ."`.

```bash
boringcache docker
```

The next docs to read are usually [Adapter commands](adapter-commands.md) and [Tool guides](tool-guides.md).

If the repo uses GitHub Actions, the next step is usually [`boringcache/one@b1d1e466317cde2d78a86f8cb94347deebb501e9`](https://github.com/boringcache/one).
See [GitHub Actions](github-actions.md).

## Security defaults

- API credentials are sent only over HTTPS. Plain HTTP is accepted only when
  `BORINGCACHE_API_URL` or the saved `api_url` names `localhost`, `127.0.0.0/8`,
  or `::1` explicitly for local development.
- Authenticated API requests do not follow redirects. Configure the final API
  URL directly.
- The official `https://api.boringcache.com` service requires a valid server
  signature for cache hits automatically. Custom and self-hosted endpoints keep
  compatibility warning behavior unless `--require-server-signature` or
  `BORINGCACHE_REQUIRE_SERVER_SIGNATURE=1` is set.
- `~/.boringcache/config.json` is replaced atomically and symlinked config
  paths are refused. On Unix, the directory is `0700` and the file is `0600`.
  On Windows, keep the user profile on a user-only ACL; the CLI still performs
  atomic replacement and symlink checks, but does not rewrite Windows ACLs.
