# Development

This file is for working on the CLI repo itself.

## Local setup

```bash
cp .boringcache.env.example .boringcache.env
$EDITOR .boringcache.env
make install-hooks
make env
```

Rust toolchain versioning is sourced from [mise.toml](/Users/gaurav/boringcache/cli/mise.toml).
[rust-toolchain.toml](/Users/gaurav/boringcache/cli/rust-toolchain.toml) is kept in sync and checked by `make check`.

## Common commands

```bash
make dev
make build
make test
make clippy
make compat
make check
./scripts/cargo-flow.sh cargo build --release --locked
```

`make install-hooks` configures `git` to use the repo-local [.githooks/pre-commit](/Users/gaurav/boringcache/cli/.githooks/pre-commit), which runs `cargo fmt -- --check` plus `cargo clippy --locked --all-targets --all-features -- -D warnings` before each commit.
The heavier test pass stays on `make check`.

The Cargo flow:

- prefers remote `sccache`
- restores the archived debug `target` directory only when the local `target/` directory is empty
- derives tags from the active Rust version and host triple
- disables git and platform suffixing for those explicit tags

The local proxy port defaults to `0`, so Cargo picks an open loopback port unless you pin `BORINGCACHE_CARGO_PROXY_PORT`.
Local runs do not save `target` back to BoringCache.
