# Onboard

`boringcache onboard` is the CLI-first setup path.

Run it once per repo:

```bash
cd your-project
boringcache onboard
```

What it does:

- checks the CLI account connection
- helps select or create the workspace
- writes the workspace into `.boringcache.toml`
- offers an opt-in scan of supported CI workflow files (the default answer is skip)
- previews proposed workflow changes before writing them
- keeps local, Docker, and CI cache names aligned

Interactive onboarding presents those steps in order. At the workflow step,
press Enter (or answer `n`) to stop after repository setup. No workflow file is
scanned, sent to AI assist, or changed when that step is skipped. GitHub secret setup is offered
only after a BoringCache GitHub Actions workflow already exists or an approved
workflow proposal has been written, and it has its own prompt.

Useful variants:

```bash
# Apply detected changes directly
boringcache onboard --apply

# Onboard the repo but leave CI workflows alone
boringcache onboard --skip-workflows

# Rails-style compact form
boringcache onboard -S

# Provision the workspace and write only the repo workspace setting
boringcache onboard \
  --workspace my-org/app \
  --create-workspace \
  --skip-workflows \
  --apply \
  --json

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
With `--skip-workflows`, that repo setting is the only repository change:
workflow discovery, deterministic optimization, AI assist, and workflow writes
do not run.

`--dry-run` previews workflow proposals without writing repository files. It
cannot be combined with `--apply`, workspace provisioning, CI token creation,
or GitHub secret mutation.

Onboard does not silently choose who may publish caches. It does not write a
read-only policy into `.boringcache.toml`, and it does not infer one from
whether the current process looks like CI. If this laptop should reuse caches
without publishing by default, opt in separately with:

```bash
boringcache config set read_only true
```

That preference stays in the machine config. An intentional local publication
uses `--write`; GitHub Actions derives its explicit read/write choice from the
Action trust policy and token capability.

`--github-secrets` uses the GitHub CLI to set `BORINGCACHE_RESTORE_TOKEN` and
`BORINGCACHE_SAVE_TOKEN` without printing token values. If both secrets already
exist, it leaves them alone; pass `--rotate-ci-tokens` to replace them.

## Automation and agents

For agents, scripts, and CI bootstrap jobs, prefer the GitHub-secrets path:

```bash
boringcache onboard \
  --workspace my-org/app \
  --create-workspace \
  --github-secrets \
  --apply \
  --json
```

That command keeps the same product path as interactive onboarding, but returns a
bounded JSON report with `schema_version`, `workspace`, `repo_config`,
`workflow_scan`, `github_secrets`, `optimize_results`, and `next_steps`.

Agents that only need the workspace and shared repo setting use the same command
with `--skip-workflows`. The JSON report then returns
`workflow_scan.status = "skipped"`, making the decision explicit without a
second provisioning command.

Use `--create-ci-tokens` only when another system must receive token values
directly. It requires `--json`, whose output includes the new restore/save token
values, so do not write that output to CI logs or commit it to the repo.

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
