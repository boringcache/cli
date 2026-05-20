# CLI Machine Output Contract

CLI JSON is product API.

It is consumed by `boringcache/one`, benchmarks, release scripts, local
automation, and future support tooling. Treat machine output changes like API
changes: intentional, reviewed, fixture-backed, and tied to the owning feature
inventory entry.

## Versioning

- Top-level JSON emitted through `src/json_output.rs` includes
  `schema_version`.
- Current version: `1`.
- Adding optional fields is allowed only after checking consumers.
- Removing fields, changing types, renaming values, or changing enum spellings
  requires a migration plan or a schema-version bump.

## First Guardrail Fixtures

The initial contract fixtures live under:

```text
tests/fixtures/machine-output/
```

Current fixtures:

- `run_dry_run_manual_archive_v1.json`
- `docker_dry_run_v1.json`
- `bazel_setup_plan_v1.json`
- `gradle_setup_plan_v1.json`
- `maven_setup_plan_v1.json`
- `check_hit_v1.json`
- `check_miss_v1.json`
- `check_pending_v1.json`
- `status_workspace_v1.json`
- `token_list_v1.json`
- `token_create_v1.json`
- `token_ci_pair_v1.json`
- `token_rotate_v1.json`

The guardrail test is:

```sh
cargo test --test machine_output_contract_tests
```

If this test fails because output changed, do not update the fixture by reflex.
First check the consumer impact for the action, benchmark workflows, release
scripts, and any docs that teach the JSON shape.

## Expansion Order

Add fixtures in this order:

1. `run --dry-run --json` archive modes.
2. Docker/BuildKit dry-run plan.
3. Adapter dry-run setup plans with `setup.schema_version`. First coverage:
   Bazel, Gradle, and Maven.
4. `check --json` and `status --json`. First coverage: check hit, miss,
   pending, and workspace status.
5. Token and auth JSON outputs. First coverage: token list, token create, CI
   token pair, and token rotate. Remaining auth/connect outputs need explicit
   fixtures.

Keep fixtures stable by using explicit workspaces, explicit tags, disabled
platform/git suffixing when the suffix is not the point, and temporary
directories without repo config.
