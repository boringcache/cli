# Cache Lifecycle Features

This file covers the archive/CAS lifecycle and the read/admin/reporting commands around it.

## Core shape

- `save`, `restore`, `mount`, and `run` are the lifecycle center.
- `project_config/**` only becomes relevant for `run` and adapter planning.
- `manifest/**`, `cache/**`, `encryption/**`, and `signing/policy.rs` are lifecycle plumbing, not general workspace/reporting plumbing.

## Feature map

| Feature | Entry points | Status | Primary code | Key shared modules | Evidence of use | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Save cache entries | `save [WORKSPACE] TAG:PATH[,TAG:PATH...]` with `--no-platform`, `--no-git`, `--force`, `--exclude`, `--recipient`, `--fail-on-cache-error` | `public-primary` | `src/commands/cache/save/mod.rs`, `src/commands/cache/save/archive.rs`, `src/commands/cache/save/cas.rs`, `src/commands/cache/save/file.rs`, `src/commands/cache/save/oci.rs` | `command_support`, `cache::{archive,cas_publish,cas_file,cas_oci,receipts}`, `manifest`, `encryption`, `progress`, `tag_utils`, `platform`, `git` | `tests/integration_tests.rs`, `tests/workspace_injection_tests.rs`, `tests/api_behavior_tests.rs`, `tests/api_contract_tests.rs`, `tests/cas_adapter_integration_tests.rs`, `docs/archive-mode.md`, `docs/quick-start.md` | Parallel batch save with shared API client and transport/layout split; encrypted archive saves scope the remote root digest to the Age recipient before cache checks so different keys do not alias |
| Restore cache entries | `restore [WORKSPACE] TAG:PATH[,TAG:PATH...]` with `--no-platform`, `--no-git`, `--fail-on-cache-miss`, `--lookup-only`, `--identity`, `--fail-on-cache-error` | `public-primary` | `src/commands/cache/restore/mod.rs`, `src/commands/cache/restore/archive.rs`, `src/commands/cache/restore/file.rs`, `src/commands/cache/restore/oci.rs` | `command_support`, `cache::{cas_restore,archive,cas_file,cas_oci,file_materialize}`, `manifest::io`, `signing::policy`, `encryption`, `telemetry`, `progress`, `transfer`, `tag_utils` | `tests/integration_tests.rs`, `tests/workspace_injection_tests.rs`, `tests/api_behavior_tests.rs`, `tests/cas_adapter_integration_tests.rs`, unit tests in `src/commands/cache/restore/mod.rs`, `docs/archive-mode.md`, `docs/quick-start.md` | Warn-only signature and digest handling unless strict mode is enabled |
| Mount and sync | `mount WORKSPACE TAG:PATH` with `--no-platform`, `--no-git`, `--force`, `--recipient`, `--identity`, `--require-server-signature` | `public-primary`, `lightly-used` | `src/commands/cache/mount/mod.rs`, `src/commands/cache/mount/archive.rs`, `src/commands/cache/mount/file.rs`, `src/commands/cache/mount/oci.rs`, `src/commands/cache/mount/cas.rs` | `cache::{cas_restore,cas_publish,archive,cas_file,cas_oci,file_materialize}`, `manifest`, `encryption`, `signing::policy`, `notify_debouncer_mini`, `ctrlc` | `tests/integration_tests.rs`, unit tests in `src/commands/cache/mount/mod.rs` | Long-running watch/sync path; encrypted archive sync uses the same recipient-scoped root digest as save; sync confirms the winning entry and waits for the exact digest to become readable before reporting success; docs are thinner than save/restore/run |
| Wrap restore -> command -> save | `run [WORKSPACE] [TAG_PATHS] -- COMMAND...`; flags `--entry`, `--profile`, `--proxy`, `--metadata-hint`, `--no-platform`, `--no-git`, `--force`, `--exclude`, `--recipient`, `--identity`, `--host`, `--endpoint-host`, `--port`, `--read-only`, `--save-on-failure`, `--skip-restore`, `--skip-save`, `--fail-on-cache-error`, `--fail-on-cache-miss`, `--dry-run`, `--json` | `public-primary` | `src/commands/cache/run.rs` | `project_config`, `command_support`, `save`, `restore`, `proxy`, `serve`, `encryption`, `manifest`, `tag_utils` | `tests/integration_tests.rs`, `tests/workspace_injection_tests.rs`, `tests/run_command_tests.rs`, `docs/archive-mode.md`, `docs/quick-start.md`, `docs/onboard.md`, `docs/github-actions.md`, `docs/tool-guides.md` | Highest-level lifecycle command; can stay archive-only or temporarily start `cache-registry` for one proxy-backed command |
| Run dry-run planner internals | hidden `run` flags `--archive-path`, `--archive-tag-prefix`, `--archive-restore-prefix`, `--cache-tag`, `--tool-tag-suffix` | `hidden-internal` | `src/commands/cache/run.rs` | `project_config`, archive-tag planning helpers | dry-run JSON tests in `src/commands/cache/run.rs` | Only valid with `--dry-run --json`; this is not meant as a normal user workflow |
| Check cache presence | `check WORKSPACE TAGS` with `--no-platform`, `--no-git`, `--fail-on-miss`, `--exact`, `--json` | `public-primary` | `src/commands/cache/check.rs` | `command_support`, `tag_utils`, `platform`, `git`, `ApiClient`, `signing::policy` | `tests/integration_tests.rs`, `tests/api_contract_tests.rs` | Read-side verification surface |
| Delete cache tags | `rm [WORKSPACE] TAG[,TAG...]` with `--no-platform`, `--no-git`; visible alias `delete` | `public-primary`, `legacy-visible-alias` | `src/commands/cache/delete.rs` | `command_support::resolve_workspace`, `tag_utils`, `proxy::internal_registry_root_tag`, `progress`, admin `ApiClient` | `tests/workspace_injection_tests.rs`, unit tests in `src/commands/cache/delete.rs` | `rm` is the canonical command name; `delete` is compatibility naming |
| Inspect one entry | `inspect TAG|ID` or `inspect WORKSPACE TAG|ID`, `--json` | `public-primary`, `lightly-used` | `src/commands/cache/inspect.rs` | `command_support::resolve_workspace`, `ApiClient`, `progress::format_bytes`, `ui` | unit tests in `src/commands/cache/inspect.rs` | Real command, but direct docs and broad workflow tests are thin |
| List entries | `ls [WORKSPACE]` with `--limit`, `--page`, `--json`, `--verbose` | `public-primary` | `src/commands/cache/ls.rs` | `command_support::get_workspace_name`, `ApiClient`, `progress::format_bytes` | `tests/integration_tests.rs`, `tests/workspace_injection_tests.rs` | Standard list/reporting command |
| Workspace cache status | `status [WORKSPACE]` with `--period`, `--limit`, `--watch`, `--interval`, `--json` | `public-primary` | `src/commands/cache/status.rs` | `command_support::resolve_workspace`, `ApiClient`, `progress::format_bytes`, `chrono`, `ui` | `tests/integration_tests.rs`, unit tests in `src/commands/cache/status.rs`, shared rendering in `src/commands/workspace/dashboard.rs` | CLI status command is real; docs more often talk about proxy status endpoints instead |
| Session reports | `sessions [WORKSPACE]` with `--period`, `--limit`, `--page`, `--json` | `public-primary`, `lightly-used` | `src/commands/cache/sessions.rs` | `command_support::resolve_workspace`, `ApiClient`, status render helpers | `tests/integration_tests.rs`, unit tests in `src/commands/cache/sessions.rs` | Public but thinly documented |
| Miss reports | `misses [WORKSPACE]` with `--period`, `--limit`, `--page`, `--json` | `public-primary`, `lightly-used` | `src/commands/cache/misses.rs` | `command_support::resolve_workspace`, `ApiClient`, status render helpers | `tests/integration_tests.rs`, unit tests in `src/commands/cache/misses.rs` | Public but thinly documented |
| Tag reports | `tags [WORKSPACE]` with `--filter`, `--all`, `--limit`, `--page`, `--json` | `public-primary`, `lightly-used` | `src/commands/cache/tags.rs` | `command_support::resolve_workspace`, `ApiClient`, status render helpers, `progress::format_bytes` | `tests/integration_tests.rs`, unit tests in `src/commands/cache/tags.rs` | Public but thinner than the core lifecycle commands |

## Cross-cutting lifecycle modules

| Module family | Used by | Why it matters |
| --- | --- | --- |
| `src/cache/**` | `save`, `restore`, `mount` | Archive/CAS transport, publish/restore helpers, file materialization |
| `src/manifest/**` | `save`, `restore`, `mount`, `run` | Manifest build, digesting, compression, apply/diff helpers |
| `src/encryption/{mod,crypto,identity,passphrase,errors}.rs` | `save`, `restore`, `mount`, `run`, `setup-encryption` | Age encryption, identity handling, passphrase flow |
| `src/signing/policy.rs` | `restore`, `mount`, `check` | Server signature verification policy; warn-only unless strict mode is enabled |
| `src/project_config/**` | `run` and adapters only | `.boringcache.toml` discovery, built-in entry inference, profile resolution |

## Strongly used vs thinner

### Strongly used and well-covered

- `save`
- `restore`
- `run`

### Real but thinner

- `mount`
- `inspect`
- `sessions`
- `misses`
- `tags`

## Intentional hidden/dormant pieces in this family

- hidden `run` planner flags are machine/planner-only
- `sessions`, `misses`, and `tags` are public, but noticeably thinner on docs
- `mount` is public and active, but it is more specialized and less documented than the archive save/restore/run path
