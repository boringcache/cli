# Workspace, Auth, And Config Features

This file covers the account/workspace/setup surface.

## Core shape

- `onboard` is the setup funnel.
- `auth` and `login` establish credentials.
- `workspaces` and `use` establish default workspace context.
- `doctor`, `config`, and `setup-encryption` are support/setup commands.
- `command_support::workspace` plus `Config` plus `ApiClient` form the real shared hub.

## Feature map

| Feature | Entry points | Status | Primary code | Key shared modules | Evidence of use | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Token auth by paste | `auth --token <token>` | `public-primary` | `src/commands/auth/auth.rs` | `ApiClient::validate_token`, `Config::save`, onboarding workspace-default helper | `tests/cli_workflow_tests.rs`, `tests/integration_tests.rs`, `README.md`, `docs/onboard.md` | Saves validated token to config and then nudges default-workspace setup |
| Interactive login | `login [--manual] [--email ...] [--name ...] [--username ...]` | `public-primary` | `src/commands/auth/login.rs` | onboarding CLI-connect helpers, `Config`, `ApiClient`, default-workspace helper | `tests/cli_workflow_tests.rs`, `tests/integration_tests.rs`, `README.md`, `docs/onboard.md` | Reuses onboarding auth helpers rather than implementing a separate auth stack |
| Workspace token management | `token list|show|create|create-ci|revoke|rotate` with pagination, JSON, shell-output, expiration, and tag-prefix flags | `public-primary`, `lightly-used` | `src/commands/auth/token.rs` | `command_support::workspace::resolve_workspace`, admin `ApiClient`, workspace token DTOs | unit tests in `src/commands/auth/token.rs` | Real admin surface, but less end-to-end coverage than onboarding/workspaces |
| Doctor | `doctor [workspace] [--json]` | `public-primary`, `lightly-used` | `src/commands/workspace/doctor.rs` | `Config`, `config/source.rs`, `ApiClient::new_for_purpose/get_session_info`, `command_support::workspace` | help coverage in `tests/integration_tests.rs`, unit tests in `src/commands/workspace/doctor.rs` | Main diagnostic consumer of token-source and api-url-source helpers |
| Dashboard | `dashboard [workspace] [--period ...] [--limit ...] [--tag-limit ...] [--interval ...]` | `public-primary`, `lightly-used` | `src/commands/workspace/dashboard.rs` | `ApiClient::workspace_status`, `workspace_tags`, `ratatui`, `crossterm`, `command_support::workspace` | internal layout tests in `src/commands/workspace/dashboard.rs` | Interactive operator surface with lighter coverage than the core CLI workflows |
| Choose default workspace | `use [workspace] [--json]` | `public-primary`, `lightly-used` | `src/commands/workspace/use_workspace.rs` | `ApiClient::list_workspaces`, `Config::load_for_write/save_config`, `config::env_var` | referenced indirectly by doctor/workspaces flows and unit tests in module | Real command, but direct workflow evidence is thinner |
| List accessible workspaces | `workspaces [--json]` | `public-primary` | `src/commands/workspace/workspaces.rs` | `ApiClient::list_workspaces`, `Config::load`, `progress::format_bytes` | `tests/integration_tests.rs`, `tests/cli_workflow_tests.rs`, `README.md`, `docs/onboard.md` | One of the better-covered workspace commands |
| Onboard project and account | `onboard [path] [--email ...] [--name ...] [--username ...] [--apply] [--dry-run] [--manual] [--json]` | `public-primary` | `src/commands/workspace/onboard.rs` | `ApiClient` CLI-connect and optimize calls, `Config`, `audit`, `project_config`, `optimize`, `ui` | `tests/onboard_command_tests.rs`, `tests/cli_workflow_tests.rs`, `README.md`, `docs/onboard.md`, `docs/github-actions.md` | This is the setup funnel and one of the biggest orchestration files |
| Audit repo cache config | `audit [root] [--path PATH]... [--write] [--json]` | `public-primary` | `src/commands/workspace/audit.rs` | `project_config::{discover,normalize_profile_name,canonical_entry_id}`, `parse_save_format`, `jwalk`, `ui` | `tests/audit_command_tests.rs`, `docs/onboard.md` | Migration/discovery helper for `.boringcache.toml` |
| Config get/set/list | `config get|set|list` with `--json` on get/list | `public-primary`, `lightly-used` | `src/commands/config/config.rs` | `Config::load`, `Config::load_for_write`, `Config::update`, env helpers | help coverage in `tests/integration_tests.rs`, behavior unit tests in `src/config/tests.rs` | Mostly a thin shell over `Config` |
| Setup workspace encryption | `setup-encryption [workspace] [--identity-output PATH]` | `public-primary`, `lightly-used` | `src/commands/config/setup_encryption.rs` | `Config`, `encryption::{generate_keypair,save_identity,load_identity,identity_to_recipient}`, `ui` | indirect encrypted-flow coverage in `tests/cli_workflow_tests.rs` | Real setup path, but not deeply covered as a command surface |
| Config and env/source plumbing | no direct entrypoint | `internal-only` | `src/config/mod.rs`, `src/config/model.rs`, `src/config/store.rs`, `src/config/env.rs`, `src/config/source.rs` | `AuthPurpose`, `ValueSource`, env token lookup, config file persistence | unit tests in `src/config/tests.rs`, `.boringcache.env.example`, `docs/github-actions.md` | This is the real source-of-truth plumbing for token, workspace, API URL, and encryption defaults |

## Shared workspace hub

These are not separate features, but they are central enough to call out:

| Hub | Why it matters |
| --- | --- |
| `src/config/{mod,model,store,env,source}.rs` | merges env, token file, config file, default workspace, and workspace encryption |
| `src/command_support/workspace.rs` | shared workspace resolution path used by doctor, use, workspaces, token, dashboard, setup-encryption, and onboarding |
| `src/api/client/workspace.rs` and related models | workspace/session/token/optimize server calls |

## Thin or weakly connected parts of this family

- `doctor` is real, but it looks lighter on runtime workflow tests than setup and workspace listing
- `dashboard` is real, but mostly backed by internal layout tests
- `use`, `config`, and `setup-encryption` are real, but their direct test/doc footprint is smaller
- `token` commands are real and admin-facing, but the scan found less end-to-end coverage than for onboarding and workspaces

## Specific callouts

- `ApiClient::validate_token(&self, _token)` does not use the parameter and effectively validates the current client session path
- `doctor` is the main user of `token_source_for`, `api_url_source`, and `default_workspace_source`; those helpers are diagnostics plumbing rather than user-facing workflows
