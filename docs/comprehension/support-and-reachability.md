# Support And Reachability

This file answers two questions:

1. What shared subsystems are on real hot paths?
2. What code exists but looks hidden, weakly connected, or underused?

## Shared subsystem map

| Subsystem | Used from | Status | Primary files | Notes |
| --- | --- | --- | --- | --- |
| CLI wiring and preprocessing | every command | `support-primary` | `src/main.rs`, `src/cli/mod.rs`, `src/cli/app.rs`, `src/cli/dispatch.rs`, `src/cli/preprocess.rs` | Thin entry stack, plus alias/default-workspace shorthand plumbing |
| Command support helpers | cache commands, adapters, doctor, workspace/token flows | `support-primary` | `src/command_support/mod.rs`, `specs.rs`, `workspace.rs`, `concurrency.rs`, `save_support.rs` | Common spec parsing, workspace resolution, concurrency choice, save helper logic |
| API client and models | nearly every command and serve path | `support-primary` | `src/api/client/mod.rs`, `http.rs`, `cache.rs`, `auth.rs`, `workspace.rs`, `metrics.rs`, `src/api/models/**` | The main transport and DTO layer; large hotspot with mixed command concerns |
| Project config planning | `run` and adapter planning only | `support-primary` | `src/project_config/mod.rs`, `discover.rs`, `resolve.rs`, `builtins.rs`, `model.rs` | Not general CLI plumbing; intentionally scoped to repo-config-based planning |
| Cache/manifest helpers | lifecycle commands only | `support-primary` | `src/cache/**`, `src/manifest/**` | Heavy orchestration logic for save/restore/mount, not report/admin commands |
| Encryption | lifecycle commands and setup-encryption | `support-primary` | `src/encryption/mod.rs`, `src/encryption/crypto.rs`, `src/encryption/identity.rs`, `src/encryption/passphrase.rs`, `src/encryption/errors.rs` | Not used by list/status/delete/reporting-only features |
| Signing policy | restore/check/mount verification | `support-primary` | `src/signing/mod.rs`, `src/signing/policy.rs` | Warn-only by default; strict mode is opt-in. Canonical server signature payloads are verified with `server_envelope_signature` when present, legacy `server_signature` remains supported, and `BORINGCACHE_TRUSTED_WORKSPACE_KEY_FINGERPRINT` adds an optional pinned workspace-key trust boundary. |
| Platform detection and sizing | lifecycle commands, adapters, serve startup | `support-primary` | `src/platform/mod.rs`, `detection.rs`, `resources.rs`, `container.rs` | Cross-cutting, active, and broadly referenced |
| Progress and UI | lifecycle commands, workspace commands, status/reporting | `support-primary` | `src/progress/mod.rs`, `src/progress/**`, `src/ui.rs`, `src/ui/summary.rs` | Real shared presentation layer, not dead code |
| Observability | API request metrics and proxy runtime events | `internal-only` | `src/observability/mod.rs`, `request_metrics.rs`, `src/api/client/metrics.rs` | Operational support, especially for proxy/runtime diagnosis. v2 API request events are also rolled up in memory so `cache_session_summary.rails` can report per-operation counts, p50/p95 duration, errors, and retries. Proxy session rollups now send a provider-neutral run identity for CI and local runs alike, including ref type/name, generic change number, and commit when detected. |
| Telemetry metrics models | save/restore/archive transport reporting | `support-primary` | `src/telemetry/model.rs`, `src/telemetry/operation.rs` | `SaveMetrics` and `RestoreMetrics` are active inputs in lifecycle code |
| Retry config | HTTP transport retries | `support-primary` | `src/retry_resume/mod.rs`, `src/retry_resume/config.rs`, `src/retry_resume/policy.rs`, `src/cache/transfer.rs`, call sites in `src/api/client/http.rs` | Retry logic is active and real. Manifest/pointer object fetches opt into a short `404` retry window for storage read-after-write lag; blob body misses keep the normal non-404 retry policy. |

## Reachability notes

### Clearly active

- `command_support/**`
- `api/**`
- `cache/**`
- `manifest/**`
- `project_config/**`
- `platform/**`
- `progress/**`
- `ui/**`
- `observability/**`
- `serve/**`

### Clearly hidden by design

- hidden `run` archive planner flags
- doc-hidden modules re-exported from `src/lib.rs` such as `cache`, `command_support`, `proxy`, `test_env`

### Present but weakly connected

| Item | Why it looks weak |
| --- | --- |
| `optimize::CiType::deterministic_supported` | explicitly marked with `allow(dead_code)` |
| `optimize::transform::no_changes_result` | explicitly marked with `allow(dead_code)` |
| `optimize::transform::error_result` | explicitly marked with `allow(dead_code)` |
| `api::client::CapabilityFlags` fields | some fields are negotiated and logged, but the type itself carries `allow(dead_code)` because not every field is read everywhere |
| several workspace DTO fields | shape-only compatibility fields carry `allow(dead_code)` in `src/api/models/workspace.rs` |

## No obvious dead public features

The scan did not find a user-facing command that looks abandoned outright.

What it did find instead:

- real public commands with thin docs/tests: `mount`, `doctor`, `dashboard`, `use`, `config`, `setup-encryption`, `inspect`, `sessions`, `misses`, `tags`
- the proxy surface is intentionally split between `cache-registry` as the standalone proxy and wrapper paths like `run --proxy` or adapter commands that temporarily start it
- supported advanced helper command with thinner docs/tests: `go-cacheprog`
- the remaining compatibility entrypoint is `delete` for `rm`
- weakly connected support code is now mostly the explicit `allow(dead_code)` optimize helpers and schema-compat DTO fields listed above; retry plumbing is active and the old telemetry collector path is gone

## Practical maintenance guidance

When you change a feature, update all three of these scopes:

1. the public command or entrypoint section
2. the shared subsystem row if reachability changed
3. the weak/dormant list if code moved onto or off of the hot path

If a future cleanup removes any of the weakly connected items above, delete them from this file rather than leaving a stale note behind.
