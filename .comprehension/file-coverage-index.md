# File Coverage Index

This file is the explicit "nothing missed" layer for the comprehension map.

Scope:

- all Rust source under `src/**`
- all Rust tests under `tests/**`
- repo automation and support code under `.github/workflows/**`, `ci/e2e/**`, `scripts/**`, `install-web/**`, and `install.sh`
- build/install/runtime config that directly shapes CLI behavior or release flow

Out of scope:

- prose docs under `docs/**`
- marketing/site metadata that is not executable or operational logic
- licenses and other non-code text

If a file moves, rename it here and keep its owning feature/support group accurate.

## Crate entry, CLI grammar, and command routing

Owner: entry/routing layer (`support-primary`)

- `src/main.rs`
- `src/lib.rs`
- `src/cli/mod.rs`
- `src/cli/app.rs`
- `src/cli/adapters.rs`
- `src/cli/auth.rs`
- `src/cli/cache.rs`
- `src/cli/config.rs`
- `src/cli/dispatch.rs`
- `src/cli/preprocess.rs`
- `src/cli/proxy.rs`
- `src/cli/tests.rs`
- `src/cli/workspace.rs`
- `src/commands/mod.rs`
- `src/commands/auth/mod.rs`
- `src/commands/cache/mod.rs`
- `src/commands/config/mod.rs`
- `src/commands/proxy/mod.rs`
- `src/commands/adapters/mod.rs`
- `src/commands/workspace/mod.rs`

## Cache lifecycle commands

Owner: cache lifecycle (`public-primary` unless noted otherwise)

- `src/commands/cache/check.rs`
- `src/commands/cache/delete.rs`
- `src/commands/cache/inspect.rs`
- `src/commands/cache/ls.rs`
- `src/commands/cache/misses.rs`
- `src/commands/cache/run.rs`
- `src/commands/cache/sessions.rs`
- `src/commands/cache/status.rs`
- `src/commands/cache/tags.rs`
- `src/commands/cache/mount/mod.rs`
- `src/commands/cache/mount/archive.rs`
- `src/commands/cache/mount/cas.rs`
- `src/commands/cache/mount/file.rs`
- `src/commands/cache/mount/oci.rs`
- `src/commands/cache/restore/mod.rs`
- `src/commands/cache/restore/archive.rs`
- `src/commands/cache/restore/file.rs`
- `src/commands/cache/restore/oci.rs`
- `src/commands/cache/save/mod.rs`
- `src/commands/cache/save/archive.rs`
- `src/commands/cache/save/cas.rs`
- `src/commands/cache/save/file.rs`
- `src/commands/cache/save/oci.rs`

Notes:

- `run` contains hidden planner-only flags that stay `hidden-internal`
- `delete` is exposed as `rm` with visible alias `delete`

## Workspace, auth, and config commands

Owner: workspace/account/setup family (`public-primary` unless noted otherwise)

- `src/commands/auth/auth.rs`
- `src/commands/auth/login.rs`
- `src/commands/auth/token.rs`
- `src/commands/config/config.rs`
- `src/commands/config/setup_encryption.rs`
- `src/commands/workspace/audit.rs`
- `src/commands/workspace/dashboard.rs`
- `src/commands/workspace/doctor.rs`
- `src/commands/workspace/onboard.rs`
- `src/commands/workspace/use_workspace.rs`
- `src/commands/workspace/workspaces.rs`

Notes:

- `token`, `doctor`, `dashboard`, `use`, `config`, and `setup-encryption` are real but thinner than `onboard` / `auth` / `workspaces`

## Proxy and adapter commands

Owner: proxy/adapter family (`public-primary`)

- `src/commands/proxy/cache_registry.rs`
- `src/commands/adapters/go_cacheprog.rs`
- `src/commands/adapters/command/mod.rs`
- `src/commands/adapters/command/bazel.rs`
- `src/commands/adapters/command/docker.rs`
- `src/commands/adapters/command/go.rs`
- `src/commands/adapters/command/gradle.rs`
- `src/commands/adapters/command/maven.rs`
- `src/commands/adapters/command/nx.rs`
- `src/commands/adapters/command/sccache.rs`
- `src/commands/adapters/command/turbo.rs`

Notes:

- `cache-registry` is the canonical standalone proxy command; wrapper paths like adapter commands and `run --proxy` temporarily start that same proxy for one command
- `go-cacheprog` is a real helper surface but thinner than the main adapter framework

## Cache lifecycle support libraries

Owner: cache lifecycle support (`support-primary`)

- `src/adapters/mod.rs`
- `src/cache/mod.rs`
- `src/cache/adapter.rs`
- `src/cache/archive.rs`
- `src/cache/cas_file.rs`
- `src/cache/cas_oci.rs`
- `src/cache/cas_publish.rs`
- `src/cache/cas_restore.rs`
- `src/cache/file_materialize.rs`
- `src/cache/multipart_upload.rs`
- `src/cache/receipts.rs`
- `src/cache/transfer.rs`
- `src/cache/transport.rs`
- `src/manifest/mod.rs`
- `src/manifest/apply.rs`
- `src/manifest/builder.rs`
- `src/manifest/diff.rs`
- `src/manifest/io.rs`
- `src/manifest/model.rs`
- `src/encryption/mod.rs`
- `src/encryption/crypto.rs`
- `src/encryption/errors.rs`
- `src/encryption/identity.rs`
- `src/encryption/passphrase.rs`
- `src/encryption/tests.rs`
- `src/signing/mod.rs`
- `src/signing/policy.rs`
- `src/git.rs`
- `src/tag_utils.rs`
- `src/ci_detection/mod.rs`
- `src/ci_detection/context.rs`
- `src/ci_detection/detect.rs`
- `src/ci_detection/tests.rs`

Notes:

- `ci_detection` is active through save/mount/CAS publish telemetry tagging and Docker run-ref planning; it owns provider-neutral `BORINGCACHE_CI_*` run metadata plus GitHub Actions mapping
- `signing/policy.rs` is restore/check/mount verification support, warn-only by default

## API transport and data models

Owner: transport/model layer (`support-primary`)

- `src/api/mod.rs`
- `src/api/client/mod.rs`
- `src/api/client/auth.rs`
- `src/api/client/cache.rs`
- `src/api/client/http.rs`
- `src/api/client/metrics.rs`
- `src/api/client/workspace.rs`
- `src/api/models/mod.rs`
- `src/api/models/cache.rs`
- `src/api/models/cache_rollups.rs`
- `src/api/models/cli_connect.rs`
- `src/api/models/metrics.rs`
- `src/api/models/optimize.rs`
- `src/api/models/workspace.rs`

Notes:

- some DTO fields are intentionally shape-only and marked `allow(dead_code)`
- capability negotiation and publish polling live in this layer and are active

## Config, planning, platform, optimize, and UI support

Owner: shared command support (`support-primary` unless noted otherwise)

- `src/config/mod.rs`
- `src/config/model.rs`
- `src/config/store.rs`
- `src/config/env.rs`
- `src/config/source.rs`
- `src/config/tests.rs`
- `src/command_support/mod.rs`
- `src/command_support/concurrency.rs`
- `src/command_support/save_support.rs`
- `src/command_support/specs.rs`
- `src/command_support/workspace.rs`
- `src/project_config/mod.rs`
- `src/project_config/builtins.rs`
- `src/project_config/discover.rs`
- `src/project_config/model.rs`
- `src/project_config/resolve.rs`
- `src/platform/mod.rs`
- `src/platform/container.rs`
- `src/platform/detection.rs`
- `src/platform/resources.rs`
- `src/optimize/mod.rs`
- `src/optimize/detect.rs`
- `src/optimize/rules_buildkite.rs`
- `src/optimize/rules_circleci.rs`
- `src/optimize/rules_dockerfile.rs`
- `src/optimize/rules_github_actions.rs`
- `src/optimize/rules_gitlab_ci.rs`
- `src/optimize/transform.rs`
- `src/progress/mod.rs`
- `src/progress/common.rs`
- `src/progress/model.rs`
- `src/progress/render.rs`
- `src/progress/reporter.rs`
- `src/progress/system.rs`
- `src/progress/tests.rs`
- `src/ui.rs`
- `src/ui/summary.rs`

Notes:

- `project_config/**` is intentionally scoped to `run` and adapter planning
- `optimize/**` is active through `onboard`, but some helper functions remain weakly connected and explicitly dead-code-tolerant

## Proxy runtime, registry protocols, and serve state

Owner: proxy runtime (`support-primary` / `internal-only`)

- `src/proxy/mod.rs`
- `src/proxy/command.rs`
- `src/proxy/tags.rs`
- `src/serve/mod.rs`
- `src/serve/cas_publish.rs`
- `src/serve/engines/mod.rs`
- `src/serve/engines/bazel.rs`
- `src/serve/engines/go_cache.rs`
- `src/serve/engines/gradle.rs`
- `src/serve/engines/maven.rs`
- `src/serve/engines/nx.rs`
- `src/serve/engines/oci/mod.rs`
- `src/serve/engines/oci/blobs.rs`
- `src/serve/engines/oci/manifest_cache.rs`
- `src/serve/engines/oci/manifests.rs`
- `src/serve/engines/oci/present_blobs.rs`
- `src/serve/engines/oci/prefetch.rs`
- `src/serve/engines/oci/publish.rs`
- `src/serve/engines/oci/uploads.rs`
- `src/serve/engines/sccache.rs`
- `src/serve/engines/turborepo.rs`
- `src/serve/http/mod.rs`
- `src/serve/http/error.rs`
- `src/serve/http/oci_route.rs`
- `src/serve/http/oci_tags.rs`
- `src/serve/http/routes.rs`
- `src/serve/http/handlers/mod.rs`
- `src/serve/http/handlers/blobs.rs`
- `src/serve/http/handlers/manifest.rs`
- `src/serve/http/handlers/uploads.rs`
- `src/serve/runtime/mod.rs`
- `src/serve/runtime/listener.rs`
- `src/serve/runtime/maintenance.rs`
- `src/serve/runtime/shutdown.rs`
- `src/serve/state/mod.rs`
- `src/serve/state/blob_locator.rs`
- `src/serve/state/blob_read_cache.rs`
- `src/serve/state/kv_pending.rs`
- `src/serve/state/kv_published_index.rs`
- `src/serve/state/metrics.rs`
- `src/serve/state/oci_negative_cache.rs`
- `src/serve/state/upload_sessions.rs`
- `src/serve/cache_registry/mod.rs`
- `src/serve/cache_registry/bazel.rs`
- `src/serve/cache_registry/cache_ops.rs`
- `src/serve/cache_registry/error.rs`
- `src/serve/cache_registry/go_cache.rs`
- `src/serve/cache_registry/gradle.rs`
- `src/serve/cache_registry/kv_publish.rs`
- `src/serve/cache_registry/maven.rs`
- `src/serve/cache_registry/nx.rs`
- `src/serve/cache_registry/route.rs`
- `src/serve/cache_registry/sccache.rs`
- `src/serve/cache_registry/turborepo.rs`
- `src/serve/cache_registry/kv/mod.rs`
- `src/serve/cache_registry/kv/blob_read.rs`
- `src/serve/cache_registry/kv/flush.rs`
- `src/serve/cache_registry/kv/index.rs`
- `src/serve/cache_registry/kv/lookup.rs`
- `src/serve/cache_registry/kv/prefetch.rs`
- `src/serve/cache_registry/kv/write.rs`

Notes:

- the KV section reflects the current workspace shape, with flush/publish orchestration still concentrated in `flush.rs`
- `serve/cas_publish.rs` is shared by manifest publish handlers and KV flush publishing; the OCI tracked-blob path consumes `PresentBlob` proofs when selecting upload sessions

## Cross-cutting diagnostics, error handling, and test support

Owner: cross-cutting support (`support-primary` with some `dormant-or-underused` pieces)

- `src/observability/mod.rs`
- `src/observability/request_metrics.rs`
- `src/telemetry.rs`
- `src/telemetry/model.rs`
- `src/telemetry/operation.rs`
- `src/retry_resume/mod.rs`
- `src/retry_resume/config.rs`
- `src/retry_resume/policy.rs`
- `src/retry_resume/tests.rs`
- `src/error/mod.rs`
- `src/error/classify.rs`
- `src/error/convert.rs`
- `src/error/kinds.rs`
- `src/error/tests.rs`
- `src/exit_code.rs`
- `src/types.rs`
- `src/test_env.rs`

Notes:

- retry logic in `src/retry_resume/{mod,config,policy}.rs` is active and used by the HTTP client
- `test_env.rs` is test-only infrastructure and intentionally not part of runtime features

## Rust test files

Owner: verification layer (`support-primary`)

### Cache lifecycle and CLI parsing

- `tests/integration_tests.rs`
- `tests/run_command_tests.rs`
- `tests/save_missing_paths_tests.rs`
- `tests/save_workspace_flag_tests.rs`
- `tests/workspace_injection_tests.rs`

### Workspace, auth, and onboarding

- `tests/audit_command_tests.rs`
- `tests/cli_workflow_tests.rs`
- `tests/onboard_command_tests.rs`

### Proxy, API, and CAS/adapter behavior

- `tests/api_behavior_tests.rs`
- `tests/api_contract_tests.rs`
- `tests/cas_adapter_integration_tests.rs`
- `tests/run_proxy_e2e_tests.rs`
- `tests/serve_tests.rs`

## Repo automation, release, install, and example assets

Owner: repo operations support (`support-primary`)

### Root build and runtime control files

- `.boringcache.env.example`
- `Cargo.toml`
- `Makefile`
- `mise.toml`
- `rust-toolchain.toml`

### GitHub Actions workflows

- `.github/workflows/ci.yml`
- `.github/workflows/e2e.yml`
- `.github/workflows/publish-images.yml`
- `.github/workflows/release.yml`
- `.github/workflows/validate-images.yml`

### Local scripts

- `scripts/cargo-flow.sh`
- `scripts/cli-version.sh`
- `scripts/release.sh`
- `scripts/rust-version.sh`
- `scripts/verify-rust-version-sync.sh`
- `scripts/ci/docker-build-cli-artifact.sh`

### E2E harness and tooling

- `ci/e2e/e2e-adapter-suite.sh`
- `ci/e2e/e2e-auth.sh`
- `ci/e2e/e2e-framework.sh`
- `ci/e2e/e2e-helpers.sh`
- `ci/e2e/e2e-local-adapter-commands.sh`
- `ci/e2e/e2e-nx-go-test.sh`
- `ci/e2e/e2e-remote-tag.sh`
- `ci/e2e/request-metrics-summary.py`
- `ci/e2e/required/e2e-all-adapters-http-test.sh`
- `ci/e2e/required/e2e-cli-core-test.sh`
- `ci/e2e/required/e2e-cli-integrity-test.sh`
- `ci/e2e/required/e2e-cross-runner-seed.sh`
- `ci/e2e/required/e2e-cross-runner-verify.sh`
- `ci/e2e/required/e2e-docker-buildkit-registry-test.sh`
- `ci/e2e/required/e2e-oci-same-alias-writer-test.sh`
- `ci/e2e/required/e2e-security-test.sh`
- `ci/e2e/required/e2e-tool-bazel-test.sh`
- `ci/e2e/required/e2e-tool-gradle-test.sh`
- `ci/e2e/required/e2e-tool-maven-test.sh`
- `ci/e2e/required/e2e-tool-nx-test.sh`
- `ci/e2e/required/e2e-tool-sccache-test.sh`
- `ci/e2e/required/e2e-tool-turbo-test.sh`
- `ci/e2e/extended/e2e-cli-contract-test.sh`
- `ci/e2e/extended/e2e-dual-proxy-contention-test.sh`
- `ci/e2e/extended/e2e-prefetch-readiness-test.sh`
- `ci/e2e/extended/e2e-sccache-test.sh`
- `ci/e2e/extended/e2e-tool-hugo-test.sh`

### Install surface

- `install.sh`
- `install-web/_config.yml`
- `install-web/index.html`
- `install-web/install.sh`

### Example and image build assets

- `images/bookworm/Dockerfile`
- `images/bookworm-build/Dockerfile`
- `images/examples/nextjs/Dockerfile`
- `images/examples/nextjs/mise.toml`
- `images/examples/rails/Dockerfile`
- `images/examples/rails/mise.toml`

## Residual ambiguity

After this file was added, the remaining ambiguity is not "what file exists" but "how active is it":

- telemetry collector path
- retry behavior in `src/retry_resume/{mod,config,policy}.rs`
- some optimize helpers marked `allow(dead_code)`
- some API model fields kept for schema compatibility

Those are all accounted for above and in `support-and-reachability.md`.
