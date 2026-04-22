# CLI Structure Comprehension View

This file is the current map of `src/` and the target organization plan for future refactors. It should track durable namespace boundaries, not transient feature work.

## What Exists Today

```text
src/
  adapters/
    mod.rs
  api/
    mod.rs
    client/
      mod.rs
      http.rs
      auth.rs
      cache.rs
      workspace.rs
      metrics.rs
    models/
      mod.rs
      cache.rs
      cache_rollups.rs
      cli_connect.rs
      metrics.rs
      optimize.rs
      workspace.rs
  cache/
    mod.rs
    adapter.rs
    archive.rs
    cas_file.rs
    cas_oci.rs
    cas_publish.rs
    cas_restore.rs
    file_materialize.rs
    multipart_upload.rs
    receipts.rs
    transfer.rs
    transport.rs
  ci_detection/
    mod.rs
    context.rs
    detect.rs
    tests.rs
  cli/
    mod.rs
    app.rs
    adapters.rs
    auth.rs
    cache.rs
    config.rs
    dispatch.rs
    preprocess.rs
    tests.rs
    proxy.rs
    workspace.rs
  command_support/
    mod.rs
    concurrency.rs
    save_support.rs
    specs.rs
    workspace.rs
  config/
    mod.rs
    env.rs
    model.rs
    source.rs
    store.rs
    tests.rs
  commands/
    mod.rs
    adapters/
      mod.rs
      command/
        mod.rs
        bazel.rs
        docker.rs
        go.rs
        gradle.rs
        maven.rs
        nx.rs
        sccache.rs
        turbo.rs
      go_cacheprog.rs
    auth/
      mod.rs
      auth.rs
      login.rs
      token.rs
    cache/
      mod.rs
      check.rs
      delete.rs
      inspect.rs
      ls.rs
      misses.rs
      run.rs
      sessions.rs
      status.rs
      tags.rs
      mount/
        mod.rs
        archive.rs
        cas.rs
        file.rs
        oci.rs
      restore/
        mod.rs
        archive.rs
        file.rs
        oci.rs
      save/
        mod.rs
        archive.rs
        cas.rs
        file.rs
        oci.rs
    config/
      mod.rs
      config.rs
      setup_encryption.rs
    proxy/
      mod.rs
      cache_registry.rs
    workspace/
      mod.rs
      audit.rs
      dashboard.rs
      doctor.rs
      onboard.rs
      use_workspace.rs
      workspaces.rs
  encryption/
    mod.rs
    crypto.rs
    errors.rs
    identity.rs
    passphrase.rs
    tests.rs
  error/
    mod.rs
    classify.rs
    convert.rs
    kinds.rs
    tests.rs
  exit_code.rs
  git.rs
  lib.rs
  main.rs
  manifest/
    mod.rs
    apply.rs
    builder.rs
    diff.rs
    io.rs
    model.rs
  observability/
    mod.rs
    request_metrics.rs
  optimize/
    mod.rs
    detect.rs
    rules_buildkite.rs
    rules_circleci.rs
    rules_dockerfile.rs
    rules_github_actions.rs
    rules_gitlab_ci.rs
    transform.rs
  platform/
    mod.rs
    container.rs
    detection.rs
    resources.rs
  progress/
    common.rs
    mod.rs
    model.rs
    render.rs
    reporter.rs
    system.rs
    tests.rs
  project_config/
    mod.rs
    builtins.rs
    discover.rs
    model.rs
    resolve.rs
  proxy/
    mod.rs
    command.rs
    tags.rs
  retry_resume/
    mod.rs
    config.rs
    policy.rs
    tests.rs
  serve/
    mod.rs
    cas_publish.rs
    engines/
      mod.rs
      bazel.rs
      go_cache.rs
      gradle.rs
      maven.rs
      nx.rs
      oci/
        mod.rs
        blobs.rs
        manifest_cache.rs
        manifests.rs
        present_blobs.rs
        prefetch.rs
        publish.rs
        uploads.rs
      sccache.rs
      turborepo.rs
    runtime/
      mod.rs
      listener.rs
      maintenance.rs
      shutdown.rs
    http/
      mod.rs
      error.rs
      handlers/
        mod.rs
        blobs.rs
        manifest.rs
        uploads.rs
      oci_route.rs
      oci_tags.rs
      routes.rs
    cache_registry/
      mod.rs
      cache_ops.rs
      error.rs
      kv_publish.rs
      route.rs
      tool_routes/
        mod.rs
        bazel.rs
        go_cache.rs
        gradle.rs
        maven.rs
        nx.rs
        sccache.rs
        turborepo.rs
      kv/
        mod.rs
        blob_read.rs
        confirm.rs
        flight.rs
        flush.rs
        handoff.rs
        index.rs
        instrumentation.rs
        lookup.rs
        policy.rs
        prefetch.rs
        refresh.rs
        schedule.rs
        types.rs
        write.rs
    state/
      mod.rs
      blob_locator.rs
      blob_read_cache.rs
      kv_pending.rs
      kv_published_index.rs
      metrics.rs
      oci_negative_cache.rs
      upload_sessions.rs
  signing/
    mod.rs
    policy.rs
  tag_utils.rs
  telemetry.rs
  telemetry/
    model.rs
    operation.rs
  test_env.rs
  types.rs
  ui.rs
  ui/
    summary.rs
```

## Current Hotspots

These are the main files that still carry multiple concerns and should be split by namespace first:

| Path | Concern mix |
| --- | --- |
| `src/api/client/mod.rs` | client construction, capability discovery, error parsing, publish polling, and batching policy still meet in one root module; tests are split to `src/api/client/tests.rs` |
| `src/serve/cache_registry/kv/mod.rs` | KV env tuning constants and root re-exports still meet in one root module; tests are split to `src/serve/cache_registry/kv/tests.rs` |
| `src/serve/cache_registry/kv/flush.rs` | KV save/upload/confirm orchestration and shutdown result handling still share one file, after scheduling, confirm classification, and cleanup handoff moved out |
| `src/commands/workspace/onboard.rs` | repo scan, optimize requests, diff/review, auth handoff, and file mutation still live together |
| `src/commands/workspace/dashboard.rs` | terminal lifecycle, input handling, API fetch orchestration, view-model formatting, and layout/render helpers still live together |

## Current Namespace Status

Most of the root-level namespace split is in place now, so the remaining work is mostly within already-established folders.

- `src/lib.rs` is the crate front door for module wiring and exports, and `src/main.rs` remains the thin binary entrypoint.
- `src/cli/mod.rs` plus `src/cli/` own Clap args and command indexing only.
- `src/commands/` is the command entrypoint layer, grouped by `auth`, `cache`, `config`, `proxy`, `workspace`, and `adapters`.
- `src/cache/`, `src/proxy/`, `src/signing/`, and `src/command_support/` carry reusable workflow code that should stay out of command entrypoints.
- `src/api/models/` is already split by response family, so future API work should prefer adding files there instead of growing `mod.rs`.
- `src/optimize/` and `src/platform/` are already real namespaces, not placeholders.
- `src/serve/runtime/`, `src/serve/http/`, `src/serve/cache_registry/`, and `src/serve/state/` are the durable runtime namespaces; the next work is to keep their remaining hot files thin.
- `src/serve/engines/` is the incremental engine-boundary namespace. `bazel.rs` owns Bazel AC/CAS method dispatch, store identity, and CAS digest integrity policy; `gradle.rs` owns Gradle HTTP build-cache write-status policy, including official `413 Payload Too Large` oversized-entry behavior; `maven.rs` owns Maven `GET`/`HEAD`/`PUT` method dispatch while preserving generic KV write rejection; `nx.rs` owns Nx bearer checks, artifact upload `Content-Length`, artifact/terminal-output/query method handling, and duplicate artifact upload conflict policy; `sccache.rs` owns WebDAV probe, `MKCOL`, object method/status behavior, and read timeout policy; `turborepo.rs` owns Turbo bearer auth, status, artifact hash and upload metadata validation, query, and event API shape; `go_cache.rs` owns the local HTTP backing route for the Go cacheprog helper; `oci/manifests.rs` owns pure OCI manifest descriptor, content-type, subject/referrers, and child-manifest classification rules; `oci/present_blobs.rs` owns descriptor proof before manifest publish; and `oci/uploads.rs` owns the OCI blob upload session state machine: start, PATCH, final PUT, mount `201`/`202`, empty finalize reuse, stale offset `416`, and streaming digest verification for one-shot upload bodies.
- `src/serve/http/handlers/` now owns the split OCI manifest, blob, and upload HTTP glue, while `handlers/mod.rs` still carries shared dispatch and proxy-status orchestration.
- `src/serve/cache_registry/tool_routes/` owns the thin non-OCI route shims that adapt detected registry routes into engine calls; adapter protocol rules stay in `src/serve/engines/`.
- `src/serve/cache_registry/kv/` now has separate `blob_read.rs`, `confirm.rs`, `flight.rs`, `handoff.rs`, `index.rs`, `instrumentation.rs`, `lookup.rs`, `policy.rs`, `prefetch.rs`, `refresh.rs`, `schedule.rs`, `tests.rs`, `types.rs`, and `write.rs` helpers. `flush.rs` remains the publish orchestrator, and `kv/mod.rs` now carries constants plus root module wiring/re-exports.
- `src/telemetry.rs` remains a thin front module, while `src/progress/mod.rs` fronts the progress namespace and `src/observability/` remains the request/event metrics namespace.
- `src/ui.rs` is the front module for `src/ui/`, and `src/test_env.rs` remains a dedicated test-only support module.

## Next Structural Targets

These are the next sensible follow-ons from the current tree.

- Insert the engine boundary described in `docs/adr/0001-engine-boundary.md` before starting snapshot-v2 or any crate/workspace split.
- Continue the OCI optimization and proof work described in `docs/adr/0002-proxy-engine-plan-b.md` and ADRs 0003-0007.
- Use the adapter progress tracker in `docs/adr/0002-proxy-engine-plan-b.md` plus `docs/adapter-contract-matrix.md` before follow-up adapter changes; first-pass engine boundaries now cover Bazel, Gradle, Maven, Nx, sccache, Turborepo, and the Go HTTP backing route.
- Use `docs/adr/0003-runner-proxy-optimization-roadmap.md` for the runner-proxy optimization sequence. Session trace, OCI negative cache, borrowed upload sessions, hidden stream-through, and Docker immutable-ref planning now have first slices; the remaining work is proof, action wiring, cache policy, and concurrency tuning from trace artifacts.
- Use `docs/adr/0004-oci-large-blob-stream-through.md`, `docs/adr/0005-borrowed-upload-sessions-and-blob-cache-policy.md`, `docs/adr/0006-cache-session-trace-and-oci-negative-cache.md`, and `docs/adr/0007-docker-immutable-run-refs-and-alias-promotion.md` for the concrete OCI hot-path and Docker correctness implementation tracks.
- ADR 0007 first slice is hidden behind Docker adapter controls: `--cache-run-ref-tag` selects immutable `--cache-to`, repeatable `--cache-from-ref-tag` selects import aliases, and repeatable `--cache-promote-ref-tag` asks the proxy to bind OCI alias refs after publish. Docker now also derives those refs from provider-neutral `BORINGCACHE_CI_*` run metadata, with GitHub Actions `GITHUB_*` as the first built-in mapper. Local runs without CI metadata preserve the old single-ref behavior.
- Focused ADR 0007 proxy coverage proves two immutable run refs can request the same promotion alias, remain readable by their run refs, and record promoted vs ignored-stale alias diagnostics. The backend-backed same-alias E2E now runs two live writer proxies plus a fresh verifier locally; CI evidence is still the rollout gate.
- Continue trimming `src/serve/cache_registry/kv/mod.rs` by moving remaining constants into focused helpers when the next behavior change needs it.
- Split `src/serve/cache_registry/kv/flush.rs` further only if save/upload/confirm orchestration grows; scheduling, confirm classification, and cleanup handoff are already isolated.
- Revisit `src/api/client/mod.rs` for capability discovery, publish/pending polling, and error parsing helpers.
- Revisit `src/commands/workspace/onboard.rs` for scan, diff/review, auth handoff, and apply helpers; tests are already split to `src/commands/workspace/onboard_tests.rs`.
- Revisit `src/commands/workspace/dashboard.rs` for terminal lifecycle, fetch orchestration, formatting, and render helpers; tests are already split to `src/commands/workspace/dashboard_tests.rs`.

## Command Surface Review

`src/commands` is now treated as the command entrypoint layer, not the shared-support layer.

- Auth/config entrypoints: `auth`, `login`, `token`, `config`, `setup_encryption`
- Cache entrypoints: `check`, `delete`, `inspect`, `ls`, `misses`, `mount`, `restore`, `run`, `save`, `sessions`, `status`, `tags`
- Workspace entrypoints: `audit`, `dashboard`, `doctor`, `onboard`, `use_workspace`, `workspaces`
- Proxy/adapter entrypoints: `cache_registry`, `go_cacheprog`, and `adapters/command/*`
- Shared support moved out of `src/commands`: `cache/{cas_publish,cas_restore,file_materialize,receipts,transport}.rs`, `proxy/{command,tags}.rs`, `signing/policy.rs`, `command_support/{workspace,specs,concurrency,save_support}.rs`

That means `src/commands` is now closer to controllers, and the clearest mixed-role command hotspots left are `src/commands/workspace/onboard.rs` and `src/commands/workspace/dashboard.rs`.

## Target Rails-Like Layout

The closest Rust equivalent to Rails-style organization here is domain-first folders with thin entry modules and focused helpers below them.

```text
src/
  api/
    client/
      mod.rs
      http.rs
      auth.rs
      cache.rs
      workspace.rs
      metrics.rs
      error.rs
      pending.rs
      publish.rs
    models/
      mod.rs
      cache.rs
      workspace.rs
      cache_rollups.rs
      metrics.rs
      optimize.rs
      cli_connect.rs
  commands/
    auth/
    cache/
      save/
      restore/
      mount/
      check.rs
      delete.rs
      inspect.rs
      ls.rs
      misses.rs
      run.rs
      sessions.rs
      status.rs
      tags.rs
    config/
    proxy/
    workspace/
  serve/
    runtime/
      mod.rs
      listener.rs
      maintenance.rs
      shutdown.rs
    engines/
      mod.rs
      bazel.rs
      oci/
        mod.rs
        manifests.rs
        present_blobs.rs
        uploads.rs
    http/
      mod.rs
      routes.rs
      error.rs
      oci_route.rs
      oci_tags.rs
      handlers/
        mod.rs
        manifest.rs
        blobs.rs
        uploads.rs
    cache_registry/
      mod.rs
      route.rs
      error.rs
      cache_ops.rs
      tool_routes/
        bazel.rs
        gradle.rs
        maven.rs
        nx.rs
        sccache.rs
        turborepo.rs
        go_cache.rs
      kv/
        mod.rs
        blob_read.rs
        index.rs
        lookup.rs
        prefetch.rs
        write.rs
        confirm.rs
        flight.rs
        flush.rs
        handoff.rs
        instrumentation.rs
        policy.rs
        refresh.rs
        schedule.rs
        types.rs
    state/
      mod.rs
      blob_locator.rs
      blob_read_cache.rs
      kv_pending.rs
      kv_published_index.rs
      metrics.rs
      oci_negative_cache.rs
      upload_sessions.rs
```

## Naming Rules

- Prefer domain nouns for folders: `cache`, `workspace`, `proxy`, `state`, `tool_routes`.
- Keep command entrypoints thin. Heavy workflow code belongs below the command namespace.
- Keep transport code separate from DTOs and from business decisions.
- Avoid generic names like `utils` and `handlers` when the code has a real domain name available.
- Use `support` only for truly shared command helpers that are not their own domain.

## Active Move Map

| Current path | Target path | Status |
| --- | --- | --- |
| `src/serve/http/handlers/manifest.rs` descriptor extraction, content-type, subject/referrers, and child-manifest classification | `src/serve/engines/oci/manifests.rs` | started |
| `src/serve/http/handlers/manifest.rs` descriptor availability and upload-session proof logic | `src/serve/engines/oci/present_blobs.rs` | started |
| `src/serve/http/handlers/uploads.rs` upload session state machine | `src/serve/engines/oci/uploads.rs` | done |
| `src/serve/cache_registry/tool_routes/bazel.rs` AC/CAS namespace and CAS digest policy | `src/serve/engines/bazel.rs` | started |
| `src/serve/cache_registry/tool_routes/gradle.rs` Gradle method and write-status policy | `src/serve/engines/gradle.rs` | done |
| `src/serve/cache_registry/tool_routes/maven.rs` Maven HTTP method dispatch | `src/serve/engines/maven.rs` | done |
| `src/serve/cache_registry/tool_routes/nx.rs` Nx auth, artifact, terminal-output, and query route rules | `src/serve/engines/nx.rs` | done |
| `src/serve/cache_registry/tool_routes/sccache.rs` WebDAV probe, `MKCOL`, object status, and timeout rules | `src/serve/engines/sccache.rs` | done |
| `src/serve/cache_registry/tool_routes/turborepo.rs` Turbo auth, status, artifact, query, and event API rules | `src/serve/engines/turborepo.rs` | done |
| `src/serve/cache_registry/tool_routes/go_cache.rs` Go cache HTTP backing route rules | `src/serve/engines/go_cache.rs` | done |
| `src/serve/mod.rs` | `src/serve/runtime/{mod,listener,maintenance,shutdown}.rs` | done |
| `src/serve/http/handlers.rs` | `src/serve/http/handlers/{mod,manifest,blobs,uploads}.rs` | done |
| `src/serve/cache_registry/kv/lookup.rs` | `src/serve/cache_registry/kv/{lookup,blob_read,prefetch,index}.rs` | done |
| `src/serve/cache_registry/kv/flush.rs` | `src/serve/cache_registry/kv/{flush,confirm,schedule,handoff,refresh}.rs` | started; scheduling, confirm classification, and cleanup handoff are split out |
| `src/serve/cache_registry/kv/mod.rs` | `src/serve/cache_registry/kv/{mod,constants,policy,flight,instrumentation,types}.rs` or nearby helpers | started; policy, flight, instrumentation, types, and tests helpers exist, but constants still live in the root module |
| `src/api/client/mod.rs` | `src/api/client/{error,pending,publish}.rs` | started; tests are split, behavior helpers still need extraction |
| `src/commands/workspace/onboard.rs` | `src/commands/workspace/onboard/{mod,scan,review,apply,auth}.rs` or sibling helpers | started; tests are split, scan/review/auth/apply still live together |
| `src/commands/workspace/dashboard.rs` | `src/commands/workspace/dashboard/{mod,app,input,render,format}.rs` or sibling helpers | started; tests are split, terminal/app/render concerns still live together |
| `src/config.rs` | `src/config/{mod,model,store}.rs` | done |
| `src/progress.rs` | `src/progress/{mod,reporter,system}.rs` | done |
| `src/retry_resume.rs` | `src/retry_resume/{mod,config,policy}.rs` | done |
| `src/error.rs` | `src/error/{mod,kinds,classify,convert}.rs` | done |
| `src/ci_detection.rs` | `src/ci_detection/{mod,context,detect}.rs` | done |
| `src/encryption.rs` | `src/encryption/{mod,crypto,identity,passphrase,errors}.rs` | done |
| `src/cli.rs` | `src/cli/{mod,app,tests}.rs` | done |
| `src/serve/cache_registry/{bazel,gradle,maven,nx,sccache,turborepo,go_cache}.rs` | `src/serve/cache_registry/tool_routes/*.rs` | done |

## Recommended Refactor Order

1. Trim `src/serve/cache_registry/kv/mod.rs` when the next KV behavior change needs it; constants are now the main root-module weight.
2. Revisit `src/api/client/mod.rs` once the serve-side boundaries are stable.
3. Revisit `src/commands/workspace/onboard.rs`, then `src/commands/workspace/dashboard.rs`, as the remaining mixed-role command hotspots.

## Notes For Current Worktree

- The worktree may be dirty with active feature work; this file is a structure map, not permission to revert unrelated edits.
- Keep structure-only follow-ups scoped to one hotspot at a time.
- Update this file when namespace boundaries change, not for routine behavior-only edits.
