# CLI Structure Comprehension View

This file is the current map of `src/` and the target organization plan for future refactors. It should track durable namespace boundaries, not transient feature work.

## What Exists Today

```text
src/
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
  cli/
    adapters.rs
    auth.rs
    cache.rs
    config.rs
    dispatch.rs
    preprocess.rs
    proxy.rs
    workspace.rs
  command_support/
    mod.rs
    concurrency.rs
    save_support.rs
    specs.rs
    workspace.rs
  config/
    env.rs
    source.rs
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
      serve.rs
    workspace/
      mod.rs
      audit.rs
      dashboard.rs
      doctor.rs
      onboard.rs
      use_workspace.rs
      workspaces.rs
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
  platform/
  progress/
    common.rs
    model.rs
    render.rs
  project_config/
    mod.rs
    builtins.rs
    discover.rs
    model.rs
    resolve.rs
  proxy/
    mod.rs
    exec.rs
    tags.rs
  serve/
    mod.rs
    cas_publish.rs
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
      bazel.rs
      cache_ops.rs
      error.rs
      go_cache.rs
      gradle.rs
      kv_publish.rs
      maven.rs
      nx.rs
      route.rs
      sccache.rs
      turborepo.rs
      kv/
        mod.rs
        blob_read.rs
        flush.rs
        index.rs
        lookup.rs
        prefetch.rs
        write.rs
    state/
      mod.rs
      blob_locator.rs
      blob_read_cache.rs
      kv_pending.rs
      kv_published_index.rs
      metrics.rs
      upload_sessions.rs
  signing/
    mod.rs
    policy.rs
  telemetry/
    collector.rs
    model.rs
    operation.rs
  ui/
    summary.rs
```

## Current Hotspots

These are the main files that still carry multiple concerns and should be split by namespace first:

| Path | Concern mix |
| --- | --- |
| `src/serve/cache_registry/kv/flush.rs` | flush scheduling, refresh, publish polling, and shutdown handoff still share one file |
| `src/api/client/mod.rs` | client construction, capability discovery, error parsing, publish polling, and batching policy still meet in one root module |
| `src/commands/workspace/onboard.rs` | repo scan, optimize requests, diff/review, auth handoff, and file mutation still live together |
| `src/config.rs` | config model, file persistence, and env-backed auth resolution still meet in one root module |

## Current Namespace Status

The root-level namespace split is in place now, so the remaining work is mostly within already-established folders.

- `src/cli.rs` plus `src/cli/` own Clap args and command indexing only.
- `src/commands/` is the command entrypoint layer, grouped by `auth`, `cache`, `config`, `proxy`, `workspace`, and `adapters`.
- `src/cache/`, `src/proxy/`, `src/signing/`, and `src/command_support/` carry reusable workflow code that should stay out of command entrypoints.
- `src/api/models/` is already split by response family, so future API work should prefer adding files there instead of growing `mod.rs`.
- `src/serve/runtime/`, `src/serve/http/`, `src/serve/cache_registry/`, and `src/serve/state/` are the durable runtime namespaces; the next work is to keep their remaining hot files thin.
- `src/serve/http/handlers/` now owns the split OCI manifest, blob, and upload flows behind one thin dispatch module.
- `src/serve/cache_registry/kv/` now has separate `blob_read.rs`, `prefetch.rs`, and `index.rs` helpers, leaving `lookup.rs` centered on request-path lookup and resolve behavior.
- `src/telemetry.rs` and `src/progress.rs` are front modules over their submodules, and `src/observability/` remains the request/event metrics namespace.

## Next Structural Targets

These are the next sensible follow-ons from the current tree.

- Split `src/serve/cache_registry/kv/flush.rs` into scheduling, refresh, and pending-publish handoff helpers.
- Revisit `src/api/client/mod.rs` for capability discovery, publish/pending polling, and error parsing helpers.
- Revisit `src/commands/workspace/onboard.rs` for scan, diff/review, auth handoff, and apply helpers.
- Revisit `src/config.rs` for a cleaner split between config model, file persistence, and auth/env resolution.

## Command Surface Review

`src/commands` is now treated as the command entrypoint layer, not the shared-support layer.

- Auth/config entrypoints: `auth`, `login`, `token`, `config`, `setup_encryption`
- Cache entrypoints: `check`, `delete`, `inspect`, `ls`, `misses`, `mount`, `restore`, `run`, `save`, `sessions`, `status`, `tags`
- Workspace entrypoints: `audit`, `dashboard`, `doctor`, `onboard`, `use_workspace`, `workspaces`
- Proxy/adapter entrypoints: `serve`, `go_cacheprog`, and `adapters/command/*`
- Shared support moved out of `src/commands`: `cache/{cas_publish,cas_restore,file_materialize,receipts,transport}.rs`, `proxy/{exec,tags}.rs`, `signing/policy.rs`, `command_support/{workspace,specs,concurrency,save_support}.rs`

That means `src/commands` is now closer to controllers, and the main mixed-role command module left is `src/commands/workspace/onboard.rs`.

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
        flush.rs
    state/
      mod.rs
      blob_locator.rs
      blob_read_cache.rs
      kv_pending.rs
      kv_published_index.rs
      metrics.rs
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
| `src/serve/mod.rs` | `src/serve/runtime/{mod,listener,maintenance,shutdown}.rs` | done |
| `src/serve/http/handlers.rs` | `src/serve/http/handlers/{mod,manifest,blobs,uploads}.rs` | done |
| `src/serve/cache_registry/kv/lookup.rs` | `src/serve/cache_registry/kv/{lookup,blob_read,prefetch,index}.rs` | done |
| `src/serve/cache_registry/kv/flush.rs` | `src/serve/cache_registry/kv/{flush,refresh,handoff}.rs` | next |
| `src/api/client/mod.rs` | `src/api/client/{error,pending,publish}.rs` | next |
| `src/commands/workspace/onboard.rs` | `src/commands/workspace/onboard/{mod,scan,review,apply,auth}.rs` or sibling helpers | next |
| `src/config.rs` | `src/config/{mod,model,persist}.rs` | next |
| `src/serve/cache_registry/{bazel,gradle,maven,nx,sccache,turborepo,go_cache}.rs` | `src/serve/cache_registry/tool_routes/*.rs` | later |

## Recommended Refactor Order

1. Split `src/serve/cache_registry/kv/flush.rs`; it is the next serve-specific bottleneck.
2. Revisit `src/api/client/mod.rs` once the serve-side boundaries are stable.
3. Revisit `src/commands/workspace/onboard.rs` after the serve/runtime and API splits.
4. Split `src/config.rs` last unless config persistence expands again sooner.

## Notes For Current Worktree

- The worktree may be dirty with active feature work; this file is a structure map, not permission to revert unrelated edits.
- Keep structure-only follow-ups scoped to one hotspot at a time.
- Update this file when namespace boundaries change, not for routine behavior-only edits.
