# CLI Structure Comprehension View

This file is the current map of `src/` and the target organization plan for future refactors.

## What Exists Today

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
    models/mod.rs
  cache/
    mod.rs
    cas_publish.rs
    cas_restore.rs
    file_materialize.rs
    receipts.rs
  cli/
    adapters.rs
    auth.rs
    config.rs
    dispatch.rs
    preprocess.rs
  command_support/
    mod.rs
    workspace.rs
    specs.rs
    concurrency.rs
    save_support.rs
  config/
    env.rs
    source.rs
  commands/
    adapters/
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
    cache/
    config/
    proxy/
    workspace/
  proxy/
    mod.rs
    exec.rs
    tags.rs
  serve/
    mod.rs
    handlers.rs
    state/
      mod.rs
      metrics.rs
      blob_read_cache.rs
      blob_locator.rs
      upload_sessions.rs
      kv_pending.rs
      kv_published_index.rs
    cache_registry/
      mod.rs
      kv/
        mod.rs
        write.rs
        lookup.rs
        flush.rs
      kv_publish.rs
      cache_ops.rs
      bazel.rs
      gradle.rs
      maven.rs
      nx.rs
      sccache.rs
      turborepo.rs
      go_cache.rs
  manifest/
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
    model.rs
    discover.rs
    builtins.rs
    resolve.rs
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

These are the main files that carry multiple concerns and should be split by namespace first:

| Path | Concern mix |
| --- | --- |
| `src/serve/cache_registry/kv/lookup.rs` | lookup, blob IO, prefetch targeting, index load |
| `src/serve/cache_registry/kv/flush.rs` | flush orchestration, refresh, polling, alias binding |
| `src/commands/cache/save/mod.rs` | entrypoint plus archive, OCI, and file save flows |
| `src/commands/cache/restore/mod.rs` | entrypoint plus archive, OCI, and file restore flows |
| `src/commands/cache/mount/mod.rs` | initial restore, watch loop, and layout-specific sync logic |
| `src/cli.rs` + `src/cli/{preprocess,dispatch}.rs` + `src/main.rs` | command declaration is still centralized even after token/adapter/config extractions |
| `src/config.rs` + `src/config/{env,source}.rs` | config persistence, config model, and env-backed auth resolution still meet in one root module |
| `src/commands/workspace/onboard.rs` | command entrypoint, prompting, repo analysis, auth handoff, and file mutation still live together |

## First-Pass Status

This branch handled the remaining root-level first pass without changing the public crate surface.

- `src/cli.rs` now keeps the command index while `src/cli/{auth,adapters,config}.rs` hold their own supporting types.
- `src/config.rs` now has focused `env` and `source` helpers under `src/config/`.
- `src/request_metrics.rs` moved under `src/observability/`.
- `src/telemetry.rs` now fronts `collector`, `model`, and `operation` modules.
- `src/progress.rs` now fronts `model` and `render`, and `src/ui.rs` now delegates summaries to `src/ui/summary.rs`.

## Second-Pass Notes

These are the next sensible follow-ons after this branch merges.

- Group the remaining command arg structs inside `src/cli.rs` by concern, likely `auth`, `cache`, `workspace`, and `proxy`.
- Split `src/config.rs` again if write/update persistence logic keeps growing alongside the data model.
- Decide whether `telemetry` should fold fully into `observability`, or stay a sibling namespace for operation-level metrics.
- Revisit `src/progress.rs` and the TUI/dashboard code together if the terminal presentation layer broadens further.

## Command Surface Review

`src/commands` is now treated as the command entrypoint layer, not the shared-support layer.

- Straight command entrypoints: `audit`, `auth`, `check`, `config`, `delete`, `doctor`, `go_cacheprog`, `inspect`, `login`, `ls`, `misses`, `mount`, `restore`, `run`, `save`, `sessions`, `setup_encryption`, `tags`, `use_workspace`, `workspaces`
- Mixed-role command-family modules that still want follow-up splits: `adapter`, `serve`, `onboard`, `status`, `token`
- Shared support moved out of `src/commands`: `cache/cas_publish.rs`, `cache/cas_restore.rs`, `cache/file_materialize.rs`, `cache/receipts.rs`, `proxy/exec.rs`, `signing/policy.rs`, `command_support/{workspace,specs,concurrency,save_support}.rs`

That means `src/commands` is closer to “controllers” and the shared workflow code is starting to live in domain namespaces instead of command namespaces.

## Target Rails-Like Layout

The closest Rust equivalent to Rails-style organization here is domain-first folders with clear roles inside each namespace.

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
    models/
      mod.rs
      cache.rs
      workspace.rs
      cache_rollups.rs
      metrics.rs
      optimize.rs
      cli_connect.rs
  cache/
    mod.rs
    archive.rs
    adapter.rs
    cas_file.rs
    cas_oci.rs
    transport.rs
    multipart_upload.rs
    receipts.rs
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
      tags.rs
    adapters/
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
    proxy/
      serve.rs
    workspace/
      status.rs
      sessions.rs
      misses.rs
      token.rs
      workspaces.rs
      use_workspace.rs
      dashboard.rs
    config/
      doctor.rs
      config.rs
      setup_encryption.rs
  project_config/
    mod.rs
    model.rs
    discover.rs
    builtins.rs
    resolve.rs
  serve/
    mod.rs
    http/
      routes.rs
      oci_dispatch.rs
      oci_route.rs
      oci_tags.rs
      error.rs
    cache_registry/
      mod.rs
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
        write.rs
        lookup.rs
        flush.rs
    state/
      mod.rs
      metrics.rs
      blob_read_cache.rs
      blob_locator.rs
      upload_sessions.rs
      kv_pending.rs
      kv_published_index.rs
```

## Naming Rules

- Prefer domain nouns for folders: `cache`, `workspace`, `proxy`, `state`, `tool_routes`.
- Keep command entrypoints thin. Heavy workflow code belongs below the command namespace.
- Keep transport code separate from DTOs and from business decisions.
- Avoid generic names like `utils` and `handlers` when the code has a real domain name available.
- Use `support` only for truly shared command helpers that are not their own domain.

## Move Map

| Current path | Target path | Status |
| --- | --- | --- |
| `src/api/client.rs` | `src/api/client/mod.rs` | done |
| `src/api/models.rs` | `src/api/models/mod.rs` | done |
| `src/commands/save.rs` | `src/commands/save/mod.rs` | done |
| `src/commands/restore.rs` | `src/commands/restore/mod.rs` | done |
| `src/commands/mount.rs` | `src/commands/mount/mod.rs` | done |
| `src/commands/save/mod.rs` | `src/commands/save/{archive,cas,file,oci}.rs` | done |
| `src/commands/restore/mod.rs` | `src/commands/restore/{archive,file,oci}.rs` | done |
| `src/commands/mount/mod.rs` | `src/commands/mount/{archive,cas,file,oci}.rs` | done |
| `src/commands/*.rs` | `src/commands/{auth,cache,config,proxy,workspace,adapters}/...` | done |
| `src/commands/adapter/*.rs` | `src/commands/adapters/command/*.rs` | done |
| `src/main.rs` | `src/cli/{preprocess,dispatch}.rs` | done |
| `src/commands/cas_publish.rs` | `src/cache/cas_publish.rs` | done |
| `src/commands/cas_restore.rs` | `src/cache/cas_restore.rs` | done |
| `src/commands/file_materialize.rs` | `src/cache/file_materialize.rs` | done |
| `src/upload_receipts.rs` | `src/cache/receipts.rs` | done |
| `src/commands/proxy_exec.rs` | `src/proxy/exec.rs` | done |
| `src/commands/signature_policy.rs` | `src/signing/policy.rs` | done |
| `src/signing.rs` | `src/signing/mod.rs` | done |
| `src/commands/utils.rs` | `src/command_support/{workspace,specs,concurrency}.rs` | done |
| `src/commands/save_support.rs` | `src/command_support/save_support.rs` | done |
| `src/archive.rs` | `src/cache/archive.rs` | done |
| `src/cache_adapter.rs` | `src/cache/adapter.rs` | done |
| `src/cas_file.rs` | `src/cache/cas_file.rs` | done |
| `src/cas_oci.rs` | `src/cache/cas_oci.rs` | done |
| `src/cas_transport.rs` | `src/cache/transport.rs` | done |
| `src/multipart_upload.rs` | `src/cache/multipart_upload.rs` | done |
| `src/transfer.rs` | `src/cache/transfer.rs` | done |
| `src/project_config.rs` | `src/project_config/{mod,model,discover,builtins,resolve}.rs` | done |
| `src/serve/cache_registry/kv.rs` | `src/serve/cache_registry/kv/{mod,write,lookup,flush}.rs` | done |
| `src/serve/state.rs` | `src/serve/state/*.rs` | done |
| `src/api/client/mod.rs` | `src/api/client/{http,auth,cache,workspace,metrics}.rs` | done |
| `src/api/models/mod.rs` | `src/api/models/*.rs` | done |

## Recommended Refactor Order

1. Split `serve/cache_registry/kv` and `serve/state`.
2. Split `project_config` into `model`, `discover`, `builtins`, and `resolve`.
3. Review whether adapter-specific CLI surface should move from the flat `Commands` enum into generated/help-grouped sections while keeping command names stable.

## Notes For Current Worktree

- `Cargo.toml`, `Cargo.lock`, docs, and some tests have unrelated local edits in this worktree and are intentionally left alone.
