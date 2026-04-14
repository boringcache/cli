# CLI Structure Comprehension View

This file is the current map of `src/` and the target organization plan for future refactors.

## What Exists Today

```text
src/
  api/
    client/mod.rs
    models/mod.rs
  cache/
    mod.rs
    cas_publish.rs
    cas_restore.rs
    file_materialize.rs
    receipts.rs
  command_support/
    mod.rs
    workspace.rs
    specs.rs
    concurrency.rs
    save_support.rs
  commands/
    save/mod.rs
    restore/mod.rs
    mount/mod.rs
    serve.rs
    run.rs
    adapter.rs
    token.rs
    status.rs
    doctor.rs
    dashboard.rs
    onboard.rs
    ...
  proxy/
    mod.rs
    exec.rs
    tags.rs
  serve/
    mod.rs
    handlers.rs
    state.rs
    cache_registry/
      mod.rs
      kv.rs
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
  optimize/
  platform/
  progress/
  signing/
    mod.rs
    policy.rs
```

## Current Hotspots

These are the main files that carry multiple concerns and should be split by namespace first:

| Path | Concern mix |
| --- | --- |
| `src/serve/cache_registry/kv.rs` | lookup, miss cache, handoff, blob IO, flush, prefetch, alias binding |
| `src/api/client/mod.rs` | HTTP transport, retries, auth/session flows, cache APIs, workspace APIs, metrics |
| `src/commands/save/mod.rs` | entrypoint plus archive, OCI, and file save flows |
| `src/commands/restore/mod.rs` | entrypoint plus archive, OCI, and file restore flows |
| `src/commands/mount/mod.rs` | initial restore, watch loop, and layout-specific sync logic |
| `src/serve/state.rs` | app state, blob cache, upload sessions, pending stores, publish index |
| `src/project_config.rs` | schema, discovery, built-ins, resolution |
| `src/cli.rs` + `src/main.rs` | command declaration, argv preprocessing, and dispatch |

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
    proxy/
      serve/
      run.rs
      adapter.rs
      proxy_exec.rs
      go_cacheprog.rs
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
        lookup.rs
        handoff.rs
        blob_io.rs
        flush.rs
        prefetch.rs
        alias_tags.rs
    state/
      mod.rs
      blob_cache.rs
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
| `src/project_config.rs` | `src/project_config/{model,discover,builtins,resolve}.rs` | planned |
| `src/serve/cache_registry/kv.rs` | `src/serve/cache_registry/kv/*.rs` | planned |
| `src/serve/state.rs` | `src/serve/state/*.rs` | planned |
| `src/api/client/mod.rs` | `src/api/client/{http,auth,cache,workspace,metrics}.rs` | planned |
| `src/api/models/mod.rs` | `src/api/models/*.rs` | done |

## Recommended Refactor Order

1. Split `save`, `restore`, and `mount` by layout flow.
2. Split `api/client` by domain method groups.
3. Split `serve/cache_registry/kv` and `serve/state`.
4. Re-group `commands/` into `cache`, `proxy`, `workspace`, `auth`, and `config` after the current in-flight command edits settle.

## Notes For Current Worktree

- `src/cli.rs`, `src/main.rs`, `src/commands/mod.rs`, `src/commands/run.rs`, `src/commands/serve.rs`, and `src/project_config.rs` already have local changes in this worktree.
- The first pass intentionally avoids reorganizing those files so structure work does not trample in-flight edits.
