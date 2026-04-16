# Proxy Readiness Contract

This is the canonical machine and automation contract for the local cache proxy.

Product shape:

- `cache-registry` is the proxy
- `run --proxy` temporarily starts that proxy for one command
- adapter commands do the same for supported remote-cache tools

- Canonical probe: `/_boringcache/status`
- Route wiring: `src/serve/http/routes.rs`
- CLI-managed readiness: `src/serve/runtime/mod.rs` and `src/commands/proxy/cache_registry.rs`
- State computation: `src/serve/http/handlers/mod.rs`

`/v2/` is protocol surface only. Do not use `/v2/`, fixed sleeps, or log scraping to decide when the proxy is ready or when publish has settled.

## HTTP contract

- Method: `GET`
- Path: `/_boringcache/status`
- Success status: `200 OK` while the proxy is alive and serving
- Cache policy: `Cache-Control: no-store`

Headers:

- `X-BoringCache-Proxy-Phase`: `warming`, `ready`, `error`, or `draining`
- `X-BoringCache-Publish-State`: `pending` or `settled`

JSON body fields:

- `phase`
- `publish_state`
- `publish_settled`
- `prefetch_complete`
- `shutdown_requested`
- `cache_entry_id`
- `tags_visible`
- `pending_entries`
- `pending_blobs`
- `pending_spool_bytes`
- `flush_in_progress`
- `pending_publish_handoff`

## Phase meanings

- `warming`: the proxy is up, but startup warming has not completed yet
- `ready`: startup warming has completed and shutdown has not started
- `error`: startup warming failed in strict mode; operations should fail fast
- `draining`: shutdown has started and the proxy may still be flushing or waiting for tag visibility

`phase=ready` is the HTTP readiness gate for external lifecycle inspection.

## Publish settlement

`publish_settled=true` means a fresh reader should be able to observe published tags now.

The current implementation computes that from all of these being true:

- `pending_entries == 0`
- `flush_in_progress == false`
- `pending_publish_handoff == false`
- `tags_visible == true`

`publish_state=settled` is the header form of the same condition.

## Caller guidance

- `cache-registry` is the standalone proxy surface that exposes this endpoint directly
- users do not need a separate readiness command; warm startup is built into the default proxy behavior
- `boringcache <tool>` and `boringcache run --proxy` wait internally before they start the wrapped tool
- detached BoringCache orchestrators that spawn `cache-registry` should consume the CLI-owned readiness handoff instead of reimplementing local HTTP polling or log scraping
- `/_boringcache/status` remains the machine-readable HTTP surface for diagnostics, explicit lifecycle assertions, and publish-settlement checks
- docs and examples should point here for HTTP readiness and drain checks when an external observer actually needs that state
- `/v2/` may still answer requests before startup warming finishes; that does not make it the readiness contract
