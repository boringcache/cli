# Turbo / Nx Remote Cache Mistake Ledger

This ledger captures source-backed guardrails for the Turbo and Nx adapter pass. The source column is the authority; current BoringCache behavior only shows where to preserve or improve compatibility.

| Failure class | False assumption | Source-backed invariant | Owning layer | Guardrail test | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Nx artifact overwrite accepted silently | A repeated `PUT` for the same task hash can replace the cached archive because generic KV accepts overwrites | The Nx custom remote cache OpenAPI defines `409` as the response when an upload cannot override an existing record | `serve::engines::nx` plus KV PUT options | `test_nx_artifact_put_returns_conflict_for_existing_record` proves duplicate artifact uploads return `409` and preserve the first payload | Cross-process races still depend on backend publish visibility; this slice protects the local proxy's pending/flushing/published state |
| Nx terminal output misses untested | Terminal output objects are secondary and can inherit artifact behavior without explicit proof | Nx task replay depends on terminal output as part of cached task behavior; BoringCache's supported route must preserve miss status and empty `HEAD` bodies | Nx terminal-output route over shared KV lookup | `test_nx_terminal_output_get_and_head_misses_return_not_found` proves `GET` and `HEAD` misses return `404` | Current Nx OpenAPI only documents artifact upload/download; keep terminal-output route support tied to observed tool traffic before widening the engine boundary |

## Research Sources

- Nx self-hosted cache OpenAPI: custom cache servers use `PUT` and `GET` under `/v1/cache/{hash}`; successful uploads are `200`, misses are `404`, auth failures are `401`/`403`, and duplicate records are `409`.
- Turborepo Remote Cache API: artifact, status, query, and events routes remain the Turbo source of truth before any Turbo-specific engine work.

Add a row before or with each Turbo/Nx engine change. The row should name the official source, the corrected invariant, the test that prevents regression, and whether the remaining risk is CLI, proxy, or user workflow.
