# Gradle / Maven HTTP Cache Mistake Ledger

This ledger captures source-backed guardrails for the Gradle and Maven adapter pass. The source column is the authority; current BoringCache behavior only shows where to preserve or improve compatibility.

| Failure class | False assumption | Source-backed invariant | Owning layer | Guardrail test | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Gradle oversized writes treated as fatal proxy errors | Every rejected KV write should be a generic `503` backlog failure | Gradle HTTP build cache treats `413 Payload Too Large` on `PUT` as an accepted oversized-entry signal, not a build-breaking cache error | `serve::engines::gradle` plus KV PUT options | `test_gradle_put_returns_413_when_spool_budget_exceeded` proves Gradle maps spool-budget rejection to `413` | Real Gradle E2E still needs to cover an actually oversized cache entry once the harness can force a task output above the limit |
| Gradle miss status drift | Any failed read can be collapsed into a generic proxy failure | Gradle cache load is `GET <cache-url>/<cache-key>`; a hit is a `2xx` body and a miss is `404 Not Found` | `serve::engines::gradle` over shared KV lookup | `test_gradle_put_get_round_trip` covers hits and `test_gradle_get_miss_returns_not_found` covers explicit 404 misses | Redirect and retry behavior remain Gradle-client owned unless real tool traffic shows BoringCache must special-case it |
| Maven `HEAD` omitted as optional noise | Maven remote cache only needs `GET` and `PUT` | The Apache Maven Build Cache Extension remote HTTP store requires support for `GET`, `HEAD`, and `PUT` | `serve::engines::maven` over shared KV lookup/write | `test_maven_put_get_round_trip` covers `PUT`, `HEAD`, and `GET` | Future Maven engine work should keep HEAD metrics distinct from GET bytes served |
| Maven payload normalized by the proxy | Maven cache artifacts can be interpreted or rewritten by BoringCache | Maven cache portability depends on raw build/source/effective-POM inputs; remote storage should preserve artifact bytes exactly | `serve::engines::maven` plus KV substrate | Maven round trip preserves payload bytes | Diagnostics should explain portability misses without parsing or mutating Maven cache artifacts |
| Gradle and Maven collapsed into one product policy | HTTP object caches all share the same write/error semantics | Gradle has a specific nonfatal `413` write status; Maven's official remote-cache docs only require the HTTP methods and storage behavior | Adapter engine option surface | Gradle oversized write test expects `413`; `test_maven_put_keeps_generic_spool_rejection_status` keeps Maven on generic `503` backlog rejection | A future Maven source-code audit may justify Maven-specific status handling, but it should be tracked here before code changes |

## Research Sources

- Gradle build cache docs: remote HTTP cache uses `GET <url>/<cache-key>`, `PUT <url>/<cache-key>`, `404 Not Found` for misses, any `2xx` for write success, and `413 Payload Too Large` as a non-error oversized-entry signal.
- Apache Maven Build Cache Extension remote-cache docs: the simplest shared remote cache is an HTTP server that supports `PUT`, `GET`, and `HEAD`.
- Apache Maven Build Cache Extension portability guidance: remote cache reuse depends on making local and remote builds comparable across source, model, and environment differences.

Add a row before or with each Gradle/Maven engine change. The row should name the official source, the corrected invariant, the test that prevents regression, and whether the remaining risk is CLI, proxy, or user workflow.
