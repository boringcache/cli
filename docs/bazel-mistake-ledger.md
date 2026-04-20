# Bazel / AC-CAS Mistake Ledger

This ledger captures source-backed guardrails for the Bazel adapter pass. The source column is the authority; current BoringCache behavior only shows where to preserve or improve compatibility.

| Failure class | False assumption | Source-backed invariant | Owning layer | Guardrail test | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Action cache and CAS collapse into one object space | Bazel remote cache objects are just generic blobs | Bazel stores action result metadata under `/ac/` and output files under `/cas/`; the action cache and content-addressable store are distinct object spaces | Bazel route and KV namespace handling | Route tests distinguish `/ac/<digest>` and `/cas/<digest>`; cache-op tool mapping treats both as Bazel while preserving the namespace | A richer engine should keep action-result diagnostics separate from CAS blob diagnostics |
| CAS key accepted without byte proof | A `/cas/<digest>` path can store any payload | Bazel CAS output files are addressed by the SHA-256 hash in the path, so a CAS PUT body must match that digest | Bazel write path | `test_bazel_put_rejects_digest_key_mismatch` rejects mismatched CAS payloads | Action cache payloads remain opaque action-result metadata and are not digest-validated as CAS blobs |
| Bazel warm proof based only on logs | Stdout/stderr text is enough to prove remote-cache behavior | Bazel docs warn that stdout/stderr inspection is not a reliable cache-hit signal; BoringCache E2E should also assert cache-op records | E2E harness and observability | Required Bazel E2E asserts `request_metrics_cache_ops_bazel_get_records_total` and `request_metrics_cache_ops_bazel_get_hits`; local adapter E2E already asserts Bazel GET hits | Bazel log text still varies by version, so logs remain secondary evidence |
| Every runner writes remote cache entries | Developers and CI should behave the same against a shared remote cache | Bazel docs call out read-only remote-cache use and recommend care over who can write, often limiting writes to CI | Adapter command planning and docs | Bazel adapter preserves explicit user flags and supports read-only upload behavior through Bazel flags | Product policy for default writer/reader roles remains outside the HTTP adapter route |

## Research Sources

- Bazel remote caching docs: remote cache stores action cache metadata and CAS output files.
- Bazel HTTP caching protocol: `/ac/` stores action result metadata, `/cas/` stores output files, `PUT` uploads blobs, and `GET` downloads blobs.
- Bazel remote-cache usage docs: `--remote_upload_local_results=false` enables read-only remote-cache use and CI is the usual remote-cache writer.

Add a row before or with each Bazel/AC-CAS engine change. The row should name the official source, the corrected invariant, the test that prevents regression, and whether the remaining risk is CLI, proxy, or user workflow.
