# CLI Architecture Decision Records

These ADRs are living decision records. When ADR-tracked work lands, update the relevant ADR before handoff with implementation progress, evidence, and remaining gates.

## Cross-Repo Ownership

CLI ADRs own runner, proxy, adapter, local cache, and BuildKit-facing behavior.

Web/API control-plane decisions live in the web repo. The canonical counterpart for the current cache-root, alias-promotion, session-insight, blob-truth, and restore-policy direction is:

- `web/docs/adr/0001-cache-control-plane-roots-aliases-and-session-insight.md`

When a CLI ADR needs Rails schema, endpoint, or state-machine behavior, describe the CLI requirement here and update the web ADR as the API source of truth.

## Status Rules

- `accepted` means the decision guides current work.
- `accepted for hidden implementation` means code may land behind internal controls, but user-visible defaults still need proof.
- `proof-gated` means benchmark or E2E artifacts are still required before broader rollout.
- `superseded` or `retained as guardrail` means the ADR remains useful only for the rule it names.

Docs-ready is not the same as rollout-ready. If testing or benchmark proof is deferred, the ADR must say which proof bundle is still required.

## Current Map

| ADR | Status | Active Role | Next Proof Gate |
| --- | --- | --- | --- |
| [0001](0001-engine-boundary.md) | accepted as snapshot-v2 guardrail | Prevent snapshot-v2 from becoming a product rewrite | Generic snapshot-v2 benchmarks before any default switch |
| [0002](0002-proxy-engine-plan-b.md) | accepted | Source-backed native adapter engine boundary | Adapter-specific source contract and E2E evidence |
| [0003](0003-runner-proxy-optimization-roadmap.md) | accepted roadmap; sub-ADR rollout remains proof-gated | Orders the runner proxy optimization and insight roadmap | Sub-ADR proof bundles before behavior claims |
| [0004](0004-oci-large-blob-stream-through.md) | accepted for hidden prototype; default rollout pending benchmark proof | Large OCI blob stream-through | First-byte/body-wait comparison artifacts before default threshold |
| [0005](0005-borrowed-upload-sessions-and-blob-cache-policy.md) | accepted for hidden implementation; cache-policy rollout pending benchmark proof | Borrowed upload-session bodies and later blob-cache policy | Large-layer disk-copy and cache-policy reuse evidence |
| [0006](0006-cache-session-trace-and-oci-negative-cache.md) | accepted as first-party insight baseline; backend/action enrichment pending | Session trace, negative cache, and platform insight spine | Local OCI `HEAD` miss -> upload/publish E2E plus metadata-only Docker artifact evidence |
| [0007](0007-docker-immutable-run-refs-and-alias-promotion.md) | accepted for hidden contract; default rollout pending concurrent-writer proof | Immutable Docker run refs and atomic alias promotion | Provider-neutral concurrent same-alias writer E2E with no `blob unknown` publish failure |

## Handoff Rule

Every ADR-related handoff should state:

- which ADRs changed;
- what implementation or documentation progress changed;
- what evidence exists now;
- what proof is intentionally deferred;
- which defaults remain unchanged.
