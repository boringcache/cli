# CLI Architecture Decision Records

These ADRs are living decision records. When ADR-tracked work lands, update the relevant ADR before handoff with implementation progress, evidence, and remaining gates.

## Cross-Repo Ownership

CLI ADRs own runner, proxy, adapter, local cache, and BuildKit-facing behavior.

Web/API control-plane decisions live in the web repo. The canonical counterpart for the current cache-root, alias-promotion, session-insight, blob-truth, and restore-policy direction is:

- `web/docs/adr/0001-cache-control-plane-roots-aliases-and-session-insight.md`
- `web/docs/adr/0008-unified-cache-telemetry-contract.md` for the cross-stack telemetry contract shared by archive, proxy, backend API, runner headroom, storage, lifecycle health, JSONL event persistence, two-sided eval loops, first-class MCP/LLM interpretation, TUI-first diagnostics, benchmark artifacts, and legacy metrics/web UI retirement.

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
| [0005](0005-borrowed-upload-sessions-and-blob-cache-policy.md) | accepted for hidden implementation; cache-policy rollout pending benchmark proof | Borrowed upload-session bodies and later blob-cache policy | Large-layer disk-copy/cache-policy evidence; required registry E2E is green through CLI main `5fd0203` without post-publish blob URL readiness polling |
| [0006](0006-cache-session-trace-and-oci-negative-cache.md) | accepted as first-party insight baseline; backend/action enrichment pending | Session trace, negative cache, and platform insight spine | Backend/action enrichment and artifact validation after CLI E2E run `24767673291`; web still needs rich session-summary persistence |
| [0007](0007-docker-immutable-run-refs-and-alias-promotion.md) | accepted; CI derivation, metadata transport, alias-root binding, and required dual-writer same-alias E2E implemented; default rollout pending released-path benchmark proof | Immutable Docker run refs and atomic alias promotion | Provider-neutral same-alias writer E2E is green locally and in CLI E2E run `24767673291`; next gates are signed CLI release if required, released action-path proof, and benchmark artifacts |
| [0008](0008-unified-repo-config-plan-lifecycle.md) | accepted launch-readiness decision | `.boringcache.toml` as durable repo cache plan, with CLI-owned planning and doctor/audit maintenance | Version dry-run schemas, add drift checks where needed, and keep action/web/copy aligned on the same setup path |
| [0009](0009-launch-maintenance-contract-and-performance-review.md) | accepted launch-readiness review | Current CLI launch audit for maintenance UX, cross-platform behavior, action/web boundaries, legacy surface review, and performance guardrails | Version JSON schemas, add drift/lint surface if needed, and reduce action per-entry planning |

## Launch ADR Review

Before launch, finish or explicitly defer these CLI ADR gates:

- ADR 0007: released action-path proof for provider run metadata and alias promotion, plus benchmark artifacts that show immutable run refs improve rolling Docker behavior.
- ADR 0006: backend/action enrichment proof with persisted `cache_session_summary` diagnostics and artifact validation.
- ADR 0005: keep hidden implementation guarded unless large-layer disk-copy/cache-policy evidence supports broader rollout.
- ADR 0004: keep stream-through hidden unless first-byte/body-wait comparison artifacts support a default threshold.
- ADR 0008: version dry-run schemas enough for action/docs stability, add drift checks if launch copy says rescan/lint, and keep Docker docs/actions aligned on CLI-planned BuildKit registry-cache refs.
- ADR 0009: keep the automatic maintenance path cheap, cross-platform warnings explicit, legacy aliases out of public copy, and action planning delegated to CLI dry-run plans.
- Web ADR 0008: move archive, proxy, and benchmark telemetry producers toward the shared session-summary schema, persist raw run JSONL in object storage, retire legacy `/metrics`, keep provider-specific storage names out of customer-facing output, split customer-owned general-purpose insights from BoringCache-owned advanced debug evaluations, expose first-class MCP tools/resources for LLM-safe interpretation, normalize miss/degradation/retirement reasons for self-reported regression review, and shift day-to-day cache diagnostics toward CLI/TUI/Actions summaries.

## Handoff Rule

Every ADR-related handoff should state:

- which ADRs changed;
- what implementation or documentation progress changed;
- what evidence exists now;
- what proof is intentionally deferred;
- which defaults remain unchanged.
