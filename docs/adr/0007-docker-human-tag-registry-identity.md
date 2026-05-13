# ADR 0007: Docker Human Tag Registry Identity

Status: accepted for new CLI paths; old generated ref controls are migration errors

## Decision

Docker and direct BuildKit registry-cache identity is the resolved human cache tag.
The same value is used as:

- the CLI cache candidate;
- the BuildKit import/export reference;
- the local proxy primary tag;
- the Rails cache-entry tag;
- the human-visible cache head in workspace reporting.

Branch, default, pull-request, and manually supplied cache candidates still come
from `TagResolver`. A command can have one or many restore candidates, but those
candidates are human cache tags, not Docker-specific run refs or generated
transport aliases.

## Non-Goals

New CLI code must not create first-class cache tags from:

- `bc_registry_*` compatibility names;
- `oci_ref_*` protocol aliases;
- `oci_digest_*` digest aliases;
- Docker run-ref/from-ref/promote-ref override flags.

Those names can remain only where they describe protocol compatibility or an old
client migration error. They should not appear in user-facing tag lists,
workspace dashboards, public docs, or normal dry-run plans.

## Rationale

The earlier immutable-ref plan solved a real same-alias race, but it made cache
identity too hard to reason about: users supplied a tag, Docker saw another ref,
the proxy wrote generated aliases, and Rails displayed a mixture of human and
transport names. The product contract is simpler and easier to debug when the
human tag is the cache head everywhere.

Rails already owns pointer updates and stale-writer handling for a tag. The CLI
should feed Rails ordered human candidates and let the backend keep any required
protocol lookup state internal.

## Implementation Notes

- `docker` and `buildkit` plan import/export refs from resolved human tags.
- Old Docker ref override flags are rejected with migration errors.
- `cache-registry --oci-alias-promotion-ref` remains an internal compatibility
  proof hook only; it is not part of the new CLI cache-tag model.
- OCI protocol aliases may still exist inside the proxy/backend to answer
  registry protocol lookups, but they are not ready cache tags.
- Registry-reserved `bc_registry_*` names are rejected as cache tags.

## Required Evidence

- Dry-run tests prove Docker/BuildKit import and export specs use resolved
  human tags.
- API and reporting tests hide internal aliases from tag feeds and dashboards.
- Local Rails-backed Docker/BuildKit E2E verifies cold and warm registry-cache
  behavior with the same human tag as the proxy cache head and BuildKit ref.
- OCI manifest/referrers E2E waits only on the protocol referrers tag needed
  for the next referrers read, not on a generated cache-head transport alias.
- Adapter E2E keeps non-Docker tools on their normal human cache tags.

## Current Proof

- `resolve_docker_plan_uses_resolved_human_tags`
- `resolve_docker_plan_rejects_old_ref_overrides`
- `test_docker_dry_run_json_rejects_old_ref_alias_flags`
- `test_docker_dry_run_json_rejects_old_ref_alias_config`
- `test_docker_dry_run_json_uses_github_actions_human_tag`
- `test_two_human_refs_promote_same_alias_without_losing_entries`

## Follow-Up

Keep pruning old generated-name compatibility once released CLIs no longer need
read fallback behavior. Compatibility code should be named as transport
compatibility, not as cache-tag identity.
