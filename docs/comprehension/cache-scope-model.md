# Cache Scope Model

This is the durable product contract for tag scope, fallback order, and owner
boundaries across archive caches, proxy-backed adapters, Docker/BuildKit, the
GitHub Action, and Rails.

## Scope Matrix

`TagResolver` is the source of truth for generated cache scope.

| Run context | Restore order | Save target |
| --- | --- | --- |
| Default branch | default tag | default tag |
| Trusted non-default branch | branch tag, then default tag | branch tag |
| Pull request, default settings | base branch tag, then default tag | no save |
| Pull request with PR saving explicitly enabled | PR tag, then base branch tag, then default tag | PR tag only |
| Outside git, no CI metadata, or `--no-git` | explicit tag only | explicit tag |

Notes:

- If the PR base branch is the default branch, the base/default restore order
  collapses to one candidate.
- PR restore does not read the PR head branch cache by default. Reading
  same-repo head-branch caches from PRs needs a separate explicit product knob.
- `save-on-pull-request: false` only affects pull request events. A manual
  branch dispatch is a trusted non-PR branch run, so it may save to the branch
  tag when save tokens and save policy allow it.
- Platform suffixing remains part of cache identity unless `--no-platform` is
  set. Fallbacks do not cross OS/architecture by accident.
- Generated branch, PR, and default suffixes are sanitized into valid cache tag
  components. Explicit user/workflow tags are not silently rewritten; callers
  that interpolate refs such as `github.ref_name` must slug them before passing
  them as `cache-tag`, `--tag`, or entry names.
- Name the cache family, not the branch, in explicit tags. For example,
  `deps` is the family; the CLI may derive `deps-branch-gt-expose-bc-tuning-knobs`
  or `deps-pr-42`. If a workflow deliberately includes a ref in the family
  name, slug it first (`gt/expose-bc-tuning-knobs` becomes
  `gt-expose-bc-tuning-knobs`) or Rails will reject the tag.
- PR archive reads are controlled by `BORINGCACHE_RESTORE_PR_CACHE=1`.
  `BORINGCACHE_SAVE_ON_PULL_REQUEST=1` is save intent only; the action exports
  the save env for its post-save phase and sets the restore env only for CLI
  restore subprocesses when `save-on-pull-request: true` is enabled.

## Archive Restore And Check

Archive `restore` and `check` both ask `TagResolver` for ordered restore
candidates and select the first ready hit for each requested cache. If no ready
hit exists, `check --json` reports the first pending/uploading candidate before
reporting a miss.

`boringcache restore` keeps the CLI compatibility behavior where a normal miss
exits successfully unless `--fail-on-cache-miss` is set. Action compatibility
must therefore derive `cache-hit` and `restore-keys` decisions from structured
`boringcache check --json` output or a future structured restore result, not
from restore process exit code.

`restore-keys` is an `actions/cache` compatibility feature owned by
`boringcache/one`. It may decide which additional exact tags to ask the CLI to
check, but it must not become a second branch/default/PR scope planner.

## Proxy And Adapter Restore

Proxy startup resolves one write root and an ordered list of restore roots from
the same `TagResolver` model. Bazel, sccache, Go, Turbo, Nx, Gradle, Maven, and
raw `cache-registry` therefore reuse branch/default/PR behavior without each
adapter carrying its own GitHub cache rules.

Rooted OCI aliases live under the proxy's primary human tag namespace. Valid
human tags use Rails `registry_path_tags` when available; unsupported explicit
tag names stay on the legacy root path. Hidden compatibility root-hash aliases
are migration reads/writes only, not a new shared fallback family.

## Docker And BuildKit

Docker and BuildKit registry-cache refs follow the same current/base/default
accessibility model, with OCI-shaped aliases instead of archive tag names:

- default branch imports/promotes the default alias;
- trusted non-default branches import branch then default and promote branch;
- PRs import base/default by default and do not read the PR head-branch alias;
- PRs with explicit save permission import PR then base/default and promote
  only the PR alias;
- local/no-CI runs keep the single legacy `buildcache` ref unless an explicit
  cache ref override is supplied.
- Default-branch Docker aliases now converge on `default`. Older caches that
  only exist under `branch-main` or `branch-master` may look cold until a
  default-branch run republishes the canonical alias, or until an explicit
  hidden import override is used for a one-off migration.

The action may probe planned OCI import refs after starting the proxy. It may
use the first readable planned ref immediately instead of waiting for every
earlier miss to time out. Missing PR refs on restore-only PRs are expected
misses, not evidence that the PR should gain branch/default write access.

## Ownership

- CLI owns generated tag scope, platform/git suffixing, repo-config planning,
  adapter defaults, proxy root planning, and Docker/BuildKit ref planning.
- `boringcache/one` owns GitHub Actions input validation, token selection,
  runtime setup, action outputs, `restore-keys` compatibility, and proxy/readiness
  orchestration. It passes provider metadata and explicit inputs into the CLI;
  it does not rederive cache scope.
- Rails owns workspace, token, storage, restore, publish, receipt, session,
  billing, and authorization truth. It resolves the ordered tags or aliases the
  client requests; it does not infer GitHub branch/PR policy for normal restore.

This keeps local runs, non-Git CI, GitHub Actions archive mode, proxy adapters,
and Docker/BuildKit on one least-surprise model.
