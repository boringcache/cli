# Terminal UX Roadmap

## Goal

Make the terminal the default day-to-day surface for BoringCache users without turning the product into a giant full-screen shell.

BoringCache is a cache tool first. The terminal surface should help users:

- point at the right workspace
- see whether cache is healthy
- inspect what exists
- understand misses
- clean up bad or stale cache state

It does not need to replace billing, team management, or every web page.

## Product stance

The terminal UX should optimize for:

- a very small set of memorable commands
- good defaults for workspace-scoped tokens
- useful output for humans by default
- `--json` for scripting and automation
- drill-down only when users ask for it

The terminal UX should avoid:

- a full-screen TUI as the first move
- exposing every internal API object as a top-level command
- making users remember long command trees for basic health checks

## Daily user jobs

From a daily user or operator point of view, the common questions are:

1. Am I pointed at the right workspace?
2. Is cache healthy right now?
3. What cache exists for this workspace or tag?
4. Why did a recent run miss?
5. Can I delete or move bad cache state?
6. Is my token, API URL, or workspace setup wrong?

Those jobs map better to a few obvious commands than to a deep command hierarchy.

## Command model

### Core commands

These should become the commands most users remember:

- `boringcache use`
- `boringcache status`
- `boringcache inspect <tag|id>`
- `boringcache doctor`
- `boringcache rm <tag>`

### Drill-down commands

These are useful once the basics exist, but they should support `status` rather than replace it:

- `boringcache workspaces`
- `boringcache ls`
- `boringcache sessions`
- `boringcache misses`
- `boringcache tags`

### Build workflow commands

These stay important, but they solve a different job than operator insight:

- `boringcache run`
- `boringcache save`
- `boringcache restore`
- `boringcache cache-registry`
- `boringcache mount`

## Current state

### Shipped

- `boringcache use`
  - lets users save a default workspace
  - works safely even when auth comes from `BORINGCACHE_API_TOKEN`
- `boringcache status`
  - shows workspace summary, inventory, cache health, savings, recent sessions, and hot misses
- `boringcache inspect <tag|id>`
  - resolves a tag or cache entry id to a detailed terminal view
  - supports `--json` for CI and scripts
- `boringcache doctor`
  - checks API URL, token source, access level, workspace resolution, and command readiness
  - supports `--json` for CI and scripts
- `boringcache rm`
  - short primary alias for cache deletion, with `delete` kept as an alias
- `boringcache workspaces`
  - now shows the saved default workspace more clearly
- local config persistence
  - saves `default_workspace` without copying an environment token into config
- workspace status API
  - `GET /api/v2/workspaces/:namespace_slug/:workspace_slug/status`
- cache inspect API
  - `GET /api/v2/workspaces/:namespace_slug/:workspace_slug/caches/inspect/:identifier`
- session info contract
  - includes token `access_level` and `write_tag_prefixes` for terminal diagnosis

### Still missing

- live watch mode for operators
- first-class session and miss drill-down in the terminal

## Phase plan

### Phase 1

Status: shipped

- `use`
- `status`
- safer default workspace persistence
- workspace status API

This gives users one landing command and one workspace-selection command, which is enough to make the terminal usable for daily checks.

### Phase 2

Status: shipped

- `boringcache inspect <tag|id>`
  - show tag, digest, storage mode, size, timestamps, hit count, versions, and related tags
- `boringcache doctor`
  - check API reachability, token validity, token scope, resolved workspace, and capabilities
- `boringcache rm`
  - short alias for cache deletion

This phase covers the most common follow-up after `status`: "show me the thing" and "tell me why this is broken".

### Phase 3

Operator drill-down:

- `boringcache status --watch`
- `boringcache sessions`
- `boringcache misses`

This phase is for active debugging, rollouts, and incident response.

### Phase 4

Optional and only if command output stops being enough:

- lightweight full-screen shell over existing commands/endpoints
- tabs or panes for `status`, `inspect`, `sessions`, and `misses`

This should only happen after the command model is solid.

## API work needed

The terminal path should stay backed by explicit JSON endpoints, not HTML-only views.

### Already available

- workspace status
- workspace list
- cache list
- session info

### Needed next

- cache/tag inspect endpoint
  - resolve by tag or cache entry id
  - include tags, digest, storage mode, counts, size, timestamps, hit count, and version context
- operator drill-down endpoints
  - sessions list
  - misses list
  - optionally watch-friendly summaries
- tag operations under v2
  - pointer details
  - move/retag flows when appropriate

## UX rules

These rules should hold across commands:

- If a token is workspace-scoped, use that workspace automatically.
- If only one workspace is accessible, avoid forcing a separate workspace argument.
- Errors should suggest the next command:
  - `boringcache use`
  - `boringcache doctor`
  - `boringcache status <workspace>`
- Human output should answer the obvious question first, then add detail.
- Important commands should support `--json`.
- The CLI should not force users to remember both a workspace and a tag for every read-only action when it can infer one safely.

## What success looks like

For most users, daily terminal use should feel like this:

```bash
boringcache use
boringcache status
boringcache inspect deps
boringcache doctor
```

If that flow answers most day-to-day cache questions, the terminal UX is doing its job.
