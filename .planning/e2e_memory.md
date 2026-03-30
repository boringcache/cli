## E2E Memory

- `CLI / Core`
  - Exercises direct archive `save`, `check`, `restore`, `delete`, plus basic config/session commands.
  - The single-file payload is intentionally stable across runs, so ordinary tag checks must stay tag-scoped instead of reusing same-digest entries from other tags.

- `CLI / Pending and Conflict Contracts`
  - Local cargo-based regression leg for pending restore handling, pending publish polling, lease/preflight wording, and publish-time CAS conflict wording.
  - This leg is the stable source of truth for `"another cache upload is in progress"` versus `412 Tag publish conflict`.

- `Proxy / HTTP Adapters`
  - Verifies the cache-registry proxy shape for HTTP adapters without depending on the heavier contention path.

- `Proxy / Dual Proxy`
  - Prewarms one proxy, verifies the published remote tag, then runs two proxy-backed sccache writers against the same logical tag and checks the post-flush remote tag again.
  - Local sccache server ports must never overlap proxy or verify ports; the script now reserves and auto-adjusts those ports before startup.

- `Registry / Docker BuildKit`
  - Covers OCI registry proxy behavior from Docker BuildKit.

- `Registry / Prefetch Readiness`
  - Seeds a large tag and verifies startup prefetch/read-cache readiness after restart.

- `Archive / Integrity`
  - Verifies archive save/restore byte integrity on the direct path.

- `Security / Tokens and Poisoning`
  - Covers token-role boundaries and cache poisoning defenses.

- `Tool / Hugo`, `Tool / Turbo`, `Tool / sccache`, `Tool / Bazel`, `Tool / Maven`, `Tool / Gradle`
  - Tool-specific end-to-end coverage through the intended CLI or proxy integration surface.

- `Benchmark / Cache Registry / Local|Proxy / Efficacy|Stress`
  - Performance and hit-rate tracking, not basic correctness smoke tests.

- `Cache Registry / Cross-Runner Seed` and `Cross-Runner Verify`
  - Publishes on one runner and validates remote reuse on another, so cross-runner visibility and reuse stay tracked in GitHub.
