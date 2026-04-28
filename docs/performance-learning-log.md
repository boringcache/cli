# Performance Learning Log

This log captures regressions, root causes, and guardrails for cache-registry performance/correctness.

## 2026-04-22 - Docker benchmark diagnostics after proxy flush

- Post-fix benchmark artifacts now prove the diagnostics ordering fix beyond
  the first PostHog rerun: BoringCache seed diagnostics contain structured
  `cache_session_summary` for PostHog fresh `24795871449`, PostHog rolling
  `24795877370`, Hugo fresh `24796205506`, Hugo rolling `24796211023`,
  Immich rolling `24796581326`, and Mastodon rolling `24796581317`.
- Run refs: PostHog used benchmark repo commit
  `9df5d523ac58db3b221f222e043aeaf23f965bf9` and upstream
  `a92bc03bf9a9f74d1aaf2653e3e8abc46a20c686`; Hugo used
  `010b43e0b480080f2c075e1635d27bd2b432a446` and upstream
  `79f030be5bdb31e014c2996da7464898df750801`; Immich rolling used
  `06e79e4ac213e1cd08b0b52ff8188e465b3ae9a8` and upstream
  `f0835d06f8d63887cc58142f079e49b586116923`; Mastodon rolling used
  `d1796634991a77189fa29f462c6102e81e30dd42` and upstream
  `c4eec632b92c800ae38dba111c4c76e63bb1c0de`.
- All checked BoringCache seed jobs used `boringcache/one@v1` at
  `c7bf06c1b6753a50890a78204e38acbaeec3c2b8`, CLI `v1.12.46`, Docker
  registry cache `mode=max`, and OCI hydration `metadata-only`.
- Fresh lanes: PostHog completed cold+warm with `cold_seconds=845`,
  `warm1_seconds=10`, `export_seconds=430.9`, and summary
  `duration_ms=838102`, `oci_engine_graph_descriptors=85`,
  `oci_engine_proof_bytes=6302509102`, `oci_engine_publish_total_duration_ms=10607`.
  Hugo completed cold+warm with `cold_seconds=173`, `warm1_seconds=9`,
  `export_seconds=24.4`, and summary `duration_ms=167601`,
  `oci_engine_graph_descriptors=20`, `oci_engine_proof_bytes=356114210`,
  `oci_engine_publish_total_duration_ms=3610`.
- Rolling lanes are reseed samples, not steady-state samples: PostHog had
  `new_blob_count=31`, `body_remote_fetches=52`, `body_remote_bytes=2181928865`,
  and `export_seconds=323.1`; Hugo had `new_blob_count=14` and
  `export_seconds=26.9`; Immich had `new_blob_count=55` and
  `export_seconds=156.4`; Mastodon had `new_blob_count=38` and
  `export_seconds=66.8`.
- Later same-ref rolling reruns on the same pre-product-ref artifact shape did
  produce steady-state samples: PostHog `24796916333` finished in `19s` with
  `export_seconds=4.2`, one `27499` byte remote body fetch, and summary
  `duration_ms=11300`; Hugo `24796581263` finished in `10s` with
  `export_seconds=2.4` and one `6599` byte remote body fetch; Immich
  `24797097761` finished in `12s` with `export_seconds=2.0` and one `13693`
  byte remote body fetch; Mastodon `24797097792` finished in `16s` with
  `export_seconds=3.2` and one `18137` byte remote body fetch. All four
  classified as `steady_state_candidate=true` with no new OCI blob uploads.
- Actions Cache comparison artifacts completed for PostHog fresh/rolling and
  Hugo fresh/rolling, but the evidence above should not be turned into a broad
  claim: Immich and Mastodon still need post-fix fresh+warm artifacts, the
  latest duplicate PostHog AC rolling dispatch `24796916343` was still running
  when checked, and all checked artifacts are still on the old CLI/action path.
- Evidence gap: downloaded artifacts still do not include `APP_REVISION`,
  `web_revision`, or a `product_refs` object. Web `/v2/health` has a nullable
  `revision` field ready for future runs, but these benchmark bundles did not
  capture it, so launch claims remain blocked on released-path artifacts with
  CLI/action/web refs in the artifact payload.
- Follow-up fix: the shared benchmark artifact writer was pushed after this
  check to PostHog `bc0d7e0`, Hugo `c1636af`, Immich `20f5203`, and Mastodon
  `1db2f3a` so future artifacts can emit `product_refs`. No benchmark artifact
  from those commits has been accepted as evidence yet.

## 2026-04-22 - Stream-through local activation proof

- Local Colima/BuildKit E2E was run with `OCI_HYDRATION=metadata-only`, per-proxy blob-cache isolation, and random payloads so restart warm had to read selected blob bodies through the proxy instead of reusing an old local cache.
- A single large-payload A/B proved the hidden threshold path activates without changing default behavior. With `BORINGCACHE_OCI_STREAM_THROUGH_MIN_BYTES` unset, restart warm fetched about `16.78 MB` remotely and recorded `stream_through_count=0`. With the threshold set to `16777216`, the same shape recorded `stream_through_count=1`, `stream_through_bytes=16782486`, and `stream_through_verify_failures=0`; restart warm wall time stayed about `3s` in this small local harness.
- A more diverse graph used random payload layers of `2,8,20,28 MiB` plus six small file layers. The default-off run fetched `60840983` bytes remotely on restart warm with `stream_through_count=0`; phase seconds were `18,10,10,7,5,6,4,8` across the eight harness builds.
- The same diverse graph with the 16 MiB threshold fetched `60841012` bytes remotely and streamed the two larger layers only: `stream_through_count=2`, `stream_through_bytes=50347369`, `stream_through_verify_failures=0`, `upload_session_materialization_bytes=0`, and borrowed upload-session bytes stayed around `121.68 MB`. Phase seconds were `14,6,6,9,7,37,5,3`; the `37s` implicit-warm phase included a transient BuildKit `HEAD` timeout and retry, so do not read it as a stream-through regression without a rerun.
- This proves threshold selection, digest verification, and cache-promotion behavior on real Docker traffic. It does not prove a default threshold yet because the artifact still lacks blob-level client first-byte wait, storage TTFB, storage body duration, and a repeated real-project matrix at `16/32/64/128 MiB`.
- Cleanup after the run pruned Docker images/volumes, stopped and deleted Colima, removed the leftover Colima data disk, and left `~/.colima` at `24K` with Docker daemon unreachable.

## 2026-04-21 - PostHog blob-unknown release check

- The `blob unknown` incident is not fixed in any released path yet. `boringcache/one@v1` resolves through action `v1.12.59`, which still pins CLI `v1.12.41`; the OCI negative-cache invalidation and ADR 0004/0005 fixes are local CLI commits only.
- Local main now carries a focused OCI regression test for the suspected failure shape: a blob `HEAD` miss creates a negative-cache entry, the same digest is uploaded locally, manifest publish succeeds, the upload session is cleaned up, and a later `HEAD` is not blocked by the stale miss.
- Local main also carries focused proxy coverage for the ADR 0007 alias shape: two immutable run refs promote the same branch alias, both run refs remain readable, and alias diagnostics distinguish the accepted promotion from the stale ignored promotion.
- Commit `83e547e` cleared the required registry E2E workflow, including Docker BuildKit, Prefetch Smoke, and Cross-Runner Verify, without verifier-side blob URL convergence polling. Commit `801dcc1` made CLI CI/E2E/release workflows use `boringcache/one@v1` with `verify: none` while the action release still pins the older CLI path.
- The required E2E matrix now includes a provider-neutral OCI same-alias writer leg. It uses the standalone proxy's hidden alias-promotion hook with two live writer proxies, publishes a newer immutable ref before an older ref, requires promoted and `ignored_stale` alias results with zero promotion failures, and verifies both immutable refs plus the winning alias through a fresh proxy.
- Local Rails-backed direct OCI same-alias writer E2E passed on 2026-04-22 after keeping proxy metadata hints within the replayable 8-key cap. The updated dual-writer version passed via `LOCAL_ADAPTER_TOOLS=oci-same-alias` with logs under `/tmp/boringcache-local-adapter-e2e/oci-same-alias-final-20260422`. Docker/OCI full-build local E2E was later rerun through Colima for the ADR 0004 stream-through activation checks above.
- The request-metrics summary now promotes OCI upload-plan reuse fields directly, including `request_metrics_oci_new_blob_count` and `request_metrics_oci_latest_new_blob_count`. Use those fields in rolling cohorts instead of inferring steady state from total wall time.
- PostHog remains excluded from compatibility proof until the local fixes are released through the action/CLI path and at least one same-ref cohort records zero new blobs, low remote fetches, short export, and no registry 4xx/5xx or digest failures.

## 2026-04-20 - OCI metadata-only release and PostHog benchmark interpretation

- Release:
  - `boringcache/one v1.12.58` was released from action commit `e22cc5a6a0039389329b4c974722196a738553ca` by workflow run `24672935639`.
  - The signed `v1` major tag now dereferences to the same commit as `v1.12.58`.
  - The released action still installs CLI `v1.12.40`; no new CLI release was needed for this action change because CLI `v1.12.40` already supports the hidden `--oci-hydration metadata-only` policy.
  - The action and Docker benchmark workflows now use the product default instead of forcing `bodies-before-ready`. The Docker-mode configure step passes `oci-hydration: metadata-only`, and logs show `Registry proxy OCI hydration: metadata-only`.
- Product decision:
  - `metadata-only` is the BuildKit product default. Startup indexes the selected OCI refs and locator/download URL metadata, reports ready quickly, and lets BuildKit fetch blob bodies on demand through the proxy.
  - `bodies-background` and `bodies-before-ready` remain diagnostic policies. `bodies-background` can still compete with a large BuildKit graph, and `bodies-before-ready` can front-load multi-GB downloads before the build starts.
  - For user-facing workflows, do not expose three ordinary modes. Keep the product path simple and use diagnostics when investigating body-plane behavior.
- Same-ref PostHog rolling signal before the next upstream sync:
  - Run `24673108689` used `boringcache/one@v1` at `e22cc5a` and CLI `v1.12.40`.
  - Proxy readiness dropped to `0.8s` with `metadata-only`; the prior strict body hydration run had waited about `119s` to prefetch about `5.8GB`.
  - Seed build wall time was `9s`; total run was `2m10s`.
  - BuildKit imported the registry cache manifest, `cached_steps=67`, and cache export was `3.7s`.
  - OCI body diagnostics: `startup_body_inserted=0`, `startup_body_failures=0`, `startup_body_cold_blobs=84`, `body_remote_fetches=1`, `body_remote_bytes=27412`, `body_remote_duration_ms=194`.
  - Publish diagnostics: `upload_requested_blobs=84`, `upload_already_present=84`, `new_blob_count=0`, `upload_batch_seconds=0.269`, no registry 4xx/5xx or digest failures. This is the clean warm/product-path signal.
- New-upstream PostHog rolling cohort after sync to `0272b80f663cf9de0ef03ad60325540402ac9ad7`:
  - BC rolling run `24673312060` finished in `12m54s`; AC rolling run `24673311004` finished in `20m49s`.
  - The BC artifact correctly classified the run as a reseed, not steady state: `new_blob_count=32`, `upload_requested_blobs=84`, `upload_already_present=52`, `body_remote_fetches=51`, `body_remote_bytes=2164140408`, `body_remote_duration_ms=30027`, and BuildKit cache export `339.1s`.
  - Backend publish was not the long pole: `oci_blob_upload_batch` was `9.501s`, manifest commit was about `81ms`, and later publish phases were short. Most of the wall time was BuildKit rebuilding/exporting the changed graph.
  - Use this run as a changed-upstream reseed sample, not as a warm headline.
- Same-upstream rerun after the reseed:
  - BC rolling run `24674563294` finished in `1m55s`; seed build wall time was `10s`.
  - It still imported the cache with `cached_steps=67`, proxy readiness stayed fast, cache export was `4.0s`, and body read-through was only one `27401` byte fetch.
  - The artifact still classified it as a reseed because `new_blob_count=1` and `upload_already_present=83`. Treat this as a near-warm signal, but not a formal zero-new-blob steady-state sample.
  - The diagnostics also showed `oci_engine_miss_blob_locator=1` and `oci_engine_proof_upload_session=1`; investigate why one small blob still needed an upload-session proof on the second same-ref run before claiming perfect steady state.
- Fresh lane note:
  - BC fresh run `24673306681` completed the seed build and the layer-miss scenario, but the workflow failed in `Scenario (warm1)` during GitHub runner action download: `An action could not be found at the URI 'https://api.github.com/repos/boringcache/one/tarball/e22cc5a...'`.
  - That failure happened in the GitHub Actions setup step while fetching `boringcache/one@v1`, after the tag move, not in the BoringCache proxy or BuildKit path. Rerun fresh after action tarball availability settles before using it for warm/stale conclusions.
  - AC fresh run `24673306674` succeeded for the same upstream commit.
- Benchmark artifact fix:
  - Docker benchmark workflows now label `oci.new_blob_bytes` from actual `oci_blob_upload` event bytes after the latest upload plan, not from the upload plan's full `requested_bytes` graph size.
  - Older artifacts before this fix are misleading when `new_blob_count=0` or `1`, because they can still report the full requested descriptor graph size. Recompute from `oci_blob_upload` events when reviewing those runs.
- Docker benchmark graph fix:
  - Docker benchmark workflows use the `boringcache/one` Docker mode and CLI-planned registry-cache refs.
  - Keep BoringCache restore/save tokens on the action/proxy and storage-probe steps for these OCI registry-cache benchmarks.
- Guardrails:
  - Rolling comparisons must use the same upstream ref and the same workflow graph. The first run after an upstream, Dockerfile, action, CLI, cache tag, or hydration-policy change is allowed to reseed.
  - A valid Docker steady-state sample needs cache import success, high cached-step count, `new_blob_count == 0`, short BuildKit export, no widespread import-time remote body reads, no startup body failures, and no registry 4xx/5xx or digest failures.
  - `oci_body_remote_fetches` is not a failure under `metadata-only`; it is the expected on-demand read-through counter. Judge it by count, bytes, duration, and whether it persists on the second same-ref run.
  - If comparing `metadata-only`, `bodies-background`, and `bodies-before-ready`, do it as a diagnostic rolling-only matrix with policy-suffixed cache tags. Do not run hydration variants in parallel against the same registry cache refs, or they will write into each other's cache state.
  - Keep benchmark pass/fail focused on body read-through metrics, startup hydration failures, BuildKit import/export wall time, new blob count/upload plan, publish phase timings, and registry/digest errors. Do not compare total run wall time without classifying reseed versus steady state.

## 2026-04-20 - OCI engine isolation before BuildKit matrix

- OCI blob behavior moved out of the HTTP handler into `serve::engines::oci::blobs`.
- Blob GET now handles single byte ranges with `206`, suffix ranges, `If-Range`, invalid `416`, `Content-Range`, `Accept-Ranges`, digest headers, and size/digest verification while streaming remote bodies into the local blob read cache.
- OCI selected-ref body hydration no longer uses the KV body-prefetch helper. Startup still has one scheduling path, but selected OCI refs delegate to `serve::engines::oci::prefetch` and body reads hydrate through the OCI blob engine. This keeps KV adapter bottlenecks or compatibility choices from shaping OCI behavior.
- OCI publish orchestration moved to `serve::engines::oci::publish`: save, tracked blob uploads from `PresentBlob` proofs, pointer upload, confirm, alias binding, publish phase timing, and session cleanup. `serve::cas_publish` remains the shared protocol-neutral sequence helper.
- Added `OciEngineDiagnostics` for proof-source counts, graph expansion, local vs remote blob reads, range/read-through details, publish phase timings, miss causes, and hydration policy. `/_boringcache/status` now exposes these alongside existing OCI body metrics.
- The request metrics summarizer now promotes `oci_engine` status keys from both `proxy-status-*.json` and real-run `status-*.json` snapshots into `request-metrics-summary.env`, including stable per-snapshot labels such as `request_metrics_status_phase2_restart_warm_oci_body_remote_fetches`, so BuildKit E2E and ad hoc project artifacts can be studied after release without hand-parsing proxy status JSON.
- The Docker BuildKit E2E harness now emits the OCI metrics summary directly and gates the default metadata-only restart path on selected ref indexing, bounded client remote body fetches, and OCI engine read-through diagnostics. The gate intentionally treats `oci_body_remote_fetches` as the client-after-ready remote read-through signal; background and strict controls can still move body reads into startup/background hydration.
- BuildKit cold/warm/restart, default metadata-only read-through, hidden background/strict controls, and random-body graph replay passed locally before real-project testing. A real Hugo multi-stage Dockerfile then passed through the committed production workspace path with `255s` cold and `15s` warm, and through an isolated local Rails plus MinIO backend with `145s` cold and `20s` warm. Both warm runs cached BuildKit stages `#18` through `#35`, recorded zero body hydration failures, and kept body-plane behavior visible through OCI diagnostics.

## 2026-04-19 - adapter-by-adapter local pass and engine direction

- Local adapter coverage checked:
  - Turbo: command/env dry-run, route detection, auth/query/events behavior, and proxy round-trip tests passed (`cargo test turbo -- --nocapture`); earlier local adapter E2E also passed against the local Rails/Tigris setup.
  - Nx: command/env dry-run, route detection, auth/query behavior, and proxy round-trip tests passed (`cargo test nx -- --nocapture` plus `test_nx_dry_run_json_injects_remote_cache_env`); earlier local adapter E2E also passed against the local Rails/Tigris setup.
  - Bazel: command injection, route detection, CAS layout/materialization, and proxy round-trip tests passed (`cargo test bazel -- --nocapture`); earlier local adapter E2E also passed.
  - Gradle: command injection, route detection, and proxy round-trip tests passed (`cargo test gradle -- --nocapture`); runtime E2E now runs through the local Rails/Tigris harness via mise (`LOCAL_ADAPTER_TOOLS=gradle`) and passed with remote tag visibility.
  - Maven: command injection, route detection, v1/v1.1 path handling, and proxy round-trip tests passed (`cargo test maven -- --nocapture`); runtime E2E now runs through the local Rails/Tigris harness via mise (`LOCAL_ADAPTER_TOOLS=maven`) and passed with restored build info/JAR state plus remote tag visibility.
  - sccache: command/env dry-run, WebDAV env planning, route detection, miss tracking, coalesced blob reads, and proxy round-trip tests passed (`cargo test sccache -- --nocapture` plus `test_sccache_dry_run_json_injects_webdav_env`); earlier local adapter E2E also passed.
  - Go/GOCACHEPROG: command/env dry-run, helper parsing, endpoint validation, built-in config, route detection, and proxy round-trip tests passed (`cargo test go_cache -- --nocapture` plus `test_go_dry_run_json_injects_gocacheprog_env`); earlier local adapter E2E also passed.
  - Docker/OCI: Docker flag planning/read-only behavior passed (`cargo test docker -- --nocapture`); OCI layout, prefetch refs, body-storage status retry policy, hydration policy, manifest/referrers, and restore/materialization tests passed (`cargo test oci -- --nocapture`). The local Docker BuildKit registry E2E also passed through local Rails and Tigris, with a plain local registry baseline recorded.
- Coverage target:
  - Every adapter needs command-surface coverage (`--dry-run --json` or unit planner), route/protocol classification where it has an HTTP surface, and proxy round-trip coverage where it stores/retrieves bytes through `cache-registry`.
  - CAS layout/materialization only applies to OCI/file-CAS adapters. For proxy-native KV/object protocols (Turbo, Nx, Gradle, Maven, sccache, Go), the equivalent materialization proof is PUT/HEAD/GET or query behavior through the proxy.
- Docker parity lesson:
  - A registry-cache hit is not complete until both the manifest graph and blob bodies are locally reachable. Metadata-only startup can be logically cached while the first warm build still pays remote body reads.
  - `metadata-only`, `bodies-background`, and `bodies-before-ready` are the right internal benchmark modes, but not ordinary user choices. The product default should be `metadata-only`, with the selected policy reported in diagnostics alongside local OCI body hits, remote body fetches, remote bytes, remote duration, startup inserted/cold/failed counts, and BuildKit import/export wall time.
  - The local Docker E2E harness now records `/_boringcache/status` snapshots after warm phases so OCI body-plane behavior is visible instead of inferred from BuildKit wall time.
  - Local Colima replay needs `REGISTRY_HOST=host.docker.internal` plus a BuildKit daemon config marking that registry as HTTP/insecure. The E2E harness now generates that config automatically for non-localhost registry refs.
  - Strict local-edge replay must isolate the proxy blob cache (`E2E_BLOB_CACHE_SCOPE=per-proxy`). Otherwise a same-machine proxy restart can reuse the previous read-through blob cache and hide the cold body-plane cost.
  - 84-layer, 32 MiB random-body replay through local Rails/Tigris passed all three policies. With per-proxy body-cache isolation, metadata-only had 86 cold selected bodies and fetched about 33.6 MB remotely during warm reads; `bodies-before-ready` inserted all 86 selected bodies before readiness in about 2.7s and avoided restart-warm remote body fetches; `bodies-background` inserted all 86 selected bodies in about 2.2s and also avoided restart-warm remote body fetches when it won the race.
- Harness/product-DX lessons:
  - The debug path must keep the benchmark graph stable when testing a new `cli_ref`. A real binary copied into a Docker build context is a BuildKit input and can legitimately reseed after a binary change.
  - Local Docker-on-macOS validation needs separate proxy and registry hosts because a `docker-container` builder resolves `localhost` inside the Linux VM/Colima context.
  - macOS Bash 3 with `set -u` needs empty-array guards in E2E harnesses.
- Review of the core-engine rewrite recommendation:
  - The direction stands: keep `one@v1`, CLI commands, repo config, split tokens, `cache-registry`, protocol adapters, and standalone benchmark repos; do not force OCI, Bazel, Turbo, sccache, Gradle, or Maven through generic archive mode.
  - The local code supports the critique: archive save still builds a full manifest and tar archive, while CAS save already follows the better check-missing-blobs -> upload-missing-blobs -> upload-index/pointer -> confirm pattern. `ManifestBuilder` still walks and hashes files directly, and adapter dispatch still has Archive/Oci/File paths plus encryption fallback.
  - The operational conclusion should be an incremental engine boundary, not a blind rewrite. The Docker incident was fixed by making body locality, diagnostics, harness determinism, and shutdown/publish behavior explicit. A snapshot-v2 filesystem engine is a product roadmap item for generic save/restore, not a prerequisite for Docker adapter parity.
  - The right next artifact is an implementation spec/ADR for a shared immutable object/session model, snapshot-v2, packing, and per-protocol adapters, with measured migration gates before replacing archive-v1 as the default.
- Primary-source cross-check:
  - GitHub Actions cache is key/restore-key based, immutable once written, branch/default-branch scoped, and subject to repository storage/eviction policy.
  - Docker BuildKit registry cache must be explicitly imported/exported with `--cache-from`/`--cache-to`; `mode=max` is needed when intermediate layers matter.
  - Bazel's native model is action cache plus CAS; Turborepo has a published Remote Cache API; sccache supports remote storage including WebDAV. Native protocol identity should stay intact.
- Completed follow-up work from this investigation:
  - Local Gradle and Maven runtime E2E legs were wired into the adapter command harness and passed on this machine through mise.
  - The diagnostics summarizer now ingests proxy status snapshots and emits both aggregate OCI body-plane metrics and per-snapshot phase metrics.
  - Local/staging Tigris workspace provisioning now treats `409` conflicts as recoverable by ensuring the bucket exists and minting a fresh workspace key.
  - Larger Docker graph replay passed locally across the product metadata-only OCI read-through path and hidden background/strict controls with both shared and per-proxy body-cache scopes.
  - The engine-boundary ADR is written in `docs/adr/0001-engine-boundary.md`; snapshot-v2/crate split work should start behind that boundary, not before it.

## 2026-04-15 - warm-first proxy startup

- Product direction:
  - `cache-registry` is the warm-first standalone proxy surface.
  - `boringcache <tool>` and `boringcache run --proxy` temporarily start that same proxy for one command and inherit the same warm-first startup behavior.
  - `--on-demand` is the explicit expert override when a caller wants immediate startup instead of startup warming.
- Concurrency follow-up:
  - The machine governor already picks safe blob download concurrency from runner headroom. Startup prefetch now uses that full safe proxy download budget before readiness instead of halving it again, so high object-count KV adapter tags warm harder while the wrapped tool is not running yet.
  - Proxy warmup uses an IO-oriented CI floor when the runner has memory and CPU headroom. The 2026-04-28 Hugo Go rolling run showed the released CLI warming 1,963 blobs / 741.6 MB with `prefetch budget: 1`, spending 181.8s before the build. That is the wrong default for network-bound object prewarm even if archive restore should stay CPU conservative.
  - Local Rails/Tigris-backed E2E with 5,000 x 4 KiB blobs measured startup-prefetch readiness at 36s with concurrency 3, 13s with concurrency 10, and 14s with concurrency 20. That shape says the useful client-side warm concurrency ceiling for many tiny objects is around 10 in this environment; above that, storage/server scheduling dominates.
  - A 20-concurrency stress attempt also exposed a save-side limit: high write pressure produced an HTTP/2 `too_many_internal_resets` storage upload error, preserved partial blob receipts, then repeatedly hit a server-side `Cache upload in progress` conflict during shutdown flush. Treat that as a separate save/publish robustness follow-up, not as a prefetch win.
  - Do not treat S3-compatible storage as unlimited for this path. AWS documents high per-prefix request floors and gradual scaling with possible `503 Slow Down`; Tigris does not publish a precise per-prefix write ceiling. Our product should classify 429/503, `Retry-After`, HTTP/2 resets, and timeout pressure as storage-write backpressure and feed that into upload concurrency and session summaries.
  - The save-side governor now caps many-small-blob upload batches instead of ramping every large batch to 64. A 20,000 x 4 KiB local Rails/Tigris E2E published cleanly with the final 11,817-object flush held at concurrency 12, then startup-prefetched all 20,000 blobs in 51s with zero verify failures.
  - The 50,000 x 4 KiB stress run also passed: the seed side uploaded all 50,000 blobs with zero failed uploads, the largest follow-up flush stayed at concurrency 12, startup prefetch inserted all 50,000 blobs in 187s, and local-cache verification read all 50,000 with zero failures.
- Guardrail:
  - Keep warm as the default user path. Treat on-demand as an advanced escape hatch, not the main story.
- Contract:
  - `/_boringcache/status` remains the machine-readable lifecycle contract underneath both modes.
  - `docs/contracts/readiness.md` is the written contract for readiness and publish-settlement semantics.

## 2026-04-14 - first-class proxy lifecycle status

- Symptom:
  - E2E scripts were still inferring readiness and publish settlement from `/v2/`, fixed sleeps, or proxy log output.
  - That kept harness logic coupled to implementation details instead of the product surface.
- Product-side changes:
  - Add `/_boringcache/status` as the proxy lifecycle endpoint.
  - Report `warming`, `ready`, and `draining` plus `publish_settled` for fresh readers.
  - Base publish settlement on real tag visibility, not just empty local queues.
- Harness cleanup:
  - Move shared proxy readiness checks to `/_boringcache/status`.
  - Move prefetch-settlement checks to `publish_settled` instead of log scraping.
  - Update standalone E2E scripts and proxy-mode smoke checks to use the status endpoint.
- Guardrail:
  - `/v2/` is the protocol surface. `/_boringcache/status` is the operator and harness lifecycle surface.

## 2026-04-15 - CLI-managed proxy readiness waits

- Symptom:
  - `boringcache <tool>` and `boringcache run --proxy` could start the wrapped command while the proxy still reported `warming`.
  - Downstream callers added their own readiness waits on top of the CLI-managed lifecycle.
- Product-side changes:
  - Make CLI-managed background proxy startup wait on the shared in-process readiness state instead of reimplementing local HTTP polling.
  - Add a hidden ready-file handoff so detached orchestrators can block on the same readiness signal without scraping logs or duplicating `/_boringcache/status` polling.
- Guardrail:
  - Keep one readiness model. User-facing CLI flows stay warm-by-default, detached internal orchestrators consume the CLI-owned readiness signal, and `/_boringcache/status` remains the HTTP lifecycle and publish-settlement surface.

## 2026-04-14 - full-tag hydration as the disk-cache contract

- Symptom:
  - Startup warming still behaved like a slice-based scheduler even though the product direction had moved to cache-first hydration.
  - Hidden startup and background byte budgets made the proxy look simple in small cases but degrade into partial warming under pressure.
- Root cause:
  - Prefetch kept separate startup blob/byte limits and a background inflight byte cap.
  - The blob read cache already had its own size ceiling and eviction path, so the extra prefetch budgets were policy duplication.
- Product-side changes:
  - Hydrate the full active tag by default during startup and continue best-effort in the background if readiness times out.
  - Remove startup selection budgets and background inflight byte budgets from cache-registry hydration.
  - Treat the fixed blob-read-cache ceiling and blob-cache eviction as the authoritative disk safety boundary.
- Guardrail:
  - For disk-backed cache-registry paths, warm selection should not invent a second capacity policy. If we add a RAM cache later, memory budgets belong there instead.

## 2026-04-09 - startup hydration and generic machine governor

- Symptom:
  - Warm `sccache` paths were spending too much time on remote reads even with high cache-hit rates.
  - Startup preload resolved too many download URLs up front and warmed too little useful data before the build began.
- Root cause:
  - Startup prefetch selection stopped at the first blob that exceeded the remaining budget, leaving usable prefetch budget idle.
  - Startup path resolved all download URLs before warming the startup slice, so control-plane latency was paid before useful local hydration.
  - Tool-detected defaults were pushing the design toward special-case tuning instead of one generic machine-safe scheduler.
- Product-side changes:
  - Skip oversized blobs during startup selection instead of aborting the remainder of the slice.
  - Use one automatic machine governor for blob-cache sizing, download concurrency, and startup work.
  - Keep startup selection generic and cache-state driven instead of routing behavior through tool profiles.
  - Resolve startup-slice download URLs first, warm that slice first, then resolve the rest in the background.
  - Emit blob-read observability for `local_cache` vs `remote_fetch`.
- Harness guardrails:
  - Add `BORINGCACHE_BLOB_READ_CACHE_DIR` so restart tests can force a truly fresh local blob cache instead of silently reusing `/tmp/boringcache-blob-cache`.
  - Fix `ci/e2e/extended/e2e-prefetch-readiness-test.sh` to work on local macOS shells by shortening `xargs` worker invocations and separating seed/restart blob-cache directories.
- Guardrail:
  - Adapters define protocol and correctness boundaries. Prefetch and read-path defaults should stay generic unless real protocol traffic proves a broader product change.

## 2026-04-08 - Shutdown publish visibility regression (Turbo/sccache)

- Symptom:
  - Warm tool runs showed local hits, but cross-process remote tag checks failed (`hits=0, misses=1`).
  - Proxy was often force-killed before publish/tag convergence completed.
- Failure shape:
  - Tag publish had not converged before teardown, so remote readers observed the old tag state.
- Product-side changes:
  - Keep shutdown flush and tag-visibility polling bounded but long enough for real storage/API convergence.
  - Add adaptive small-batch flush behavior in cache-registry so tiny pending sets are flushed sooner during active runs instead of being deferred to shutdown.
- Harness guardrails (CLI repo e2e scripts):
  - Centralized proxy graceful-stop default to `210s`.
  - Enforce a minimum graceful-stop budget of `210s` even if lower env values are set.
  - Remove per-tool hardcoded remote-tag verify timings (`30/2`), use shared defaults.

## 2026-04-08 - OCI publish confirm timed out before tag settled (Hugo/Turbo)

- Symptom:
  - OCI tool e2e legs failed with remote tag not published after cold save.
  - Proxy logs showed `Best-effort OCI manifest publish fallback ... (500 Internal Server Error)`.
- Root cause:
  - OCI manifest put wrapped `api_client.confirm(...)` in a hard `30s` handler timeout.
  - Confirm can legitimately take longer than `30s` when upload receipts, storage visibility, and pointer publish are all in flight.
  - On timeout, the request degraded/fell back before publish completed, so tag checks observed misses.
- Secondary pressure signal:
  - Generic request retries under concurrent CI load amplified backend pressure.
- Product-side changes:
  - Remove the extra `30s` wrapper around OCI confirm in `serve/handlers.rs`; rely on the shared confirm path.
  - Add explicit poll backoff on `429` (rate-limit aware) to reduce retry storms.
- Guardrail:
  - Do not add short outer timeouts around publish confirm paths; use one authoritative confirm/retry lifecycle.

## 2026-04-16 - OCI proxy parity and warm-path backlog

- Completed:
  - Added explicit startup OCI prewarm via `--oci-prefetch-ref` for selected `repo@ref` pairs, which seeds both manifest and blob locator state during startup when not using `--on-demand`.

- Spec cross-check:
- Distribution manifest pushes should fail with `400 MANIFEST_BLOB_UNKNOWN` when referenced blobs are missing.
  - Distribution resumable blob uploads should reject stale or out-of-order chunk offsets with `416 Requested Range Not Satisfiable`.
  - OCI 1.1 subject-aware manifest pushes should return `OCI-Subject` when the registry supports referrers processing.
- Current gaps:
  - OCI startup now defaults to metadata-only selected-ref hydration; the remaining gap is proving that default against the full BuildKit acceptance matrix and keeping hidden background/strict modes as controls.
  - Track the new OCI manifest-contract E2E leg alongside the existing BuildKit registry-cache leg so subject/referrers and restart behavior stay covered as proxy changes land.
  - Measure whether the new OCI inflight dedupe meaningfully reduces restore, pointer, download-url, and blob-fetch fan-out under concurrent reader load.
  - Add an E2E BuildKit OCI-spec mirror that covers manifest PUT validation, resumable upload edge cases, warm restart behavior, and cache import/export parity.

## 2026-04-16 - shutdown flush stall and session cleanup race

- Symptom:
  - Proxy runs with writes occasionally took 180s to shut down instead of the expected 10–15s.
  - `cleanup_blob_sessions` used global `find_by_digest`, which could remove upload sessions belonging to a different OCI repository during concurrent multi-repo manifest pushes.
- Root cause (shutdown):
  - After a Conflict or transient Error during `flush_pending_on_shutdown`, the normal-mode backoff gate (`kv_next_flush_at`) was inherited by the shutdown loop, causing up to 10s sleep per retry iteration.
  - The replication worker did not check `shutdown_requested` and could hold `kv_flush_lock` during a slow network flush while the shutdown path waited for the lock.
  - The sweep task continued enqueuing new flush hints after shutdown was requested.
- Root cause (session cleanup):
  - `cleanup_blob_sessions` called `find_by_digest` (global) instead of `find_by_name_and_digest`, so a completed manifest push for repo A could remove the staged session for repo B if they shared a blob digest.
- Product-side changes:
  - Clear `kv_next_flush_at` on Conflict/Error during shutdown flush loop so retries happen immediately.
  - Use a fixed 1s retry interval during shutdown instead of reading the normal-mode backoff gate.
  - Skip replication worker flush processing and sweep task enqueuing once `shutdown_requested` is set.
  - Scope `cleanup_blob_sessions` by repository name using `find_by_name_and_digest`.
- Guardrail:
  - Shutdown flush path should never inherit normal-mode backoff timing. Background maintenance tasks must check `shutdown_requested` before acquiring `kv_flush_lock`.
  - Upload session lookups should always be scoped by repository name. Global `find_by_digest` is only safe for read-only queries where cross-repo hits are acceptable.

## 2026-04-16 - OCI manifest confirm lock as best-effort error

- Symptom:
  - OCI manifest PUT failed when the backend returned `423` during confirm.
- Root cause:
  - OCI path used plain `confirm()` and treated `423` as a hard error.
- Product-side changes:
  - Switch OCI manifest confirm and alias bind to `confirm_with_retry`, which uses the shared optimistic confirm path.
  - Treat an unresolved lock as an internal error (`500`) that triggers best-effort degraded fallback when `fail_on_cache_error` is false.
  - Check for `prefetch_error` after `Notify` wakeup in `await_startup_prefetch_readiness` to avoid an unnecessary loop iteration on error.
- Guardrail:
  - OCI confirm paths should use the same optimistic confirm helper as archive and KV flush paths.

## Merge Checklist For Cache-Registry Changes

Before merging changes touching `src/serve/cache_registry/*`, `src/serve/mod.rs`, or publish/confirm client paths:

1. Run targeted correctness tests:
   - `cargo test confirm_retry_reason_retries_transient_server_errors -- --nocapture`
   - `cargo test should_flush_pending_values -- --nocapture`
2. Validate at least one tool e2e path that relies on remote tag visibility across process restarts.
3. Confirm no workflow-only tuning is required for correctness.
4. Record any new latency/correctness tradeoff in this log.
