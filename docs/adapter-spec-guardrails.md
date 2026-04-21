# Adapter Spec Guardrails

Status date: 2026-04-21.

This ledger is the source-to-test map for native adapter paths. "Aligned" here means the currently supported BoringCache adapter subset has an official source, a route/status contract, and named guardrails. If a source exposes behavior outside the supported subset, that behavior must stay explicit as residual risk until implemented and tested.

Official sources checked:

- OCI / Docker: [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec/blob/main/spec.md), [OCI Image Spec](https://github.com/opencontainers/image-spec/blob/main/spec.md), [Docker registry cache backend](https://docs.docker.com/build/cache/backends/registry/), [BuildKit registry cache source](https://github.com/moby/buildkit/blob/master/cache/remotecache/registry/registry.go)
- sccache: [sccache WebDAV configuration](https://docs.rs/crate/sccache/latest/source/docs/Configuration.md)
- Bazel: [Bazel remote caching](https://bazel.build/remote/caching)
- Gradle: [Gradle build cache](https://docs.gradle.org/current/userguide/build_cache.html)
- Maven: [Maven Build Cache Extension remote cache](https://maven.apache.org/extensions/maven-build-cache-extension/remote-cache.html)
- Nx: [Nx self-hosted caching](https://nx.dev/docs/guides/tasks--caching/self-hosted-caching)
- Turborepo: [Remote Cache API](https://turborepo.com/docs/openapi)
- Go: [`cmd/go/internal/cacheprog`](https://tip.golang.org/src/cmd/go/internal/cacheprog/cacheprog.go)

| Adapter path | Official source | Supported route surface | Guardrails in this repo | Residual risk / next proof |
| --- | --- | --- | --- | --- |
| OCI / Docker BuildKit registry cache | OCI Distribution Spec, OCI Image Spec, Docker registry cache backend docs, BuildKit registry cache source | `/v2/<name>/manifests/<reference>`, `/v2/<name>/blobs/<digest>`, upload sessions, cross-repo mount, referrers, selected-ref prefetch | OCI manifest/blob/upload/publish tests in `tests/serve_tests.rs`; `docs/oci-kv-path-audit.md`; `docs/oci-mistake-ledger.md`; Docker BuildKit E2E | Full OCI conformance is not claimed; BoringCache claims the BuildKit registry-cache subset. ADRs 0003-0007 track session trace, stream-through, borrowed bodies, negative cache, and immutable run refs before broader claims |
| sccache / WebDAV | sccache WebDAV docs/configuration and sccache/OpenDAL storage behavior | `.sccache_check`, `MKCOL`, WebDAV object `GET`/`HEAD`/`PUT` under the configured root/key prefix | `test_sccache_put_head_get_round_trip`, `test_sccache_head_miss_returns_not_found_without_body`, `.sccache_check` and `MKCOL` tests, concurrent GET coalescing, `docs/sccache-mistake-ledger.md`, sccache E2E | `PROPFIND` is not implemented because current sccache/OpenDAL traffic does not require it. Add only with real traffic evidence |
| Bazel AC/CAS | Bazel remote caching docs and HTTP caching protocol | `/ac/<sha256>` and `/cas/<sha256>` with `GET`/`HEAD`/`PUT` | AC/CAS round trip, `test_bazel_ac_and_cas_misses_return_not_found`, invalid digest rejection, CAS write/read integrity tests, `docs/bazel-mistake-ledger.md`, local Bazel E2E | HTTP Basic Auth is tool-side URL configuration; the local proxy remains anonymous. gRPC remote execution/cache is outside this HTTP adapter |
| Gradle HTTP build cache | Gradle HTTP build cache docs | `/cache/<cache-key>` with `GET`/`HEAD`/`PUT` | Gradle round trip, `test_gradle_get_miss_returns_not_found`, unsupported method test, `test_gradle_put_returns_413_when_spool_budget_exceeded`, local Gradle E2E | Redirect and retry behavior is Gradle client-owned. Add redirect tests only if the local proxy starts issuing redirects |
| Maven Build Cache Extension | Apache Maven Build Cache Extension remote-cache docs | `/v1/...` and `/v1.1/...` cache artifact paths with `GET`/`HEAD`/`PUT` | Maven round trip covers `PUT`/`HEAD`/`GET`, `test_maven_get_and_head_misses_return_not_found`, unsupported method test, Maven generic spool rejection test, local Maven E2E | Maven portability diagnostics remain shallow; BoringCache preserves bytes and does not normalize Maven cache artifacts |
| Nx custom remote cache | Nx self-hosted custom remote cache OpenAPI | `/v1/cache/{hash}`, `/v1/terminalOutputs/{hash}`, and `POST /v1/cache` query | bearer auth test, artifact round trip, `test_nx_artifact_get_miss_returns_not_found`, query miss test | Terminal output miss and upload conflict semantics should get explicit tests before a richer Nx engine boundary |
| Turborepo Remote Cache API | Turborepo Remote Cache OpenAPI | `/v8/artifacts/status`, `/v8/artifacts/{hash}`, `POST /v8/artifacts`, `POST /v8/artifacts/events` | bearer auth/status tests, artifact round trip, `test_turborepo_artifact_get_miss_returns_not_found`, query metadata test, events tests | The API's full OpenAPI response schema should be rechecked before changing metadata headers or event payload handling |
| Go GOCACHEPROG helper | Go `cmd/go/internal/cacheprog` source protocol | Subprocess JSON in the Go tool; BoringCache helper maps action IDs to local HTTP `/gocache/<action>` objects | go-cacheprog unit tests, HTTP backing object round trip, invalid action-id test, `test_go_cache_get_miss_returns_not_found`, Go adapter E2E | The HTTP route is an implementation detail, not the Go spec. Subprocess JSON request/response and DiskPath lifetime remain the public protocol to protect |

## Rules For New Adapter Work

- Re-open the official source before changing route behavior.
- Add or update the adapter mistake ledger before merging a behavior fix.
- Every supported read path needs a hit test and a miss-status test.
- Every supported write path needs a success test and at least one failure/status guardrail from source behavior.
- Every path with auth in the official source needs an auth-shape test or a note explaining why the local proxy is intentionally anonymous.
- Real-tool E2E is required before claiming product alignment for an adapter, even when route unit tests pass.
