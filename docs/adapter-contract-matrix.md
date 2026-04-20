# Adapter Contract Matrix

This matrix records adapter behavior from primary sources. The implementation should treat these rows as the contract until a newer primary source says otherwise.

| Adapter | Primary source | Protocol root | Objects and aliases | Read path | Write path | Miss / error shape | BoringCache engine invariant |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OCI / Docker BuildKit registry cache | OCI Distribution Spec, OCI Image Spec, Docker registry cache docs | `/v2/<name>/...` registry API | Blobs by digest, manifests by digest or tag, referrers by subject digest | `GET`/`HEAD` manifests and blobs; referrers query returns an OCI image index shape | Start upload, PATCH or monolithic body, closing PUT with whole-blob digest; manifest PUT last | Missing blobs/manifests are 404-shaped; out-of-order upload is 416; manifest references to missing non-subject descriptors are `MANIFEST_BLOB_UNKNOWN` | Manifest publish must prove every non-subject descriptor through a named local or remote source before BoringCache confirm/alias |
| sccache WebDAV | sccache WebDAV docs, configuration docs, and WebdavCache/Storage source | WebDAV endpoint plus optional key prefix/root | Compiler cache entries under sccache-normalized WebDAV keys (`a/b/c/<key>`), plus `.sccache_check` capability probe | OpenDAL read by normalized key; not found is a cache miss; unexpected read errors are treated as misses by sccache storage | OpenDAL write by normalized key; WebDAV may create parent collections with `MKCOL`; startup check writes `.sccache_check` to detect read-write mode | Missing objects should behave like cache misses; unsupported WebDAV methods should be explicit; probe reads/writes must not poison user cache entries | Preserve exact WebDAV path/key identity, `MKCOL`/probe behavior, auth shape, and binary payload bytes; do not inspect sccache zip payloads or reinterpret them as archive/cache-entry manifests |
| Bazel | Bazel remote caching docs | `--remote_cache` HTTP/gRPC root | AC under `/ac/`; CAS under `/cas/` | HTTP GET for AC/CAS blobs | HTTP PUT for AC/CAS blobs | Missing object is HTTP miss; writers should usually be CI-controlled | Keep AC and CAS distinct; never collapse action metadata and output blobs into one namespace |
| Gradle | Gradle build cache docs | HTTP build cache URL | Cache entry by cache key | `GET <url>/<cache-key>`; 2xx body is hit; 404 is miss | `PUT <url>/<cache-key>`; any 2xx is success; 413 is accepted as oversized-not-error | Redirect and retry rules are Gradle-owned | Return exactly the status shapes Gradle expects; do not make 413 fatal |
| Maven | Apache Maven Build Cache Extension docs | Configured remote cache URL or Maven Resolver storage | Build cache artifacts keyed by the extension's hash tree | HTTP server must support GET and HEAD | HTTP server must support PUT | Portability misses come from raw-byte/source/effective-POM differences | Keep Maven's raw-byte portability assumptions visible in diagnostics; do not normalize content behind its back |
| Turborepo | Turborepo Remote Cache API | Remote Cache API | Artifacts by content-addressable hash | `HEAD`/`GET /artifacts/{hash}`, batch `POST /artifacts` | `PUT /artifacts/{hash}` plus event endpoint | Bearer auth; artifact miss through status/body defined by API | Preserve API shape and bearer auth; record artifact status/events without inventing task semantics |
| Nx | Nx custom remote cache OpenAPI | `/v1/cache/{hash}` | Task output tar archives by hash | OpenAPI-defined download | OpenAPI-defined upload | Auth errors are explicit 401/403 text responses; archive data is binary | Treat payload as Nx task-output archive bytes; do not inspect or mutate archive format |
| Go GOCACHEPROG | Go `cmd/go/internal/cacheprog` source | Subprocess JSON over stdin/stdout | ActionID to OutputID/body, with local DiskPath | `get` request returns miss or OutputID, size, DiskPath | `put` request stores body and returns DiskPath | Each JSON response echoes request ID; initial response declares supported commands | This is not HTTP. Preserve line-oriented JSON and local file lifetime through close |

## Source-Rooted Rules

- If a source says the client owns retries, keep the proxy response simple and let the tool retry.
- If a source says an object namespace is split, model it explicitly.
- If a source says a miss has a special non-error status, preserve it.
- If a source says local file paths are part of the protocol, do not stream-only the implementation.
- If an adapter source is silent, add tests against the real tool before making product policy.

## Adapter Research Checklist

Before changing an adapter engine:

- Confirm the current primary source URLs still point at the relevant official docs or source code.
- Name at least one open-source or standard industry implementation to compare against for compatibility and performance expectations.
- Extract the protocol root, object identities, alias model, read methods, write methods, miss statuses, retry behavior, and auth shape into the matrix row.
- Add or update a mistake-ledger row for every product failure class the change is meant to prevent.
- Write acceptance tests from source behavior before optimizing implementation details.
- Keep shared code only where the behavior is protocol-neutral.

## Known Rewrite Findings

Carry these findings into the relevant adapter rewrite plan. A rewrite is not done until every applicable row is either closed by tests and code, or left as an explicit residual risk.

| Adapter / area | Finding | Rewrite owner | Required guardrail |
| --- | --- | --- | --- |
| OCI / blob reads | Blob pulls used to ignore `Range` and return full `200` bodies. | `serve::engines::oci::blobs` | Closed for the current CLI path: blob engine owns `Accept-Ranges`, partial `206`, invalid `416`, `If-Range`, remote read-through, digest/size verification, and diagnostics. Keep focused range/status tests and BuildKit E2E summary gates as regression coverage before release. |
| OCI / upload resume | Upload offset parsing accepted Docker-style bare ranges but not equivalent byte-range forms. | `serve::engines::oci::uploads` | Closed for the current CLI path: upload parsing accepts supported `Range` / `Content-Range` byte spellings, preserves exact offsets, and returns `416` for stale or out-of-order offsets. |
| OCI / engine boundary | OCI must not be treated as generic KV. Registry truth is manifest/blob/session/referrer shaped. | `serve::engines::oci` | Closed for the current OCI pass: uploads, manifest resolution, manifest cache entries, child-manifest staging, blob HEAD/GET, selected-ref prefetch, publish, referrers, and diagnostics live under the OCI engine. Keep `docs/oci-kv-path-audit.md` current and do not move OCI protocol decisions back into KV or HTTP handlers. |
| Shared KV adapters | KV is justified for object-cache adapters, but only as substrate. | sccache, Gradle, Maven, Turbo, Nx, Go, and Bazel HTTP rewrites | Keep key identity, status codes, auth shape, retry/miss behavior, and binary payload ownership in the adapter row; do not add archive or OCI assumptions to shared KV. |
| Example selection | The comparison implementation must match the adapter protocol. | Per-adapter research step | Use BuildKit/containerd for OCI, sccache's own backend behavior for sccache, BuildBuddy-style behavior for Bazel AC/CAS, Develocity-style behavior for Gradle, official Turbo/Nx APIs for Turbo/Nx, Apache Maven extension behavior for Maven, and Go cacheprog source for Go. |
| Transfer hot path | HTTP/2 and pool settings are part of adapter performance, not incidental transport defaults. | Transfer client/runtime work | Benchmark BuildKit import/export before changing pool sizing, h2 fallback, adaptive windows, connection limits, or compression behavior. |

## Implementation Examples To Audit

| Adapter | Examples to audit before rewrite | Compatibility and performance questions |
| --- | --- | --- |
| OCI / Docker BuildKit registry cache | BuildKit registry cache source, BuildKit GitHub Actions cache source, containerd distribution resolver behavior | Does the path preserve digest-addressed manifests/blobs, resumable upload offsets, cross-repository mount, referrers, digest `ETag`, streaming digest verification, pooled HTTP/2 transfer, and fast metadata decisions before body movement? |
| sccache WebDAV | sccache WebDAV docs, configuration docs, `WebdavCache::build`, sccache `Storage` implementation over OpenDAL, OpenDAL WebDAV behavior, and any production WebDAV cache deployment used by real CI | Does the path preserve WebDAV key identity, `.sccache_check`, `MKCOL`, read-miss semantics, bearer/basic auth, high-concurrency artifact reads, and opaque binary cache-entry bytes without forcing archive semantics? |
| Bazel AC/CAS | Bazel remote cache docs and BuildBuddy-style AC/CAS behavior | Are action cache and CAS namespaces distinct, are digest and size checks strict, and are misses surfaced in the shape Bazel retries correctly? |
| Gradle | Gradle build cache docs and Develocity-style HTTP cache behavior | Are `GET`/`PUT` status codes, redirect behavior, oversized `413`, and binary object identity preserved without inspecting payloads? |
| Maven | Maven Build Cache Extension source/docs and Maven Resolver storage behavior | Are raw-byte/source/effective-POM portability misses visible, and do `GET`/`HEAD`/`PUT` behave as Maven expects? |
| Turborepo and Nx | Official Turbo Remote Cache API and Nx custom remote cache OpenAPI/server examples | Are artifact hash routes, bearer auth, batch/event APIs, and binary archive bodies preserved exactly? |
| Go GOCACHEPROG | Go `cmd/go/internal/cacheprog` source | Is the line-oriented JSON subprocess protocol preserved, including request IDs, supported commands, and local file lifetime? |

## OCI / BuildKit Focus

OCI is the active adapter pass. The goal is not generic "registry-like" behavior; the goal is the best BoringCache product path for Docker BuildKit registry cache.

Implementation work should stay aligned with:

- OCI Distribution Spec pull, push, mount, manifest, blob, HEAD, error, and referrers behavior.
- OCI Image Spec descriptor graph rules for config, layers, image indexes, artifact manifests, and subject relationships.
- Docker BuildKit registry cache import/export behavior through `--cache-to type=registry` and `--cache-from type=registry`, including `mode=max`, OCI media types, image-manifest vs image-index output, and cache refs separate from final image refs.
- BuildKit `application/vnd.buildkit.cacheconfig.v0` cache config handling before the manifest engine moves descriptor traversal; this media type is product-critical and should be researched explicitly instead of treated as a generic unknown blob.
- BuildKit/distribution best practices for streaming digest verification, cross-repository mount `201`/`202`, digest-valued `ETag`, pooled HTTP/2 transfer, resumable upload offset validation, and ranged blob reads.

The OCI engine should own OCI-specific correctness and performance. Shared runtime and BoringCache API plumbing should not grow OCI branches unless the branch is truly protocol-neutral.

## sccache / WebDAV Next

sccache is the next native adapter pass. The source-backed contract starts from:

- sccache WebDAV docs: endpoint, key prefix/root, basic auth, and bearer token configuration.
- sccache configuration docs: `SCCACHE_WEBDAV_ENDPOINT`, `SCCACHE_WEBDAV_KEY_PREFIX`, `SCCACHE_WEBDAV_USERNAME`, `SCCACHE_WEBDAV_PASSWORD`, and `SCCACHE_WEBDAV_TOKEN`.
- sccache `WebdavCache::build`: WebDAV is delegated to OpenDAL with endpoint, root, username/password, token, user-agent, and logging layers.
- sccache `Storage` implementation: `get` reads `normalize_key(key)`, maps not found and unexpected read errors to cache misses, `put` writes `normalize_key(key)`, `check` reads and writes `.sccache_check`, and `normalize_key` maps a key to `a/b/c/<key>`.
- OpenDAL WebDAV behavior: writes may create parent collections with `MKCOL`; some compatible servers skip or reject directory creation differently.

The next engine boundary should start by preserving the existing route behavior in `src/serve/cache_registry/sccache.rs` while moving the WebDAV-specific truth out of generic KV helpers only when the behavior is not protocol-neutral. The acceptance list should cover `.sccache_check`, `MKCOL`, `GET`/`HEAD` misses, `PUT` writes, unsupported methods, exact key paths, and concurrent warm reads.
