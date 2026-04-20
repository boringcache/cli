# Adapter Contract Matrix

This matrix records adapter behavior from primary sources. The implementation should treat these rows as the contract until a newer primary source says otherwise.

| Adapter | Primary source | Protocol root | Objects and aliases | Read path | Write path | Miss / error shape | BoringCache engine invariant |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OCI / Docker BuildKit registry cache | OCI Distribution Spec, OCI Image Spec, Docker registry cache docs | `/v2/<name>/...` registry API | Blobs by digest, manifests by digest or tag, referrers by subject digest | `GET`/`HEAD` manifests and blobs; referrers query returns an OCI image index shape | Start upload, PATCH or monolithic body, closing PUT with whole-blob digest; manifest PUT last | Missing blobs/manifests are 404-shaped; out-of-order upload is 416; manifest references to missing non-subject descriptors are `MANIFEST_BLOB_UNKNOWN` | Manifest publish must prove every non-subject descriptor through a named local or remote source before BoringCache confirm/alias |
| sccache WebDAV | sccache configuration docs | WebDAV endpoint plus optional key prefix | Compiler artifact objects under WebDAV keys | WebDAV read by key | WebDAV write by key | Tool treats backend failure as cache failure or miss depending sccache behavior | Preserve WebDAV key prefix and object identity; do not reinterpret as filesystem archive |
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
- Extract the protocol root, object identities, alias model, read methods, write methods, miss statuses, retry behavior, and auth shape into the matrix row.
- Add or update a mistake-ledger row for every product failure class the change is meant to prevent.
- Write acceptance tests from source behavior before optimizing implementation details.
- Keep shared code only where the behavior is protocol-neutral.

## OCI / BuildKit Focus

OCI is the active adapter pass. The goal is not generic "registry-like" behavior; the goal is the best BoringCache product path for Docker BuildKit registry cache.

Implementation work should stay aligned with:

- OCI Distribution Spec pull, push, mount, manifest, blob, HEAD, error, and referrers behavior.
- OCI Image Spec descriptor graph rules for config, layers, image indexes, artifact manifests, and subject relationships.
- Docker BuildKit registry cache import/export behavior through `--cache-to type=registry` and `--cache-from type=registry`, including `mode=max`, OCI media types, image-manifest vs image-index output, and cache refs separate from final image refs.

The OCI engine should own OCI-specific correctness and performance. Shared runtime and BoringCache API plumbing should not grow OCI branches unless the branch is truly protocol-neutral.
