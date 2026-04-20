# OCI / KV Path Audit

This audit answers whether OCI uses KV as its protocol engine.

Short answer: no. OCI registry requests do not go through `KvNamespace`, `put_kv_object`, or `get_or_head_kv_object`. The reason to audit KV before the next OCI engine moves is that a few shared runtime helpers and one OCI startup path currently live under `serve::cache_registry::kv`, so a manifest/blob extraction needs to keep protocol-neutral substrate separate from OCI registry behavior.

| Area | Current OCI contact | Classification | Next action |
| --- | --- | --- | --- |
| `src/serve/cache_registry/kv/**` | No OCI route uses `KvNamespace` or KV object PUT/GET. `kv/prefetch.rs` does run selected OCI prefetch before full-tag KV warmup and exposes `prefetch_oci_blob_bodies`. | Mostly KV adapter engine; one misplaced OCI startup/body hydration bridge. | Do not add OCI behavior here. Move selected-ref OCI prefetch and OCI body hydration entrypoints into `serve::engines::oci` when the blob/diagnostics engine lands. |
| `src/serve/cache_registry/kv_publish.rs` | No OCI call path. KV flush uses this to upload object-cache blobs. | KV-specific publish helper. | Leave out of OCI. OCI publish should continue through its own `PresentBlob` proof path. |
| `src/serve/cas_publish.rs` | Used by both KV flush and OCI manifest publish after `save_entry`. | Protocol-neutral CAS publish substrate: upload blobs, upload pointer/manifest, confirm. | Keep shared. OCI publish engine should call this helper rather than copy it. |
| `src/serve/state/blob_read_cache.rs` | OCI blob GET, mounted blob reuse, local body-cache proofs, and startup body hydration share this cache with KV object reads. | Protocol-neutral local byte cache. | Keep shared, but move `OciManifestCacheEntry` out of this file because manifest metadata is OCI-specific. |
| `src/serve/state/blob_locator.rs` | OCI manifest resolution seeds `(name, digest) -> cache_entry_id/download_url`; OCI blob GET refreshes and reads it. | OCI blob locator, not KV. | Move ownership toward `serve::engines::oci::blobs` with blob range/read-through work. |
| `src/serve/state/upload_sessions.rs` | OCI upload start/PATCH/final PUT, mount reuse, child-manifest staging, and local-body-cache proof materialization use this store. | OCI upload/session substrate. | Keep under OCI engine ownership; do not route through KV. |
| `src/serve/http/handlers/manifest.rs` | Owns descriptor extraction, content-type resolution, child expansion, digest-ref validation, referrers, and publish orchestration. | OCI behavior still sitting in HTTP handler. | Move semantic pieces into `serve::engines::oci::manifests` and publish orchestration into `serve::engines::oci::publish`. |
| `src/serve/http/handlers/blobs.rs` | Owns HEAD/GET locality, body cache lookup, locator URL refresh, remote read-through, and retry handling; currently no ranged GET support. | OCI blob behavior still sitting in HTTP handler. | Move to `serve::engines::oci::blobs`, add range semantics and diagnostics there. |
| `src/serve/runtime/mod.rs` and `src/serve/cache_registry::prefetch_manifest_blobs` | Runtime startup calls a KV-named prefetch function that first handles selected OCI refs, then full-tag KV warmup. | Mixed orchestration boundary. | Split startup prefetch into OCI selected-ref hydration and KV full-tag warmup so readiness diagnostics can name each path. |
| `src/serve/http/handlers/mod.rs` proxy status | Reports KV pending/flush settlement and OCI body metrics in one status payload. | Shared proxy status surface, not protocol truth. | Keep status unified, but feed it OCI diagnostics from the OCI engine and KV diagnostics from KV state. |

## Boundary Rule

KV remains justified for object-cache adapters such as sccache, Gradle, Maven, Turbo, Nx, Go, and Bazel. OCI should only share protocol-neutral substrate: local blob byte cache, backend blob URL resolution, transfer clients, CAS publish sequencing, metrics plumbing, and runtime task scheduling. OCI manifest graphs, blob range semantics, upload sessions, referrers, digest response metadata, and BuildKit cacheconfig behavior belong in `serve::engines::oci`.
