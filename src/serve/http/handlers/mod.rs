mod blobs;
pub(crate) mod manifest;
mod uploads;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use self::blobs::get_blob;
#[cfg(test)]
use self::manifest::{
    adaptive_blob_upload_concurrency, detect_manifest_content_type_for_tests,
    expand_manifest_blob_descriptors, extract_blob_descriptors,
    resolve_pushed_manifest_content_type_for_tests, stage_manifest_reference_uploads,
};
use self::manifest::{empty_referrers_response, get_manifest, get_referrers, put_manifest};
use self::uploads::{delete_upload, get_upload_status, patch_upload, put_upload, start_upload};
#[cfg(test)]
use self::uploads::{parse_put_upload_offset, parse_upload_offset};

use super::error::OciError;
use super::oci_route::{
    OciRoute, oci_cache_op_for_route_method, oci_miss_key, oci_success_rollup_result,
    parse_oci_path, record_oci_cache_op,
};
#[cfg(test)]
use super::oci_tags::{
    AliasBinding, alias_tags_for_manifest, scoped_restore_tags, scoped_save_tag,
};
#[cfg(test)]
use crate::cas_oci;
use crate::serve::cache_registry;
use crate::serve::state::{AppState, diagnostics_enabled};
#[cfg(test)]
use crate::serve::state::{OciManifestCacheEntry, digest_tag};

const OCI_DEGRADED_HEADER: &str = "X-BoringCache-Cache-Degraded";
const OCI_PREFETCH_STATE_HEADER: &str = "X-BoringCache-Prefetch-State";
const OCI_PREFETCH_STATE_READY: &str = "ready";
const OCI_PREFETCH_STATE_WARMING: &str = "warming";
const PROXY_PHASE_HEADER: &str = "X-BoringCache-Proxy-Phase";
const PROXY_PUBLISH_STATE_HEADER: &str = "X-BoringCache-Publish-State";

fn oci_request_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(diagnostics_enabled)
}

#[derive(Serialize)]
struct ProxyStatusResponse {
    phase: &'static str,
    publish_state: &'static str,
    publish_settled: bool,
    prefetch_complete: bool,
    prefetch_error: Option<String>,
    startup_prefetch: BTreeMap<String, String>,
    oci_body: BTreeMap<String, String>,
    oci_engine: BTreeMap<String, String>,
    oci_negative_cache: BTreeMap<String, String>,
    singleflight: BTreeMap<String, String>,
    shutdown_requested: bool,
    cache_entry_id: Option<String>,
    tags_visible: bool,
    pending_entries: usize,
    pending_blobs: usize,
    pending_spool_bytes: u64,
    flush_in_progress: bool,
}

pub async fn proxy_status(State(state): State<AppState>) -> impl IntoResponse {
    let prefetch_complete = state
        .prefetch_complete
        .load(std::sync::atomic::Ordering::Acquire);
    let prefetch_error = state.prefetch_error.read().await.clone();
    let startup_prefetch = state.prefetch_metrics.metadata_hints();
    let oci_body = state.oci_body_metrics.metadata_hints();
    let oci_engine = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    let oci_negative_cache = state.oci_negative_cache.metadata_hints();
    let singleflight = state.singleflight_metrics.metadata_hints();
    let shutdown_requested = state
        .shutdown_requested
        .load(std::sync::atomic::Ordering::Acquire);
    let phase = if shutdown_requested {
        "draining"
    } else if prefetch_error.is_some() {
        "error"
    } else if prefetch_complete {
        "ready"
    } else {
        "warming"
    };

    let (pending_entries, pending_blobs, pending_spool_bytes) = {
        let pending = state.kv_pending.read().await;
        (
            pending.entry_count(),
            pending.blob_count(),
            pending.total_spool_bytes(),
        )
    };
    let flush_in_progress = state.kv_flushing.read().await.is_some();
    let cache_entry_id = {
        let published = state.kv_published_index.read().await;
        published.cache_entry_id().map(str::to_string)
    };
    let tags_visible = match cache_entry_id.as_deref() {
        Some(cache_entry_id) => {
            cache_registry::kv_publish_tags_visible(&state, cache_entry_id).await
        }
        None => true,
    };
    let publish_settled = pending_entries == 0 && !flush_in_progress && tags_visible;
    let publish_state = if publish_settled {
        "settled"
    } else {
        "pending"
    };

    (
        [
            ("Cache-Control", "no-store"),
            (PROXY_PHASE_HEADER, phase),
            (PROXY_PUBLISH_STATE_HEADER, publish_state),
        ],
        Json(ProxyStatusResponse {
            phase,
            publish_state,
            publish_settled,
            prefetch_complete,
            prefetch_error,
            startup_prefetch,
            oci_body,
            oci_engine,
            oci_negative_cache,
            singleflight,
            shutdown_requested,
            cache_entry_id,
            tags_visible,
            pending_entries,
            pending_blobs,
            pending_spool_bytes,
            flush_in_progress,
        }),
    )
}

pub async fn v2_base(State(state): State<AppState>) -> impl IntoResponse {
    if !state
        .prefetch_complete
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return (
            StatusCode::OK,
            [
                ("Docker-Distribution-API-Version", "registry/2.0"),
                (OCI_PREFETCH_STATE_HEADER, OCI_PREFETCH_STATE_WARMING),
            ],
            "",
        );
    }
    (
        StatusCode::OK,
        [
            ("Docker-Distribution-API-Version", "registry/2.0"),
            (OCI_PREFETCH_STATE_HEADER, OCI_PREFETCH_STATE_READY),
        ],
        "",
    )
}

pub async fn oci_dispatch(
    method: Method,
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, OciError> {
    let request_method = method.clone();
    let request_path = format!("/v2/{path}");
    let request_start = Instant::now();
    if oci_request_log_enabled() {
        eprintln!("REQUEST: {} {}", request_method, request_path);
    }
    let fail_on_cache_error = state.fail_on_cache_error;
    let route = match parse_oci_path(&path) {
        Some(route) => route,
        None => return Err(OciError::name_unknown("not found")),
    };
    let maybe_cache_op = oci_cache_op_for_route_method(&route, &request_method);
    let miss_key = oci_miss_key(&route);
    if oci_request_log_enabled() {
        eprintln!("OCI {} {}", request_method, request_path);
    }

    let response = match route.clone() {
        OciRoute::Manifest { name, reference } => match method {
            Method::GET | Method::HEAD => {
                get_manifest(method, state.clone(), name, reference).await
            }
            Method::PUT => put_manifest(state.clone(), name, reference, headers, body).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        OciRoute::Referrers { name, digest } => match method {
            Method::GET | Method::HEAD => {
                get_referrers(method, state.clone(), name, digest, params).await
            }
            _ => Err(OciError::unsupported("method not allowed")),
        },
        OciRoute::Blob { name, digest } => match method {
            Method::GET | Method::HEAD => {
                get_blob(method, headers, state.clone(), name, digest).await
            }
            _ => Err(OciError::unsupported("method not allowed")),
        },
        OciRoute::BlobUploadStart { name } => match method {
            Method::POST => start_upload(state.clone(), name, params, body).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        OciRoute::BlobUpload { name, uuid } => match method {
            Method::GET => get_upload_status(state.clone(), name, uuid).await,
            Method::PATCH => patch_upload(state.clone(), name, uuid, headers, body).await,
            Method::PUT => put_upload(state.clone(), name, uuid, params, headers, body).await,
            Method::DELETE => delete_upload(state.clone(), uuid).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
    };

    match response {
        Ok(response) => {
            let response_status = response.status();
            if request_method != Method::GET
                && request_method != Method::HEAD
                && !response_status.is_success()
            {
                eprintln!(
                    "OCI {} {} -> {}",
                    request_method, request_path, response_status
                );
            }
            if let Some(op) = maybe_cache_op {
                let (result, degraded) = oci_success_rollup_result(&response, OCI_DEGRADED_HEADER);
                let bytes = response
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                record_oci_cache_op(
                    &state,
                    op,
                    result,
                    degraded,
                    bytes,
                    request_start.elapsed().as_millis() as u64,
                    None,
                );
            }
            Ok(response)
        }
        Err(error) => {
            let error_status = error.status();
            if fail_on_cache_error || !error_status.is_server_error() {
                eprintln!(
                    "OCI {} {} -> {} ({})",
                    request_method,
                    request_path,
                    error_status,
                    error.message()
                );
                if let Some(op) = maybe_cache_op {
                    let result = if error_status == StatusCode::NOT_FOUND
                        && op == crate::serve::cache_registry::cache_ops::Op::Get
                    {
                        crate::serve::cache_registry::cache_ops::OpResult::Miss
                    } else {
                        crate::serve::cache_registry::cache_ops::OpResult::Error
                    };
                    record_oci_cache_op(
                        &state,
                        op,
                        result,
                        false,
                        0,
                        request_start.elapsed().as_millis() as u64,
                        miss_key.as_deref(),
                    );
                }
                return Err(error);
            }
            if request_method != Method::GET && request_method != Method::HEAD {
                eprintln!(
                    "OCI {} {} -> {} ({})",
                    request_method,
                    request_path,
                    error_status,
                    error.message()
                );
                if let Some(op) = maybe_cache_op {
                    record_oci_cache_op(
                        &state,
                        op,
                        crate::serve::cache_registry::cache_ops::OpResult::Error,
                        false,
                        0,
                        request_start.elapsed().as_millis() as u64,
                        None,
                    );
                }
                return Err(error);
            }
            let warning = format!(
                "Best-effort OCI fallback on {} {} ({})",
                request_method, request_path, error_status
            );
            eprintln!("{warning}");
            log::warn!("{warning}");
            if let Some(op) = maybe_cache_op {
                record_oci_cache_op(
                    &state,
                    op,
                    crate::serve::cache_registry::cache_ops::OpResult::Error,
                    true,
                    0,
                    request_start.elapsed().as_millis() as u64,
                    None,
                );
            }
            best_effort_oci_read_response(&route)
        }
    }
}

fn best_effort_oci_read_response(route: &OciRoute) -> Result<Response, OciError> {
    match route {
        OciRoute::Manifest { name, reference } => {
            Err(OciError::manifest_unknown(format!("{name}:{reference}")))
        }
        OciRoute::Referrers { .. } => empty_referrers_response(Method::GET, None),
        OciRoute::Blob { name, digest } => Err(OciError::blob_unknown(format!("{name}@{digest}"))),
        OciRoute::BlobUploadStart { .. } => Err(OciError::name_unknown("not found")),
        OciRoute::BlobUpload { name, uuid } => {
            Err(OciError::blob_upload_unknown(format!("{name}:{uuid}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::client::ApiClient;
    use crate::api::models::cache::BlobDescriptor;
    use crate::git::GitContext;
    use crate::platform::Platform;
    use crate::serve::engines::oci::{
        PresentBlob, PresentBlobSource, ensure_manifest_blobs_present,
    };
    use crate::serve::state::{
        BlobLocatorCache, BlobReadCache, BlobReadMetrics, KvPendingStore, KvPublishedIndex,
        UploadSession, UploadSessionBody, UploadSessionStore, ref_tag_for_input,
    };
    use crate::tag_utils::TagResolver;
    use axum::body::Bytes;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::RwLock;

    fn test_state() -> AppState {
        let (kv_replication_work_tx, _kv_replication_work_rx) =
            tokio::sync::mpsc::channel(crate::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY);
        let runtime_temp_dir = std::env::temp_dir().join(format!(
            "boringcache-handler-runtime-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(runtime_temp_dir.join("kv-blobs")).expect("kv blob temp dir");
        std::fs::create_dir_all(runtime_temp_dir.join("oci-uploads")).expect("oci upload temp dir");
        AppState {
            api_client: ApiClient::new_with_token_override(Some("test-token".to_string()))
                .expect("api client"),
            workspace: "boringcache/benchmarks".to_string(),
            started_at: Instant::now(),
            runtime_temp_dir: runtime_temp_dir.clone(),
            kv_blob_temp_dir: runtime_temp_dir.join("kv-blobs"),
            oci_upload_temp_dir: runtime_temp_dir.join("oci-uploads"),
            read_only: false,
            tag_resolver: TagResolver::new(None, GitContext::default(), false),
            configured_human_tags: Vec::new(),
            registry_root_tag: "registry".to_string(),
            oci_alias_promotion_refs: Vec::new(),
            proxy_metadata_hints: std::collections::BTreeMap::new(),
            fail_on_cache_error: true,
            oci_hydration_policy: crate::serve::OciHydrationPolicy::MetadataOnly,
            blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
            upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
            kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
            kv_flush_lock: Arc::new(tokio::sync::Mutex::new(())),
            kv_lookup_inflight: Arc::new(dashmap::DashMap::new()),
            oci_lookup_inflight: Arc::new(dashmap::DashMap::new()),
            oci_negative_cache: Arc::new(crate::serve::state::OciNegativeCache::new()),
            singleflight_metrics: Arc::new(crate::serve::state::SingleflightMetrics::new()),
            kv_last_put: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_backlog_rejects: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_enqueue_deferred: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_conflict: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_error: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_permanent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_queue_depth: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_work_tx,
            kv_next_flush_at: Arc::new(RwLock::new(None)),
            kv_flush_scheduled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            kv_published_index: Arc::new(RwLock::new(KvPublishedIndex::default())),
            kv_flushing: Arc::new(RwLock::new(None)),
            shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            kv_recent_misses: Arc::new(dashmap::DashMap::new()),
            kv_miss_generations: Arc::new(dashmap::DashMap::new()),
            blob_read_cache: Arc::new(
                BlobReadCache::new_at(
                    std::env::temp_dir().join(format!(
                        "boringcache-handler-blob-cache-{}",
                        uuid::Uuid::new_v4()
                    )),
                    2 * 1024 * 1024 * 1024,
                )
                .expect("blob read cache"),
            ),
            blob_read_metrics: Arc::new(BlobReadMetrics::new()),
            oci_body_metrics: Arc::new(crate::serve::state::OciBodyMetrics::new()),
            oci_engine_diagnostics: Arc::new(crate::serve::state::OciEngineDiagnostics::new()),
            prefetch_metrics: Arc::new(crate::serve::state::PrefetchMetrics::new()),
            blob_download_max_concurrency: 16,
            blob_download_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
            blob_prefetch_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
            cache_ops: Arc::new(crate::serve::cache_registry::cache_ops::Aggregator::new()),
            oci_manifest_cache: Arc::new(dashmap::DashMap::new()),
            backend_breaker: Arc::new(crate::serve::state::BackendCircuitBreaker::new()),
            prefetch_complete: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prefetch_complete_notify: Arc::new(tokio::sync::Notify::new()),
            prefetch_error: Arc::new(RwLock::new(None)),
        }
    }

    async fn write_temp_upload_file(contents: &[u8]) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("boringcache-upload-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.expect("temp dir");
        let path = dir.join("blob.bin");
        tokio::fs::write(&path, contents).await.expect("temp file");
        path
    }

    async fn read_upload_session_body(session: &UploadSession) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let mut file = tokio::fs::File::open(session.body_path())
            .await
            .expect("open upload session body");
        if session.body_offset() > 0 {
            file.seek(std::io::SeekFrom::Start(session.body_offset()))
                .await
                .expect("seek upload session body");
        }
        let mut bytes = vec![0u8; session.body_size() as usize];
        file.read_exact(&mut bytes)
            .await
            .expect("read upload session body");
        bytes
    }

    #[test]
    fn parse_single_segment_manifest() {
        match parse_oci_path("my-cache/manifests/main") {
            Some(OciRoute::Manifest { name, reference }) => {
                assert_eq!(name, "my-cache");
                assert_eq!(reference, "main");
            }
            _ => panic!("expected Manifest"),
        }
    }

    #[test]
    fn parse_multi_segment_manifest() {
        match parse_oci_path("org/cache/manifests/latest") {
            Some(OciRoute::Manifest { name, reference }) => {
                assert_eq!(name, "org/cache");
                assert_eq!(reference, "latest");
            }
            _ => panic!("expected Manifest"),
        }
    }

    #[test]
    fn parse_deeply_nested_name() {
        match parse_oci_path("a/b/c/blobs/sha256:abc") {
            Some(OciRoute::Blob { name, digest }) => {
                assert_eq!(name, "a/b/c");
                assert_eq!(digest, "sha256:abc");
            }
            _ => panic!("expected Blob"),
        }
    }

    #[test]
    fn parse_referrers_route() {
        match parse_oci_path("org/cache/referrers/sha256:abc") {
            Some(OciRoute::Referrers { name, digest }) => {
                assert_eq!(name, "org/cache");
                assert_eq!(digest, "sha256:abc");
            }
            _ => panic!("expected Referrers"),
        }
    }

    #[test]
    fn oci_success_rollup_without_degraded_header_is_hit() {
        let response = (StatusCode::CREATED, Body::empty()).into_response();
        let (result, degraded) = oci_success_rollup_result(&response, OCI_DEGRADED_HEADER);
        assert_eq!(
            result,
            crate::serve::cache_registry::cache_ops::OpResult::Hit
        );
        assert!(!degraded);
    }

    #[test]
    fn oci_success_rollup_with_degraded_header_is_error() {
        let response = (
            StatusCode::CREATED,
            [(OCI_DEGRADED_HEADER, "1")],
            Body::empty(),
        )
            .into_response();
        let (result, degraded) = oci_success_rollup_result(&response, OCI_DEGRADED_HEADER);
        assert_eq!(
            result,
            crate::serve::cache_registry::cache_ops::OpResult::Error
        );
        assert!(degraded);
    }

    #[test]
    fn oci_success_rollup_with_non_success_response_is_error() {
        let response = (StatusCode::RANGE_NOT_SATISFIABLE, Body::empty()).into_response();
        let (result, degraded) = oci_success_rollup_result(&response, OCI_DEGRADED_HEADER);
        assert_eq!(
            result,
            crate::serve::cache_registry::cache_ops::OpResult::Error
        );
        assert!(!degraded);
    }

    #[tokio::test]
    async fn oci_dispatch_records_blob_miss_rollup_and_missed_key() {
        let state = test_state();
        let result = oci_dispatch(
            Method::GET,
            State(state.clone()),
            Path(
                "cache/blobs/sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_string(),
            ),
            Query(HashMap::new()),
            HeaderMap::new(),
            Body::empty(),
        )
        .await;

        let error = result.expect_err("blob should be missing");
        assert_eq!(error.status(), StatusCode::NOT_FOUND);

        let (rollups, missed, sessions) = state.cache_ops.drain();
        assert!(sessions.is_empty());
        let miss_rollup = rollups
            .iter()
            .find(|record| {
                record.tool == "oci" && record.operation == "get" && record.result == "miss"
            })
            .expect("expected oci miss rollup");
        assert_eq!(miss_rollup.event_count, 1);

        let miss_key = missed
            .iter()
            .find(|record| record.tool == "oci")
            .expect("expected oci missed key");
        assert_eq!(miss_key.miss_count, 1);
    }

    #[tokio::test]
    async fn put_upload_allows_local_reuse_when_finalize_payload_is_empty() {
        let state = test_state();
        let digest = cas_oci::prefixed_sha256_digest(b"existing payload");
        let filled_path = write_temp_upload_file(b"existing payload").await;
        let empty_path = write_temp_upload_file(&[]).await;

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "filled-session".to_string(),
                name: "cache".to_string(),
                temp_path: filled_path.clone(),
                body: UploadSessionBody::OwnedTempFile,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 16,
                finalized_digest: Some(digest.clone()),
                finalized_size: Some(16),
                created_at: Instant::now(),
            });
            sessions.create(UploadSession {
                id: "empty-session".to_string(),
                name: "cache".to_string(),
                temp_path: empty_path.clone(),
                body: UploadSessionBody::OwnedTempFile,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 0,
                finalized_digest: None,
                finalized_size: None,
                created_at: Instant::now(),
            });
        }

        let mut params = HashMap::new();
        params.insert("digest".to_string(), digest.clone());
        let response = put_upload(
            state.clone(),
            "cache".to_string(),
            "empty-session".to_string(),
            params,
            HeaderMap::new(),
            Body::empty(),
        )
        .await
        .expect("put upload should succeed via local reuse");

        assert_eq!(response.status(), StatusCode::CREATED);
        let sessions = state.upload_sessions.read().await;
        let empty = sessions.get("empty-session").expect("empty session");
        assert_eq!(empty.finalized_digest.as_deref(), Some(digest.as_str()));

        let _ = tokio::fs::remove_file(&filled_path).await;
        let _ = tokio::fs::remove_file(&empty_path).await;
    }

    #[tokio::test]
    async fn start_upload_mount_returns_created_for_existing_local_digest() {
        let state = test_state();
        let digest = cas_oci::prefixed_sha256_digest(b"mount-existing");
        let filled_path = write_temp_upload_file(b"mount-existing").await;

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "filled-session".to_string(),
                name: "cache".to_string(),
                temp_path: filled_path.clone(),
                body: UploadSessionBody::OwnedTempFile,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 14,
                finalized_digest: Some(digest.clone()),
                finalized_size: Some(14),
                created_at: Instant::now(),
            });
        }

        let mut params = HashMap::new();
        params.insert("mount".to_string(), digest.clone());
        params.insert("from".to_string(), "cache".to_string());

        let response = start_upload(state, "cache".to_string(), params, Body::empty())
            .await
            .expect("start upload mount should reuse local blob");
        assert_eq!(response.status(), StatusCode::CREATED);

        let _ = tokio::fs::remove_file(&filled_path).await;
    }

    #[tokio::test]
    async fn blob_head_uses_prefetched_local_blob_without_locator_entry() {
        let state = test_state();
        let payload = b"prefetched-oci-blob";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        state
            .blob_read_cache
            .insert(&digest, payload)
            .await
            .expect("insert prefetched blob");

        let response = get_blob(
            Method::HEAD,
            HeaderMap::new(),
            state,
            "cache".to_string(),
            digest.clone(),
        )
        .await
        .expect("head should use prefetched local blob");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Docker-Content-Digest")
                .and_then(|value| value.to_str().ok()),
            Some(digest.as_str())
        );
        assert_eq!(
            response
                .headers()
                .get("Content-Length")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            Some(payload.len().to_string())
        );
    }

    #[tokio::test]
    async fn start_upload_mount_reuses_prefetched_local_blob() {
        let state = test_state();
        let payload = b"prefetched-mount";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        state
            .blob_read_cache
            .insert(&digest, payload)
            .await
            .expect("insert prefetched blob");

        let mut params = HashMap::new();
        params.insert("mount".to_string(), digest.clone());
        params.insert("from".to_string(), "cache".to_string());

        let response = start_upload(state.clone(), "cache".to_string(), params, Body::empty())
            .await
            .expect("start upload mount should reuse prefetched blob");

        assert_eq!(response.status(), StatusCode::CREATED);

        let sessions = state.upload_sessions.read().await;
        let mounted = sessions
            .find_by_name_and_digest("cache", &digest)
            .expect("mount should create publish session");
        assert_eq!(mounted.finalized_size, Some(payload.len() as u64));
        assert_eq!(read_upload_session_body(mounted).await, payload);
        assert!(!mounted.owns_temp_file());
    }

    #[tokio::test]
    async fn delete_upload_releases_borrowed_session_without_deleting_cache_body() {
        let state = test_state();
        let payload = b"borrowed-delete";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        state
            .blob_read_cache
            .insert(&digest, payload)
            .await
            .expect("insert prefetched blob");

        let mut params = HashMap::new();
        params.insert("mount".to_string(), digest.clone());
        params.insert("from".to_string(), "cache".to_string());
        let response = start_upload(state.clone(), "cache".to_string(), params, Body::empty())
            .await
            .expect("start upload mount should reuse prefetched blob");
        assert_eq!(response.status(), StatusCode::CREATED);

        let (session_id, body_path) = {
            let sessions = state.upload_sessions.read().await;
            let session = sessions
                .find_by_name_and_digest("cache", &digest)
                .expect("borrowed session");
            assert!(!session.owns_temp_file());
            (session.id.clone(), session.body_path().to_path_buf())
        };

        let response = delete_upload(state.clone(), session_id.clone())
            .await
            .expect("delete borrowed session");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let sessions = state.upload_sessions.read().await;
        assert!(sessions.get(&session_id).is_none());
        drop(sessions);
        assert!(tokio::fs::metadata(&body_path).await.is_ok());
        assert!(state.blob_read_cache.get_handle(&digest).await.is_some());
    }

    #[tokio::test]
    async fn published_owned_upload_session_is_promoted_to_body_cache() {
        let state = test_state();
        let payload = b"published-upload-body";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        let temp_path = write_temp_upload_file(payload).await;
        let session_id = "upload-session-promote".to_string();

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession::owned_temp_file(
                session_id.clone(),
                "cache".to_string(),
                temp_path,
                payload.len() as u64,
                Some(digest.clone()),
                Some(payload.len() as u64),
            ));
        }

        crate::serve::engines::oci::publish::cleanup_present_blob_sessions(
            &state,
            &[PresentBlob {
                digest: digest.clone(),
                size_bytes: payload.len() as u64,
                source: PresentBlobSource::UploadSession,
                upload_session_id: Some(session_id.clone()),
            }],
        )
        .await;

        let sessions = state.upload_sessions.read().await;
        assert!(sessions.get(&session_id).is_none());
        drop(sessions);

        let handle = state
            .blob_read_cache
            .get_handle(&digest)
            .await
            .expect("published body should be promoted to read cache");
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut file = tokio::fs::File::open(handle.path())
            .await
            .expect("open promoted body");
        if handle.offset() > 0 {
            file.seek(std::io::SeekFrom::Start(handle.offset()))
                .await
                .expect("seek promoted body");
        }
        let mut restored = vec![0; handle.size_bytes() as usize];
        file.read_exact(&mut restored)
            .await
            .expect("read promoted body");
        assert_eq!(restored, payload);
    }

    #[tokio::test]
    async fn manifest_availability_stages_local_body_cache_for_publish() {
        let state = test_state();
        let payload = b"local-body-cache-publish";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        state
            .blob_read_cache
            .insert(&digest, payload)
            .await
            .expect("insert local body cache blob");

        let present = ensure_manifest_blobs_present(
            &state,
            "cache",
            &[BlobDescriptor {
                digest: digest.clone(),
                size_bytes: payload.len() as u64,
            }],
        )
        .await
        .expect("local body cache should prove descriptor availability");

        assert_eq!(present.len(), 1);
        assert_eq!(present[0].source, PresentBlobSource::LocalBodyCache);

        let staged_body = {
            let sessions = state.upload_sessions.read().await;
            let session = sessions
                .find_by_name_and_digest("cache", &digest)
                .expect("local body cache should be staged as upload session");
            assert!(!session.owns_temp_file());
            read_upload_session_body(session).await
        };
        assert_eq!(staged_body, payload);
    }

    #[tokio::test]
    async fn manifest_availability_rejects_local_body_cache_size_mismatch() {
        let state = test_state();
        let payload = b"wrong-size-local-body-cache";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        state
            .blob_read_cache
            .insert(&digest, payload)
            .await
            .expect("insert local body cache blob");

        let error = ensure_manifest_blobs_present(
            &state,
            "cache",
            &[BlobDescriptor {
                digest: digest.clone(),
                size_bytes: payload.len() as u64 + 1,
            }],
        )
        .await
        .expect_err("descriptor size mismatch should fail");

        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert!(error.message().contains("descriptor size mismatch"));
    }

    #[tokio::test]
    async fn start_upload_mount_from_existing_session_stages_target_session() {
        let state = test_state();
        let payload = b"source-repo-mount";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        let source_path = write_temp_upload_file(payload).await;

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "source-session".to_string(),
                name: "source".to_string(),
                temp_path: source_path.clone(),
                body: UploadSessionBody::OwnedTempFile,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: payload.len() as u64,
                finalized_digest: Some(digest.clone()),
                finalized_size: Some(payload.len() as u64),
                created_at: Instant::now(),
            });
        }

        let mut params = HashMap::new();
        params.insert("mount".to_string(), digest.clone());
        params.insert("from".to_string(), "source".to_string());

        let response = start_upload(state.clone(), "cache".to_string(), params, Body::empty())
            .await
            .expect("start upload mount should stage target session");

        assert_eq!(response.status(), StatusCode::CREATED);

        let target_path = {
            let sessions = state.upload_sessions.read().await;
            let mounted = sessions
                .find_by_name_and_digest("cache", &digest)
                .expect("mount should stage target session");
            assert_eq!(mounted.finalized_size, Some(payload.len() as u64));
            mounted.temp_path.clone()
        };
        assert_eq!(
            tokio::fs::read(&target_path).await.expect("mounted copy"),
            payload
        );

        let _ = tokio::fs::remove_file(&source_path).await;
        let _ = tokio::fs::remove_file(&target_path).await;
    }

    #[tokio::test]
    async fn concurrent_start_upload_mounts_stage_one_target_session() {
        let state = test_state();
        let payload = b"prefetched-concurrent-mount";
        let digest = cas_oci::prefixed_sha256_digest(payload);
        state
            .blob_read_cache
            .insert(&digest, payload)
            .await
            .expect("insert prefetched blob");

        let mut tasks = Vec::new();
        for _ in 0..12 {
            let state = state.clone();
            let digest = digest.clone();
            tasks.push(tokio::spawn(async move {
                let mut params = HashMap::new();
                params.insert("mount".to_string(), digest);
                params.insert("from".to_string(), "source".to_string());
                start_upload(state, "cache".to_string(), params, Body::empty()).await
            }));
        }

        for task in tasks {
            let response = task
                .await
                .expect("mount task should complete")
                .expect("mount request should succeed");
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let staged_body = {
            let sessions = state.upload_sessions.read().await;
            let mounted = sessions
                .find_by_name_and_digest("cache", &digest)
                .expect("mount should stage target session");
            assert_eq!(mounted.finalized_size, Some(payload.len() as u64));
            assert!(!mounted.owns_temp_file());
            read_upload_session_body(mounted).await
        };
        assert_eq!(staged_body, payload);
    }

    #[tokio::test]
    async fn put_upload_retries_local_reuse_before_remote_lookup() {
        let state = test_state();
        let digest = cas_oci::prefixed_sha256_digest(b"delayed payload");
        let delayed_path = write_temp_upload_file(b"delayed payload").await;
        let empty_path = write_temp_upload_file(&[]).await;

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "delayed-session".to_string(),
                name: "cache".to_string(),
                temp_path: delayed_path.clone(),
                body: UploadSessionBody::OwnedTempFile,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 0,
                finalized_digest: None,
                finalized_size: None,
                created_at: Instant::now(),
            });
            sessions.create(UploadSession {
                id: "empty-session".to_string(),
                name: "cache".to_string(),
                temp_path: empty_path.clone(),
                body: UploadSessionBody::OwnedTempFile,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 0,
                finalized_digest: None,
                finalized_size: None,
                created_at: Instant::now(),
            });
        }

        let state_for_finalize = state.clone();
        let digest_for_finalize = digest.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let mut sessions = state_for_finalize.upload_sessions.write().await;
            let session = sessions
                .get_mut("delayed-session")
                .expect("delayed session exists");
            session.bytes_received = 15;
            session.finalized_size = Some(15);
            session.finalized_digest = Some(digest_for_finalize);
        });

        let mut params = HashMap::new();
        params.insert("digest".to_string(), digest.clone());
        let response = put_upload(
            state,
            "cache".to_string(),
            "empty-session".to_string(),
            params,
            HeaderMap::new(),
            Body::empty(),
        )
        .await
        .expect("empty finalize should reuse delayed local digest");

        assert_eq!(response.status(), StatusCode::CREATED);

        let _ = tokio::fs::remove_file(&delayed_path).await;
        let _ = tokio::fs::remove_file(&empty_path).await;
    }

    #[tokio::test]
    async fn put_upload_returns_internal_error_on_body_stream_error() {
        let state = test_state();
        let path = write_temp_upload_file(&[]).await;
        let digest = cas_oci::prefixed_sha256_digest(b"payload");

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "stream-error-session".to_string(),
                name: "cache".to_string(),
                temp_path: path.clone(),
                body: UploadSessionBody::OwnedTempFile,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 0,
                finalized_digest: None,
                finalized_size: None,
                created_at: Instant::now(),
            });
        }

        let mut params = HashMap::new();
        params.insert("digest".to_string(), digest);

        let body = Body::from_stream(futures_util::stream::once(async {
            let error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
            Err::<Bytes, std::io::Error>(error)
        }));

        let error = put_upload(
            state,
            "cache".to_string(),
            "stream-error-session".to_string(),
            params,
            HeaderMap::new(),
            body,
        )
        .await
        .expect_err("stream error should fail finalize");

        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(error.message().contains("body stream error"));

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[test]
    fn parse_blob_upload_start() {
        match parse_oci_path("my-cache/blobs/uploads/") {
            Some(OciRoute::BlobUploadStart { name }) => {
                assert_eq!(name, "my-cache");
            }
            _ => panic!("expected BlobUploadStart"),
        }
    }

    #[test]
    fn parse_blob_upload_start_without_trailing_slash() {
        match parse_oci_path("my-cache/blobs/uploads") {
            Some(OciRoute::BlobUploadStart { name }) => {
                assert_eq!(name, "my-cache");
            }
            _ => panic!("expected BlobUploadStart"),
        }
    }

    #[test]
    fn parse_blob_upload_uuid() {
        match parse_oci_path("my-cache/blobs/uploads/some-uuid-here") {
            Some(OciRoute::BlobUpload { name, uuid }) => {
                assert_eq!(name, "my-cache");
                assert_eq!(uuid, "some-uuid-here");
            }
            _ => panic!("expected BlobUpload"),
        }
    }

    #[test]
    fn parse_blob_upload_uuid_uses_last_upload_marker() {
        match parse_oci_path("org/blobs/uploads/cache/blobs/uploads/some-uuid-here") {
            Some(OciRoute::BlobUpload { name, uuid }) => {
                assert_eq!(name, "org/blobs/uploads/cache");
                assert_eq!(uuid, "some-uuid-here");
            }
            _ => panic!("expected BlobUpload"),
        }
    }

    #[test]
    fn parse_blob_route_uses_last_blob_marker() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path = format!("org/blobs/cache/blobs/{digest}");
        match parse_oci_path(&path) {
            Some(OciRoute::Blob {
                name,
                digest: parsed_digest,
            }) => {
                assert_eq!(name, "org/blobs/cache");
                assert_eq!(parsed_digest, digest);
            }
            _ => panic!("expected Blob"),
        }
    }

    #[test]
    fn parse_leading_slash_stripped() {
        match parse_oci_path("/my-cache/manifests/v1") {
            Some(OciRoute::Manifest { name, reference }) => {
                assert_eq!(name, "my-cache");
                assert_eq!(reference, "v1");
            }
            _ => panic!("expected Manifest"),
        }
    }

    #[test]
    fn parse_invalid_path_returns_none() {
        assert!(parse_oci_path("").is_none());
        assert!(parse_oci_path("just-a-name").is_none());
        assert!(parse_oci_path("/manifests/ref").is_none());
    }

    #[test]
    fn parse_upload_offset_prefers_range_start() {
        let mut headers = HeaderMap::new();
        headers.insert("Range", "0-1023".parse().unwrap());
        assert_eq!(parse_upload_offset(&headers), Some(0));
    }

    #[test]
    fn parse_put_upload_offset_uses_content_range_start() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Range", "bytes 4096-8191".parse().unwrap());
        assert_eq!(parse_put_upload_offset(&headers, 4096), Ok(Some(4096)));
    }

    #[test]
    fn parse_put_upload_offset_uses_range_end_for_finalize() {
        let mut headers = HeaderMap::new();
        headers.insert("Range", "0-8191".parse().unwrap());
        assert_eq!(parse_put_upload_offset(&headers, 8192), Ok(Some(8192)));
    }

    #[test]
    fn parse_put_upload_offset_clamps_empty_range_to_current_size() {
        let mut headers = HeaderMap::new();
        headers.insert("Range", "0-0".parse().unwrap());
        assert_eq!(parse_put_upload_offset(&headers, 1), Ok(Some(1)));
    }

    #[test]
    fn extract_blob_descriptors_includes_child_manifests_for_index() {
        let index_json = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 500, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
                {"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "size": 600, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
            ]
        });
        let blobs = extract_blob_descriptors(&index_json).unwrap();
        assert_eq!(blobs.len(), 2);
        assert_eq!(
            blobs[0].digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            blobs[1].digest,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn extract_blob_descriptors_includes_config_and_layers() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 100},
            "layers": [
                {"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "size": 2000},
                {"digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "size": 3000}
            ]
        });
        let blobs = extract_blob_descriptors(&manifest_json).unwrap();
        assert_eq!(blobs.len(), 3);
        assert_eq!(
            blobs[0].digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            blobs[1].digest,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            blobs[2].digest,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn extract_blob_descriptors_dedupes_by_digest() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
            "layers": [
                {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
                {"digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "size": 3000}
            ]
        });

        let blobs = extract_blob_descriptors(&manifest_json).unwrap();
        assert_eq!(blobs.len(), 2);
        assert_eq!(
            blobs[0].digest,
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            blobs[1].digest,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
    }

    #[test]
    fn extract_blob_descriptors_rejects_conflicting_sizes_for_same_digest() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
            "layers": [
                {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 64}
            ]
        });

        let error = extract_blob_descriptors(&manifest_json).unwrap_err();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn extract_blob_descriptors_rejects_invalid_digest_format() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:not-a-real-digest", "size": 32},
            "layers": []
        });

        let error = extract_blob_descriptors(&manifest_json).unwrap_err();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn detect_manifest_content_type_prefers_declared_media_type() {
        let docker_manifest = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 32
            },
            "layers": []
        }"#;

        assert_eq!(
            detect_manifest_content_type_for_tests(docker_manifest),
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn resolve_pushed_manifest_content_type_prefers_header_when_body_omits_media_type() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "manifests": []
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.docker.distribution.manifest.list.v2+json"
                .parse()
                .unwrap(),
        );

        assert_eq!(
            resolve_pushed_manifest_content_type_for_tests(&headers, &manifest_json).unwrap(),
            "application/vnd.docker.distribution.manifest.list.v2+json"
        );
    }

    #[test]
    fn resolve_pushed_manifest_content_type_rejects_header_media_type_mismatch() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": []
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.docker.distribution.manifest.list.v2+json"
                .parse()
                .unwrap(),
        );

        let error =
            resolve_pushed_manifest_content_type_for_tests(&headers, &manifest_json).unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert!(
            error
                .message()
                .contains("does not match declared mediaType")
        );
    }

    #[tokio::test]
    async fn expand_manifest_blob_descriptors_skips_non_manifest_entries_in_manifests_array() {
        let state = test_state();
        let layer_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cache_config_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let manifest_list = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [
                {
                    "digest": layer_digest,
                    "size": 128,
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"
                },
                {
                    "digest": cache_config_digest,
                    "size": 64,
                    "mediaType": "application/vnd.buildkit.cacheconfig.v0"
                }
            ]
        });

        let blobs = expand_manifest_blob_descriptors(&state, "cache", &manifest_list)
            .await
            .expect("expand top-level descriptors without recursing into non-manifests");
        let digests: Vec<&str> = blobs.iter().map(|blob| blob.digest.as_str()).collect();

        assert_eq!(blobs.len(), 2);
        assert!(digests.contains(&layer_digest));
        assert!(digests.contains(&cache_config_digest));
    }

    #[tokio::test]
    async fn stage_manifest_reference_uploads_ignores_non_manifest_entries() {
        let state = test_state();
        let layer_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cache_config_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let manifest_list = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [
                {
                    "digest": layer_digest,
                    "size": 128,
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"
                },
                {
                    "digest": cache_config_digest,
                    "size": 64,
                    "mediaType": "application/vnd.buildkit.cacheconfig.v0"
                }
            ]
        });

        let blob_descriptors = extract_blob_descriptors(&manifest_list).unwrap();
        stage_manifest_reference_uploads(&state, "cache", &blob_descriptors, &manifest_list)
            .await
            .expect("ignore non-manifest top-level descriptors");

        let sessions = state.upload_sessions.read().await;
        assert!(
            sessions.find_by_digest(layer_digest).is_none(),
            "layer descriptor should not be staged as a manifest upload"
        );
        assert!(
            sessions.find_by_digest(cache_config_digest).is_none(),
            "cache config descriptor should not be staged as a manifest upload"
        );
    }

    #[tokio::test]
    async fn expand_manifest_blob_descriptors_includes_child_manifest_descendants() {
        let state = test_state();
        let child_config_digest =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let child_layer_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let child_manifest = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{"digest": "{child_config_digest}", "size": 12}},
                "layers": [
                    {{"digest": "{child_layer_digest}", "size": 34}}
                ]
            }}"#
        );
        let child_digest = cas_oci::prefixed_sha256_digest(child_manifest.as_bytes());
        let child_size = child_manifest.len() as u64;
        let child_tag = digest_tag(&child_digest);
        state.oci_manifest_cache.insert(
            child_tag,
            Arc::new(OciManifestCacheEntry {
                index_json: child_manifest.into_bytes(),
                content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                manifest_digest: child_digest.clone(),
                cache_entry_id: "entry-child".to_string(),
                blobs: vec![],
                name: "cache".to_string(),
                inserted_at: Instant::now(),
            }),
        );

        let index_json = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {
                    "digest": child_digest,
                    "size": child_size,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json"
                }
            ]
        });

        let blobs = expand_manifest_blob_descriptors(&state, "cache", &index_json)
            .await
            .expect("expand child descriptors");
        let digests: Vec<&str> = blobs.iter().map(|blob| blob.digest.as_str()).collect();

        assert_eq!(blobs.len(), 3);
        assert!(digests.contains(&child_digest.as_str()));
        assert!(digests.contains(&child_config_digest));
        assert!(digests.contains(&child_layer_digest));
    }

    #[tokio::test]
    async fn stage_manifest_reference_uploads_seeds_child_manifest_sessions() {
        let state = test_state();
        let child_manifest = br#"{"schemaVersion":2,"config":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":12},"layers":[]}"#;
        let child_digest = cas_oci::prefixed_sha256_digest(child_manifest);
        let child_size = child_manifest.len() as u64;
        let child_tag = digest_tag(&child_digest);
        state.oci_manifest_cache.insert(
            child_tag,
            Arc::new(OciManifestCacheEntry {
                index_json: child_manifest.to_vec(),
                content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                manifest_digest: child_digest.clone(),
                cache_entry_id: "entry-1".to_string(),
                blobs: vec![],
                name: "cache".to_string(),
                inserted_at: Instant::now(),
            }),
        );

        let index_json = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": child_digest, "size": child_size, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
            ]
        });
        let blob_descriptors = extract_blob_descriptors(&index_json).unwrap();
        stage_manifest_reference_uploads(&state, "cache", &blob_descriptors, &index_json)
            .await
            .expect("stage child manifest");

        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .find_by_name_and_digest("cache", &blob_descriptors[0].digest)
            .expect("staged upload session");
        assert_eq!(session.finalized_size, Some(child_size));
        assert_eq!(
            session.finalized_digest.as_deref(),
            Some(blob_descriptors[0].digest.as_str())
        );
    }

    #[test]
    fn scoped_save_tag_applies_git_suffix() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = scoped_save_tag(&resolver, "registry-root", "buildkit-cache", "main").unwrap();
        assert_eq!(
            tag,
            ref_tag_for_input("registry-root:buildkit-cache:main-branch-feature-x")
        );
    }

    #[test]
    fn scoped_restore_tags_use_root_scoped_tag_with_legacy_fallback() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tags = scoped_restore_tags(&resolver, "registry-root", "buildkit-cache", "main");
        assert_eq!(
            tags,
            vec![
                ref_tag_for_input("registry-root:buildkit-cache:main-branch-feature-x"),
                ref_tag_for_input("buildkit-cache:main-branch-feature-x")
            ]
        );
    }

    #[test]
    fn scoped_save_tag_on_default_branch_uses_base() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("main".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = scoped_save_tag(&resolver, "registry-root", "buildkit-cache", "main").unwrap();
        assert_eq!(tag, ref_tag_for_input("registry-root:buildkit-cache:main"));
    }

    #[test]
    fn scoped_save_tag_applies_platform_suffix() {
        let resolver = TagResolver::new(
            Some(Platform::new_for_testing(
                "linux",
                "x86_64",
                Some("ubuntu"),
                Some("22"),
            )),
            GitContext::default(),
            false,
        );

        let tag = scoped_save_tag(&resolver, "registry-root", "buildkit-cache", "main").unwrap();
        assert_eq!(
            tag,
            ref_tag_for_input("registry-root:buildkit-cache:main-ubuntu-22-x86_64")
        );
    }

    #[test]
    fn adaptive_blob_upload_concurrency_is_bounded() {
        assert_eq!(adaptive_blob_upload_concurrency(1), 1);

        let medium = adaptive_blob_upload_concurrency(5);
        assert!((1..=5).contains(&medium));

        let larger = adaptive_blob_upload_concurrency(32);
        assert!((1..=32).contains(&larger));
    }

    #[test]
    fn alias_tags_include_digest_and_human_alias_when_distinct() {
        let tags = alias_tags_for_manifest(
            "oci_ref_primary",
            "sha256:abc123",
            Some("posthog-build:pr-123"),
            &["posthog-docker-build".to_string()],
            &[],
        );
        assert_eq!(
            tags,
            vec![
                AliasBinding {
                    tag: "oci_digest_abc123".to_string(),
                    write_scope_tag: Some("posthog-build:pr-123".to_string())
                },
                AliasBinding {
                    tag: "posthog-docker-build".to_string(),
                    write_scope_tag: None
                }
            ]
        );
    }

    #[test]
    fn alias_tags_skip_primary_and_deduplicate() {
        let tags = alias_tags_for_manifest(
            "oci_digest_abc123",
            "sha256:abc123",
            Some("posthog-build:pr-123"),
            &["oci_digest_abc123".to_string()],
            &[],
        );
        assert!(tags.is_empty());
    }

    #[test]
    fn alias_tags_include_multiple_human_aliases() {
        let tags = alias_tags_for_manifest(
            "oci_ref_primary",
            "sha256:abc123",
            Some("posthog-build:pr-123"),
            &[
                "posthog-build".to_string(),
                "posthog-stable".to_string(),
                "posthog-build".to_string(),
            ],
            &[],
        );
        assert_eq!(
            tags,
            vec![
                AliasBinding {
                    tag: "oci_digest_abc123".to_string(),
                    write_scope_tag: Some("posthog-build:pr-123".to_string())
                },
                AliasBinding {
                    tag: "posthog-build".to_string(),
                    write_scope_tag: None
                },
                AliasBinding {
                    tag: "posthog-stable".to_string(),
                    write_scope_tag: None
                },
            ]
        );
    }

    #[test]
    fn alias_tags_include_additional_aliases() {
        let tags = alias_tags_for_manifest(
            "oci_digest_abc123",
            "sha256:abc123",
            Some("posthog-build:pr-123"),
            &["posthog-build".to_string()],
            &[
                AliasBinding {
                    tag: "oci_ref_latest".to_string(),
                    write_scope_tag: Some("posthog-build:latest".to_string()),
                },
                AliasBinding {
                    tag: "posthog-build".to_string(),
                    write_scope_tag: None,
                },
                AliasBinding {
                    tag: "oci_ref_latest".to_string(),
                    write_scope_tag: Some("posthog-build:latest".to_string()),
                },
            ],
        );
        assert_eq!(
            tags,
            vec![
                AliasBinding {
                    tag: "posthog-build".to_string(),
                    write_scope_tag: None
                },
                AliasBinding {
                    tag: "oci_ref_latest".to_string(),
                    write_scope_tag: Some("posthog-build:latest".to_string())
                }
            ]
        );
    }
}
