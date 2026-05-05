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
use crate::serve::engines::oci::blobs as oci_blobs;
use crate::serve::state::{
    AppState, CacheSessionSummarySnapshot, HttpTransportConfig, build_cache_session_summary,
    diagnostics_enabled,
};
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
    http_transport: HttpTransportConfig,
    oci_stream_through_min_bytes: Option<u64>,
    oci_stream_through_enabled: bool,
    session_summary: CacheSessionSummarySnapshot,
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
    let oci_stream_through_min_bytes = oci_blobs::stream_through_min_bytes();
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
            http_transport: state.http_transport,
            oci_stream_through_min_bytes,
            oci_stream_through_enabled: oci_stream_through_min_bytes.is_some(),
            session_summary: build_cache_session_summary(&state),
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
mod tests;
