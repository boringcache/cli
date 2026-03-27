use axum::http::{HeaderMap, Method};
use axum::response::Response;

use crate::serve::error::OciError;
use crate::serve::state::AppState;

#[derive(Clone)]
pub(crate) enum OciRoute {
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    BlobUploadStart { name: String },
    BlobUpload { name: String, uuid: String },
}

pub(crate) fn insert_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), OciError> {
    let header_name = axum::http::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|e| OciError::internal(format!("Invalid header name {name}: {e}")))?;
    let header_value = axum::http::header::HeaderValue::from_str(value)
        .map_err(|e| OciError::internal(format!("Invalid header value for {name}: {e}")))?;
    headers.insert(header_name, header_value);
    Ok(())
}

pub(crate) fn parse_oci_path(path: &str) -> Option<OciRoute> {
    let path = path.strip_prefix('/').unwrap_or(path);

    if let Some(idx) = path.rfind("/blobs/uploads/") {
        let name = &path[..idx];
        let uuid = &path[idx + "/blobs/uploads/".len()..];
        if !name.is_empty() && !uuid.is_empty() {
            return Some(OciRoute::BlobUpload {
                name: name.to_string(),
                uuid: uuid.to_string(),
            });
        }
    }

    if let Some(name) = path.strip_suffix("/blobs/uploads")
        && !name.is_empty()
    {
        return Some(OciRoute::BlobUploadStart {
            name: name.to_string(),
        });
    }

    if let Some(name) = path.strip_suffix("/blobs/uploads/")
        && !name.is_empty()
    {
        return Some(OciRoute::BlobUploadStart {
            name: name.to_string(),
        });
    }

    if let Some(idx) = path.rfind("/blobs/") {
        let name = &path[..idx];
        let digest = &path[idx + "/blobs/".len()..];
        if !name.is_empty() && !digest.is_empty() {
            return Some(OciRoute::Blob {
                name: name.to_string(),
                digest: digest.to_string(),
            });
        }
    }

    if let Some(idx) = path.rfind("/manifests/") {
        let name = &path[..idx];
        let reference = &path[idx + "/manifests/".len()..];
        if !name.is_empty() && !reference.is_empty() {
            return Some(OciRoute::Manifest {
                name: name.to_string(),
                reference: reference.to_string(),
            });
        }
    }

    None
}

pub(crate) fn oci_cache_op_for_route_method(
    route: &OciRoute,
    method: &Method,
) -> Option<crate::serve::cache_registry::cache_ops::Op> {
    match route {
        OciRoute::Manifest { .. } => {
            if *method == Method::GET || *method == Method::HEAD {
                Some(crate::serve::cache_registry::cache_ops::Op::Get)
            } else if *method == Method::PUT {
                Some(crate::serve::cache_registry::cache_ops::Op::Put)
            } else {
                None
            }
        }
        OciRoute::Blob { .. } => {
            if *method == Method::GET || *method == Method::HEAD {
                Some(crate::serve::cache_registry::cache_ops::Op::Get)
            } else {
                None
            }
        }
        OciRoute::BlobUpload { .. } => {
            if *method == Method::PUT {
                Some(crate::serve::cache_registry::cache_ops::Op::Put)
            } else {
                None
            }
        }
        OciRoute::BlobUploadStart { .. } => None,
    }
}

pub(crate) fn oci_miss_key(route: &OciRoute) -> Option<String> {
    match route {
        OciRoute::Manifest { name, reference } => Some(format!("manifest:{name}:{reference}")),
        OciRoute::Blob { name, digest } => Some(format!("blob:{name}@{digest}")),
        OciRoute::BlobUploadStart { .. } | OciRoute::BlobUpload { .. } => None,
    }
}

pub(crate) fn record_oci_cache_op(
    state: &AppState,
    op: crate::serve::cache_registry::cache_ops::Op,
    result: crate::serve::cache_registry::cache_ops::OpResult,
    degraded: bool,
    bytes: u64,
    latency_ms: u64,
    miss_key: Option<&str>,
) {
    state.cache_ops.record(
        crate::serve::cache_registry::cache_ops::Tool::Oci,
        op,
        result,
        degraded,
        bytes,
        latency_ms,
    );

    if result == crate::serve::cache_registry::cache_ops::OpResult::Miss
        && let Some(key) = miss_key
    {
        state
            .cache_ops
            .record_miss(crate::serve::cache_registry::cache_ops::Tool::Oci, key);
    }
}

pub(crate) fn oci_success_rollup_result(
    response: &Response,
    degraded_header: &str,
) -> (crate::serve::cache_registry::cache_ops::OpResult, bool) {
    if response.headers().get(degraded_header).is_some() {
        (
            crate::serve::cache_registry::cache_ops::OpResult::Error,
            true,
        )
    } else {
        (
            crate::serve::cache_registry::cache_ops::OpResult::Hit,
            false,
        )
    }
}
