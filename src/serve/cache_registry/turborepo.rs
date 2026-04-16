use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::BTreeMap;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{
    KvNamespace, await_startup_prefetch_readiness, do_download_blob_to_cache,
    get_or_head_kv_object, lookup_published_blob, maybe_refresh_published_index_for_lookup,
    put_kv_object, resolve_kv_entries,
};

const TURBOREPO_BODY_LIMIT_BYTES: usize = 512 * 1024;
const TURBOREPO_METADATA_LIMIT_BYTES: u64 = 16 * 1024;
const TURBOREPO_MAX_TAG_BYTES: usize = 600;
const TURBOREPO_HEADER_DURATION: &str = "x-artifact-duration";
const TURBOREPO_HEADER_TAG: &str = "x-artifact-tag";
const TURBOREPO_HEADER_SHA: &str = "x-artifact-sha";
const TURBOREPO_HEADER_DIRTY_HASH: &str = "x-artifact-dirty-hash";

pub(crate) fn handle_status(
    method: Method,
    headers: &HeaderMap,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers).map_err(turborepo_error)?;
    if method == Method::GET {
        Ok((
            StatusCode::OK,
            [("Content-Type", "application/json")],
            r#"{"status":"enabled"}"#,
        )
            .into_response())
    } else {
        Err(turborepo_error(RegistryError::method_not_allowed(
            "Turborepo status endpoint supports GET",
        )))
    }
}

pub(crate) async fn handle_artifact(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers).map_err(turborepo_error)?;
    match method {
        Method::PUT => {
            let metadata = parse_artifact_metadata(headers).map_err(turborepo_error)?;
            put_turborepo_metadata(state, hash, &metadata)
                .await
                .map_err(turborepo_error)?;
            let _ = put_kv_object(
                state,
                KvNamespace::Turborepo,
                hash,
                body,
                StatusCode::ACCEPTED,
            )
            .await
            .map_err(turborepo_error)?;
            Ok((
                StatusCode::ACCEPTED,
                [("Content-Type", "application/json")],
                r#"{"urls":[]}"#,
            )
                .into_response())
        }
        read_method @ (Method::GET | Method::HEAD) => {
            let mut response = get_or_head_kv_object(
                state,
                KvNamespace::Turborepo,
                hash,
                read_method == Method::HEAD,
            )
            .await
            .map_err(turborepo_error)?;
            match load_turborepo_metadata(state, hash).await {
                Ok(Some(metadata)) => {
                    apply_artifact_metadata_headers(response.headers_mut(), &metadata, read_method);
                }
                Ok(None) => {}
                Err(error) => {
                    log::warn!("Turborepo metadata lookup failed for {hash}: {error:#}");
                }
            }
            Ok(response)
        }
        _ => Err(turborepo_error(RegistryError::method_not_allowed(
            "Turborepo artifact endpoint supports GET, HEAD, and PUT",
        ))),
    }
}

pub(crate) async fn handle_query_artifacts(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers).map_err(turborepo_error)?;
    if method != Method::POST {
        return Err(turborepo_error(RegistryError::method_not_allowed(
            "Turborepo artifact query endpoint supports POST",
        )));
    }
    handle_query_artifacts_body(state, body)
        .await
        .map_err(turborepo_error)
}

pub(crate) async fn handle_events(
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers).map_err(turborepo_error)?;
    if method != Method::POST {
        return Err(turborepo_error(RegistryError::method_not_allowed(
            "Turborepo events endpoint supports POST",
        )));
    }

    let bytes = axum::body::to_bytes(body, TURBOREPO_BODY_LIMIT_BYTES)
        .await
        .map_err(|e| {
            turborepo_error(RegistryError::bad_request(format!(
                "Invalid events request body: {e}"
            )))
        })?;
    let events: Vec<TurborepoCacheEvent> = if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        Vec::new()
    } else {
        serde_json::from_slice(&bytes).map_err(|e| {
            turborepo_error(RegistryError::bad_request(format!(
                "Invalid events request payload: {e}"
            )))
        })?
    };
    for event in &events {
        if event.session_id.trim().is_empty() || event.hash.trim().is_empty() {
            return Err(turborepo_error(RegistryError::bad_request(
                "Event payload is missing required values",
            )));
        }
        let _ = (&event.source, &event.event, event.duration);
    }

    Ok((StatusCode::OK, Body::empty()).into_response())
}

pub(crate) fn ensure_proxy_bearer_header(headers: &HeaderMap) -> Result<(), RegistryError> {
    let value = headers.get("authorization").ok_or_else(|| {
        RegistryError::new(StatusCode::UNAUTHORIZED, "Missing Authorization header")
    })?;
    let value = value.to_str().map_err(|_| {
        RegistryError::new(StatusCode::UNAUTHORIZED, "Invalid Authorization header")
    })?;
    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token = parts.next().map(str::trim).unwrap_or("");
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(RegistryError::new(
            StatusCode::UNAUTHORIZED,
            "Authorization header must be Bearer token",
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct TurborepoQueryRequest {
    hashes: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
struct TurborepoArtifactMetadata {
    #[serde(rename = "taskDurationMs", skip_serializing_if = "Option::is_none")]
    task_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<String>,
    #[serde(rename = "dirtyHash", skip_serializing_if = "Option::is_none")]
    dirty_hash: Option<String>,
}

#[derive(serde::Serialize)]
struct TurborepoArtifactInfo {
    size: u64,
    #[serde(rename = "taskDurationMs")]
    task_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum TurborepoCacheEventSource {
    Local,
    Remote,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum TurborepoCacheEventType {
    Hit,
    Miss,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TurborepoCacheEvent {
    session_id: String,
    source: TurborepoCacheEventSource,
    event: TurborepoCacheEventType,
    hash: String,
    duration: Option<u64>,
}

async fn handle_query_artifacts_body(
    state: &AppState,
    body: Body,
) -> Result<Response, RegistryError> {
    let bytes = axum::body::to_bytes(body, TURBOREPO_BODY_LIMIT_BYTES)
        .await
        .map_err(|e| RegistryError::bad_request(format!("Invalid query request body: {e}")))?;
    let request: TurborepoQueryRequest = serde_json::from_slice(&bytes)
        .map_err(|e| RegistryError::bad_request(format!("Invalid query request payload: {e}")))?;

    let valid_hashes: Vec<&str> = request
        .hashes
        .iter()
        .filter(|h| !h.is_empty())
        .map(|h| h.as_str())
        .collect();

    let sizes = match resolve_kv_entries(state, KvNamespace::Turborepo, &valid_hashes).await {
        Ok(map) => map,
        Err(error) if error.status == StatusCode::NOT_FOUND => Default::default(),
        Err(error) => return Err(error),
    };

    let mut response: BTreeMap<String, Option<TurborepoArtifactInfo>> = BTreeMap::new();
    for hash in request.hashes {
        if hash.is_empty() {
            continue;
        }
        let scoped_key = KvNamespace::Turborepo.scoped_key(&hash);
        let size = sizes.get(&scoped_key).copied();
        let metadata = match load_turborepo_metadata(state, &hash).await {
            Ok(metadata) => metadata.unwrap_or_default(),
            Err(error) => {
                log::warn!("Turborepo metadata lookup failed for {hash}: {error:#}");
                TurborepoArtifactMetadata::default()
            }
        };
        response.insert(
            hash,
            size.map(|size| TurborepoArtifactInfo {
                size,
                task_duration_ms: metadata.task_duration_ms.unwrap_or(0),
                tag: metadata.tag,
            }),
        );
    }

    let payload = serde_json::to_string(&response)
        .map_err(|e| RegistryError::internal(format!("Failed to serialize query response: {e}")))?;
    Ok((
        StatusCode::OK,
        [("Content-Type", "application/json")],
        payload,
    )
        .into_response())
}

fn turborepo_error(error: RegistryError) -> RegistryError {
    let code = match error.status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
        _ => "internal_error",
    };
    error.with_json_code(code)
}

fn parse_optional_string_header(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, RegistryError> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| RegistryError::bad_request(format!("Invalid {name} header encoding")))
        })
        .transpose()
        .map(|value| {
            value
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
}

fn parse_optional_u64_header(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<u64>, RegistryError> {
    match parse_optional_string_header(headers, name)? {
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| RegistryError::bad_request(format!("Invalid {name} header value"))),
        None => Ok(None),
    }
}

fn parse_artifact_metadata(
    headers: &HeaderMap,
) -> Result<TurborepoArtifactMetadata, RegistryError> {
    let tag = parse_optional_string_header(headers, TURBOREPO_HEADER_TAG)?;
    if tag
        .as_ref()
        .is_some_and(|value| value.len() > TURBOREPO_MAX_TAG_BYTES)
    {
        return Err(RegistryError::bad_request(format!(
            "{TURBOREPO_HEADER_TAG} exceeds {TURBOREPO_MAX_TAG_BYTES} bytes"
        )));
    }

    Ok(TurborepoArtifactMetadata {
        task_duration_ms: parse_optional_u64_header(headers, TURBOREPO_HEADER_DURATION)?,
        tag,
        sha: parse_optional_string_header(headers, TURBOREPO_HEADER_SHA)?,
        dirty_hash: parse_optional_string_header(headers, TURBOREPO_HEADER_DIRTY_HASH)?,
    })
}

async fn put_turborepo_metadata(
    state: &AppState,
    hash: &str,
    metadata: &TurborepoArtifactMetadata,
) -> Result<(), RegistryError> {
    let payload = serde_json::to_vec(metadata).map_err(|e| {
        RegistryError::internal(format!("Failed to serialize artifact metadata: {e}"))
    })?;
    let _ = put_kv_object(
        state,
        KvNamespace::TurborepoMeta,
        hash,
        Body::from(payload),
        StatusCode::ACCEPTED,
    )
    .await?;
    Ok(())
}

fn apply_artifact_metadata_headers(
    headers: &mut HeaderMap,
    metadata: &TurborepoArtifactMetadata,
    method: Method,
) {
    insert_optional_u64_header(
        headers,
        TURBOREPO_HEADER_DURATION,
        metadata.task_duration_ms,
    );
    insert_optional_string_header(headers, TURBOREPO_HEADER_SHA, metadata.sha.as_deref());
    insert_optional_string_header(
        headers,
        TURBOREPO_HEADER_DIRTY_HASH,
        metadata.dirty_hash.as_deref(),
    );
    if method == Method::GET {
        insert_optional_string_header(headers, TURBOREPO_HEADER_TAG, metadata.tag.as_deref());
    }
}

fn insert_optional_u64_header(headers: &mut HeaderMap, name: &'static str, value: Option<u64>) {
    let Some(value) = value else {
        return;
    };
    if let Ok(parsed) = value.to_string().parse() {
        headers.insert(name, parsed);
    }
}

fn insert_optional_string_header(headers: &mut HeaderMap, name: &'static str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    if let Ok(parsed) = value.parse() {
        headers.insert(name, parsed);
    }
}

async fn load_turborepo_metadata(
    state: &AppState,
    hash: &str,
) -> Result<Option<TurborepoArtifactMetadata>, RegistryError> {
    let metadata_key = KvNamespace::TurborepoMeta.scoped_key(hash);

    {
        let pending = state.kv_pending.read().await;
        if let Some(blob) = pending.get(&metadata_key) {
            let path = pending.blob_path(&blob.digest).ok_or_else(|| {
                RegistryError::internal("Metadata blob path missing from pending store")
            })?;
            let bytes = read_metadata_blob_bytes(path, 0, blob.size_bytes).await?;
            return parse_turborepo_metadata(&bytes).map(Some);
        }
    }

    {
        let flushing = state.kv_flushing.read().await;
        if let Some(snapshot) = flushing.as_ref()
            && let Some(blob) = snapshot.get(&metadata_key)
            && let Some(path) = snapshot.blob_path(&blob.digest)
        {
            let bytes = read_metadata_blob_bytes(path, 0, blob.size_bytes).await?;
            return parse_turborepo_metadata(&bytes).map(Some);
        }
    }

    await_startup_prefetch_readiness(state).await?;
    if let Some(metadata) = load_published_turborepo_metadata(state, &metadata_key).await? {
        return Ok(Some(metadata));
    }

    maybe_refresh_published_index_for_lookup(state).await?;
    load_published_turborepo_metadata(state, &metadata_key).await
}

async fn load_published_turborepo_metadata(
    state: &AppState,
    metadata_key: &str,
) -> Result<Option<TurborepoArtifactMetadata>, RegistryError> {
    let Some((blob, cache_entry_id, cached_url)) = lookup_published_blob(state, metadata_key).await
    else {
        return Ok(None);
    };

    let handle =
        do_download_blob_to_cache(state, &cache_entry_id, &blob, cached_url.as_deref(), None)
            .await?
            .0;
    let bytes =
        read_metadata_blob_bytes(handle.path(), handle.offset(), handle.size_bytes()).await?;
    parse_turborepo_metadata(&bytes).map(Some)
}

async fn read_metadata_blob_bytes(
    path: &std::path::Path,
    offset: u64,
    size_bytes: u64,
) -> Result<Vec<u8>, RegistryError> {
    if size_bytes > TURBOREPO_METADATA_LIMIT_BYTES {
        return Err(RegistryError::internal(format!(
            "Artifact metadata exceeds {} bytes",
            TURBOREPO_METADATA_LIMIT_BYTES
        )));
    }

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to open artifact metadata: {e}")))?;
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| {
                RegistryError::internal(format!("Failed to seek artifact metadata: {e}"))
            })?;
    }
    let mut bytes = vec![0u8; size_bytes as usize];
    file.read_exact(&mut bytes)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to read artifact metadata: {e}")))?;
    Ok(bytes)
}

fn parse_turborepo_metadata(bytes: &[u8]) -> Result<TurborepoArtifactMetadata, RegistryError> {
    serde_json::from_slice(bytes)
        .map_err(|e| RegistryError::internal(format!("Invalid artifact metadata payload: {e}")))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn ensure_proxy_bearer_header_accepts_lowercase_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("bearer token"));
        assert!(ensure_proxy_bearer_header(&headers).is_ok());
    }

    #[test]
    fn ensure_proxy_bearer_header_rejects_missing_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer "));
        let error = ensure_proxy_bearer_header(&headers).unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn ensure_proxy_bearer_header_accepts_arbitrary_non_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer any-non-empty-token"),
        );
        assert!(ensure_proxy_bearer_header(&headers).is_ok());
    }

    #[tokio::test]
    async fn handle_events_accepts_empty_body() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        let response = handle_events(Method::POST, &headers, Body::empty())
            .await
            .expect("events handler should accept empty body");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_events_rejects_invalid_non_json_body() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        let response = handle_events(Method::POST, &headers, Body::from("EOF")).await;
        assert!(response.is_err());
    }
}
