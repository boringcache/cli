use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::BTreeMap;

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{get_or_head_kv_object, put_kv_object, resolve_kv_entries, KvNamespace};

pub(crate) fn handle_status(
    method: Method,
    headers: &HeaderMap,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers)?;
    if method == Method::GET {
        Ok((
            StatusCode::OK,
            [("Content-Type", "application/json")],
            r#"{"status":"enabled"}"#,
        )
            .into_response())
    } else {
        Err(RegistryError::method_not_allowed(
            "Turborepo status endpoint supports GET",
        ))
    }
}

pub(crate) async fn handle_artifact(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers)?;
    match method {
        Method::PUT => {
            let _ = put_kv_object(
                state,
                KvNamespace::Turborepo,
                hash,
                body,
                StatusCode::ACCEPTED,
            )
            .await?;
            Ok((
                StatusCode::ACCEPTED,
                [("Content-Type", "application/json")],
                r#"{"urls":[]}"#,
            )
                .into_response())
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(state, KvNamespace::Turborepo, hash, method == Method::HEAD).await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Turborepo artifact endpoint supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_query_artifacts(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers)?;
    if method != Method::POST {
        return Err(RegistryError::method_not_allowed(
            "Turborepo artifact query endpoint supports POST",
        ));
    }
    handle_query_artifacts_body(state, body).await
}

pub(crate) fn handle_events(
    method: Method,
    headers: &HeaderMap,
) -> Result<Response, RegistryError> {
    ensure_proxy_bearer_header(headers)?;
    if method != Method::POST {
        return Err(RegistryError::method_not_allowed(
            "Turborepo events endpoint supports POST",
        ));
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

#[derive(serde::Serialize)]
struct TurborepoArtifactInfo {
    size: u64,
    #[serde(rename = "taskDurationMs")]
    task_duration_ms: u64,
}

async fn handle_query_artifacts_body(
    state: &AppState,
    body: Body,
) -> Result<Response, RegistryError> {
    let bytes = axum::body::to_bytes(body, 512 * 1024)
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
        response.insert(
            hash,
            size.map(|size| TurborepoArtifactInfo {
                size,
                task_duration_ms: 0,
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

#[cfg(test)]
mod tests {
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
}
