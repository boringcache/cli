use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::serve::cache_registry::{
    KvNamespace, KvPutOptions, RegistryError, get_or_head_kv_object, put_kv_object,
    put_kv_object_with_options, resolve_kv_entries,
};
use crate::serve::state::AppState;

pub(crate) fn nx_artifact_put_options() -> KvPutOptions {
    KvPutOptions::default().with_existing_reject_status(StatusCode::CONFLICT)
}

pub(crate) async fn handle_artifact(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_bearer_header(headers)?;
    match method {
        Method::PUT => {
            validate_required_content_length(headers)?;
            let _ = put_kv_object_with_options(
                state,
                KvNamespace::Nx,
                hash,
                body,
                StatusCode::OK,
                nx_artifact_put_options(),
            )
            .await?;
            Ok((StatusCode::OK, Body::empty()).into_response())
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(state, KvNamespace::Nx, hash, method == Method::HEAD).await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Nx artifact endpoint supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_terminal_output(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_bearer_header(headers)?;
    match method {
        Method::PUT => {
            let _ = put_kv_object(
                state,
                KvNamespace::NxTerminalOutput,
                hash,
                body,
                StatusCode::OK,
            )
            .await?;
            Ok((StatusCode::OK, Body::empty()).into_response())
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(
                state,
                KvNamespace::NxTerminalOutput,
                hash,
                method == Method::HEAD,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Nx terminal output endpoint supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_query(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_bearer_header(headers)?;
    if method != Method::POST {
        return Err(RegistryError::method_not_allowed(
            "Nx cache query endpoint supports POST",
        ));
    }

    let bytes = axum::body::to_bytes(body, 512 * 1024)
        .await
        .map_err(|e| RegistryError::bad_request(format!("Invalid Nx query request body: {e}")))?;
    let request: NxQueryRequest = serde_json::from_slice(&bytes).map_err(|e| {
        RegistryError::bad_request(format!("Invalid Nx query request payload: {e}"))
    })?;
    let valid_hashes: Vec<&str> = request
        .hashes
        .iter()
        .filter(|hash| !hash.is_empty())
        .map(|hash| hash.as_str())
        .collect();

    let sizes = match resolve_kv_entries(state, KvNamespace::Nx, &valid_hashes).await {
        Ok(map) => map,
        Err(error) if error.status == StatusCode::NOT_FOUND => Default::default(),
        Err(error) => return Err(error),
    };

    let misses = request
        .hashes
        .into_iter()
        .filter(|hash| !hash.is_empty())
        .filter(|hash| !sizes.contains_key(&KvNamespace::Nx.scoped_key(hash)))
        .collect::<Vec<_>>();
    let payload = serde_json::to_string(&NxQueryResponse { misses }).map_err(|e| {
        RegistryError::internal(format!("Failed to serialize Nx query response: {e}"))
    })?;
    Ok((
        StatusCode::OK,
        [("Content-Type", "application/json")],
        payload,
    )
        .into_response())
}

fn ensure_bearer_header(headers: &HeaderMap) -> Result<(), RegistryError> {
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

fn validate_required_content_length(headers: &HeaderMap) -> Result<(), RegistryError> {
    let Some(value) = headers.get(header::CONTENT_LENGTH) else {
        return Err(RegistryError::bad_request(
            "Nx artifact uploads require Content-Length",
        ));
    };
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| RegistryError::bad_request("Invalid Content-Length header value"))?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct NxQueryRequest {
    hashes: Vec<String>,
}

#[derive(serde::Serialize)]
struct NxQueryResponse {
    misses: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nx_artifact_put_rejects_existing_records_with_conflict() {
        let options = nx_artifact_put_options();
        assert_eq!(options.existing_reject_status(), Some(StatusCode::CONFLICT));
    }
}
