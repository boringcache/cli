use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{get_or_head_kv_object, put_kv_object, resolve_kv_entries, KvNamespace};
use super::turborepo;

pub(crate) async fn handle_artifact(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    turborepo::ensure_proxy_bearer_header(headers)?;
    match method {
        Method::PUT => {
            let _ = put_kv_object(state, KvNamespace::Nx, hash, body, StatusCode::OK).await?;
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
    turborepo::ensure_proxy_bearer_header(headers)?;
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
    turborepo::ensure_proxy_bearer_header(headers)?;
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

#[derive(serde::Deserialize)]
struct NxQueryRequest {
    hashes: Vec<String>,
}

#[derive(serde::Serialize)]
struct NxQueryResponse {
    misses: Vec<String>,
}
