use axum::body::Body;
use axum::http::{HeaderMap, Method};
use axum::response::Response;

use crate::serve::state::AppState;

use crate::serve::cache_registry::RegistryError;

pub(crate) async fn handle_artifact(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::nx::handle_artifact(state, method, headers, hash, body).await
}

pub(crate) async fn handle_terminal_output(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::nx::handle_terminal_output(state, method, headers, hash, body).await
}

pub(crate) async fn handle_query(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::nx::handle_query(state, method, headers, body).await
}
