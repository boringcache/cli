use axum::body::Body;
use axum::http::{HeaderMap, Method};
use axum::response::Response;

use crate::serve::state::AppState;

use super::error::RegistryError;

pub(crate) fn handle_status(
    method: Method,
    headers: &HeaderMap,
) -> Result<Response, RegistryError> {
    crate::serve::engines::turborepo::handle_status(method, headers)
}

pub(crate) async fn handle_artifact(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::turborepo::handle_artifact(state, method, headers, hash, body).await
}

pub(crate) async fn handle_query_artifacts(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::turborepo::handle_query_artifacts(state, method, headers, body).await
}

pub(crate) async fn handle_events(
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::turborepo::handle_events(method, headers, body).await
}
