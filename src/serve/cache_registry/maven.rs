use axum::body::Body;
use axum::http::Method;
use axum::response::Response;

use crate::serve::state::AppState;

use super::error::RegistryError;

pub(crate) async fn handle(
    state: &AppState,
    method: Method,
    cache_key: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::maven::handle(state, method, cache_key, body).await
}
