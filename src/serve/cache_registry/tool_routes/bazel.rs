use axum::body::Body;
use axum::http::Method;
use axum::response::Response;

use crate::serve::state::AppState;

use crate::serve::cache_registry::RegistryError;

pub(crate) async fn handle_ac(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::bazel::handle_ac(state, method, digest_hex, body).await
}

pub(crate) async fn handle_cas(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::bazel::handle_cas(state, method, digest_hex, body).await
}
