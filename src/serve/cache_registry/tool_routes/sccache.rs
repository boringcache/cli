use axum::body::Body;
use axum::http::Method;
use axum::response::Response;

use crate::serve::state::AppState;

use crate::serve::cache_registry::RegistryError;

pub(crate) fn handle_mkcol(method: Method) -> Result<Response, RegistryError> {
    crate::serve::engines::sccache::handle_mkcol(method)
}

pub(crate) async fn handle_probe(method: Method, _path: &str) -> Result<Response, RegistryError> {
    crate::serve::engines::sccache::handle_probe(method, _path).await
}

pub(crate) async fn handle_object(
    state: &AppState,
    method: Method,
    key_path: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::sccache::handle_object(state, method, key_path, body).await
}
