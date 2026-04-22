use axum::body::Body;
use axum::http::Method;
use axum::response::Response;

use crate::serve::state::AppState;

use crate::serve::cache_registry::RegistryError;

pub(crate) async fn handle_action(
    state: &AppState,
    method: Method,
    action_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    crate::serve::engines::go_cache::handle_action(state, method, action_hex, body).await
}
