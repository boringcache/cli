use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{get_or_head_kv_object, put_kv_object, KvNamespace};

pub(crate) async fn handle_action(
    state: &AppState,
    method: Method,
    action_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    match method {
        Method::PUT => {
            put_kv_object(
                state,
                KvNamespace::GoCache,
                action_hex,
                body,
                StatusCode::CREATED,
            )
            .await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(
                state,
                KvNamespace::GoCache,
                action_hex,
                method == Method::HEAD,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Go cache endpoint supports GET, HEAD, and PUT",
        )),
    }
}
