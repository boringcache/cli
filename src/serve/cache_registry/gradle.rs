use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{KvNamespace, get_or_head_kv_object, put_kv_object_with_options};
use crate::serve::engines::gradle::gradle_put_options;

pub(crate) async fn handle(
    state: &AppState,
    method: Method,
    cache_key: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    match method {
        Method::PUT => {
            put_kv_object_with_options(
                state,
                KvNamespace::Gradle,
                cache_key,
                body,
                StatusCode::OK,
                gradle_put_options(),
            )
            .await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(
                state,
                KvNamespace::Gradle,
                cache_key,
                method == Method::HEAD,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Gradle cache supports GET, HEAD, and PUT",
        )),
    }
}
