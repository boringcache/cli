use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;

use crate::serve::cache_registry::{
    KvNamespace, RegistryError, get_or_head_kv_object, put_kv_object,
};
use crate::serve::state::AppState;

pub(crate) async fn handle(
    state: &AppState,
    method: Method,
    cache_key: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    match method {
        Method::PUT => {
            put_kv_object(state, KvNamespace::Maven, cache_key, body, StatusCode::OK).await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(state, KvNamespace::Maven, cache_key, method == Method::HEAD)
                .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Maven cache supports GET, HEAD, and PUT",
        )),
    }
}
