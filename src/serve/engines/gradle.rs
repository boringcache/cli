use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;

use crate::serve::cache_registry::{
    KvNamespace, KvPutOptions, RegistryError, get_or_head_kv_object, put_kv_object_with_options,
};
use crate::serve::state::AppState;

pub(crate) fn gradle_put_options() -> KvPutOptions {
    KvPutOptions::default().with_spool_reject_status(StatusCode::PAYLOAD_TOO_LARGE)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gradle_put_rejects_oversized_payloads_with_gradle_nonfatal_status() {
        let options = gradle_put_options();
        assert_eq!(options.spool_reject_status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
