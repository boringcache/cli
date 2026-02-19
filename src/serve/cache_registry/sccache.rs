use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{get_or_head_kv_object, put_kv_object, KvNamespace};

pub(crate) fn handle_mkcol(method: Method) -> Result<Response, RegistryError> {
    if method.as_str() == "MKCOL" {
        Ok((StatusCode::CREATED, Body::empty()).into_response())
    } else {
        Err(RegistryError::method_not_allowed(
            "sccache path supports MKCOL, GET, HEAD, and PUT",
        ))
    }
}

pub(crate) async fn handle_object(
    state: &AppState,
    method: Method,
    key_path: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    match method {
        Method::PUT => {
            put_kv_object(
                state,
                KvNamespace::Sccache,
                key_path,
                body,
                StatusCode::CREATED,
            )
            .await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(
                state,
                KvNamespace::Sccache,
                key_path,
                method == Method::HEAD,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "sccache cache supports GET, HEAD, PUT, and MKCOL",
        )),
    }
}
