use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{get_or_head_kv_object, put_kv_object, KvNamespace};

pub(crate) async fn handle_ac(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    match method {
        Method::PUT => {
            put_kv_object(
                state,
                KvNamespace::BazelAc,
                digest_hex,
                body,
                StatusCode::OK,
            )
            .await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(
                state,
                KvNamespace::BazelAc,
                digest_hex,
                method == Method::HEAD,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Bazel cache supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_cas(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    match method {
        Method::PUT => {
            put_kv_object(
                state,
                KvNamespace::BazelCas,
                digest_hex,
                body,
                StatusCode::OK,
            )
            .await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(
                state,
                KvNamespace::BazelCas,
                digest_hex,
                method == Method::HEAD,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Bazel cache supports GET, HEAD, and PUT",
        )),
    }
}
