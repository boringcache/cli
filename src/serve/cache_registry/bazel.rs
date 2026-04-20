use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{get_or_head_kv_object_with_integrity, put_kv_object_with_integrity};
use crate::serve::engines::bazel::BazelStore;

async fn handle_store(
    state: &AppState,
    store: BazelStore,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    let namespace = store.namespace();
    let integrity = store.blob_integrity();
    match method {
        Method::PUT => {
            put_kv_object_with_integrity(
                state,
                namespace,
                digest_hex,
                body,
                StatusCode::OK,
                integrity,
            )
            .await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object_with_integrity(
                state,
                namespace,
                digest_hex,
                method == Method::HEAD,
                integrity,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Bazel cache supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_ac(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    handle_store(state, BazelStore::ActionCache, method, digest_hex, body).await
}

pub(crate) async fn handle_cas(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    handle_store(
        state,
        BazelStore::ContentAddressableStore,
        method,
        digest_hex,
        body,
    )
    .await
}
