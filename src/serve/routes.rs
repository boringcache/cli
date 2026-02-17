use axum::extract::DefaultBodyLimit;
use axum::routing::{any, get};
use axum::Router;

use crate::serve::handlers;
use crate::serve::state::AppState;

const MAX_OCI_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024 * 1024;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v2/", get(handlers::v2_base))
        .route("/v2/{*path}", any(handlers::oci_dispatch))
        .layer(DefaultBodyLimit::max(MAX_OCI_REQUEST_BODY_BYTES))
        .with_state(state)
}
