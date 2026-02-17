use axum::routing::{any, get};
use axum::Router;

use crate::serve::handlers;
use crate::serve::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v2/", get(handlers::v2_base))
        .route("/v2/{*path}", any(handlers::oci_dispatch))
        .with_state(state)
}
