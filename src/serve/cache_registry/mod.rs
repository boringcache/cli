use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::serve::state::AppState;

mod bazel;
mod error;
mod gradle;
mod kv;
mod route;
mod sccache;
mod turborepo;

pub use error::RegistryError;
pub(crate) use kv::flush_kv_index;
pub(crate) use kv::preload_kv_index;
pub(crate) use kv::FlushResult;

pub async fn dispatch_root(
    method: Method,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    dispatch_with_path(method, state, String::new(), headers, body).await
}

pub async fn dispatch(
    method: Method,
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    dispatch_with_path(method, state, path, headers, body).await
}

async fn dispatch_with_path(
    method: Method,
    state: AppState,
    path: String,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    let normalized_path = normalize_path(&path);
    let route = match route::detect_route(&method, &normalized_path) {
        Ok(r) => r,
        Err(e) if e.status == StatusCode::NOT_FOUND && method == Method::PUT => {
            return Ok((StatusCode::CREATED, Body::empty()).into_response());
        }
        Err(e) => return Err(e),
    };

    match route {
        route::RegistryRoute::BazelAc { digest_hex } => {
            bazel::handle_ac(&state, method, &digest_hex, body).await
        }
        route::RegistryRoute::BazelCas { digest_hex } => {
            bazel::handle_cas(&state, method, &digest_hex, body).await
        }
        route::RegistryRoute::Gradle { cache_key } => {
            gradle::handle(&state, method, &cache_key, body).await
        }
        route::RegistryRoute::TurborepoStatus => turborepo::handle_status(method, &headers),
        route::RegistryRoute::TurborepoArtifact { hash } => {
            turborepo::handle_artifact(&state, method, &headers, &hash, body).await
        }
        route::RegistryRoute::TurborepoQueryArtifacts => {
            turborepo::handle_query_artifacts(&state, method, &headers, body).await
        }
        route::RegistryRoute::TurborepoEvents => turborepo::handle_events(method, &headers),
        route::RegistryRoute::SccacheObject { key_path } => {
            sccache::handle_object(&state, method, &key_path, body).await
        }
        route::RegistryRoute::SccacheMkcol => sccache::handle_mkcol(method),
    }
}

fn normalize_path(path: &str) -> String {
    path.trim_matches('/').to_string()
}
