use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::serve::state::AppState;

mod bazel;
mod error;
mod go_cache;
mod gradle;
mod kv;
mod nx;
mod route;
mod sccache;
mod turborepo;

pub use error::RegistryError;
pub(crate) use kv::flush_kv_index;
pub(crate) use kv::preload_kv_index;
pub(crate) use kv::refresh_kv_index;
pub(crate) use kv::try_schedule_flush;
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
    let request_method = method.clone();
    let normalized_path = normalize_path(&path);
    let route = match route::detect_route(&method, &normalized_path) {
        Ok(r) => r,
        Err(e) if e.status == StatusCode::NOT_FOUND && method == Method::PUT => {
            return Ok((StatusCode::CREATED, Body::empty()).into_response());
        }
        Err(e) => return Err(e),
    };

    let response = match route {
        route::RegistryRoute::BazelAc { digest_hex } => {
            bazel::handle_ac(&state, method, &digest_hex, body).await
        }
        route::RegistryRoute::BazelCas { digest_hex } => {
            bazel::handle_cas(&state, method, &digest_hex, body).await
        }
        route::RegistryRoute::Gradle { cache_key } => {
            gradle::handle(&state, method, &cache_key, body).await
        }
        route::RegistryRoute::NxArtifact { hash } => {
            nx::handle_artifact(&state, method, &headers, &hash, body).await
        }
        route::RegistryRoute::NxTerminalOutput { hash } => {
            nx::handle_terminal_output(&state, method, &headers, &hash, body).await
        }
        route::RegistryRoute::NxQuery => nx::handle_query(&state, method, &headers, body).await,
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
        route::RegistryRoute::GoCacheObject { action_hex } => {
            go_cache::handle_action(&state, method, &action_hex, body).await
        }
    };

    match response {
        Ok(response) => Ok(response),
        Err(error) => {
            if state.fail_on_cache_error || !error.status.is_server_error() {
                return Err(error);
            }
            log::warn!(
                "Best-effort cache-registry fallback on {} {} ({})",
                request_method,
                normalized_path,
                error.status
            );
            Ok(best_effort_cache_registry_response(&request_method))
        }
    }
}

fn normalize_path(path: &str) -> String {
    path.trim_matches('/').to_string()
}

fn best_effort_cache_registry_response(method: &Method) -> Response {
    let status = if *method == Method::GET || *method == Method::HEAD {
        StatusCode::NOT_FOUND
    } else if *method == Method::PUT {
        StatusCode::OK
    } else if *method == Method::POST || *method == Method::PATCH {
        StatusCode::ACCEPTED
    } else if *method == Method::DELETE {
        StatusCode::NO_CONTENT
    } else if method.as_str() == "MKCOL" {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    (status, Body::empty()).into_response()
}
