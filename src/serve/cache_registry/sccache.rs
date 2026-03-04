use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::time::Duration;

use crate::serve::state::AppState;

use super::error::RegistryError;
use super::kv::{get_or_head_kv_object, put_kv_object, KvNamespace};

const SCCACHE_GET_HEAD_TIMEOUT_MIN_SECS: u64 = 15;
const SCCACHE_GET_HEAD_TIMEOUT_MAX_SECS: u64 = 180;
const SCCACHE_GET_TIMEOUT_BASE_SECS: u64 = 45;
const SCCACHE_HEAD_TIMEOUT_BASE_SECS: u64 = 30;
const SCCACHE_TIMEOUT_MEDIUM_LOAD_ADD_SECS: u64 = 20;
const SCCACHE_TIMEOUT_HIGH_LOAD_ADD_SECS: u64 = 45;
const SCCACHE_TIMEOUT_BREAKER_CAP_SECS: u64 = 30;

fn sccache_get_head_timeout(state: &AppState, is_head: bool) -> Duration {
    if let Some(secs) = std::env::var("BORINGCACHE_SCCACHE_GET_HEAD_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
    {
        return Duration::from_secs(secs.clamp(
            SCCACHE_GET_HEAD_TIMEOUT_MIN_SECS,
            SCCACHE_GET_HEAD_TIMEOUT_MAX_SECS,
        ));
    }

    let mut timeout_secs = if is_head {
        SCCACHE_HEAD_TIMEOUT_BASE_SECS
    } else {
        SCCACHE_GET_TIMEOUT_BASE_SECS
    };

    let max_concurrency = state.blob_download_max_concurrency.max(1);
    let available = state
        .blob_download_semaphore
        .available_permits()
        .min(max_concurrency);
    let busy = max_concurrency.saturating_sub(available);
    let load_pct = busy.saturating_mul(100) / max_concurrency;
    if load_pct >= 80 {
        timeout_secs = timeout_secs.saturating_add(SCCACHE_TIMEOUT_HIGH_LOAD_ADD_SECS);
    } else if load_pct >= 50 {
        timeout_secs = timeout_secs.saturating_add(SCCACHE_TIMEOUT_MEDIUM_LOAD_ADD_SECS);
    }

    if state.backend_breaker.is_open() {
        timeout_secs = timeout_secs.min(SCCACHE_TIMEOUT_BREAKER_CAP_SECS);
    }

    Duration::from_secs(timeout_secs.clamp(
        SCCACHE_GET_HEAD_TIMEOUT_MIN_SECS,
        SCCACHE_GET_HEAD_TIMEOUT_MAX_SECS,
    ))
}

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
            let is_head = method == Method::HEAD;
            let timeout = sccache_get_head_timeout(state, is_head);
            match tokio::time::timeout(
                timeout,
                get_or_head_kv_object(state, KvNamespace::Sccache, key_path, is_head),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(RegistryError::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    format!(
                        "sccache GET/HEAD request timed out after {}s",
                        timeout.as_secs()
                    ),
                )),
            }
        }
        _ => Err(RegistryError::method_not_allowed(
            "sccache cache supports GET, HEAD, PUT, and MKCOL",
        )),
    }
}
