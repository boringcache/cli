use axum::http::{HeaderMap, Method};
use axum::response::Response;

use crate::serve::engines::oci::blobs as oci_blobs;
use crate::serve::http::error::OciError;
use crate::serve::state::AppState;

pub(super) async fn get_blob(
    method: Method,
    headers: HeaderMap,
    state: AppState,
    name: String,
    digest: String,
) -> Result<Response, OciError> {
    oci_blobs::get_blob(method, &headers, state, name, digest).await
}
