use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

use crate::serve::engines::oci::uploads as engine_uploads;
use crate::serve::engines::oci::uploads::{
    PatchUploadOutcome, PutUploadOutcome, StartUploadOutcome, UploadProgress, UploadRangeHeaders,
};
use crate::serve::http::error::OciError;
use crate::serve::http::oci_route::{insert_digest_etag, insert_header};
use crate::serve::state::AppState;

pub(super) async fn start_upload(
    state: AppState,
    name: String,
    params: HashMap<String, String>,
    body: Body,
) -> Result<Response, OciError> {
    let outcome = engine_uploads::start_upload(
        &state,
        &name,
        params.get("mount").map(String::as_str),
        params.get("digest").map(String::as_str),
        body,
    )
    .await?;

    match outcome {
        StartUploadOutcome::Mounted { digest } => created_blob_response(&name, &digest, None),
        StartUploadOutcome::Completed { uuid, digest } => {
            created_blob_response(&name, &digest, Some(&uuid))
        }
        StartUploadOutcome::Accepted { uuid } => started_upload_response(&name, &uuid),
    }
}

pub(super) async fn get_upload_status(
    state: AppState,
    _name: String,
    uuid: String,
) -> Result<Response, OciError> {
    let progress = engine_uploads::get_upload_status(&state, &uuid).await?;
    upload_progress_response(StatusCode::NO_CONTENT, &progress)
}

pub(super) async fn patch_upload(
    state: AppState,
    _name: String,
    uuid: String,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, OciError> {
    match engine_uploads::patch_upload(&state, &uuid, upload_range_headers(&headers), body).await? {
        PatchUploadOutcome::Accepted(progress) => {
            upload_progress_response(StatusCode::ACCEPTED, &progress)
        }
        PatchUploadOutcome::RangeInvalid(progress) => {
            upload_progress_response(StatusCode::RANGE_NOT_SATISFIABLE, &progress)
        }
    }
}

pub(super) async fn put_upload(
    state: AppState,
    name: String,
    uuid: String,
    params: HashMap<String, String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, OciError> {
    let digest = params.get("digest").map(String::as_str);
    match engine_uploads::put_upload(
        &state,
        &name,
        &uuid,
        digest,
        upload_range_headers(&headers),
        body,
    )
    .await?
    {
        PutUploadOutcome::Completed { digest } => created_blob_response(&name, &digest, None),
        PutUploadOutcome::RangeInvalid(progress) => {
            upload_progress_response(StatusCode::RANGE_NOT_SATISFIABLE, &progress)
        }
    }
}

pub(super) async fn delete_upload(state: AppState, uuid: String) -> Result<Response, OciError> {
    engine_uploads::delete_upload(&state, &uuid).await;
    Ok((StatusCode::NO_CONTENT, Body::empty()).into_response())
}

fn started_upload_response(name: &str, uuid: &str) -> Result<Response, OciError> {
    let location = format!("/v2/{name}/blobs/uploads/{uuid}");
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Location", &location)?;
    insert_header(&mut headers, "Docker-Upload-UUID", uuid)?;
    insert_header(&mut headers, "Range", "0-0")?;
    insert_header(&mut headers, "Content-Length", "0")?;
    Ok((StatusCode::ACCEPTED, headers, Body::empty()).into_response())
}

fn created_blob_response(
    name: &str,
    digest: &str,
    upload_uuid: Option<&str>,
) -> Result<Response, OciError> {
    let location = format!("/v2/{name}/blobs/{digest}");
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Location", &location)?;
    if let Some(upload_uuid) = upload_uuid {
        insert_header(&mut headers, "Docker-Upload-UUID", upload_uuid)?;
    }
    insert_header(&mut headers, "Docker-Content-Digest", digest)?;
    insert_digest_etag(&mut headers, digest)?;
    insert_header(&mut headers, "Content-Length", "0")?;
    Ok((StatusCode::CREATED, headers, Body::empty()).into_response())
}

fn upload_progress_response(
    status: StatusCode,
    progress: &UploadProgress,
) -> Result<Response, OciError> {
    let headers = upload_status_headers(&progress.name, &progress.uuid, progress.bytes_received)?;
    Ok((status, headers, Body::empty()).into_response())
}

fn upload_status_headers(
    name: &str,
    uuid: &str,
    bytes_received: u64,
) -> Result<HeaderMap, OciError> {
    let end = if bytes_received == 0 {
        0
    } else {
        bytes_received - 1
    };
    let location = format!("/v2/{name}/blobs/uploads/{uuid}");
    let range = format!("0-{end}");
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Location", &location)?;
    insert_header(&mut headers, "Docker-Upload-UUID", uuid)?;
    insert_header(&mut headers, "Range", &range)?;
    insert_header(&mut headers, "Content-Length", "0")?;
    Ok(headers)
}

fn upload_range_headers(headers: &HeaderMap) -> UploadRangeHeaders<'_> {
    let content_range = headers.get("Content-Range");
    let range = headers.get("Range");
    UploadRangeHeaders {
        content_range: content_range.and_then(|value| value.to_str().ok()),
        range: range.and_then(|value| value.to_str().ok()),
        has_content_range: content_range.is_some(),
        has_range: range.is_some(),
    }
}

#[cfg(test)]
pub(super) fn parse_upload_offset(headers: &HeaderMap) -> Option<u64> {
    engine_uploads::parse_upload_offset(upload_range_headers(headers))
}

#[cfg(test)]
pub(super) fn parse_put_upload_offset(
    headers: &HeaderMap,
    bytes_before: u64,
) -> Result<Option<u64>, ()> {
    engine_uploads::parse_put_upload_offset(upload_range_headers(headers), bytes_before)
}
