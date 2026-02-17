use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::HashMap;

use crate::api::models::cache::{BlobDescriptor, ConfirmRequest, SaveRequest};
use crate::cas_oci;
use crate::cas_transport::upload_payload;
use crate::serve::error::OciError;
use crate::serve::state::{
    digest_tag, ref_tag_for_input, AppState, BlobLocatorEntry, UploadSession,
};
use crate::tag_utils::TagResolver;

enum OciRoute {
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    BlobUploadStart { name: String },
    BlobUpload { name: String, uuid: String },
}

fn parse_oci_path(path: &str) -> Option<OciRoute> {
    let path = path.strip_prefix('/').unwrap_or(path);

    if let Some(idx) = path.find("/blobs/uploads") {
        let name = &path[..idx];
        let rest = &path[idx + "/blobs/uploads".len()..];
        if name.is_empty() {
            return None;
        }
        return match rest {
            "" | "/" => Some(OciRoute::BlobUploadStart {
                name: name.to_string(),
            }),
            _ if rest.starts_with('/') => Some(OciRoute::BlobUpload {
                name: name.to_string(),
                uuid: rest.trim_start_matches('/').to_string(),
            }),
            _ => None,
        };
    }

    if let Some(idx) = path.find("/blobs/") {
        let name = &path[..idx];
        let digest = &path[idx + "/blobs/".len()..];
        if !name.is_empty() && !digest.is_empty() {
            return Some(OciRoute::Blob {
                name: name.to_string(),
                digest: digest.to_string(),
            });
        }
    }

    if let Some(idx) = path.find("/manifests/") {
        let name = &path[..idx];
        let reference = &path[idx + "/manifests/".len()..];
        if !name.is_empty() && !reference.is_empty() {
            return Some(OciRoute::Manifest {
                name: name.to_string(),
                reference: reference.to_string(),
            });
        }
    }

    None
}

pub async fn v2_base() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Docker-Distribution-API-Version", "registry/2.0")],
        "",
    )
}

pub async fn oci_dispatch(
    method: Method,
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, OciError> {
    match parse_oci_path(&path) {
        Some(OciRoute::Manifest { name, reference }) => match method {
            Method::GET | Method::HEAD => get_manifest(method, state, name, reference).await,
            Method::PUT => put_manifest(state, name, reference, body).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        Some(OciRoute::Blob { name, digest }) => match method {
            Method::GET | Method::HEAD => get_blob(method, state, name, digest).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        Some(OciRoute::BlobUploadStart { name }) => match method {
            Method::POST => start_upload(state, name, params, body).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        Some(OciRoute::BlobUpload { name, uuid }) => match method {
            Method::PATCH => patch_upload(state, name, uuid, headers, body).await,
            Method::PUT => put_upload(state, name, uuid, params, headers, body).await,
            Method::DELETE => delete_upload(state, uuid).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        None => Err(OciError::name_unknown("not found")),
    }
}

async fn get_manifest(
    method: Method,
    state: AppState,
    name: String,
    reference: String,
) -> Result<Response, OciError> {
    let (manifest_bytes, content_type, digest) =
        resolve_manifest(&state, &name, &reference).await?;

    let mut headers = HeaderMap::new();
    headers.insert("Docker-Content-Digest", digest.parse().unwrap());
    headers.insert("Content-Type", content_type.parse().unwrap());
    headers.insert(
        "Docker-Distribution-API-Version",
        "registry/2.0".parse().unwrap(),
    );
    headers.insert(
        "Content-Length",
        manifest_bytes.len().to_string().parse().unwrap(),
    );

    if method == Method::HEAD {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    Ok((StatusCode::OK, headers, Body::from(manifest_bytes)).into_response())
}

async fn resolve_manifest(
    state: &AppState,
    name: &str,
    reference: &str,
) -> Result<(Vec<u8>, String, String), OciError> {
    let tags = if reference.starts_with("sha256:") {
        vec![digest_tag(reference)]
    } else {
        scoped_restore_tags(&state.tag_resolver, name, reference)
    };

    let entries = state
        .api_client
        .restore(&state.workspace, &tags)
        .await
        .map_err(|e| OciError::internal(format!("Backend restore failed: {e}")))?;

    let mut entries_by_tag: HashMap<String, _> = entries
        .into_iter()
        .map(|entry| (entry.tag.clone(), entry))
        .collect();
    let mut selected = None;
    for tag in &tags {
        if let Some(entry) = entries_by_tag.remove(tag) {
            if entry.status == "hit" {
                selected = Some(entry);
                break;
            }
        }
    }
    if selected.is_none() {
        selected = entries_by_tag
            .into_values()
            .find(|entry| entry.status == "hit");
    }
    let entry =
        selected.ok_or_else(|| OciError::manifest_unknown(format!("{name}:{reference}")))?;

    let cache_entry_id = entry
        .cache_entry_id
        .as_ref()
        .ok_or_else(|| OciError::internal("Missing cache_entry_id"))?;

    let manifest_url = entry
        .manifest_url
        .as_ref()
        .ok_or_else(|| OciError::internal("Missing manifest_url"))?;

    let pointer_bytes = state
        .api_client
        .transfer_client()
        .get(manifest_url)
        .send()
        .await
        .map_err(|e| OciError::internal(format!("Failed to download pointer: {e}")))?
        .bytes()
        .await
        .map_err(|e| OciError::internal(format!("Failed to read pointer bytes: {e}")))?;

    let pointer = cas_oci::parse_pointer(&pointer_bytes)
        .map_err(|e| OciError::internal(format!("Failed to parse pointer: {e}")))?;

    let index_json = pointer
        .index_json_bytes()
        .map_err(|e| OciError::internal(format!("Failed to decode index_json: {e}")))?;

    {
        let mut locator = state.blob_locator.write().await;
        for blob in &pointer.blobs {
            locator.insert(
                name,
                &blob.digest,
                BlobLocatorEntry {
                    cache_entry_id: cache_entry_id.clone(),
                    size_bytes: blob.size_bytes,
                },
            );
        }
    }

    let content_type = detect_manifest_content_type(&index_json);
    let digest = cas_oci::prefixed_sha256_digest(&index_json);

    Ok((index_json, content_type, digest))
}

fn scoped_restore_tags(tag_resolver: &TagResolver, name: &str, reference: &str) -> Vec<String> {
    let scoped_input = format!("{name}:{reference}");
    tag_resolver
        .restore_tag_candidates(&scoped_input)
        .into_iter()
        .map(|candidate| ref_tag_for_input(&candidate))
        .collect()
}

fn scoped_save_tag(
    tag_resolver: &TagResolver,
    name: &str,
    reference: &str,
) -> Result<String, OciError> {
    let scoped_input = format!("{name}:{reference}");
    let scoped = tag_resolver
        .effective_save_tag(&scoped_input)
        .map_err(|e| OciError::internal(format!("Failed to resolve scoped tag: {e}")))?;
    Ok(ref_tag_for_input(&scoped))
}

fn detect_manifest_content_type(json_bytes: &[u8]) -> String {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(json_bytes) {
        if val.get("manifests").is_some() {
            return "application/vnd.oci.image.index.v1+json".to_string();
        }
    }
    "application/vnd.oci.image.manifest.v1+json".to_string()
}

async fn get_blob(
    method: Method,
    state: AppState,
    name: String,
    digest: String,
) -> Result<Response, OciError> {
    let locator_entry = {
        let locator = state.blob_locator.read().await;
        locator
            .get(&name, &digest)
            .cloned()
            .ok_or_else(|| OciError::blob_unknown(format!("{name}@{digest}")))?
    };

    let blob_desc = BlobDescriptor {
        digest: digest.clone(),
        size_bytes: locator_entry.size_bytes,
    };

    let download_response = state
        .api_client
        .blob_download_urls(
            &state.workspace,
            &locator_entry.cache_entry_id,
            &[blob_desc],
        )
        .await
        .map_err(|e| OciError::internal(format!("Failed to get blob download URL: {e}")))?;

    let download_url = download_response
        .download_urls
        .first()
        .ok_or_else(|| OciError::blob_unknown(format!("No download URL for {digest}")))?;

    let mut headers = HeaderMap::new();
    headers.insert("Docker-Content-Digest", digest.parse().unwrap());
    headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
    headers.insert(
        "Content-Length",
        locator_entry.size_bytes.to_string().parse().unwrap(),
    );
    headers.insert(
        "Docker-Distribution-API-Version",
        "registry/2.0".parse().unwrap(),
    );

    if method == Method::HEAD {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    let response = state
        .api_client
        .transfer_client()
        .get(&download_url.url)
        .send()
        .await
        .map_err(|e| OciError::internal(format!("Failed to download blob: {e}")))?
        .error_for_status()
        .map_err(|e| OciError::internal(format!("Blob storage returned error: {e}")))?;

    let stream = response.bytes_stream();
    let body = Body::from_stream(stream);

    Ok((StatusCode::OK, headers, body).into_response())
}

async fn start_upload(
    state: AppState,
    name: String,
    params: HashMap<String, String>,
    body: axum::body::Bytes,
) -> Result<Response, OciError> {
    let session_id = uuid::Uuid::new_v4().to_string();

    let temp_dir = std::env::temp_dir().join("boringcache-uploads");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp dir: {e}")))?;
    let temp_path = temp_dir.join(&session_id);

    if let Some(digest_param) = params.get("digest") {
        if !body.is_empty() {
            tokio::fs::write(&temp_path, &body)
                .await
                .map_err(|e| OciError::internal(format!("Failed to write blob: {e}")))?;

            let actual_digest = cas_oci::prefixed_sha256_digest(&body);
            if actual_digest != *digest_param {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(OciError::digest_invalid(format!(
                    "expected {digest_param}, got {actual_digest}"
                )));
            }

            let size = body.len() as u64;
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: session_id.clone(),
                name: name.clone(),
                temp_path,
                bytes_received: size,
                finalized_digest: Some(digest_param.clone()),
                finalized_size: Some(size),
                created_at: std::time::Instant::now(),
            });

            let location = format!("/v2/{name}/blobs/uploads/{session_id}");
            let mut headers = HeaderMap::new();
            headers.insert("Location", location.parse().unwrap());
            headers.insert("Docker-Upload-UUID", session_id.parse().unwrap());
            headers.insert("Docker-Content-Digest", digest_param.parse().unwrap());
            headers.insert("Content-Length", "0".parse().unwrap());
            return Ok((StatusCode::CREATED, headers, Body::empty()).into_response());
        }
    }

    tokio::fs::write(&temp_path, &[])
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp file: {e}")))?;

    let mut sessions = state.upload_sessions.write().await;
    sessions.create(UploadSession {
        id: session_id.clone(),
        name: name.clone(),
        temp_path,
        bytes_received: 0,
        finalized_digest: None,
        finalized_size: None,
        created_at: std::time::Instant::now(),
    });

    let location = format!("/v2/{name}/blobs/uploads/{session_id}");
    let mut headers = HeaderMap::new();
    headers.insert("Location", location.parse().unwrap());
    headers.insert("Docker-Upload-UUID", session_id.parse().unwrap());
    headers.insert("Range", "0-0".parse().unwrap());
    headers.insert("Content-Length", "0".parse().unwrap());

    Ok((StatusCode::ACCEPTED, headers, Body::empty()).into_response())
}

async fn patch_upload(
    state: AppState,
    _name: String,
    uuid: String,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, OciError> {
    let mut sessions = state.upload_sessions.write().await;
    let session = sessions
        .get_mut(&uuid)
        .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;

    let write_offset = parse_upload_offset(&headers).unwrap_or(session.bytes_received);
    if write_offset > session.bytes_received {
        return Err(OciError::digest_invalid(format!(
            "upload offset {write_offset} exceeds current size {}",
            session.bytes_received
        )));
    }

    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&session.temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to open temp file: {e}")))?;
    file.seek(std::io::SeekFrom::Start(write_offset))
        .await
        .map_err(|e| OciError::internal(format!("Failed to seek temp file: {e}")))?;

    file.write_all(&body)
        .await
        .map_err(|e| OciError::internal(format!("Failed to append data: {e}")))?;

    let written_until = write_offset.saturating_add(body.len() as u64);
    if written_until > session.bytes_received {
        session.bytes_received = written_until;
    }
    let end = if session.bytes_received == 0 {
        0
    } else {
        session.bytes_received - 1
    };
    let name = session.name.clone();

    let location = format!("/v2/{name}/blobs/uploads/{uuid}");
    let range = format!("0-{end}");
    let mut headers = HeaderMap::new();
    headers.insert("Location", location.parse().unwrap());
    headers.insert("Docker-Upload-UUID", uuid.parse().unwrap());
    headers.insert("Range", range.parse().unwrap());
    headers.insert("Content-Length", "0".parse().unwrap());

    Ok((StatusCode::ACCEPTED, headers, Body::empty()).into_response())
}

async fn put_upload(
    state: AppState,
    name: String,
    uuid: String,
    params: HashMap<String, String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, OciError> {
    let digest_param = params
        .get("digest")
        .ok_or_else(|| OciError::digest_invalid("missing digest query parameter"))?
        .clone();

    let upload_offset = parse_upload_offset(&headers);
    let (temp_path, bytes_before, bytes_after_write, write_offset) = {
        let mut sessions = state.upload_sessions.write().await;
        let session = sessions
            .get_mut(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        let bytes_before = session.bytes_received;
        let write_offset = upload_offset.unwrap_or(bytes_before);
        if write_offset > bytes_before {
            return Err(OciError::digest_invalid(format!(
                "upload offset {write_offset} exceeds current size {bytes_before}"
            )));
        }

        if !body.is_empty() {
            use tokio::io::{AsyncSeekExt, AsyncWriteExt};
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&session.temp_path)
                .await
                .map_err(|e| OciError::internal(format!("Failed to open temp file: {e}")))?;
            file.seek(std::io::SeekFrom::Start(write_offset))
                .await
                .map_err(|e| OciError::internal(format!("Failed to seek temp file: {e}")))?;
            file.write_all(&body)
                .await
                .map_err(|e| OciError::internal(format!("Failed to append data: {e}")))?;
            let written_until = write_offset.saturating_add(body.len() as u64);
            if written_until > session.bytes_received {
                session.bytes_received = written_until;
            }
        }

        (
            session.temp_path.clone(),
            bytes_before,
            session.bytes_received,
            write_offset,
        )
    };

    let mut finalized_size = bytes_after_write;
    let mut file_data = tokio::fs::read(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to read temp file: {e}")))?;
    let mut actual_digest = cas_oci::prefixed_sha256_digest(&file_data);

    if actual_digest != digest_param
        && !body.is_empty()
        && bytes_before > 0
        && write_offset == bytes_before
    {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&temp_path)
            .await
            .map_err(|e| OciError::internal(format!("Failed to reopen temp file: {e}")))?;
        file.set_len(bytes_before)
            .await
            .map_err(|e| OciError::internal(format!("Failed to truncate temp file: {e}")))?;

        file_data = tokio::fs::read(&temp_path)
            .await
            .map_err(|e| OciError::internal(format!("Failed to read truncated temp file: {e}")))?;
        actual_digest = cas_oci::prefixed_sha256_digest(&file_data);
        finalized_size = bytes_before;

        if actual_digest != digest_param {
            let body_digest = cas_oci::prefixed_sha256_digest(&body);
            if body_digest == digest_param {
                tokio::fs::write(&temp_path, &body)
                    .await
                    .map_err(|e| OciError::internal(format!("Failed to rewrite temp file: {e}")))?;
                file_data = body.to_vec();
                actual_digest = body_digest;
                finalized_size = body.len() as u64;
            }
        }
    }

    if actual_digest != digest_param && !body.is_empty() {
        let body_digest = cas_oci::prefixed_sha256_digest(&body);
        if body_digest == digest_param {
            tokio::fs::write(&temp_path, &body)
                .await
                .map_err(|e| OciError::internal(format!("Failed to rewrite temp file: {e}")))?;
            file_data = body.to_vec();
            actual_digest = body_digest;
            finalized_size = body.len() as u64;
        }
    }

    let allow_remote_reuse = actual_digest != digest_param && file_data.is_empty();
    if allow_remote_reuse {
        let check = state
            .api_client
            .check_blobs(
                &state.workspace,
                &[BlobDescriptor {
                    digest: digest_param.clone(),
                    size_bytes: 0,
                }],
            )
            .await
            .map_err(|e| OciError::internal(format!("Failed to check blob existence: {e}")))?;
        let exists = check
            .results
            .iter()
            .any(|result| result.digest == digest_param && result.exists);
        if !exists {
            return Err(OciError::digest_invalid(format!(
                "expected {digest_param}, got {actual_digest}"
            )));
        }
    } else if actual_digest != digest_param {
        return Err(OciError::digest_invalid(format!(
            "expected {digest_param}, got {actual_digest}"
        )));
    }

    {
        let mut sessions = state.upload_sessions.write().await;
        let session = sessions
            .get_mut(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        session.bytes_received = finalized_size;
        session.finalized_digest = Some(digest_param.clone());
        session.finalized_size = Some(finalized_size);
    }

    let location = format!("/v2/{name}/blobs/{digest_param}");
    let mut headers = HeaderMap::new();
    headers.insert("Location", location.parse().unwrap());
    headers.insert("Docker-Content-Digest", digest_param.parse().unwrap());
    headers.insert("Content-Length", "0".parse().unwrap());

    Ok((StatusCode::CREATED, headers, Body::empty()).into_response())
}

fn parse_upload_offset(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("Content-Range")
        .or_else(|| headers.get("Range"))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_start)
}

fn parse_range_start(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("bytes ").unwrap_or(trimmed);
    let range = without_prefix.split('/').next().unwrap_or(without_prefix);
    range.split('-').next()?.trim().parse::<u64>().ok()
}

async fn delete_upload(state: AppState, uuid: String) -> Result<Response, OciError> {
    let mut sessions = state.upload_sessions.write().await;
    if let Some(session) = sessions.remove(&uuid) {
        let _ = tokio::fs::remove_file(&session.temp_path).await;
    }
    Ok((StatusCode::NO_CONTENT, Body::empty()).into_response())
}

async fn put_manifest(
    state: AppState,
    name: String,
    reference: String,
    body: axum::body::Bytes,
) -> Result<Response, OciError> {
    let manifest_body: Vec<u8> = body.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let index_json_base64 = STANDARD.encode(&manifest_body);

    let parsed: serde_json::Value = serde_json::from_slice(&manifest_body)
        .map_err(|e| OciError::internal(format!("Invalid manifest JSON: {e}")))?;

    let blob_descriptors = extract_blob_descriptors(&parsed);

    let pointer = cas_oci::OciPointer {
        format_version: 1,
        adapter: "oci-v1".to_string(),
        index_json_base64,
        oci_layout_base64: STANDARD.encode(br#"{"imageLayoutVersion":"1.0.0"}"#),
        blobs: blob_descriptors
            .iter()
            .map(|b| cas_oci::OciPointerBlob {
                digest: b.digest.clone(),
                size_bytes: b.size_bytes,
            })
            .collect(),
    };

    let pointer_bytes = serde_json::to_vec(&pointer)
        .map_err(|e| OciError::internal(format!("Failed to serialize pointer: {e}")))?;
    let manifest_root_digest = cas_oci::prefixed_sha256_digest(&pointer_bytes);

    let tag = if reference.starts_with("sha256:") {
        digest_tag(&reference)
    } else {
        scoped_save_tag(&state.tag_resolver, &name, &reference)?
    };
    let blob_count = blob_descriptors.len() as u64;
    let blob_total_size_bytes: u64 = blob_descriptors.iter().map(|b| b.size_bytes).sum();
    let total_size_bytes = blob_total_size_bytes + manifest_body.len() as u64;

    let save_request = SaveRequest {
        tag: tag.clone(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout: Some("oci-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(blob_count.min(u32::MAX as u64) as u32),
        expected_manifest_digest: Some(manifest_root_digest.clone()),
        expected_manifest_size: Some(pointer_bytes.len() as u64),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let save_response = state
        .api_client
        .save_entry(&state.workspace, &save_request)
        .await
        .map_err(|e| OciError::internal(format!("save_entry failed: {e}")))?;

    if !save_response.exists {
        if !blob_descriptors.is_empty() {
            let upload_plan = state
                .api_client
                .blob_upload_urls(
                    &state.workspace,
                    &save_response.cache_entry_id,
                    &blob_descriptors,
                )
                .await
                .map_err(|e| OciError::internal(format!("blob_upload_urls failed: {e}")))?;

            let sessions = state.upload_sessions.read().await;
            for upload_url_info in &upload_plan.upload_urls {
                let session = sessions
                    .find_by_digest(&upload_url_info.digest)
                    .ok_or_else(|| {
                        OciError::internal(format!(
                            "No upload session for blob {}",
                            upload_url_info.digest
                        ))
                    })?;

                let blob_data = tokio::fs::read(&session.temp_path).await.map_err(|e| {
                    OciError::internal(format!("Failed to read blob temp file: {e}"))
                })?;

                upload_payload(
                    state.api_client.transfer_client(),
                    &upload_url_info.url,
                    &blob_data,
                    "application/octet-stream",
                    &upload_url_info.headers,
                )
                .await
                .map_err(|e| OciError::internal(format!("Blob upload failed: {e}")))?;
            }
        }

        let manifest_upload_url = save_response
            .manifest_upload_url
            .as_ref()
            .ok_or_else(|| OciError::internal("Missing manifest_upload_url"))?;

        upload_payload(
            state.api_client.transfer_client(),
            manifest_upload_url,
            &pointer_bytes,
            "application/cbor",
            &save_response.upload_headers,
        )
        .await
        .map_err(|e| OciError::internal(format!("Pointer upload failed: {e}")))?;
    }

    let confirm_request = ConfirmRequest {
        manifest_digest: manifest_root_digest.clone(),
        manifest_size: pointer_bytes.len() as u64,
        manifest_etag: None,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        file_count: Some(blob_count.min(u32::MAX as u64) as u32),
        uncompressed_size: None,
        compressed_size: None,
        tag: Some(tag.clone()),
    };

    state
        .api_client
        .confirm(
            &state.workspace,
            &save_response.cache_entry_id,
            &confirm_request,
        )
        .await
        .map_err(|e| OciError::internal(format!("confirm failed: {e}")))?;

    cleanup_blob_sessions(&state, &blob_descriptors).await;

    let digest_tag_name = digest_tag(&manifest_digest);
    let alias_request = SaveRequest {
        tag: digest_tag_name,
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout: Some("oci-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(blob_count.min(u32::MAX as u64) as u32),
        expected_manifest_digest: Some(manifest_root_digest.clone()),
        expected_manifest_size: Some(pointer_bytes.len() as u64),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let alias_save = state
        .api_client
        .save_entry(&state.workspace, &alias_request)
        .await
        .map_err(|e| OciError::internal(format!("digest alias save_entry failed: {e}")))?;

    let alias_confirm = ConfirmRequest {
        manifest_digest: manifest_root_digest.clone(),
        manifest_size: pointer_bytes.len() as u64,
        manifest_etag: None,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        file_count: Some(blob_count.min(u32::MAX as u64) as u32),
        uncompressed_size: None,
        compressed_size: None,
        tag: None,
    };

    state
        .api_client
        .confirm(&state.workspace, &alias_save.cache_entry_id, &alias_confirm)
        .await
        .map_err(|e| OciError::internal(format!("digest alias confirm failed: {e}")))?;

    let mut headers = HeaderMap::new();
    headers.insert("Docker-Content-Digest", manifest_digest.parse().unwrap());
    headers.insert(
        "Location",
        format!("/v2/{name}/manifests/{manifest_digest}")
            .parse()
            .unwrap(),
    );
    headers.insert("Content-Length", "0".parse().unwrap());

    Ok((StatusCode::CREATED, headers, Body::empty()).into_response())
}

fn extract_blob_descriptors(manifest: &serde_json::Value) -> Vec<BlobDescriptor> {
    let mut blobs = Vec::new();

    if let Some(config) = manifest.get("config") {
        if let (Some(digest), Some(size)) = (
            config.get("digest").and_then(|d| d.as_str()),
            config.get("size").and_then(|s| s.as_u64()),
        ) {
            blobs.push(BlobDescriptor {
                digest: digest.to_string(),
                size_bytes: size,
            });
        }
    }

    if let Some(layers) = manifest.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let (Some(digest), Some(size)) = (
                layer.get("digest").and_then(|d| d.as_str()),
                layer.get("size").and_then(|s| s.as_u64()),
            ) {
                blobs.push(BlobDescriptor {
                    digest: digest.to_string(),
                    size_bytes: size,
                });
            }
        }
    }

    blobs
}

async fn cleanup_blob_sessions(state: &AppState, blob_descriptors: &[BlobDescriptor]) {
    let mut sessions = state.upload_sessions.write().await;
    for blob in blob_descriptors {
        if let Some(session) = sessions.find_by_digest(&blob.digest).map(|s| s.id.clone()) {
            if let Some(removed) = sessions.remove(&session) {
                let _ = tokio::fs::remove_file(&removed.temp_path).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::GitContext;
    use crate::platform::Platform;
    use crate::tag_utils::TagResolver;

    #[test]
    fn parse_single_segment_manifest() {
        match parse_oci_path("my-cache/manifests/main") {
            Some(OciRoute::Manifest { name, reference }) => {
                assert_eq!(name, "my-cache");
                assert_eq!(reference, "main");
            }
            _ => panic!("expected Manifest"),
        }
    }

    #[test]
    fn parse_multi_segment_manifest() {
        match parse_oci_path("org/cache/manifests/latest") {
            Some(OciRoute::Manifest { name, reference }) => {
                assert_eq!(name, "org/cache");
                assert_eq!(reference, "latest");
            }
            _ => panic!("expected Manifest"),
        }
    }

    #[test]
    fn parse_deeply_nested_name() {
        match parse_oci_path("a/b/c/blobs/sha256:abc") {
            Some(OciRoute::Blob { name, digest }) => {
                assert_eq!(name, "a/b/c");
                assert_eq!(digest, "sha256:abc");
            }
            _ => panic!("expected Blob"),
        }
    }

    #[test]
    fn parse_blob_upload_start() {
        match parse_oci_path("my-cache/blobs/uploads/") {
            Some(OciRoute::BlobUploadStart { name }) => {
                assert_eq!(name, "my-cache");
            }
            _ => panic!("expected BlobUploadStart"),
        }
    }

    #[test]
    fn parse_blob_upload_start_without_trailing_slash() {
        match parse_oci_path("my-cache/blobs/uploads") {
            Some(OciRoute::BlobUploadStart { name }) => {
                assert_eq!(name, "my-cache");
            }
            _ => panic!("expected BlobUploadStart"),
        }
    }

    #[test]
    fn parse_blob_upload_uuid() {
        match parse_oci_path("my-cache/blobs/uploads/some-uuid-here") {
            Some(OciRoute::BlobUpload { name, uuid }) => {
                assert_eq!(name, "my-cache");
                assert_eq!(uuid, "some-uuid-here");
            }
            _ => panic!("expected BlobUpload"),
        }
    }

    #[test]
    fn parse_leading_slash_stripped() {
        match parse_oci_path("/my-cache/manifests/v1") {
            Some(OciRoute::Manifest { name, reference }) => {
                assert_eq!(name, "my-cache");
                assert_eq!(reference, "v1");
            }
            _ => panic!("expected Manifest"),
        }
    }

    #[test]
    fn parse_invalid_path_returns_none() {
        assert!(parse_oci_path("").is_none());
        assert!(parse_oci_path("just-a-name").is_none());
        assert!(parse_oci_path("/manifests/ref").is_none());
    }

    #[test]
    fn extract_blob_descriptors_excludes_child_manifests() {
        let index_json = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": "sha256:child1", "size": 500, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
                {"digest": "sha256:child2", "size": 600, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
            ]
        });
        let blobs = extract_blob_descriptors(&index_json);
        assert!(blobs.is_empty());
    }

    #[test]
    fn extract_blob_descriptors_includes_config_and_layers() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:cfg", "size": 100},
            "layers": [
                {"digest": "sha256:layer1", "size": 2000},
                {"digest": "sha256:layer2", "size": 3000}
            ]
        });
        let blobs = extract_blob_descriptors(&manifest_json);
        assert_eq!(blobs.len(), 3);
        assert_eq!(blobs[0].digest, "sha256:cfg");
        assert_eq!(blobs[1].digest, "sha256:layer1");
        assert_eq!(blobs[2].digest, "sha256:layer2");
    }

    #[test]
    fn scoped_save_tag_applies_git_suffix() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = scoped_save_tag(&resolver, "buildkit-cache", "main").unwrap();
        assert_eq!(
            tag,
            ref_tag_for_input("buildkit-cache:main-branch-feature-x")
        );
    }

    #[test]
    fn scoped_restore_tags_include_default_branch_fallback() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tags = scoped_restore_tags(&resolver, "buildkit-cache", "main");
        assert_eq!(
            tags,
            vec![
                ref_tag_for_input("buildkit-cache:main-branch-feature-x"),
                ref_tag_for_input("buildkit-cache:main"),
            ]
        );
    }

    #[test]
    fn scoped_save_tag_on_default_branch_uses_base() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("main".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = scoped_save_tag(&resolver, "buildkit-cache", "main").unwrap();
        assert_eq!(tag, ref_tag_for_input("buildkit-cache:main"));
    }

    #[test]
    fn scoped_save_tag_applies_platform_suffix() {
        let resolver = TagResolver::new(
            Some(Platform::new_for_testing(
                "linux",
                "x86_64",
                Some("ubuntu"),
                Some("22"),
            )),
            GitContext::default(),
            false,
        );

        let tag = scoped_save_tag(&resolver, "buildkit-cache", "main").unwrap();
        assert_eq!(
            tag,
            ref_tag_for_input("buildkit-cache:main-ubuntu-22-x86_64")
        );
    }
}
