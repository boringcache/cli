use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::serve::http::error::OciError;
use crate::serve::http::oci_route::insert_header;
use crate::serve::state::{AppState, BlobReadHandle, UploadSession};

use super::blobs::has_remote_blob;
use super::{
    EMPTY_FINALIZE_LOCAL_RETRY_ATTEMPTS, EMPTY_FINALIZE_LOCAL_RETRY_DELAY_MS,
    EMPTY_FINALIZE_REMOTE_RETRY_ATTEMPTS, EMPTY_FINALIZE_REMOTE_RETRY_DELAY_MS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmptyFinalizeReuse {
    Local,
    Remote,
    Missing,
}

pub(super) async fn find_local_uploaded_blob(
    state: &AppState,
    name: &str,
    digest: &str,
) -> Option<BlobReadHandle> {
    let sessions = state.upload_sessions.read().await;
    let session = sessions.find_by_name_and_digest(name, digest)?;
    let size_bytes = session.finalized_size.unwrap_or(session.bytes_received);
    if size_bytes == 0 {
        return None;
    }
    Some(BlobReadHandle::from_file(
        session.temp_path.clone(),
        size_bytes,
    ))
}

pub(super) async fn has_non_empty_local_blob(state: &AppState, digest: &str) -> bool {
    {
        let sessions = state.upload_sessions.read().await;
        if sessions
            .find_by_digest(digest)
            .is_some_and(|session| session.finalized_size.unwrap_or(session.bytes_received) > 0)
        {
            return true;
        }
    }

    state.blob_read_cache.get_handle(digest).await.is_some()
}

pub(super) async fn start_upload(
    state: AppState,
    name: String,
    params: HashMap<String, String>,
    body: Body,
) -> Result<Response, OciError> {
    if let Some(mount_digest) = params.get("mount") {
        if !crate::cas_oci::is_valid_sha256_digest(mount_digest) {
            return Err(OciError::digest_invalid(format!(
                "unsupported mount digest format: {mount_digest}"
            )));
        }

        if stage_mounted_blob_session(&state, &name, mount_digest).await? {
            let location = format!("/v2/{name}/blobs/{mount_digest}");
            let mut headers = HeaderMap::new();
            insert_header(&mut headers, "Location", &location)?;
            insert_header(&mut headers, "Docker-Content-Digest", mount_digest)?;
            insert_header(&mut headers, "Content-Length", "0")?;
            return Ok((StatusCode::CREATED, headers, Body::empty()).into_response());
        }
    }

    let session_id = uuid::Uuid::new_v4().to_string();

    let temp_dir = state.oci_upload_temp_dir.clone();
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp dir: {e}")))?;
    let temp_path = temp_dir.join(&session_id);

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp file: {e}")))?;
    let body_size = write_body_to_file(body, &mut file).await?;
    drop(file);

    if let Some(digest_param) = params.get("digest")
        && body_size > 0
    {
        let (_, actual_digest) = read_file_digest_and_size(&temp_path).await?;
        if actual_digest != *digest_param {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(OciError::digest_invalid(format!(
                "expected {digest_param}, got {actual_digest}"
            )));
        }

        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: session_id.clone(),
            name: name.clone(),
            temp_path,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: body_size,
            finalized_digest: Some(digest_param.clone()),
            finalized_size: Some(body_size),
            created_at: std::time::Instant::now(),
        });

        let location = format!("/v2/{name}/blobs/{digest_param}");
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, "Location", &location)?;
        insert_header(&mut headers, "Docker-Upload-UUID", &session_id)?;
        insert_header(&mut headers, "Docker-Content-Digest", digest_param)?;
        insert_header(&mut headers, "Content-Length", "0")?;
        return Ok((StatusCode::CREATED, headers, Body::empty()).into_response());
    }

    let mut sessions = state.upload_sessions.write().await;
    sessions.create(UploadSession {
        id: session_id.clone(),
        name: name.clone(),
        temp_path,
        write_lock: Arc::new(tokio::sync::Mutex::new(())),
        bytes_received: body_size,
        finalized_digest: None,
        finalized_size: None,
        created_at: std::time::Instant::now(),
    });

    let location = format!("/v2/{name}/blobs/uploads/{session_id}");
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Location", &location)?;
    insert_header(&mut headers, "Docker-Upload-UUID", &session_id)?;
    insert_header(&mut headers, "Range", "0-0")?;
    insert_header(&mut headers, "Content-Length", "0")?;

    Ok((StatusCode::ACCEPTED, headers, Body::empty()).into_response())
}

async fn stage_mounted_blob_session(
    state: &AppState,
    name: &str,
    digest: &str,
) -> Result<bool, OciError> {
    {
        let sessions = state.upload_sessions.read().await;
        if sessions.find_by_name_and_digest(name, digest).is_some() {
            return Ok(true);
        }
    }

    if let Some(handle) = existing_mounted_blob_handle(state, name, digest).await {
        let session_id = format!("oci-mount-{}", uuid::Uuid::new_v4());
        let temp_path = materialize_mounted_blob(state, digest, &handle).await?;
        let size_bytes = handle.size_bytes();

        let mut sessions = state.upload_sessions.write().await;
        if sessions.find_by_name_and_digest(name, digest).is_some() {
            drop(sessions);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Ok(true);
        }

        sessions.create(UploadSession {
            id: session_id,
            name: name.to_string(),
            temp_path,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: size_bytes,
            finalized_digest: Some(digest.to_string()),
            finalized_size: Some(size_bytes),
            created_at: std::time::Instant::now(),
        });
        return Ok(true);
    }

    Ok(false)
}

async fn existing_mounted_blob_handle(
    state: &AppState,
    name: &str,
    digest: &str,
) -> Option<BlobReadHandle> {
    {
        let sessions = state.upload_sessions.read().await;
        if let Some(session) = sessions.find_by_name_and_digest(name, digest) {
            let size_bytes = session.finalized_size.unwrap_or(session.bytes_received);
            if size_bytes > 0 {
                return Some(BlobReadHandle::from_file(
                    session.temp_path.clone(),
                    size_bytes,
                ));
            }
        }
        if let Some(session) = sessions.find_by_digest(digest) {
            let size_bytes = session.finalized_size.unwrap_or(session.bytes_received);
            if size_bytes > 0 {
                return Some(BlobReadHandle::from_file(
                    session.temp_path.clone(),
                    size_bytes,
                ));
            }
        }
    }

    state.blob_read_cache.get_handle(digest).await
}

async fn materialize_mounted_blob(
    state: &AppState,
    digest: &str,
    handle: &BlobReadHandle,
) -> Result<std::path::PathBuf, OciError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    let digest_hex = crate::cas_oci::digest_hex_component(digest)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            crate::cas_oci::sha256_hex(format!("{digest}:{}", uuid::Uuid::new_v4()).as_bytes())
        });
    let temp_dir = state.oci_upload_temp_dir.join("mounts");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create mount temp dir: {e}")))?;
    let temp_path = temp_dir.join(format!(
        "blob-{}-{}",
        &digest_hex[..digest_hex.len().min(16)],
        uuid::Uuid::new_v4()
    ));

    let mut source = tokio::fs::File::open(handle.path()).await.map_err(|e| {
        OciError::internal(format!(
            "Failed to open mounted blob source {}: {e}",
            handle.path().display()
        ))
    })?;
    if handle.offset() > 0 {
        source
            .seek(std::io::SeekFrom::Start(handle.offset()))
            .await
            .map_err(|e| OciError::internal(format!("Failed to seek mounted blob source: {e}")))?;
    }

    let mut dest = tokio::fs::File::create(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create mounted blob copy: {e}")))?;
    let mut limited = source.take(handle.size_bytes());
    let copied = tokio::io::copy(&mut limited, &mut dest)
        .await
        .map_err(|e| OciError::internal(format!("Failed to copy mounted blob: {e}")))?;
    if copied != handle.size_bytes() {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(OciError::internal(format!(
            "Mounted blob copy was incomplete for {digest}: expected {} bytes, copied {}",
            handle.size_bytes(),
            copied
        )));
    }
    dest.flush()
        .await
        .map_err(|e| OciError::internal(format!("Failed to flush mounted blob copy: {e}")))?;
    dest.sync_data()
        .await
        .map_err(|e| OciError::internal(format!("Failed to sync mounted blob copy: {e}")))?;

    Ok(temp_path)
}

pub(super) async fn get_upload_status(
    state: AppState,
    _name: String,
    uuid: String,
) -> Result<Response, OciError> {
    let (name, bytes_received) = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .get(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        (session.name.clone(), session.bytes_received)
    };

    let headers = upload_status_headers(&name, &uuid, bytes_received)?;

    Ok((StatusCode::NO_CONTENT, headers, Body::empty()).into_response())
}

pub(super) async fn patch_upload(
    state: AppState,
    _name: String,
    uuid: String,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, OciError> {
    let (temp_path, session_write_lock) = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .get(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        (session.temp_path.clone(), session.write_lock.clone())
    };
    let _session_guard = session_write_lock.lock().await;

    let (name, bytes_before) = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .get(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        (session.name.clone(), session.bytes_received)
    };

    let write_offset = if headers.contains_key("Content-Range") || headers.contains_key("Range") {
        let Some(write_offset) = parse_upload_offset(&headers) else {
            return invalid_upload_range_response(&name, &uuid, bytes_before);
        };
        if write_offset != bytes_before {
            return invalid_upload_range_response(&name, &uuid, bytes_before);
        }
        write_offset
    } else {
        bytes_before
    };

    use tokio::io::AsyncSeekExt;

    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to open temp file: {e}")))?;
    file.seek(std::io::SeekFrom::Start(write_offset))
        .await
        .map_err(|e| OciError::internal(format!("Failed to seek temp file: {e}")))?;

    let bytes_written = write_body_to_file(body, &mut file).await?;
    drop(file);

    let mut sessions = state.upload_sessions.write().await;
    let session = sessions
        .get_mut(&uuid)
        .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
    let written_until = write_offset.saturating_add(bytes_written);
    if written_until > session.bytes_received {
        session.bytes_received = written_until;
    }
    let name = session.name.clone();

    let headers = upload_status_headers(&name, &uuid, session.bytes_received)?;

    Ok((StatusCode::ACCEPTED, headers, Body::empty()).into_response())
}

pub(super) async fn put_upload(
    state: AppState,
    name: String,
    uuid: String,
    params: HashMap<String, String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, OciError> {
    let digest_param = params
        .get("digest")
        .ok_or_else(|| OciError::digest_invalid("missing digest query parameter"))?
        .clone();

    let (temp_path, session_write_lock) = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .get(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        (session.temp_path.clone(), session.write_lock.clone())
    };
    let _session_guard = session_write_lock.lock().await;

    let (session_name, bytes_before) = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .get(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        (session.name.clone(), session.bytes_received)
    };
    let write_offset = match parse_put_upload_offset(&headers, bytes_before) {
        Ok(Some(write_offset)) => write_offset,
        Ok(None) => bytes_before,
        Err(()) => return invalid_upload_range_response(&session_name, &uuid, bytes_before),
    };

    use tokio::io::AsyncSeekExt;

    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to open temp file: {e}")))?;
    file.seek(std::io::SeekFrom::Start(write_offset))
        .await
        .map_err(|e| OciError::internal(format!("Failed to seek temp file: {e}")))?;
    let bytes_written = write_body_to_file(body, &mut file)
        .await
        .map_err(|e| {
            OciError::internal(format!(
                "OCI PUT body stream error: upload={} digest={} error={} bytes_before={} write_offset={}",
                uuid,
                digest_param,
                e.message(),
                bytes_before,
                write_offset
            ))
        })?;
    if write_offset == 0 && bytes_before > 0 && bytes_written > 0 {
        file.set_len(bytes_written)
            .await
            .map_err(|e| OciError::internal(format!("Failed to resize temp file: {e}")))?;
    }
    let mut bytes_after_write = bytes_before;
    if bytes_written > 0 {
        if write_offset == 0 {
            bytes_after_write = bytes_written;
        } else {
            let written_until = write_offset.saturating_add(bytes_written);
            if written_until > bytes_after_write {
                bytes_after_write = written_until;
            }
        }
    }

    let mut finalized_size = bytes_after_write;
    let (mut file_size, mut actual_digest) = read_open_file_digest_and_size(&mut file).await?;

    if actual_digest != digest_param
        && bytes_written > 0
        && bytes_before > 0
        && write_offset == bytes_before
    {
        file.set_len(bytes_before)
            .await
            .map_err(|e| OciError::internal(format!("Failed to truncate temp file: {e}")))?;

        let (truncated_size, truncated_digest) = read_open_file_digest_and_size(&mut file).await?;
        file_size = truncated_size;
        actual_digest = truncated_digest;
        finalized_size = bytes_before;
    }

    if actual_digest != digest_param && file_size == 0 {
        match resolve_empty_finalize_reuse(&state, &digest_param).await? {
            EmptyFinalizeReuse::Local => {
                log::debug!(
                    "OCI finalize accepted local blob reuse: name={} upload={} digest={} bytes_before={} bytes_written={} write_offset={}",
                    name,
                    uuid,
                    digest_param,
                    bytes_before,
                    bytes_written,
                    write_offset
                );
            }
            EmptyFinalizeReuse::Remote => {
                log::debug!(
                    "OCI finalize accepted remote blob reuse: name={} upload={} digest={} bytes_before={} bytes_written={} write_offset={}",
                    name,
                    uuid,
                    digest_param,
                    bytes_before,
                    bytes_written,
                    write_offset
                );
            }
            EmptyFinalizeReuse::Missing => {
                eprintln!(
                    "OCI finalize empty payload (no local/remote reuse): upload={} digest={} bytes_before={} bytes_written={} write_offset={}",
                    uuid, digest_param, bytes_before, bytes_written, write_offset
                );
                return Err(OciError::digest_invalid(format!(
                    "expected {digest_param}, got {actual_digest}"
                )));
            }
        }
    } else if actual_digest != digest_param {
        log::warn!(
            "OCI finalize digest mismatch: name={} upload={} expected={} actual={} bytes_before={} bytes_written={} write_offset={} file_size={}",
            name,
            uuid,
            digest_param,
            actual_digest,
            bytes_before,
            bytes_written,
            write_offset,
            file_size
        );
        return Err(OciError::digest_invalid(format!(
            "expected {digest_param}, got {actual_digest}"
        )));
    }
    drop(file);

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
    insert_header(&mut headers, "Location", &location)?;
    insert_header(&mut headers, "Docker-Content-Digest", &digest_param)?;
    insert_header(&mut headers, "Content-Length", "0")?;

    Ok((StatusCode::CREATED, headers, Body::empty()).into_response())
}

pub(super) async fn delete_upload(state: AppState, uuid: String) -> Result<Response, OciError> {
    let mut sessions = state.upload_sessions.write().await;
    if let Some(session) = sessions.remove(&uuid) {
        let _ = tokio::fs::remove_file(&session.temp_path).await;
    }
    Ok((StatusCode::NO_CONTENT, Body::empty()).into_response())
}

pub(super) fn parse_upload_offset(headers: &HeaderMap) -> Option<u64> {
    if !(headers.contains_key("Content-Range") || headers.contains_key("Range")) {
        return None;
    }
    headers
        .get("Content-Range")
        .or_else(|| headers.get("Range"))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_start)
}

pub(super) fn parse_put_upload_offset(
    headers: &HeaderMap,
    bytes_before: u64,
) -> Result<Option<u64>, ()> {
    if let Some(offset) = headers
        .get("Content-Range")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_start)
    {
        if offset != bytes_before {
            return Err(());
        }
        return Ok(Some(offset));
    }
    if headers.contains_key("Content-Range") {
        return Err(());
    }

    if let Some(end) = headers
        .get("Range")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_end)
    {
        let reported_bytes = end.saturating_add(1);
        if reported_bytes != bytes_before {
            return Err(());
        }
        return Ok(Some(bytes_before));
    }
    if headers.contains_key("Range") {
        return Err(());
    }

    Ok(None)
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

fn invalid_upload_range_response(
    name: &str,
    uuid: &str,
    bytes_received: u64,
) -> Result<Response, OciError> {
    let headers = upload_status_headers(name, uuid, bytes_received)?;
    Ok((StatusCode::RANGE_NOT_SATISFIABLE, headers, Body::empty()).into_response())
}

async fn write_body_to_file(body: Body, file: &mut tokio::fs::File) -> Result<u64, OciError> {
    use tokio::io::AsyncWriteExt;

    let mut stream = body.into_data_stream();
    let mut bytes_written: u64 = 0;

    loop {
        let next_chunk = stream.next().await;
        let Some(chunk_result) = next_chunk else {
            break;
        };
        let chunk = chunk_result
            .map_err(|e| OciError::internal(format!("Failed to read request body chunk: {e}")))?;
        if chunk.is_empty() {
            continue;
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| OciError::internal(format!("Failed to write request body chunk: {e}")))?;
        bytes_written = bytes_written.saturating_add(chunk.len() as u64);
    }

    Ok(bytes_written)
}

async fn read_file_digest_and_size(path: &std::path::Path) -> Result<(u64, String), OciError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(u64, String), String> {
        use std::io::Read;

        let mut file = std::fs::File::open(&path)
            .map_err(|e| format!("Failed to open temp file {}: {e}", path.display()))?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut hasher = Sha256::new();
        let mut size = 0u64;

        loop {
            let read = file
                .read(&mut buf)
                .map_err(|e| format!("Failed to read temp file {}: {e}", path.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
            size = size.saturating_add(read as u64);
        }

        let digest = format!("sha256:{:x}", hasher.finalize());
        Ok((size, digest))
    })
    .await
    .map_err(|e| OciError::internal(format!("Digest worker join failed: {e}")))?
    .map_err(OciError::internal)
}

async fn read_open_file_digest_and_size(
    file: &mut tokio::fs::File,
) -> Result<(u64, String), OciError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    file.flush()
        .await
        .map_err(|e| OciError::internal(format!("Failed to flush temp file: {e}")))?;
    file.sync_data()
        .await
        .map_err(|e| OciError::internal(format!("Failed to sync temp file: {e}")))?;
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|e| OciError::internal(format!("Failed to seek temp file for digest: {e}")))?;

    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buf)
            .await
            .map_err(|e| OciError::internal(format!("Failed to read temp file for digest: {e}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size = size.saturating_add(read as u64);
    }

    Ok((size, format!("sha256:{:x}", hasher.finalize())))
}

async fn resolve_empty_finalize_reuse(
    state: &AppState,
    digest: &str,
) -> Result<EmptyFinalizeReuse, OciError> {
    for attempt in 0..EMPTY_FINALIZE_LOCAL_RETRY_ATTEMPTS {
        if has_non_empty_local_blob(state, digest).await {
            return Ok(EmptyFinalizeReuse::Local);
        }
        if attempt + 1 < EMPTY_FINALIZE_LOCAL_RETRY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(EMPTY_FINALIZE_LOCAL_RETRY_DELAY_MS)).await;
        }
    }

    for attempt in 0..EMPTY_FINALIZE_REMOTE_RETRY_ATTEMPTS {
        if has_remote_blob(state, digest).await? {
            return Ok(EmptyFinalizeReuse::Remote);
        }
        if attempt + 1 < EMPTY_FINALIZE_REMOTE_RETRY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(EMPTY_FINALIZE_REMOTE_RETRY_DELAY_MS)).await;
        }
    }

    Ok(EmptyFinalizeReuse::Missing)
}

fn parse_range_start(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("bytes ").unwrap_or(trimmed);
    let range = without_prefix.split('/').next().unwrap_or(without_prefix);
    range.split('-').next()?.trim().parse::<u64>().ok()
}

fn parse_range_end(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("bytes ").unwrap_or(trimmed);
    let range = without_prefix.split('/').next().unwrap_or(without_prefix);
    range.split('-').nth(1)?.trim().parse::<u64>().ok()
}
