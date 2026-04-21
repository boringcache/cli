use axum::body::Body;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::models::cache::BlobDescriptor;
use crate::serve::http::error::OciError;
use crate::serve::state::{AppState, BlobReadHandle, BlobReadLease, UploadSession};

const OCI_API_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const EMPTY_FINALIZE_LOCAL_RETRY_ATTEMPTS: usize = 20;
const EMPTY_FINALIZE_LOCAL_RETRY_DELAY_MS: u64 = 75;
const EMPTY_FINALIZE_REMOTE_RETRY_ATTEMPTS: usize = 3;
const EMPTY_FINALIZE_REMOTE_RETRY_DELAY_MS: u64 = 100;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UploadRangeHeaders<'a> {
    pub(crate) content_range: Option<&'a str>,
    pub(crate) range: Option<&'a str>,
    pub(crate) has_content_range: bool,
    pub(crate) has_range: bool,
}

impl UploadRangeHeaders<'_> {
    fn has_any(self) -> bool {
        self.has_content_range || self.has_range
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UploadProgress {
    pub(crate) name: String,
    pub(crate) uuid: String,
    pub(crate) bytes_received: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StartUploadOutcome {
    Mounted { digest: String },
    Completed { uuid: String, digest: String },
    Accepted { uuid: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PatchUploadOutcome {
    Accepted(UploadProgress),
    RangeInvalid(UploadProgress),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PutUploadOutcome {
    Completed { digest: String },
    RangeInvalid(UploadProgress),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmptyFinalizeReuse {
    Local,
    Remote,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WrittenBody {
    bytes_written: u64,
    digest: String,
}

enum ExistingMountedBlob {
    UploadSession(BlobReadHandle),
    BlobReadCache(BlobReadLease),
}

impl ExistingMountedBlob {
    fn size_bytes(&self) -> u64 {
        match self {
            Self::UploadSession(handle) => handle.size_bytes(),
            Self::BlobReadCache(lease) => lease.size_bytes(),
        }
    }
}

pub(crate) async fn find_local_uploaded_blob(
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
    Some(BlobReadHandle::from_file_range(
        session.body_path().to_path_buf(),
        session.body_offset(),
        size_bytes,
    ))
}

pub(crate) async fn has_non_empty_local_blob(state: &AppState, digest: &str) -> bool {
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

pub(crate) async fn has_remote_blob(state: &AppState, digest: &str) -> Result<bool, OciError> {
    let check = tokio::time::timeout(
        OCI_API_CALL_TIMEOUT,
        state.api_client.check_blobs_verified(
            &state.workspace,
            &[BlobDescriptor {
                digest: digest.to_string(),
                size_bytes: 0,
            }],
        ),
    )
    .await
    .map_err(|_| {
        OciError::internal(format!(
            "Timed out checking blob existence after {}s",
            OCI_API_CALL_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| OciError::internal(format!("Failed to check blob existence: {e}")))?;

    Ok(check
        .results
        .iter()
        .any(|result| result.digest == digest && result.exists))
}

pub(crate) async fn start_upload(
    state: &AppState,
    name: &str,
    mount_digest: Option<&str>,
    digest_param: Option<&str>,
    body: Body,
) -> Result<StartUploadOutcome, OciError> {
    if let Some(mount_digest) = mount_digest {
        if !crate::cas_oci::is_valid_sha256_digest(mount_digest) {
            return Err(OciError::digest_invalid(format!(
                "unsupported mount digest format: {mount_digest}"
            )));
        }

        if stage_mounted_blob_session(state, name, mount_digest).await? {
            return Ok(StartUploadOutcome::Mounted {
                digest: mount_digest.to_string(),
            });
        }
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let temp_path = create_upload_temp_file(state, &session_id).await?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp file: {e}")))?;
    let written = write_body_to_file(body, &mut file).await?;
    let body_size = written.bytes_written;
    drop(file);

    if let Some(digest_param) = digest_param
        && body_size > 0
    {
        let actual_digest = written.digest;
        if actual_digest != digest_param {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(OciError::digest_invalid(format!(
                "expected {digest_param}, got {actual_digest}"
            )));
        }

        create_upload_session(
            state,
            session_id.clone(),
            name,
            temp_path,
            body_size,
            Some(digest_param.to_string()),
            Some(body_size),
        )
        .await;
        state.oci_negative_cache.invalidate_blob(name, digest_param);

        return Ok(StartUploadOutcome::Completed {
            uuid: session_id,
            digest: digest_param.to_string(),
        });
    }

    create_upload_session(
        state,
        session_id.clone(),
        name,
        temp_path,
        body_size,
        None,
        None,
    )
    .await;

    Ok(StartUploadOutcome::Accepted { uuid: session_id })
}

pub(crate) async fn get_upload_status(
    state: &AppState,
    uuid: &str,
) -> Result<UploadProgress, OciError> {
    upload_progress(state, uuid).await
}

pub(crate) async fn patch_upload(
    state: &AppState,
    uuid: &str,
    range_headers: UploadRangeHeaders<'_>,
    body: Body,
) -> Result<PatchUploadOutcome, OciError> {
    let (temp_path, session_write_lock) = session_path_and_lock(state, uuid).await?;
    let _session_guard = session_write_lock.lock().await;

    let progress_before = upload_progress(state, uuid).await?;
    let write_offset = if range_headers.has_any() {
        let Some(write_offset) = parse_upload_offset(range_headers) else {
            return Ok(PatchUploadOutcome::RangeInvalid(progress_before));
        };
        if write_offset != progress_before.bytes_received {
            return Ok(PatchUploadOutcome::RangeInvalid(progress_before));
        }
        write_offset
    } else {
        progress_before.bytes_received
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

    let bytes_written = write_body_to_file(body, &mut file).await?.bytes_written;
    drop(file);

    let mut sessions = state.upload_sessions.write().await;
    let session = sessions
        .get_mut(uuid)
        .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
    let written_until = write_offset.saturating_add(bytes_written);
    if written_until > session.bytes_received {
        session.bytes_received = written_until;
    }

    Ok(PatchUploadOutcome::Accepted(UploadProgress {
        name: session.name.clone(),
        uuid: uuid.to_string(),
        bytes_received: session.bytes_received,
    }))
}

pub(crate) async fn put_upload(
    state: &AppState,
    name: &str,
    uuid: &str,
    digest_param: Option<&str>,
    range_headers: UploadRangeHeaders<'_>,
    body: Body,
) -> Result<PutUploadOutcome, OciError> {
    let digest_param = digest_param
        .ok_or_else(|| OciError::digest_invalid("missing digest query parameter"))?
        .to_string();

    let (temp_path, session_write_lock) = session_path_and_lock(state, uuid).await?;
    let _session_guard = session_write_lock.lock().await;

    let progress_before = upload_progress(state, uuid).await?;
    let write_offset = match parse_put_upload_offset(range_headers, progress_before.bytes_received)
    {
        Ok(Some(write_offset)) => write_offset,
        Ok(None) => progress_before.bytes_received,
        Err(()) => return Ok(PutUploadOutcome::RangeInvalid(progress_before)),
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
    let written = write_body_to_file(body, &mut file)
        .await
        .map_err(|e| {
            OciError::internal(format!(
                "OCI PUT body stream error: upload={} digest={} error={} bytes_before={} write_offset={}",
                uuid,
                digest_param,
                e.message(),
                progress_before.bytes_received,
                write_offset
            ))
        })?;
    let bytes_written = written.bytes_written;
    if write_offset == 0 && progress_before.bytes_received > 0 && bytes_written > 0 {
        file.set_len(bytes_written)
            .await
            .map_err(|e| OciError::internal(format!("Failed to resize temp file: {e}")))?;
    }
    let mut bytes_after_write = progress_before.bytes_received;
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
    let (mut file_size, mut actual_digest) = if write_offset == 0 && bytes_written > 0 {
        flush_open_file(&mut file).await?;
        (bytes_written, written.digest)
    } else {
        read_open_file_digest_and_size(&mut file).await?
    };

    if actual_digest != digest_param
        && bytes_written > 0
        && progress_before.bytes_received > 0
        && write_offset == progress_before.bytes_received
    {
        file.set_len(progress_before.bytes_received)
            .await
            .map_err(|e| OciError::internal(format!("Failed to truncate temp file: {e}")))?;

        let (truncated_size, truncated_digest) = read_open_file_digest_and_size(&mut file).await?;
        file_size = truncated_size;
        actual_digest = truncated_digest;
        finalized_size = progress_before.bytes_received;
    }

    if actual_digest != digest_param && file_size == 0 {
        match resolve_empty_finalize_reuse(state, &digest_param).await? {
            EmptyFinalizeReuse::Local => {
                log::debug!(
                    "OCI finalize accepted local blob reuse: name={} upload={} digest={} bytes_before={} bytes_written={} write_offset={}",
                    name,
                    uuid,
                    digest_param,
                    progress_before.bytes_received,
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
                    progress_before.bytes_received,
                    bytes_written,
                    write_offset
                );
            }
            EmptyFinalizeReuse::Missing => {
                eprintln!(
                    "OCI finalize empty payload (no local/remote reuse): upload={} digest={} bytes_before={} bytes_written={} write_offset={}",
                    uuid, digest_param, progress_before.bytes_received, bytes_written, write_offset
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
            progress_before.bytes_received,
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
            .get_mut(uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        session.bytes_received = finalized_size;
        session.finalized_digest = Some(digest_param.clone());
        session.finalized_size = Some(finalized_size);
    }
    state
        .oci_negative_cache
        .invalidate_blob(name, &digest_param);

    Ok(PutUploadOutcome::Completed {
        digest: digest_param,
    })
}

pub(crate) async fn delete_upload(state: &AppState, uuid: &str) {
    let mut sessions = state.upload_sessions.write().await;
    if let Some(session) = sessions.remove(uuid)
        && session.owns_temp_file()
    {
        let _ = tokio::fs::remove_file(&session.temp_path).await;
    }
}

pub(crate) fn parse_upload_offset(headers: UploadRangeHeaders<'_>) -> Option<u64> {
    if !headers.has_any() {
        return None;
    }
    headers
        .content_range
        .or(headers.range)
        .and_then(parse_range_start)
}

pub(crate) fn parse_put_upload_offset(
    headers: UploadRangeHeaders<'_>,
    bytes_before: u64,
) -> Result<Option<u64>, ()> {
    if let Some(offset) = headers.content_range.and_then(parse_range_start) {
        if offset != bytes_before {
            return Err(());
        }
        return Ok(Some(offset));
    }
    if headers.has_content_range {
        return Err(());
    }

    if let Some(end) = headers.range.and_then(parse_range_end) {
        let reported_bytes = end.saturating_add(1);
        if reported_bytes != bytes_before {
            return Err(());
        }
        return Ok(Some(bytes_before));
    }
    if headers.has_range {
        return Err(());
    }

    Ok(None)
}

async fn upload_progress(state: &AppState, uuid: &str) -> Result<UploadProgress, OciError> {
    let sessions = state.upload_sessions.read().await;
    let session = sessions
        .get(uuid)
        .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
    Ok(UploadProgress {
        name: session.name.clone(),
        uuid: uuid.to_string(),
        bytes_received: session.bytes_received,
    })
}

async fn session_path_and_lock(
    state: &AppState,
    uuid: &str,
) -> Result<(PathBuf, Arc<tokio::sync::Mutex<()>>), OciError> {
    let sessions = state.upload_sessions.read().await;
    let session = sessions
        .get(uuid)
        .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
    if !session.owns_temp_file() {
        return Err(OciError::blob_upload_unknown(format!(
            "upload {uuid} is finalized"
        )));
    }
    Ok((session.temp_path.clone(), session.write_lock.clone()))
}

async fn create_upload_temp_file(state: &AppState, session_id: &str) -> Result<PathBuf, OciError> {
    let temp_dir = state.oci_upload_temp_dir.clone();
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp dir: {e}")))?;
    Ok(temp_dir.join(session_id))
}

async fn create_upload_session(
    state: &AppState,
    session_id: String,
    name: &str,
    temp_path: PathBuf,
    bytes_received: u64,
    finalized_digest: Option<String>,
    finalized_size: Option<u64>,
) {
    let mut sessions = state.upload_sessions.write().await;
    sessions.create(UploadSession::owned_temp_file(
        session_id,
        name.to_string(),
        temp_path,
        bytes_received,
        finalized_digest,
        finalized_size,
    ));
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

    if let Some(existing) = existing_mounted_blob_handle(state, name, digest).await {
        let session_id = format!("oci-mount-{}", uuid::Uuid::new_v4());
        let size_bytes = existing.size_bytes();

        let mut sessions = state.upload_sessions.write().await;
        if sessions.find_by_name_and_digest(name, digest).is_some() {
            return Ok(true);
        }

        match existing {
            ExistingMountedBlob::UploadSession(handle) => {
                drop(sessions);
                let temp_path = materialize_mounted_blob(state, digest, &handle).await?;
                let mut sessions = state.upload_sessions.write().await;
                if sessions.find_by_name_and_digest(name, digest).is_some() {
                    drop(sessions);
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return Ok(true);
                }
                sessions.create(UploadSession::owned_temp_file(
                    session_id,
                    name.to_string(),
                    temp_path,
                    size_bytes,
                    Some(digest.to_string()),
                    Some(size_bytes),
                ));
            }
            ExistingMountedBlob::BlobReadCache(lease) => {
                sessions.create(UploadSession::borrowed_blob_read(
                    session_id,
                    name.to_string(),
                    digest.to_string(),
                    size_bytes,
                    lease,
                ));
                state
                    .oci_engine_diagnostics
                    .record_borrowed_upload_session(size_bytes);
            }
        }
        state.oci_negative_cache.invalidate_blob(name, digest);
        return Ok(true);
    }

    Ok(false)
}

async fn existing_mounted_blob_handle(
    state: &AppState,
    name: &str,
    digest: &str,
) -> Option<ExistingMountedBlob> {
    {
        let sessions = state.upload_sessions.read().await;
        if let Some(session) = sessions.find_by_name_and_digest(name, digest) {
            let size_bytes = session.finalized_size.unwrap_or(session.bytes_received);
            if size_bytes > 0 {
                return Some(ExistingMountedBlob::UploadSession(
                    BlobReadHandle::from_file_range(
                        session.body_path().to_path_buf(),
                        session.body_offset(),
                        size_bytes,
                    ),
                ));
            }
        }
        if let Some(session) = sessions.find_by_digest(digest) {
            let size_bytes = session.finalized_size.unwrap_or(session.bytes_received);
            if size_bytes > 0 {
                return Some(ExistingMountedBlob::UploadSession(
                    BlobReadHandle::from_file_range(
                        session.body_path().to_path_buf(),
                        session.body_offset(),
                        size_bytes,
                    ),
                ));
            }
        }
    }

    state
        .blob_read_cache
        .lease_handle(digest)
        .await
        .map(ExistingMountedBlob::BlobReadCache)
}

async fn materialize_mounted_blob(
    state: &AppState,
    digest: &str,
    handle: &BlobReadHandle,
) -> Result<PathBuf, OciError> {
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
    let copy_started_at = Instant::now();
    let mut limited = source.take(handle.size_bytes());
    let copied = tokio::io::copy(&mut limited, &mut dest)
        .await
        .map_err(|e| OciError::internal(format!("Failed to copy mounted blob: {e}")))?;
    let copy_duration_ms = copy_started_at.elapsed().as_millis() as u64;
    if copied != handle.size_bytes() {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(OciError::internal(format!(
            "Mounted blob copy was incomplete for {digest}: expected {} bytes, copied {}",
            handle.size_bytes(),
            copied
        )));
    }
    let sync_started_at = Instant::now();
    dest.flush()
        .await
        .map_err(|e| OciError::internal(format!("Failed to flush mounted blob copy: {e}")))?;
    dest.sync_data()
        .await
        .map_err(|e| OciError::internal(format!("Failed to sync mounted blob copy: {e}")))?;
    let sync_duration_ms = sync_started_at.elapsed().as_millis() as u64;
    state
        .oci_engine_diagnostics
        .record_upload_session_materialization(copied, copy_duration_ms, sync_duration_ms);

    Ok(temp_path)
}

async fn write_body_to_file(
    body: Body,
    file: &mut tokio::fs::File,
) -> Result<WrittenBody, OciError> {
    use tokio::io::AsyncWriteExt;

    let mut stream = body.into_data_stream();
    let mut bytes_written: u64 = 0;
    let mut hasher = Sha256::new();

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
        hasher.update(&chunk);
    }

    Ok(WrittenBody {
        bytes_written,
        digest: format!("sha256:{:x}", hasher.finalize()),
    })
}

async fn flush_open_file(file: &mut tokio::fs::File) -> Result<(), OciError> {
    use tokio::io::AsyncWriteExt;

    file.flush()
        .await
        .map_err(|e| OciError::internal(format!("Failed to flush temp file: {e}")))?;
    file.sync_data()
        .await
        .map_err(|e| OciError::internal(format!("Failed to sync temp file: {e}")))?;
    Ok(())
}

async fn read_open_file_digest_and_size(
    file: &mut tokio::fs::File,
) -> Result<(u64, String), OciError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    flush_open_file(file).await?;
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
