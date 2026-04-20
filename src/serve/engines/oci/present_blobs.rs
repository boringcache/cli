use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::models::cache::BlobDescriptor;
use crate::serve::http::error::OciError;
use crate::serve::state::{AppState, BlobReadHandle, UploadSession};

const OCI_API_CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PresentBlob {
    pub(crate) digest: String,
    pub(crate) size_bytes: u64,
    pub(crate) source: PresentBlobSource,
    pub(crate) upload_session_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PresentBlobSource {
    UploadSession,
    MountedSession,
    ManifestReferenceSession,
    LocalBodyCache,
    RemoteStorage,
}

impl PresentBlobSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UploadSession => "upload-session",
            Self::MountedSession => "mounted-session",
            Self::ManifestReferenceSession => "manifest-reference-session",
            Self::LocalBodyCache => "local-body-cache",
            Self::RemoteStorage => "remote-storage",
        }
    }
}

pub(crate) async fn ensure_manifest_blobs_present(
    state: &AppState,
    name: &str,
    blob_descriptors: &[BlobDescriptor],
) -> Result<Vec<PresentBlob>, OciError> {
    let mut present: Vec<Option<PresentBlob>> = (0..blob_descriptors.len()).map(|_| None).collect();
    let mut remote_check = Vec::new();

    for (idx, descriptor) in blob_descriptors.iter().enumerate() {
        if let Some((source, upload_session_id)) =
            local_session_source(state, name, descriptor).await?
        {
            present[idx] = Some(PresentBlob {
                digest: descriptor.digest.clone(),
                size_bytes: descriptor.size_bytes,
                source,
                upload_session_id: Some(upload_session_id),
            });
            continue;
        }

        if let Some(handle) = state.blob_read_cache.get_handle(&descriptor.digest).await {
            validate_size(descriptor, handle.size_bytes(), "local body cache")?;
            let upload_session_id =
                stage_local_body_cache_session(state, name, descriptor, &handle).await?;
            let source = source_for_session_id(&upload_session_id);
            present[idx] = Some(PresentBlob {
                digest: descriptor.digest.clone(),
                size_bytes: descriptor.size_bytes,
                source,
                upload_session_id: Some(upload_session_id),
            });
            continue;
        }

        remote_check.push((idx, descriptor.clone()));
    }

    if remote_check.is_empty() {
        return collect_present_blobs(present);
    }

    let remote_descriptors = remote_check
        .iter()
        .map(|(_, descriptor)| descriptor.clone())
        .collect::<Vec<_>>();
    let check = tokio::time::timeout(
        OCI_API_CALL_TIMEOUT,
        state
            .api_client
            .check_blobs_verified(&state.workspace, &remote_descriptors),
    )
    .await
    .map_err(|_| {
        OciError::internal(format!(
            "Blob verification timed out after {}s",
            OCI_API_CALL_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| OciError::internal(format!("Blob verification failed: {e}")))?;

    let available: HashSet<&str> = check
        .results
        .iter()
        .filter(|result| result.exists)
        .map(|result| result.digest.as_str())
        .collect();
    let mut missing = Vec::new();
    for (idx, descriptor) in remote_check {
        if available.contains(descriptor.digest.as_str()) {
            present[idx] = Some(PresentBlob {
                digest: descriptor.digest,
                size_bytes: descriptor.size_bytes,
                source: PresentBlobSource::RemoteStorage,
                upload_session_id: None,
            });
        } else {
            missing.push(descriptor.digest);
        }
    }

    if missing.is_empty() {
        collect_present_blobs(present)
    } else {
        Err(OciError::blob_unknown_upload(missing))
    }
}

fn collect_present_blobs(present: Vec<Option<PresentBlob>>) -> Result<Vec<PresentBlob>, OciError> {
    present
        .into_iter()
        .enumerate()
        .map(|(idx, blob)| {
            blob.ok_or_else(|| {
                OciError::internal(format!("Missing descriptor proof at index {idx}"))
            })
        })
        .collect()
}

async fn local_session_source(
    state: &AppState,
    name: &str,
    descriptor: &BlobDescriptor,
) -> Result<Option<(PresentBlobSource, String)>, OciError> {
    let sessions = state.upload_sessions.read().await;
    let Some(session) = sessions.find_by_name_and_digest(name, &descriptor.digest) else {
        return Ok(None);
    };
    let actual_size = session.finalized_size.unwrap_or(session.bytes_received);
    if actual_size == 0 && descriptor.size_bytes > 0 {
        return Ok(None);
    }
    validate_size(descriptor, actual_size, "upload session")?;
    Ok(Some((
        source_for_session_id(&session.id),
        session.id.clone(),
    )))
}

fn source_for_session_id(session_id: &str) -> PresentBlobSource {
    if session_id.starts_with("oci-mount-") {
        PresentBlobSource::MountedSession
    } else if session_id.starts_with("oci-manifest-") {
        PresentBlobSource::ManifestReferenceSession
    } else if session_id.starts_with("oci-local-body-") {
        PresentBlobSource::LocalBodyCache
    } else {
        PresentBlobSource::UploadSession
    }
}

async fn stage_local_body_cache_session(
    state: &AppState,
    name: &str,
    descriptor: &BlobDescriptor,
    handle: &BlobReadHandle,
) -> Result<String, OciError> {
    let session_id = format!("oci-local-body-{}", uuid::Uuid::new_v4());
    let temp_path = materialize_blob_read_handle(state, &descriptor.digest, handle).await?;

    let mut sessions = state.upload_sessions.write().await;
    if let Some(existing) = sessions.find_by_name_and_digest(name, &descriptor.digest) {
        let existing_id = existing.id.clone();
        drop(sessions);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Ok(existing_id);
    }

    sessions.create(UploadSession {
        id: session_id.clone(),
        name: name.to_string(),
        temp_path,
        write_lock: Arc::new(tokio::sync::Mutex::new(())),
        bytes_received: descriptor.size_bytes,
        finalized_digest: Some(descriptor.digest.clone()),
        finalized_size: Some(descriptor.size_bytes),
        created_at: Instant::now(),
    });

    Ok(session_id)
}

async fn materialize_blob_read_handle(
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
    let temp_dir = state.oci_upload_temp_dir.join("local-body");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create local body temp dir: {e}")))?;
    let temp_path = temp_dir.join(format!(
        "blob-{}-{}",
        &digest_hex[..digest_hex.len().min(16)],
        uuid::Uuid::new_v4()
    ));

    let mut source = tokio::fs::File::open(handle.path()).await.map_err(|e| {
        OciError::internal(format!(
            "Failed to open local body source {}: {e}",
            handle.path().display()
        ))
    })?;
    if handle.offset() > 0 {
        source
            .seek(std::io::SeekFrom::Start(handle.offset()))
            .await
            .map_err(|e| OciError::internal(format!("Failed to seek local body source: {e}")))?;
    }

    let mut dest = tokio::fs::File::create(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create local body copy: {e}")))?;
    let mut limited = source.take(handle.size_bytes());
    let copied = tokio::io::copy(&mut limited, &mut dest)
        .await
        .map_err(|e| OciError::internal(format!("Failed to copy local body: {e}")))?;
    if copied != handle.size_bytes() {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(OciError::internal(format!(
            "Local body copy was incomplete for {digest}: expected {} bytes, copied {}",
            handle.size_bytes(),
            copied
        )));
    }
    dest.flush()
        .await
        .map_err(|e| OciError::internal(format!("Failed to flush local body copy: {e}")))?;
    dest.sync_data()
        .await
        .map_err(|e| OciError::internal(format!("Failed to sync local body copy: {e}")))?;

    Ok(temp_path)
}

fn validate_size(
    descriptor: &BlobDescriptor,
    actual_size: u64,
    source: &str,
) -> Result<(), OciError> {
    if actual_size == descriptor.size_bytes {
        return Ok(());
    }

    Err(OciError::digest_invalid(format!(
        "descriptor size mismatch for {} from {}: expected {}, got {}",
        descriptor.digest, source, descriptor.size_bytes, actual_size
    )))
}
