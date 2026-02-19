use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::api::models::cache::{BlobDescriptor, ConfirmRequest, SaveRequest};
use crate::cas_transport::upload_payload;
use crate::progress::TransferProgress;
use crate::serve::state::AppState;

use super::error::RegistryError;

#[derive(Debug, Clone, Copy)]
pub(crate) enum KvNamespace {
    BazelAc,
    BazelCas,
    Gradle,
    Turborepo,
    Sccache,
}

impl KvNamespace {
    fn tag_for_key(self, key: &str) -> String {
        match self {
            KvNamespace::BazelAc => format!("registry_bazel_ac_{}", key.to_ascii_lowercase()),
            KvNamespace::BazelCas => format!("registry_bazel_cas_{}", key.to_ascii_lowercase()),
            KvNamespace::Gradle => format!("registry_gradle_{}", key.to_ascii_lowercase()),
            KvNamespace::Turborepo => {
                let digest = crate::cas_oci::sha256_hex(key.as_bytes());
                format!("registry_turbo_{digest}")
            }
            KvNamespace::Sccache => {
                let digest = crate::cas_oci::sha256_hex(key.as_bytes());
                format!("registry_sccache_{digest}")
            }
        }
    }
}

pub(crate) async fn put_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    body: Body,
    put_status: StatusCode,
) -> Result<Response, RegistryError> {
    let (temp_blob_path, blob_size, blob_digest) = write_body_to_temp_file(body).await?;
    let pointer_bytes = build_single_blob_pointer(&blob_digest, blob_size)?;
    let manifest_root_digest = crate::cas_file::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_size = pointer_bytes.len() as u64;
    let tag = namespace.tag_for_key(key);

    let request = SaveRequest {
        tag: tag.clone(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(1),
        blob_total_size_bytes: Some(blob_size),
        cas_layout: Some("file-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes: blob_size,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(1),
        expected_manifest_digest: Some(manifest_root_digest.clone()),
        expected_manifest_size: Some(expected_manifest_size),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let save_response = state
        .api_client
        .save_entry(&state.workspace, &request)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to create cache entry: {e}")))?;

    if !save_response.exists {
        upload_blob_if_missing(
            state,
            &save_response.cache_entry_id,
            &temp_blob_path,
            &blob_digest,
            blob_size,
        )
        .await?;

        let manifest_upload_url = save_response
            .manifest_upload_url
            .as_ref()
            .ok_or_else(|| RegistryError::internal("Missing manifest upload URL"))?;
        upload_payload(
            state.api_client.transfer_client(),
            manifest_upload_url,
            &pointer_bytes,
            "application/cbor",
            &save_response.upload_headers,
        )
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to upload manifest pointer: {e}")))?;

        let confirm_request = ConfirmRequest {
            manifest_digest: manifest_root_digest,
            manifest_size: expected_manifest_size,
            manifest_etag: None,
            archive_size: None,
            archive_etag: None,
            blob_count: Some(1),
            blob_total_size_bytes: Some(blob_size),
            file_count: Some(1),
            uncompressed_size: None,
            compressed_size: None,
            tag: Some(tag),
        };

        state
            .api_client
            .confirm(
                &state.workspace,
                &save_response.cache_entry_id,
                &confirm_request,
            )
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to confirm cache entry: {e}")))?;
    }

    Ok((put_status, Body::empty()).into_response())
}

pub(crate) async fn get_or_head_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let tag = namespace.tag_for_key(key);
    let hit = resolve_hit(state, &tag).await?;
    let manifest_url = hit
        .manifest_url
        .ok_or_else(|| RegistryError::internal("Cache hit is missing manifest_url"))?;
    let cache_entry_id = hit
        .cache_entry_id
        .ok_or_else(|| RegistryError::internal("Cache hit is missing cache_entry_id"))?;

    let pointer_response = state
        .api_client
        .transfer_client()
        .get(&manifest_url)
        .send()
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to fetch manifest pointer: {e}")))?
        .error_for_status()
        .map_err(|e| RegistryError::internal(format!("Manifest pointer request failed: {e}")))?;
    let pointer_bytes = pointer_response
        .bytes()
        .await
        .map_err(|e| {
            RegistryError::internal(format!("Failed to read manifest pointer bytes: {e}"))
        })?
        .to_vec();

    let pointer = crate::cas_file::parse_pointer(&pointer_bytes).map_err(|e| {
        RegistryError::internal(format!("Invalid file CAS pointer for key lookup: {e}"))
    })?;
    let blob = pointer
        .blobs
        .first()
        .ok_or_else(|| RegistryError::internal("Manifest pointer missing blob metadata"))?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        CONTENT_TYPE,
        "application/octet-stream"
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-type header: {e}")))?,
    );
    response_headers.insert(
        CONTENT_LENGTH,
        blob.size_bytes
            .to_string()
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-length header: {e}")))?,
    );

    if is_head {
        return Ok((StatusCode::OK, response_headers, Body::empty()).into_response());
    }

    let download_urls = state
        .api_client
        .blob_download_urls(
            &state.workspace,
            &cache_entry_id,
            &[BlobDescriptor {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            }],
        )
        .await
        .map_err(|e| {
            RegistryError::internal(format!("Failed to resolve blob download URL: {e}"))
        })?;

    if download_urls
        .missing
        .iter()
        .any(|digest| digest == &blob.digest)
    {
        return Err(RegistryError::not_found(
            "Cache object is missing blob data",
        ));
    }

    let download_url = download_urls
        .download_urls
        .iter()
        .find(|item| item.digest == blob.digest)
        .map(|item| item.url.clone())
        .ok_or_else(|| RegistryError::internal("Missing blob download URL in API response"))?;

    let download_response = state
        .api_client
        .transfer_client()
        .get(download_url)
        .send()
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to download blob bytes: {e}")))?
        .error_for_status()
        .map_err(|e| RegistryError::internal(format!("Blob storage returned an error: {e}")))?;
    let body = Body::from_stream(download_response.bytes_stream());

    Ok((StatusCode::OK, response_headers, body).into_response())
}

pub(crate) async fn resolve_hit(
    state: &AppState,
    tag: &str,
) -> Result<crate::api::models::cache::CacheResolutionEntry, RegistryError> {
    let response = state
        .api_client
        .restore(&state.workspace, &[tag.to_string()])
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to resolve cache key: {e}")))?;

    response
        .into_iter()
        .find(|entry| entry.status == "hit")
        .ok_or_else(|| RegistryError::not_found("Cache key not found"))
}

async fn upload_blob_if_missing(
    state: &AppState,
    cache_entry_id: &str,
    blob_path: &tempfile::TempPath,
    blob_digest: &str,
    blob_size: u64,
) -> Result<(), RegistryError> {
    let blob_descriptor = BlobDescriptor {
        digest: blob_digest.to_string(),
        size_bytes: blob_size,
    };

    let upload_plan = state
        .api_client
        .blob_upload_urls(&state.workspace, cache_entry_id, &[blob_descriptor])
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to request blob upload URL: {e}")))?;

    if let Some(upload) = upload_plan
        .upload_urls
        .iter()
        .find(|item| item.digest == blob_digest)
    {
        let progress = TransferProgress::new_noop();
        crate::multipart_upload::upload_via_single_url(
            blob_path.as_ref(),
            &upload.url,
            &progress,
            state.api_client.transfer_client(),
            &upload.headers,
        )
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to upload blob: {e}")))?;
    }

    Ok(())
}

fn build_single_blob_pointer(digest: &str, size_bytes: u64) -> Result<Vec<u8>, RegistryError> {
    let pointer = crate::cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: Vec::new(),
        blobs: vec![crate::cas_file::FilePointerBlob {
            digest: digest.to_string(),
            size_bytes,
        }],
    };
    serde_json::to_vec(&pointer)
        .map_err(|e| RegistryError::internal(format!("Failed to serialize file pointer: {e}")))
}

async fn write_body_to_temp_file(
    body: Body,
) -> Result<(tempfile::TempPath, u64, String), RegistryError> {
    let temp_file = tempfile::Builder::new()
        .prefix("boringcache-registry-blob-")
        .tempfile()
        .map_err(|e| RegistryError::internal(format!("Failed to allocate temp file: {e}")))?;
    let temp_path = temp_file.into_temp_path();

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&temp_path)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to open temp file: {e}")))?;

    let mut stream = body.into_data_stream();
    let mut total_size = 0u64;
    let mut hasher = Sha256::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result
            .map_err(|e| RegistryError::internal(format!("Failed to read request body: {e}")))?;
        if chunk.is_empty() {
            continue;
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to write temp file: {e}")))?;
        hasher.update(&chunk);
        total_size = total_size.saturating_add(chunk.len() as u64);
    }

    file.flush()
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to flush temp file: {e}")))?;

    let digest = format!("sha256:{:x}", hasher.finalize());
    Ok((temp_path, total_size, digest))
}
