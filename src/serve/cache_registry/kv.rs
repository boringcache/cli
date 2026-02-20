use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use tokio::io::AsyncWriteExt;

use crate::api::models::cache::{
    BlobDescriptor, CacheResolutionEntry, ConfirmRequest, SaveRequest,
};
use crate::cas_transport::upload_payload;
use crate::manifest::EntryType;
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
    pub(crate) fn normalize_key(self, key: &str) -> String {
        match self {
            KvNamespace::BazelAc | KvNamespace::BazelCas | KvNamespace::Gradle => {
                key.to_ascii_lowercase()
            }
            KvNamespace::Turborepo | KvNamespace::Sccache => key.to_string(),
        }
    }

    fn namespace_prefix(self) -> &'static str {
        match self {
            KvNamespace::BazelAc => "bazel_ac",
            KvNamespace::BazelCas => "bazel_cas",
            KvNamespace::Gradle => "gradle",
            KvNamespace::Turborepo => "turbo",
            KvNamespace::Sccache => "sccache",
        }
    }

    pub(crate) fn scoped_key(self, key: &str) -> String {
        format!("{}/{}", self.namespace_prefix(), self.normalize_key(key))
    }

    pub(crate) fn root_tag(self, state: &AppState) -> String {
        let _ = self;
        let prefix = state.registry_root_tag.trim();
        prefix.to_string()
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
    let scoped_key = namespace.scoped_key(key);
    let tag = namespace.root_tag(state);

    let mut existing_entries = load_index_entries(state, &tag).await?;
    existing_entries.insert(
        scoped_key,
        BlobDescriptor {
            digest: blob_digest.clone(),
            size_bytes: blob_size,
        },
    );

    let (pointer_bytes, blobs) = build_index_pointer(&existing_entries)?;
    let manifest_root_digest = crate::cas_file::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_size = pointer_bytes.len() as u64;
    let blob_count = blobs.len() as u64;
    let blob_total_size_bytes: u64 = blobs.iter().map(|blob| blob.size_bytes).sum();
    let file_count = existing_entries.len().min(u32::MAX as usize) as u32;

    let request = SaveRequest {
        tag: tag.clone(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout: Some("file-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes: blob_total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(file_count),
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
        let mut local_blob_paths = HashMap::new();
        local_blob_paths.insert(blob_digest.clone(), temp_blob_path.to_path_buf());

        upload_blobs_if_missing(
            state,
            &save_response.cache_entry_id,
            &blobs,
            &local_blob_paths,
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
            blob_count: Some(blob_count),
            blob_total_size_bytes: Some(blob_total_size_bytes),
            file_count: Some(file_count),
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
    let scoped_key = namespace.scoped_key(key);
    let tag = namespace.root_tag(state);
    let hit = resolve_hit(state, &tag).await?;
    let pointer = fetch_pointer(state, &hit).await?;
    let cache_entry_id = hit
        .cache_entry_id
        .ok_or_else(|| RegistryError::internal("Cache hit is missing cache_entry_id"))?;
    let blob = select_blob_for_key(&pointer, &scoped_key)?
        .ok_or_else(|| RegistryError::not_found("Cache key not found"))?;

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

pub(crate) async fn load_kv_blob_map(
    state: &AppState,
    namespace: KvNamespace,
) -> Result<HashMap<String, BlobDescriptor>, RegistryError> {
    let tag = namespace.root_tag(state);
    let hit = resolve_hit(state, &tag).await?;
    let pointer = fetch_pointer(state, &hit).await?;
    pointer_entries_to_blob_map(&pointer)
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

async fn load_index_entries(
    state: &AppState,
    tag: &str,
) -> Result<BTreeMap<String, BlobDescriptor>, RegistryError> {
    let hit = match resolve_hit(state, tag).await {
        Ok(hit) => hit,
        Err(error) if error.status == StatusCode::NOT_FOUND => return Ok(BTreeMap::new()),
        Err(error) => return Err(error),
    };

    let pointer = fetch_pointer(state, &hit).await?;
    let map = pointer_entries_to_blob_map(&pointer)?;
    Ok(map.into_iter().collect())
}

async fn fetch_pointer(
    state: &AppState,
    hit: &CacheResolutionEntry,
) -> Result<crate::cas_file::FilePointer, RegistryError> {
    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| RegistryError::internal("Cache hit is missing manifest_url"))?;

    let pointer_response = state
        .api_client
        .transfer_client()
        .get(manifest_url)
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

    crate::cas_file::parse_pointer(&pointer_bytes)
        .map_err(|e| RegistryError::internal(format!("Invalid file CAS pointer: {e}")))
}

fn pointer_entries_to_blob_map(
    pointer: &crate::cas_file::FilePointer,
) -> Result<HashMap<String, BlobDescriptor>, RegistryError> {
    let mut map = HashMap::with_capacity(pointer.entries.len());
    for entry in &pointer.entries {
        if !matches!(entry.entry_type, EntryType::File) {
            continue;
        }
        let digest = entry.digest.clone().ok_or_else(|| {
            RegistryError::internal(format!(
                "Cache pointer entry is missing digest: {}",
                entry.path
            ))
        })?;
        map.insert(
            entry.path.clone(),
            BlobDescriptor {
                digest,
                size_bytes: entry.size_bytes,
            },
        );
    }
    Ok(map)
}

fn select_blob_for_key(
    pointer: &crate::cas_file::FilePointer,
    key: &str,
) -> Result<Option<BlobDescriptor>, RegistryError> {
    for entry in &pointer.entries {
        if !matches!(entry.entry_type, EntryType::File) || entry.path != key {
            continue;
        }
        let digest = entry.digest.clone().ok_or_else(|| {
            RegistryError::internal(format!(
                "Cache pointer entry is missing digest: {}",
                entry.path
            ))
        })?;
        return Ok(Some(BlobDescriptor {
            digest,
            size_bytes: entry.size_bytes,
        }));
    }

    if pointer.entries.is_empty() {
        if let Some(blob) = pointer.blobs.first() {
            return Ok(Some(BlobDescriptor {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            }));
        }
    }

    Ok(None)
}

fn build_index_pointer(
    entries: &BTreeMap<String, BlobDescriptor>,
) -> Result<(Vec<u8>, Vec<BlobDescriptor>), RegistryError> {
    let mut blob_sizes: HashMap<String, u64> = HashMap::new();
    let mut pointer_entries = Vec::with_capacity(entries.len());

    for (key, blob) in entries {
        if let Some(existing_size) = blob_sizes.get(&blob.digest) {
            if *existing_size != blob.size_bytes {
                return Err(RegistryError::internal(format!(
                    "Digest {} has inconsistent sizes ({} vs {})",
                    blob.digest, existing_size, blob.size_bytes
                )));
            }
        } else {
            blob_sizes.insert(blob.digest.clone(), blob.size_bytes);
        }

        pointer_entries.push(crate::cas_file::FilePointerEntry {
            path: key.clone(),
            entry_type: EntryType::File,
            size_bytes: blob.size_bytes,
            executable: None,
            target: None,
            digest: Some(blob.digest.clone()),
        });
    }

    let mut blobs: Vec<BlobDescriptor> = blob_sizes
        .into_iter()
        .map(|(digest, size_bytes)| BlobDescriptor { digest, size_bytes })
        .collect();
    blobs.sort_by(|left, right| left.digest.cmp(&right.digest));

    let pointer = crate::cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: pointer_entries,
        blobs: blobs
            .iter()
            .map(|blob| crate::cas_file::FilePointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            })
            .collect(),
    };
    let pointer_bytes = serde_json::to_vec(&pointer)
        .map_err(|e| RegistryError::internal(format!("Failed to serialize file pointer: {e}")))?;

    Ok((pointer_bytes, blobs))
}

async fn upload_blobs_if_missing(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    local_blob_paths: &HashMap<String, std::path::PathBuf>,
) -> Result<(), RegistryError> {
    let upload_plan = state
        .api_client
        .blob_upload_urls(&state.workspace, cache_entry_id, blobs)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to request blob upload URL: {e}")))?;

    for upload in &upload_plan.upload_urls {
        let blob_path = local_blob_paths.get(&upload.digest).ok_or_else(|| {
            RegistryError::internal(format!(
                "Missing local blob bytes required for digest {} while updating index",
                upload.digest
            ))
        })?;
        let progress = TransferProgress::new_noop();
        crate::multipart_upload::upload_via_single_url(
            blob_path.as_path(),
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
