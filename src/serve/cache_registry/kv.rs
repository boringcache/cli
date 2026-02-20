use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use rand::Rng;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
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
}

pub(crate) async fn put_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    body: Body,
    put_status: StatusCode,
) -> Result<Response, RegistryError> {
    {
        let pending = state.kv_pending.read().await;
        if pending.total_spool_bytes() >= crate::serve::state::MAX_SPOOL_BYTES {
            return Err(RegistryError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "KV spool budget exceeded, try again after flush",
            ));
        }
    }

    let (path, blob_size, blob_digest) = write_body_to_temp_file(body).await?;
    let scoped_key = namespace.scoped_key(key);

    let redundant = {
        let mut pending = state.kv_pending.write().await;
        pending.insert(
            scoped_key.clone(),
            BlobDescriptor {
                digest: blob_digest.clone(),
                size_bytes: blob_size,
            },
            path,
        )
    };
    if let Some(redundant_path) = redundant {
        let _ = tokio::fs::remove_file(&redundant_path).await;
    }

    {
        let mut last_put = state.kv_last_put.write().await;
        *last_put = Some(std::time::Instant::now());
    }

    {
        let gated = {
            let gate = state.kv_next_flush_at.read().await;
            gate.is_some_and(|t| std::time::Instant::now() < t)
        };
        if !gated {
            let pending = state.kv_pending.read().await;
            if pending.blob_count() >= crate::serve::state::FLUSH_BLOB_THRESHOLD
                || pending.total_spool_bytes() >= crate::serve::state::FLUSH_SIZE_THRESHOLD
            {
                let flush_state = state.clone();
                tokio::spawn(async move {
                    flush_kv_index(&flush_state).await;
                });
            }
        }
    }

    log::debug!("KV PUT {scoped_key}: queued ({blob_size} bytes, digest={blob_digest})");
    Ok((put_status, Body::empty()).into_response())
}

async fn resolve_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
) -> Result<String, RegistryError> {
    let download_urls = state
        .api_client
        .blob_download_urls(&state.workspace, cache_entry_id, std::slice::from_ref(blob))
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

    download_urls
        .download_urls
        .iter()
        .find(|item| item.digest == blob.digest)
        .map(|item| item.url.clone())
        .ok_or_else(|| RegistryError::internal("Missing blob download URL in API response"))
}

async fn serve_backend_blob(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    cached_url: Option<&str>,
    is_head: bool,
) -> Result<Response, RegistryError> {
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

    let (download_url, from_cache) = if let Some(url) = cached_url {
        (url.to_string(), true)
    } else {
        (
            resolve_download_url(state, cache_entry_id, blob).await?,
            false,
        )
    };

    let download_result = state
        .api_client
        .transfer_client()
        .get(&download_url)
        .send()
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to download blob bytes: {e}")))?;

    if from_cache && download_result.status() == StatusCode::FORBIDDEN {
        {
            let mut published = state.kv_published_index.write().await;
            published.invalidate_download_url(&blob.digest);
        }
        let fresh_url = resolve_download_url(state, cache_entry_id, blob).await?;
        let retry_response = state
            .api_client
            .transfer_client()
            .get(&fresh_url)
            .send()
            .await
            .map_err(|e| RegistryError::internal(format!("Failed to download blob bytes: {e}")))?
            .error_for_status()
            .map_err(|e| RegistryError::internal(format!("Blob storage returned an error: {e}")))?;
        let body = Body::from_stream(retry_response.bytes_stream());
        return Ok((StatusCode::OK, response_headers, body).into_response());
    }

    let download_response = download_result
        .error_for_status()
        .map_err(|e| RegistryError::internal(format!("Blob storage returned an error: {e}")))?;
    let body = Body::from_stream(download_response.bytes_stream());

    Ok((StatusCode::OK, response_headers, body).into_response())
}

pub(crate) async fn get_or_head_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let scoped_key = namespace.scoped_key(key);

    let local = {
        let pending = state.kv_pending.read().await;
        pending.get(&scoped_key).and_then(|blob| {
            pending
                .blob_path(&blob.digest)
                .map(|path| (blob.clone(), path.clone()))
        })
    };

    if let Some((blob, path)) = local {
        match serve_local_blob(&blob, &path, is_head).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                log::warn!("KV local blob read failed, falling back to backend: {e:?}");
            }
        }
    }

    {
        let published = state.kv_published_index.read().await;
        if let Some((blob, cache_entry_id)) = published.get(&scoped_key) {
            let blob = blob.clone();
            let cache_entry_id = cache_entry_id.to_string();
            let cached_url = published.download_url(&blob.digest).map(|s| s.to_string());
            drop(published);
            return serve_backend_blob(
                state,
                &cache_entry_id,
                &blob,
                cached_url.as_deref(),
                is_head,
            )
            .await;
        }
    }

    let tag = state.registry_root_tag.trim().to_string();
    let hit = resolve_hit(state, &tag).await?;
    let pointer = fetch_pointer(state, &hit).await?;
    let cache_entry_id = hit
        .cache_entry_id
        .ok_or_else(|| RegistryError::internal("Cache hit is missing cache_entry_id"))?;
    let blob = select_blob_for_key(&pointer, &scoped_key)?
        .ok_or_else(|| RegistryError::not_found("Cache key not found"))?;

    serve_backend_blob(state, &cache_entry_id, &blob, None, is_head).await
}

async fn serve_local_blob(
    blob: &BlobDescriptor,
    path: &PathBuf,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        "application/octet-stream"
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-type header: {e}")))?,
    );
    headers.insert(
        CONTENT_LENGTH,
        blob.size_bytes
            .to_string()
            .parse()
            .map_err(|e| RegistryError::internal(format!("Invalid content-length header: {e}")))?,
    );

    if is_head {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    let data = tokio::fs::read(path)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to read local blob: {e}")))?;

    Ok((StatusCode::OK, headers, Body::from(data)).into_response())
}

pub(crate) async fn resolve_kv_entries(
    state: &AppState,
    namespace: KvNamespace,
    keys: &[&str],
) -> Result<HashMap<String, u64>, RegistryError> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }

    let mut sizes = HashMap::new();
    let scoped_keys: Vec<String> = keys.iter().map(|k| namespace.scoped_key(k)).collect();

    {
        let pending = state.kv_pending.read().await;
        for scoped in &scoped_keys {
            if let Some(blob) = pending.get(scoped) {
                sizes.insert(scoped.clone(), blob.size_bytes);
            }
        }
    }

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    {
        let published = state.kv_published_index.read().await;
        for scoped in &scoped_keys {
            if !sizes.contains_key(scoped) {
                if let Some((blob, _)) = published.get(scoped) {
                    sizes.insert(scoped.clone(), blob.size_bytes);
                }
            }
        }
    }

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    let tag = state.registry_root_tag.trim().to_string();
    if let Ok(hit) = resolve_hit(state, &tag).await {
        if let Ok(pointer) = fetch_pointer(state, &hit).await {
            for entry in &pointer.entries {
                if !matches!(entry.entry_type, EntryType::File) {
                    continue;
                }
                if scoped_keys.contains(&entry.path) && !sizes.contains_key(&entry.path) {
                    sizes.insert(entry.path.clone(), entry.size_bytes);
                }
            }
        }
    }

    Ok(sizes)
}

pub(crate) async fn resolve_hit(
    state: &AppState,
    tag: &str,
) -> Result<CacheResolutionEntry, RegistryError> {
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

pub(crate) enum FlushResult {
    Ok,
    Conflict,
    Error,
}

enum FlushError {
    Conflict(String),
    Transient(String),
}

pub(crate) async fn flush_kv_index(state: &AppState) -> FlushResult {
    let _guard = state.kv_flush_lock.lock().await;

    let (pending_entries, pending_blob_paths) = {
        let mut pending = state.kv_pending.write().await;
        if pending.is_empty() {
            return FlushResult::Ok;
        }
        pending.take_all()
    };

    if pending_entries.is_empty() {
        return FlushResult::Ok;
    }

    let entry_count = pending_entries.len();

    match do_flush(state, &pending_entries, &pending_blob_paths).await {
        Ok((merged_entries, cache_entry_id)) => {
            for path in pending_blob_paths.values() {
                let _ = tokio::fs::remove_file(path).await;
            }

            {
                let mut published = state.kv_published_index.write().await;
                published.update(merged_entries.into_iter().collect(), cache_entry_id.clone());
            }

            {
                let mut last_put = state.kv_last_put.write().await;
                *last_put = None;
            }

            eprintln!(
                "KV batch: flushed {entry_count} new entries ({} blobs cleaned up)",
                pending_blob_paths.len()
            );

            preload_download_urls(state, &cache_entry_id).await;
            FlushResult::Ok
        }
        Err(FlushError::Conflict(msg)) => {
            eprintln!("KV batch flush: skipped — tag conflict ({msg})");
            let mut pending = state.kv_pending.write().await;
            pending.restore(pending_entries, pending_blob_paths);
            drop(pending);
            let jitter_ms = rand::thread_rng().gen_range(0..3000);
            let backoff = std::time::Duration::from_millis(5000 + jitter_ms);
            let mut next = state.kv_next_flush_at.write().await;
            *next = Some(std::time::Instant::now() + backoff);
            FlushResult::Conflict
        }
        Err(FlushError::Transient(msg)) => {
            eprintln!("KV batch flush failed: {msg}");
            let mut pending = state.kv_pending.write().await;
            pending.restore(pending_entries, pending_blob_paths);
            FlushResult::Error
        }
    }
}

pub(crate) async fn preload_kv_index(state: &AppState) {
    let tag = state.registry_root_tag.trim().to_string();
    match load_existing_index(state, &tag).await {
        Ok((entries, Some(cache_entry_id))) if !entries.is_empty() => {
            let count = entries.len();
            {
                let mut published = state.kv_published_index.write().await;
                if published.entry_count() > 0 {
                    eprintln!("KV index preload: skipped, flush already published");
                    return;
                }
                published.update(entries.into_iter().collect(), cache_entry_id.clone());
            }
            eprintln!("KV index preloaded: {count} entries, resolving download URLs...");
            preload_download_urls(state, &cache_entry_id).await;
        }
        Ok(_) => {
            eprintln!("KV index preload: no existing entries");
        }
        Err(e) => {
            log::warn!("KV index preload failed: {e:?}");
        }
    }
}

async fn preload_download_urls(state: &AppState, cache_entry_id: &str) {
    let blobs = {
        let published = state.kv_published_index.read().await;
        published.unique_blobs()
    };

    if blobs.is_empty() {
        return;
    }

    match state
        .api_client
        .blob_download_urls(&state.workspace, cache_entry_id, &blobs)
        .await
    {
        Ok(response) => {
            let urls: HashMap<String, String> = response
                .download_urls
                .into_iter()
                .map(|u| (u.digest, u.url))
                .collect();
            let url_count = urls.len();
            let mut published = state.kv_published_index.write().await;
            published.set_download_urls(urls);
            eprintln!("KV index preload: resolved {url_count} download URLs");
        }
        Err(e) => {
            log::warn!("KV index preload: failed to resolve download URLs: {e}");
        }
    }
}

async fn do_flush(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
) -> Result<(BTreeMap<String, BlobDescriptor>, String), FlushError> {
    let tag = state.registry_root_tag.trim().to_string();

    let existing_count;
    let mut entries = match load_existing_index(state, &tag).await {
        Ok((existing, _)) => {
            existing_count = existing.len();
            existing
        }
        Err(e) => {
            log::warn!("KV flush: failed to load existing index: {e:?}");
            existing_count = 0;
            BTreeMap::new()
        }
    };
    entries.extend(pending_entries.iter().map(|(k, v)| (k.clone(), v.clone())));
    let total_count = entries.len();
    eprintln!(
        "KV flush: merging {existing_count} existing + {} pending = {total_count} total entries",
        pending_entries.len()
    );

    let (pointer_bytes, blobs) = build_index_pointer(&entries)
        .map_err(|e| FlushError::Transient(format!("build pointer failed: {e:?}")))?;

    let manifest_root_digest = crate::cas_file::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_size = pointer_bytes.len() as u64;
    let blob_count = blobs.len() as u64;
    let blob_total_size_bytes: u64 = blobs.iter().map(|b| b.size_bytes).sum();
    let file_count = entries.len().min(u32::MAX as usize) as u32;

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

    let save_response = match state
        .api_client
        .save_entry(&state.workspace, &request)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let msg = format!("{e}");
            let is_conflict = e
                .downcast_ref::<crate::error::BoringCacheError>()
                .is_some_and(|bc| matches!(bc, crate::error::BoringCacheError::CacheConflict(_)))
                || msg.contains("another cache upload is in progress");
            if is_conflict {
                return Err(FlushError::Conflict(msg));
            }
            return Err(FlushError::Transient(format!("save_entry failed: {msg}")));
        }
    };

    if save_response.exists {
        eprintln!("KV flush: save_entry returned exists=true ({total_count} entries, {blob_count} blobs, digest={manifest_root_digest})");
        return Ok((entries, save_response.cache_entry_id));
    }
    eprintln!("KV flush: uploading {total_count} entries, {blob_count} blobs, pointer={expected_manifest_size} bytes");

    if !blobs.is_empty() {
        upload_blobs(
            state,
            &save_response.cache_entry_id,
            &blobs,
            pending_blob_paths,
        )
        .await
        .map_err(|e| FlushError::Transient(format!("blob upload failed: {e:?}")))?;
    }

    let manifest_upload_url = save_response
        .manifest_upload_url
        .as_ref()
        .ok_or(FlushError::Transient("missing manifest upload URL".into()))?;

    upload_payload(
        state.api_client.transfer_client(),
        manifest_upload_url,
        &pointer_bytes,
        "application/cbor",
        &save_response.upload_headers,
    )
    .await
    .map_err(|e| FlushError::Transient(format!("manifest upload failed: {e}")))?;

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
        .map_err(|e| FlushError::Transient(format!("confirm failed: {e}")))?;

    Ok((entries, save_response.cache_entry_id))
}

async fn upload_blobs(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    local_blob_paths: &HashMap<String, PathBuf>,
) -> Result<(), RegistryError> {
    let upload_plan = state
        .api_client
        .blob_upload_urls(&state.workspace, cache_entry_id, blobs)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to get blob upload URLs: {e}")))?;

    for upload in &upload_plan.upload_urls {
        let blob_path = match local_blob_paths.get(&upload.digest) {
            Some(path) => path,
            None => {
                log::warn!(
                    "KV batch flush: skipping blob {} (no local file)",
                    upload.digest
                );
                continue;
            }
        };
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

async fn load_existing_index(
    state: &AppState,
    tag: &str,
) -> Result<(BTreeMap<String, BlobDescriptor>, Option<String>), RegistryError> {
    let hit = match resolve_hit(state, tag).await {
        Ok(hit) => hit,
        Err(error) if error.status == StatusCode::NOT_FOUND => return Ok((BTreeMap::new(), None)),
        Err(error) => return Err(error),
    };

    let cache_entry_id = hit.cache_entry_id.clone();
    let pointer = fetch_pointer(state, &hit).await?;
    let mut map = BTreeMap::new();
    for entry in &pointer.entries {
        if !matches!(entry.entry_type, EntryType::File) {
            continue;
        }
        if let Some(digest) = &entry.digest {
            map.insert(
                entry.path.clone(),
                BlobDescriptor {
                    digest: digest.clone(),
                    size_bytes: entry.size_bytes,
                },
            );
        }
    }
    Ok((map, cache_entry_id))
}

async fn write_body_to_temp_file(body: Body) -> Result<(PathBuf, u64, String), RegistryError> {
    let temp_dir = std::env::temp_dir().join("boringcache-kv-blobs");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to create temp dir: {e}")))?;
    let path = temp_dir.join(uuid::Uuid::new_v4().to_string());

    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(|e| RegistryError::internal(format!("Failed to create temp file: {e}")))?;

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
    Ok((path, total_size, digest))
}
