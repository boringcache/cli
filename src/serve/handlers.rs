use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::api::models::cache::{BlobDescriptor, ConfirmRequest, SaveRequest};
use crate::cas_oci;
use crate::cas_transport::upload_payload;
use crate::multipart_upload::upload_via_single_url;
use crate::serve::error::OciError;
use crate::serve::state::{
    digest_tag, ref_tag_for_input, AppState, BlobLocatorEntry, UploadSession,
};
use crate::tag_utils::TagResolver;

const DOWNLOAD_URL_CACHE_TTL: Duration = Duration::from_secs(45 * 60);
const OCI_PREFETCH_BLOB_URL_LIMIT: usize = 128;
const EMPTY_FINALIZE_LOCAL_RETRY_ATTEMPTS: usize = 20;
const EMPTY_FINALIZE_LOCAL_RETRY_DELAY_MS: u64 = 75;
const EMPTY_FINALIZE_REMOTE_RETRY_ATTEMPTS: usize = 3;
const EMPTY_FINALIZE_REMOTE_RETRY_DELAY_MS: u64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmptyFinalizeReuse {
    Local,
    Remote,
    Missing,
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), OciError> {
    let header_name = axum::http::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|e| OciError::internal(format!("Invalid header name {name}: {e}")))?;
    let header_value = axum::http::header::HeaderValue::from_str(value)
        .map_err(|e| OciError::internal(format!("Invalid header value for {name}: {e}")))?;
    headers.insert(header_name, header_value);
    Ok(())
}

#[derive(Clone)]
enum OciRoute {
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    BlobUploadStart { name: String },
    BlobUpload { name: String, uuid: String },
}

fn parse_oci_path(path: &str) -> Option<OciRoute> {
    let path = path.strip_prefix('/').unwrap_or(path);

    if let Some(idx) = path.rfind("/blobs/uploads/") {
        let name = &path[..idx];
        let uuid = &path[idx + "/blobs/uploads/".len()..];
        if !name.is_empty() && !uuid.is_empty() {
            return Some(OciRoute::BlobUpload {
                name: name.to_string(),
                uuid: uuid.to_string(),
            });
        }
    }

    if let Some(name) = path.strip_suffix("/blobs/uploads") {
        if !name.is_empty() {
            return Some(OciRoute::BlobUploadStart {
                name: name.to_string(),
            });
        }
    }

    if let Some(name) = path.strip_suffix("/blobs/uploads/") {
        if !name.is_empty() {
            return Some(OciRoute::BlobUploadStart {
                name: name.to_string(),
            });
        }
    }

    if let Some(idx) = path.rfind("/blobs/") {
        let name = &path[..idx];
        let digest = &path[idx + "/blobs/".len()..];
        if !name.is_empty() && !digest.is_empty() {
            return Some(OciRoute::Blob {
                name: name.to_string(),
                digest: digest.to_string(),
            });
        }
    }

    if let Some(idx) = path.rfind("/manifests/") {
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
    body: Body,
) -> Result<Response, OciError> {
    let request_method = method.clone();
    let request_path = format!("/v2/{path}");
    let fail_on_cache_error = state.fail_on_cache_error;
    let route = match parse_oci_path(&path) {
        Some(route) => route,
        None => return Err(OciError::name_unknown("not found")),
    };
    eprintln!("OCI {} {}", request_method, request_path);

    let response = match route.clone() {
        OciRoute::Manifest { name, reference } => match method {
            Method::GET | Method::HEAD => get_manifest(method, state, name, reference).await,
            Method::PUT => put_manifest(state, name, reference, body).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        OciRoute::Blob { name, digest } => match method {
            Method::GET | Method::HEAD => get_blob(method, state, name, digest).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        OciRoute::BlobUploadStart { name } => match method {
            Method::POST => start_upload(state, name, params, body).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
        OciRoute::BlobUpload { name, uuid } => match method {
            Method::GET => get_upload_status(state, name, uuid).await,
            Method::PATCH => patch_upload(state, name, uuid, headers, body).await,
            Method::PUT => put_upload(state, name, uuid, params, headers, body).await,
            Method::DELETE => delete_upload(state, uuid).await,
            _ => Err(OciError::unsupported("method not allowed")),
        },
    };

    match response {
        Ok(response) => {
            let response_status = response.status();
            if request_method != Method::GET
                && request_method != Method::HEAD
                && !response_status.is_success()
            {
                eprintln!(
                    "OCI {} {} -> {}",
                    request_method, request_path, response_status
                );
            }
            Ok(response)
        }
        Err(error) => {
            let error_status = error.status();
            if fail_on_cache_error || !error_status.is_server_error() {
                eprintln!(
                    "OCI {} {} -> {} ({})",
                    request_method,
                    request_path,
                    error_status,
                    error.message()
                );
                return Err(error);
            }
            if request_method != Method::GET && request_method != Method::HEAD {
                eprintln!(
                    "OCI {} {} -> {} ({})",
                    request_method,
                    request_path,
                    error_status,
                    error.message()
                );
                return Err(error);
            }
            let warning = format!(
                "Best-effort OCI fallback on {} {} ({})",
                request_method, request_path, error_status
            );
            eprintln!("{warning}");
            log::warn!("{warning}");
            best_effort_oci_read_response(&route)
        }
    }
}

fn best_effort_oci_read_response(route: &OciRoute) -> Result<Response, OciError> {
    match route {
        OciRoute::Manifest { name, reference } => {
            Err(OciError::manifest_unknown(format!("{name}:{reference}")))
        }
        OciRoute::Blob { name, digest } => Err(OciError::blob_unknown(format!("{name}@{digest}"))),
        OciRoute::BlobUploadStart { .. } => Err(OciError::name_unknown("not found")),
        OciRoute::BlobUpload { name, uuid } => {
            Err(OciError::blob_upload_unknown(format!("{name}:{uuid}")))
        }
    }
}

async fn get_manifest(
    method: Method,
    state: AppState,
    name: String,
    reference: String,
) -> Result<Response, OciError> {
    let (manifest_bytes, content_type, digest) =
        resolve_manifest(&state, &name, &reference, method == Method::GET).await?;

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", &digest)?;
    insert_header(&mut headers, "Content-Type", &content_type)?;
    insert_header(
        &mut headers,
        "Docker-Distribution-API-Version",
        "registry/2.0",
    )?;
    insert_header(
        &mut headers,
        "Content-Length",
        &manifest_bytes.len().to_string(),
    )?;

    if method == Method::HEAD {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    Ok((StatusCode::OK, headers, Body::from(manifest_bytes)).into_response())
}

async fn resolve_manifest(
    state: &AppState,
    name: &str,
    reference: &str,
    prefetch_blob_urls: bool,
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

    let should_prefetch_blob_urls =
        prefetch_blob_urls && pointer.blobs.len() <= OCI_PREFETCH_BLOB_URL_LIMIT;
    let mut prefetched_urls: HashMap<String, String> = HashMap::new();
    if should_prefetch_blob_urls {
        let blob_descriptors: Vec<BlobDescriptor> = pointer
            .blobs
            .iter()
            .map(|blob| BlobDescriptor {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            })
            .collect();
        if !blob_descriptors.is_empty() {
            if let Ok(response) = state
                .api_client
                .blob_download_urls(&state.workspace, cache_entry_id, &blob_descriptors)
                .await
            {
                for entry in response.download_urls {
                    prefetched_urls.insert(entry.digest, entry.url);
                }
            }
        }
    }
    let prefetched_at = if should_prefetch_blob_urls {
        Some(std::time::Instant::now())
    } else {
        None
    };

    {
        let mut locator = state.blob_locator.write().await;
        for blob in &pointer.blobs {
            let download_url = prefetched_urls.get(&blob.digest).cloned();
            locator.insert(
                name,
                &blob.digest,
                BlobLocatorEntry {
                    cache_entry_id: cache_entry_id.clone(),
                    size_bytes: blob.size_bytes,
                    download_url: download_url.clone(),
                    download_url_cached_at: download_url.as_ref().and(prefetched_at),
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
    let scoped = tag_resolver
        .effective_save_tag(&scoped_input)
        .unwrap_or(scoped_input);
    vec![ref_tag_for_input(&scoped)]
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

fn alias_tags_for_manifest(
    primary_tag: &str,
    manifest_digest: &str,
    configured_human_tags: &[String],
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();

    let digest_alias = digest_tag(manifest_digest);
    if digest_alias != primary_tag && seen.insert(digest_alias.clone()) {
        aliases.push(digest_alias);
    }

    for human_tag in configured_human_tags {
        if human_tag != primary_tag && seen.insert(human_tag.clone()) {
            aliases.push(human_tag.clone());
        }
    }

    aliases
}

async fn bind_alias_tag(
    state: &AppState,
    alias_tag: &str,
    manifest_root_digest: &str,
    manifest_size: u64,
    blob_count: u64,
    blob_total_size_bytes: u64,
    total_size_bytes: u64,
) -> Result<(), String> {
    let alias_request = SaveRequest {
        tag: alias_tag.to_string(),
        manifest_root_digest: manifest_root_digest.to_string(),
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
        expected_manifest_digest: Some(manifest_root_digest.to_string()),
        expected_manifest_size: Some(manifest_size),
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
        .map_err(|e| format!("save_entry failed: {e}"))?;

    let alias_confirm = ConfirmRequest {
        manifest_digest: manifest_root_digest.to_string(),
        manifest_size,
        manifest_etag: None,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        file_count: Some(blob_count.min(u32::MAX as u64) as u32),
        uncompressed_size: None,
        compressed_size: None,
        storage_mode: Some("cas".to_string()),
        tag: Some(alias_tag.to_string()),
    };

    state
        .api_client
        .confirm(&state.workspace, &alias_save.cache_entry_id, &alias_confirm)
        .await
        .map_err(|e| format!("confirm failed: {e}"))?;

    Ok(())
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
    let (cache_entry_id, size_bytes, cached_download_url) = {
        let locator = state.blob_locator.read().await;
        let entry = locator
            .get(&name, &digest)
            .ok_or_else(|| OciError::blob_unknown(format!("{name}@{digest}")))?;
        (
            entry.cache_entry_id.clone(),
            entry.size_bytes,
            fresh_download_url(entry),
        )
    };

    let blob_desc = BlobDescriptor {
        digest: digest.clone(),
        size_bytes,
    };

    let (download_url, from_cache) = if let Some(url) = cached_download_url {
        (url, true)
    } else {
        let url =
            resolve_oci_download_url(&state, &cache_entry_id, &blob_desc, &name, &digest).await?;
        (url, false)
    };

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", &digest)?;
    insert_header(&mut headers, "Content-Type", "application/octet-stream")?;
    insert_header(&mut headers, "Content-Length", &size_bytes.to_string())?;
    insert_header(
        &mut headers,
        "Docker-Distribution-API-Version",
        "registry/2.0",
    )?;

    if method == Method::HEAD {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }

    let download_result = state
        .api_client
        .transfer_client()
        .get(&download_url)
        .send()
        .await
        .map_err(|e| OciError::internal(format!("Failed to download blob: {e}")))?;

    if from_cache && download_result.status() == StatusCode::FORBIDDEN {
        {
            let mut locator = state.blob_locator.write().await;
            if let Some(entry) = locator.get_mut(&name, &digest) {
                entry.download_url = None;
            }
        }
        let fresh_url =
            resolve_oci_download_url(&state, &cache_entry_id, &blob_desc, &name, &digest).await?;
        let retry_response = state
            .api_client
            .transfer_client()
            .get(&fresh_url)
            .send()
            .await
            .map_err(|e| OciError::internal(format!("Failed to download blob: {e}")))?
            .error_for_status()
            .map_err(|e| OciError::internal(format!("Blob storage returned error: {e}")))?;
        let body = Body::from_stream(retry_response.bytes_stream());
        return Ok((StatusCode::OK, headers, body).into_response());
    }

    let response = download_result
        .error_for_status()
        .map_err(|e| OciError::internal(format!("Blob storage returned error: {e}")))?;
    let body = Body::from_stream(response.bytes_stream());

    Ok((StatusCode::OK, headers, body).into_response())
}

async fn resolve_oci_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob_desc: &BlobDescriptor,
    name: &str,
    digest: &str,
) -> Result<String, OciError> {
    let download_response = state
        .api_client
        .blob_download_urls(
            &state.workspace,
            cache_entry_id,
            std::slice::from_ref(blob_desc),
        )
        .await
        .map_err(|e| OciError::internal(format!("Failed to get blob download URL: {e}")))?;

    let url = download_response
        .download_urls
        .first()
        .ok_or_else(|| OciError::blob_unknown(format!("No download URL for {digest}")))?
        .url
        .clone();
    {
        let mut locator = state.blob_locator.write().await;
        if let Some(entry) = locator.get_mut(name, digest) {
            entry.download_url = Some(url.clone());
            entry.download_url_cached_at = Some(std::time::Instant::now());
        }
    }
    Ok(url)
}

fn fresh_download_url(entry: &BlobLocatorEntry) -> Option<String> {
    let cached_at = entry.download_url_cached_at?;
    if cached_at.elapsed() >= DOWNLOAD_URL_CACHE_TTL {
        return None;
    }
    entry.download_url.clone()
}

fn adaptive_blob_upload_concurrency(operation_count: usize) -> usize {
    use crate::platform::resources::{MemoryStrategy, SystemResources};

    if operation_count == 0 {
        return 1;
    }

    let resources = SystemResources::detect();
    let mut concurrency: usize = match resources.memory_strategy {
        MemoryStrategy::Balanced => 2,
        MemoryStrategy::Aggressive => 4,
        MemoryStrategy::UltraAggressive => 6,
    };

    if resources.cpu_load_percent > 75.0 {
        concurrency = concurrency.saturating_sub(1).max(1);
    }

    if std::env::var_os("CI").is_some() {
        concurrency = concurrency.min(4);
    }

    concurrency = concurrency
        .min(resources.cpu_cores.max(1))
        .min(resources.max_parallel_chunks.max(1));

    concurrency.min(operation_count).max(1)
}

async fn write_body_to_file(body: Body, file: &mut tokio::fs::File) -> Result<u64, OciError> {
    use tokio::io::AsyncWriteExt;

    let mut stream = body.into_data_stream();
    let mut bytes_written: u64 = 0;

    while let Some(chunk_result) = stream.next().await {
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
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to open temp file: {e}")))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    let mut size = 0u64;

    loop {
        let read = file
            .read(&mut buf)
            .await
            .map_err(|e| OciError::internal(format!("Failed to read temp file: {e}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size = size.saturating_add(read as u64);
    }

    let digest = format!("sha256:{:x}", hasher.finalize());
    Ok((size, digest))
}

async fn has_non_empty_local_blob(state: &AppState, digest: &str) -> bool {
    let sessions = state.upload_sessions.read().await;
    sessions
        .find_by_digest(digest)
        .map(|session| session.finalized_size.unwrap_or(session.bytes_received) > 0)
        .unwrap_or(false)
}

async fn has_remote_blob(state: &AppState, digest: &str) -> Result<bool, OciError> {
    let check = state
        .api_client
        .check_blobs(
            &state.workspace,
            &[BlobDescriptor {
                digest: digest.to_string(),
                size_bytes: 0,
            }],
        )
        .await
        .map_err(|e| OciError::internal(format!("Failed to check blob existence: {e}")))?;

    Ok(check
        .results
        .iter()
        .any(|result| result.digest == digest && result.exists))
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

async fn start_upload(
    state: AppState,
    name: String,
    params: HashMap<String, String>,
    body: Body,
) -> Result<Response, OciError> {
    if let Some(mount_digest) = params.get("mount") {
        if !cas_oci::is_valid_sha256_digest(mount_digest) {
            return Err(OciError::digest_invalid(format!(
                "unsupported mount digest format: {mount_digest}"
            )));
        }

        if has_non_empty_local_blob(&state, mount_digest).await {
            let location = format!("/v2/{name}/blobs/{mount_digest}");
            let mut headers = HeaderMap::new();
            insert_header(&mut headers, "Location", &location)?;
            insert_header(&mut headers, "Docker-Content-Digest", mount_digest)?;
            insert_header(&mut headers, "Content-Length", "0")?;
            return Ok((StatusCode::CREATED, headers, Body::empty()).into_response());
        }
    }

    let session_id = uuid::Uuid::new_v4().to_string();

    let temp_dir = std::env::temp_dir().join("boringcache-uploads");
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

    if let Some(digest_param) = params.get("digest") {
        if body_size > 0 {
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

async fn get_upload_status(
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

    let end = if bytes_received == 0 {
        0
    } else {
        bytes_received - 1
    };
    let location = format!("/v2/{name}/blobs/uploads/{uuid}");
    let range = format!("0-{end}");
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Location", &location)?;
    insert_header(&mut headers, "Docker-Upload-UUID", &uuid)?;
    insert_header(&mut headers, "Range", &range)?;
    insert_header(&mut headers, "Content-Length", "0")?;

    Ok((StatusCode::NO_CONTENT, headers, Body::empty()).into_response())
}

async fn patch_upload(
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

    let bytes_before = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .get(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        session.bytes_received
    };

    let write_offset = parse_upload_offset(&headers).unwrap_or(bytes_before);
    if write_offset > bytes_before {
        return Err(OciError::digest_invalid(format!(
            "upload offset {write_offset} exceeds current size {bytes_before}"
        )));
    }

    use tokio::io::AsyncSeekExt;
    let mut file = tokio::fs::OpenOptions::new()
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
    if write_offset > session.bytes_received {
        return Err(OciError::digest_invalid(format!(
            "upload offset {write_offset} exceeds current size {}",
            session.bytes_received
        )));
    }
    let written_until = write_offset.saturating_add(bytes_written);
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
    insert_header(&mut headers, "Location", &location)?;
    insert_header(&mut headers, "Docker-Upload-UUID", &uuid)?;
    insert_header(&mut headers, "Range", &range)?;
    insert_header(&mut headers, "Content-Length", "0")?;

    Ok((StatusCode::ACCEPTED, headers, Body::empty()).into_response())
}

async fn put_upload(
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

    let (bytes_before, write_offset) = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .get(&uuid)
            .ok_or_else(|| OciError::blob_upload_unknown(format!("upload {uuid}")))?;
        let bytes_before = session.bytes_received;
        let write_offset = parse_put_upload_offset(&headers, bytes_before);
        if write_offset > bytes_before {
            return Err(OciError::digest_invalid(format!(
                "upload offset {write_offset} exceeds current size {bytes_before}"
            )));
        }
        (bytes_before, write_offset)
    };

    use tokio::io::AsyncSeekExt;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|e| OciError::internal(format!("Failed to open temp file: {e}")))?;
    file.seek(std::io::SeekFrom::Start(write_offset))
        .await
        .map_err(|e| OciError::internal(format!("Failed to seek temp file: {e}")))?;
    let bytes_written = match write_body_to_file(body, &mut file).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "OCI PUT body stream error: upload={} digest={} error={} bytes_before={} write_offset={}",
                uuid, digest_param, e.message(), bytes_before, write_offset
            );
            0
        }
    };
    if write_offset == 0 && bytes_before > 0 && bytes_written > 0 {
        file.set_len(bytes_written)
            .await
            .map_err(|e| OciError::internal(format!("Failed to resize temp file: {e}")))?;
    }
    drop(file);

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
    let (mut file_size, mut actual_digest) = read_file_digest_and_size(&temp_path).await?;

    if actual_digest != digest_param
        && bytes_written > 0
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

        let (truncated_size, truncated_digest) = read_file_digest_and_size(&temp_path).await?;
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
                    uuid,
                    digest_param,
                    bytes_before,
                    bytes_written,
                    write_offset
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

fn parse_upload_offset(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("Content-Range")
        .or_else(|| headers.get("Range"))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_start)
}

fn parse_put_upload_offset(headers: &HeaderMap, bytes_before: u64) -> u64 {
    if let Some(offset) = headers
        .get("Content-Range")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_start)
    {
        return offset;
    }

    if let Some(end) = headers
        .get("Range")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_end)
    {
        let reported_bytes = end.saturating_add(1);
        if reported_bytes != bytes_before {
            log::debug!(
                "OCI finalize Range header differs from tracked size: reported={} tracked={}",
                reported_bytes,
                bytes_before
            );
        }
        return bytes_before;
    }

    bytes_before
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
    body: Body,
) -> Result<Response, OciError> {
    let manifest_body = axum::body::to_bytes(body, 32 * 1024 * 1024)
        .await
        .map_err(|e| OciError::internal(format!("Failed to read manifest body: {e}")))?;
    let manifest_body: Vec<u8> = manifest_body.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let index_json_base64 = STANDARD.encode(&manifest_body);

    let parsed: serde_json::Value = serde_json::from_slice(&manifest_body)
        .map_err(|e| OciError::internal(format!("Invalid manifest JSON: {e}")))?;

    let blob_descriptors = extract_blob_descriptors(&parsed)?;

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

    let persist_result: Result<(), OciError> = async {
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

                let upload_jobs = {
                    let sessions = state.upload_sessions.read().await;
                    let mut jobs = Vec::with_capacity(upload_plan.upload_urls.len());
                    for upload_url_info in &upload_plan.upload_urls {
                        let session = sessions
                            .find_by_digest(&upload_url_info.digest)
                            .ok_or_else(|| {
                                OciError::internal(format!(
                                    "No upload session for blob {}",
                                    upload_url_info.digest
                                ))
                            })?;
                        jobs.push((
                            upload_url_info.digest.clone(),
                            session.temp_path.clone(),
                            upload_url_info.url.clone(),
                            upload_url_info.headers.clone(),
                        ));
                    }
                    jobs
                };

                if !upload_jobs.is_empty() {
                    let max_concurrent = adaptive_blob_upload_concurrency(upload_jobs.len());
                    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
                    let transfer_client = state.api_client.transfer_client().clone();
                    let mut tasks = Vec::with_capacity(upload_jobs.len());

                    for (digest, temp_path, upload_url, upload_headers) in upload_jobs {
                        let semaphore = semaphore.clone();
                        let transfer_client = transfer_client.clone();
                        let task = tokio::spawn(async move {
                            let _permit = semaphore.acquire().await.map_err(|e| {
                                OciError::internal(format!("Blob upload semaphore closed: {e}"))
                            })?;
                            let progress = crate::progress::TransferProgress::new_noop();
                            upload_via_single_url(
                                temp_path.as_path(),
                                &upload_url,
                                &progress,
                                &transfer_client,
                                &upload_headers,
                            )
                            .await
                            .map_err(|e| {
                                OciError::internal(format!(
                                    "Blob upload failed for {}: {}",
                                    digest, e
                                ))
                            })?;
                            Ok::<(), OciError>(())
                        });
                        tasks.push(task);
                    }

                    for task in tasks {
                        task.await.map_err(|e| {
                            OciError::internal(format!("Blob upload task failed: {e}"))
                        })??;
                    }
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
            storage_mode: Some("cas".to_string()),
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

        let alias_tags =
            alias_tags_for_manifest(&tag, &manifest_digest, &state.configured_human_tags);
        for alias_tag in alias_tags {
            if let Err(error) = bind_alias_tag(
                &state,
                &alias_tag,
                &manifest_root_digest,
                pointer_bytes.len() as u64,
                blob_count,
                blob_total_size_bytes,
                total_size_bytes,
            )
            .await
            {
                if state.fail_on_cache_error {
                    return Err(OciError::internal(format!(
                        "Alias write failed for {alias_tag} (workspace={}): {error}",
                        state.workspace
                    )));
                }
                let warning = format!(
                    "Alias write skipped for {} (workspace={}): {}",
                    alias_tag, state.workspace, error
                );
                eprintln!("{warning}");
                log::warn!("{warning}");
            }
        }

        Ok(())
    }
    .await;

    cleanup_blob_sessions(&state, &blob_descriptors).await;

    if let Err(error) = persist_result {
        if state.fail_on_cache_error || !error.status().is_server_error() {
            return Err(error);
        }
        let warning = format!(
            "Best-effort OCI manifest publish fallback on {}:{} ({})",
            name,
            reference,
            error.status()
        );
        eprintln!("{warning}");
        log::warn!("{warning}");
    }

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", &manifest_digest)?;
    insert_header(
        &mut headers,
        "Location",
        &format!("/v2/{name}/manifests/{manifest_digest}"),
    )?;
    insert_header(&mut headers, "Content-Length", "0")?;

    Ok((StatusCode::CREATED, headers, Body::empty()).into_response())
}

fn extract_blob_descriptors(manifest: &serde_json::Value) -> Result<Vec<BlobDescriptor>, OciError> {
    let mut blobs = Vec::new();

    if let Some(config) = manifest.get("config") {
        if let (Some(digest), Some(size)) = (
            config.get("digest").and_then(|d| d.as_str()),
            config.get("size").and_then(|s| s.as_u64()),
        ) {
            if !cas_oci::is_valid_sha256_digest(digest) {
                return Err(OciError::digest_invalid(format!(
                    "unsupported config digest format: {digest}"
                )));
            }
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
                if !cas_oci::is_valid_sha256_digest(digest) {
                    return Err(OciError::digest_invalid(format!(
                        "unsupported layer digest format: {digest}"
                    )));
                }
                blobs.push(BlobDescriptor {
                    digest: digest.to_string(),
                    size_bytes: size,
                });
            }
        }
    }

    let mut deduped: Vec<BlobDescriptor> = Vec::with_capacity(blobs.len());
    let mut positions: HashMap<String, usize> = HashMap::new();
    for descriptor in blobs {
        if let Some(idx) = positions.get(&descriptor.digest) {
            let existing = &deduped[*idx];
            if existing.size_bytes != descriptor.size_bytes {
                return Err(OciError::digest_invalid(format!(
                    "conflicting descriptor sizes for {}: {} vs {}",
                    descriptor.digest, existing.size_bytes, descriptor.size_bytes
                )));
            }
            continue;
        }

        positions.insert(descriptor.digest.clone(), deduped.len());
        deduped.push(descriptor);
    }

    Ok(deduped)
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
    use crate::api::client::ApiClient;
    use crate::git::GitContext;
    use crate::platform::Platform;
    use crate::serve::state::{
        BlobLocatorCache, BlobReadCache, KvPendingStore, KvPublishedIndex, UploadSessionStore,
    };
    use crate::tag_utils::TagResolver;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::RwLock;

    fn test_state() -> AppState {
        AppState {
            api_client: ApiClient::new_with_token_override(Some("test-token".to_string()))
                .expect("api client"),
            workspace: "boringcache/benchmarks".to_string(),
            tag_resolver: TagResolver::new(None, GitContext::default(), false),
            configured_human_tags: Vec::new(),
            registry_root_tag: "registry".to_string(),
            fail_on_cache_error: true,
            blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
            upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
            kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
            kv_flush_lock: Arc::new(tokio::sync::Mutex::new(())),
            kv_lookup_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            kv_last_put: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_next_flush_at: Arc::new(RwLock::new(None)),
            kv_flush_scheduled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            kv_published_index: Arc::new(RwLock::new(KvPublishedIndex::default())),
            kv_recent_misses: Arc::new(dashmap::DashMap::new()),
            blob_read_cache: Arc::new(
                BlobReadCache::new_at(
                    std::env::temp_dir().join(format!(
                        "boringcache-handler-blob-cache-{}",
                        uuid::Uuid::new_v4()
                    )),
                    2 * 1024 * 1024 * 1024,
                )
                .expect("blob read cache"),
            ),
        }
    }

    async fn write_temp_upload_file(contents: &[u8]) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("boringcache-upload-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.expect("temp dir");
        let path = dir.join("blob.bin");
        tokio::fs::write(&path, contents).await.expect("temp file");
        path
    }

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

    #[tokio::test]
    async fn put_upload_allows_local_reuse_when_finalize_payload_is_empty() {
        let state = test_state();
        let digest = cas_oci::prefixed_sha256_digest(b"existing payload");
        let filled_path = write_temp_upload_file(b"existing payload").await;
        let empty_path = write_temp_upload_file(&[]).await;

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "filled-session".to_string(),
                name: "cache".to_string(),
                temp_path: filled_path.clone(),
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 16,
                finalized_digest: Some(digest.clone()),
                finalized_size: Some(16),
                created_at: Instant::now(),
            });
            sessions.create(UploadSession {
                id: "empty-session".to_string(),
                name: "cache".to_string(),
                temp_path: empty_path.clone(),
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 0,
                finalized_digest: None,
                finalized_size: None,
                created_at: Instant::now(),
            });
        }

        let mut params = HashMap::new();
        params.insert("digest".to_string(), digest.clone());
        let response = put_upload(
            state.clone(),
            "cache".to_string(),
            "empty-session".to_string(),
            params,
            HeaderMap::new(),
            Body::empty(),
        )
        .await
        .expect("put upload should succeed via local reuse");

        assert_eq!(response.status(), StatusCode::CREATED);
        let sessions = state.upload_sessions.read().await;
        let empty = sessions.get("empty-session").expect("empty session");
        assert_eq!(empty.finalized_digest.as_deref(), Some(digest.as_str()));

        let _ = tokio::fs::remove_file(&filled_path).await;
        let _ = tokio::fs::remove_file(&empty_path).await;
    }

    #[tokio::test]
    async fn start_upload_mount_returns_created_for_existing_local_digest() {
        let state = test_state();
        let digest = cas_oci::prefixed_sha256_digest(b"mount-existing");
        let filled_path = write_temp_upload_file(b"mount-existing").await;

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "filled-session".to_string(),
                name: "cache".to_string(),
                temp_path: filled_path.clone(),
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 14,
                finalized_digest: Some(digest.clone()),
                finalized_size: Some(14),
                created_at: Instant::now(),
            });
        }

        let mut params = HashMap::new();
        params.insert("mount".to_string(), digest.clone());
        params.insert("from".to_string(), "cache".to_string());

        let response = start_upload(state, "cache".to_string(), params, Body::empty())
            .await
            .expect("start upload mount should reuse local blob");
        assert_eq!(response.status(), StatusCode::CREATED);

        let _ = tokio::fs::remove_file(&filled_path).await;
    }

    #[tokio::test]
    async fn put_upload_retries_local_reuse_before_remote_lookup() {
        let state = test_state();
        let digest = cas_oci::prefixed_sha256_digest(b"delayed payload");
        let delayed_path = write_temp_upload_file(b"delayed payload").await;
        let empty_path = write_temp_upload_file(&[]).await;

        {
            let mut sessions = state.upload_sessions.write().await;
            sessions.create(UploadSession {
                id: "delayed-session".to_string(),
                name: "cache".to_string(),
                temp_path: delayed_path.clone(),
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 0,
                finalized_digest: None,
                finalized_size: None,
                created_at: Instant::now(),
            });
            sessions.create(UploadSession {
                id: "empty-session".to_string(),
                name: "cache".to_string(),
                temp_path: empty_path.clone(),
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
                bytes_received: 0,
                finalized_digest: None,
                finalized_size: None,
                created_at: Instant::now(),
            });
        }

        let state_for_finalize = state.clone();
        let digest_for_finalize = digest.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let mut sessions = state_for_finalize.upload_sessions.write().await;
            let session = sessions
                .get_mut("delayed-session")
                .expect("delayed session exists");
            session.bytes_received = 15;
            session.finalized_size = Some(15);
            session.finalized_digest = Some(digest_for_finalize);
        });

        let mut params = HashMap::new();
        params.insert("digest".to_string(), digest.clone());
        let response = put_upload(
            state,
            "cache".to_string(),
            "empty-session".to_string(),
            params,
            HeaderMap::new(),
            Body::empty(),
        )
        .await
        .expect("empty finalize should reuse delayed local digest");

        assert_eq!(response.status(), StatusCode::CREATED);

        let _ = tokio::fs::remove_file(&delayed_path).await;
        let _ = tokio::fs::remove_file(&empty_path).await;
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
    fn parse_blob_upload_uuid_uses_last_upload_marker() {
        match parse_oci_path("org/blobs/uploads/cache/blobs/uploads/some-uuid-here") {
            Some(OciRoute::BlobUpload { name, uuid }) => {
                assert_eq!(name, "org/blobs/uploads/cache");
                assert_eq!(uuid, "some-uuid-here");
            }
            _ => panic!("expected BlobUpload"),
        }
    }

    #[test]
    fn parse_blob_route_uses_last_blob_marker() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path = format!("org/blobs/cache/blobs/{digest}");
        match parse_oci_path(&path) {
            Some(OciRoute::Blob {
                name,
                digest: parsed_digest,
            }) => {
                assert_eq!(name, "org/blobs/cache");
                assert_eq!(parsed_digest, digest);
            }
            _ => panic!("expected Blob"),
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
    fn parse_upload_offset_prefers_range_start() {
        let mut headers = HeaderMap::new();
        headers.insert("Range", "0-1023".parse().unwrap());
        assert_eq!(parse_upload_offset(&headers), Some(0));
    }

    #[test]
    fn parse_put_upload_offset_uses_content_range_start() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Range", "bytes 4096-8191".parse().unwrap());
        assert_eq!(parse_put_upload_offset(&headers, 8192), 4096);
    }

    #[test]
    fn parse_put_upload_offset_uses_range_end_for_finalize() {
        let mut headers = HeaderMap::new();
        headers.insert("Range", "0-8191".parse().unwrap());
        assert_eq!(parse_put_upload_offset(&headers, 8192), 8192);
    }

    #[test]
    fn parse_put_upload_offset_clamps_empty_range_to_current_size() {
        let mut headers = HeaderMap::new();
        headers.insert("Range", "0-0".parse().unwrap());
        assert_eq!(parse_put_upload_offset(&headers, 0), 0);
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
        let blobs = extract_blob_descriptors(&index_json).unwrap();
        assert!(blobs.is_empty());
    }

    #[test]
    fn extract_blob_descriptors_includes_config_and_layers() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 100},
            "layers": [
                {"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "size": 2000},
                {"digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "size": 3000}
            ]
        });
        let blobs = extract_blob_descriptors(&manifest_json).unwrap();
        assert_eq!(blobs.len(), 3);
        assert_eq!(
            blobs[0].digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            blobs[1].digest,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            blobs[2].digest,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn extract_blob_descriptors_dedupes_by_digest() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
            "layers": [
                {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
                {"digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "size": 3000}
            ]
        });

        let blobs = extract_blob_descriptors(&manifest_json).unwrap();
        assert_eq!(blobs.len(), 2);
        assert_eq!(
            blobs[0].digest,
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            blobs[1].digest,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
    }

    #[test]
    fn extract_blob_descriptors_rejects_conflicting_sizes_for_same_digest() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
            "layers": [
                {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 64}
            ]
        });

        let error = extract_blob_descriptors(&manifest_json).unwrap_err();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn extract_blob_descriptors_rejects_invalid_digest_format() {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": "sha256:not-a-real-digest", "size": 32},
            "layers": []
        });

        let error = extract_blob_descriptors(&manifest_json).unwrap_err();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
    fn scoped_restore_tags_use_single_effective_tag() {
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
            vec![ref_tag_for_input("buildkit-cache:main-branch-feature-x")]
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

    #[test]
    fn adaptive_blob_upload_concurrency_is_bounded() {
        assert_eq!(adaptive_blob_upload_concurrency(1), 1);

        let medium = adaptive_blob_upload_concurrency(5);
        assert!((1..=5).contains(&medium));

        let larger = adaptive_blob_upload_concurrency(32);
        assert!((1..=32).contains(&larger));
    }

    #[test]
    fn alias_tags_include_digest_and_human_alias_when_distinct() {
        let tags = alias_tags_for_manifest(
            "oci_ref_primary",
            "sha256:abc123",
            &["posthog-docker-build".to_string()],
        );
        assert_eq!(
            tags,
            vec![
                "oci_digest_abc123".to_string(),
                "posthog-docker-build".to_string()
            ]
        );
    }

    #[test]
    fn alias_tags_skip_primary_and_deduplicate() {
        let tags = alias_tags_for_manifest(
            "oci_digest_abc123",
            "sha256:abc123",
            &["oci_digest_abc123".to_string()],
        );
        assert!(tags.is_empty());
    }

    #[test]
    fn alias_tags_include_multiple_human_aliases() {
        let tags = alias_tags_for_manifest(
            "oci_ref_primary",
            "sha256:abc123",
            &[
                "posthog-build".to_string(),
                "posthog-stable".to_string(),
                "posthog-build".to_string(),
            ],
        );
        assert_eq!(
            tags,
            vec![
                "oci_digest_abc123".to_string(),
                "posthog-build".to_string(),
                "posthog-stable".to_string(),
            ]
        );
    }
}
