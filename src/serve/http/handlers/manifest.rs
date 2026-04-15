use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use crate::api::models::cache::{BlobDescriptor, ConfirmRequest, SaveRequest};
use crate::cas_oci;
use crate::cas_transport::upload_payload;
use crate::serve::http::error::OciError;
use crate::serve::http::oci_route::insert_header;
use crate::serve::http::oci_tags::{
    AliasBinding, AliasTagManifest, alias_tags_for_manifest, bind_alias_tag, scoped_restore_tags,
    scoped_save_tag, scoped_write_scope_tag,
};
use crate::serve::state::{
    AppState, BlobLocatorEntry, OCI_MANIFEST_CACHE_TTL, OciManifestCacheEntry, UploadSession,
    digest_tag,
};

use super::uploads::has_non_empty_local_blob;
use super::{
    OCI_API_CALL_TIMEOUT, OCI_DEGRADED_HEADER, OCI_POINTER_FETCH_TIMEOUT, OCI_TRANSFER_CALL_TIMEOUT,
};

pub(super) async fn get_manifest(
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

pub(super) async fn put_manifest(
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

    let blob_descriptors = extract_blob_descriptors_impl(&parsed)?;
    stage_manifest_reference_uploads_impl(&state, &name, &blob_descriptors, &parsed).await?;

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
                sequence: None,
            })
            .collect(),
    };

    let pointer_bytes = serde_json::to_vec(&pointer)
        .map_err(|e| OciError::internal(format!("Failed to serialize pointer: {e}")))?;
    let manifest_root_digest = cas_oci::prefixed_sha256_digest(&pointer_bytes);

    let write_scope_tag = scoped_write_scope_tag(&state.tag_resolver, &name, &reference)?;
    let tag = if reference.starts_with("sha256:") {
        digest_tag(&reference)
    } else {
        scoped_save_tag(&state.tag_resolver, &name, &reference)?
    };
    let additional_aliases = if reference.starts_with("sha256:") {
        vec![AliasBinding {
            tag: scoped_save_tag(&state.tag_resolver, &name, "latest")?,
            write_scope_tag: Some(scoped_write_scope_tag(
                &state.tag_resolver,
                &name,
                "latest",
            )?),
        }]
    } else {
        Vec::new()
    };
    let blob_count = blob_descriptors.len() as u64;
    let blob_total_size_bytes: u64 = blob_descriptors.iter().map(|b| b.size_bytes).sum();
    let total_size_bytes = blob_total_size_bytes + manifest_body.len() as u64;

    let alias_manifest = AliasTagManifest {
        manifest_root_digest: manifest_root_digest.clone(),
        manifest_size: pointer_bytes.len() as u64,
        blob_count,
        blob_total_size_bytes,
        total_size_bytes,
    };

    let save_request = SaveRequest {
        tag: tag.clone(),
        write_scope_tag: Some(write_scope_tag.clone()),
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
        expected_manifest_size: Some(alias_manifest.manifest_size),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let persist_result: Result<(), OciError> = async {
        let save_response = tokio::time::timeout(
            OCI_API_CALL_TIMEOUT,
            state.api_client.save_entry(&state.workspace, &save_request),
        )
        .await
        .map_err(|_| {
            OciError::internal(format!(
                "save_entry timed out after {}s",
                OCI_API_CALL_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| OciError::internal(format!("save_entry failed: {e}")))?;

        let blob_state = state.clone();
        let manifest_state = state.clone();
        let confirm_state = state.clone();
        let publish_blob_descriptors = blob_descriptors.clone();
        let publish_pointer_bytes = pointer_bytes.clone();
        let confirm_tag = tag.clone();
        let confirm_write_scope_tag = write_scope_tag.clone();
        let confirm_cache_entry_id = save_response.cache_entry_id.clone();
        let confirm_manifest_digest = manifest_root_digest.clone();
        let confirm_manifest_size = pointer_bytes.len() as u64;
        let confirm_file_count = blob_count.min(u32::MAX as u64) as u32;
        crate::serve::cas_publish::publish_after_save(
            &state.api_client,
            &state.workspace,
            &save_response,
            manifest_root_digest.clone(),
            pointer_bytes.len() as u64,
            move |save_response| {
                let state = blob_state.clone();
                let blob_descriptors = publish_blob_descriptors.clone();
                let cache_entry_id = save_response.cache_entry_id.clone();
                async move {
                    tokio::time::timeout(
                        OCI_API_CALL_TIMEOUT,
                        crate::serve::cas_publish::upload_tracked_blobs(
                            &state.api_client,
                            &state.workspace,
                            &cache_entry_id,
                            &blob_descriptors,
                            &state.upload_sessions,
                            adaptive_blob_upload_concurrency_impl(blob_descriptors.len()),
                            OCI_TRANSFER_CALL_TIMEOUT,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        OciError::internal(format!(
                            "blob_upload_urls timed out after {}s",
                            OCI_API_CALL_TIMEOUT.as_secs()
                        ))
                    })?
                }
            },
            move |save_response| {
                let state = manifest_state.clone();
                let pointer_bytes = publish_pointer_bytes.clone();
                let manifest_upload_url = save_response.manifest_upload_url.clone();
                let upload_headers = save_response.upload_headers.clone();
                async move {
                    let manifest_upload_url = manifest_upload_url
                        .as_ref()
                        .ok_or_else(|| OciError::internal("Missing manifest_upload_url"))?;

                    tokio::time::timeout(
                        OCI_TRANSFER_CALL_TIMEOUT,
                        upload_payload(
                            state.api_client.transfer_client(),
                            manifest_upload_url,
                            &pointer_bytes,
                            "application/cbor",
                            &upload_headers,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        OciError::internal(format!(
                            "Pointer upload timed out after {}s",
                            OCI_TRANSFER_CALL_TIMEOUT.as_secs()
                        ))
                    })?
                    .map_err(|e| OciError::internal(format!("Pointer upload failed: {e}")))
                }
            },
            move |_manifest_etag| {
                let state = confirm_state.clone();
                let tag = confirm_tag.clone();
                let write_scope_tag = confirm_write_scope_tag.clone();
                let cache_entry_id = confirm_cache_entry_id.clone();
                let manifest_digest = confirm_manifest_digest.clone();
                async move {
                    let confirm_request = ConfirmRequest {
                        manifest_digest,
                        manifest_size: confirm_manifest_size,
                        manifest_etag: None,
                        archive_size: None,
                        archive_etag: None,
                        blob_count: Some(blob_count),
                        blob_total_size_bytes: Some(blob_total_size_bytes),
                        file_count: Some(confirm_file_count),
                        uncompressed_size: None,
                        compressed_size: None,
                        storage_mode: Some("cas".to_string()),
                        tag: Some(tag),
                        write_scope_tag: Some(write_scope_tag),
                    };

                    state
                        .api_client
                        .confirm(&state.workspace, &cache_entry_id, &confirm_request)
                        .await
                        .map_err(|e| OciError::internal(format!("confirm failed: {e}")))?;
                    Ok(())
                }
            },
        )
        .await?;

        {
            let cached = OciManifestCacheEntry {
                index_json: manifest_body.clone(),
                content_type: detect_manifest_content_type(&manifest_body),
                manifest_digest: manifest_digest.clone(),
                cache_entry_id: save_response.cache_entry_id.clone(),
                blobs: blob_descriptors.clone(),
                name: name.clone(),
                inserted_at: Instant::now(),
            };
            let cached = Arc::new(cached);
            state
                .oci_manifest_cache
                .insert(tag.clone(), Arc::clone(&cached));
            state
                .oci_manifest_cache
                .insert(digest_tag(&manifest_digest), Arc::clone(&cached));
        }

        let alias_tags = alias_tags_for_manifest(
            &tag,
            &manifest_digest,
            Some(write_scope_tag.as_str()),
            &state.configured_human_tags,
            &additional_aliases,
        );
        for alias in alias_tags {
            if let Err(error) = bind_alias_tag(
                &state,
                &alias.tag,
                alias.write_scope_tag.as_deref(),
                &alias_manifest,
            )
            .await
            {
                if state.fail_on_cache_error {
                    return Err(OciError::internal(format!(
                        "Alias write failed for {} (workspace={}): {error}",
                        alias.tag, state.workspace
                    )));
                }
                let warning = format!(
                    "Alias write skipped for {} (workspace={}): {}",
                    alias.tag, state.workspace, error
                );
                eprintln!("{warning}");
                log::warn!("{warning}");
            }
        }

        Ok(())
    }
    .await;

    cleanup_blob_sessions(&state, &blob_descriptors).await;
    let mut degraded_fallback = false;

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
        degraded_fallback = true;
    }

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", &manifest_digest)?;
    insert_header(
        &mut headers,
        "Location",
        &format!("/v2/{name}/manifests/{manifest_digest}"),
    )?;
    insert_header(&mut headers, "Content-Length", "0")?;
    if degraded_fallback {
        insert_header(&mut headers, OCI_DEGRADED_HEADER, "1")?;
    }

    Ok((StatusCode::CREATED, headers, Body::empty()).into_response())
}

#[cfg(test)]
pub(super) fn adaptive_blob_upload_concurrency(operation_count: usize) -> usize {
    adaptive_blob_upload_concurrency_impl(operation_count)
}

#[cfg(test)]
pub(super) fn extract_blob_descriptors(
    manifest: &serde_json::Value,
) -> Result<Vec<BlobDescriptor>, OciError> {
    extract_blob_descriptors_impl(manifest)
}

#[cfg(test)]
pub(super) async fn stage_manifest_reference_uploads(
    state: &AppState,
    name: &str,
    blob_descriptors: &[BlobDescriptor],
    manifest: &serde_json::Value,
) -> Result<(), OciError> {
    stage_manifest_reference_uploads_impl(state, name, blob_descriptors, manifest).await
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

    if let Some(cached) = lookup_oci_manifest_cache(state, &tags) {
        cache_blob_locator_entries(
            state,
            &cached.name,
            &cached.cache_entry_id,
            &cached.blobs,
            &HashMap::new(),
        )
        .await;
        let content_type = if cached.content_type.is_empty() {
            detect_manifest_content_type(&cached.index_json)
        } else {
            cached.content_type.clone()
        };
        return Ok((
            cached.index_json.clone(),
            content_type,
            cached.manifest_digest.clone(),
        ));
    }

    let entries = tokio::time::timeout(
        OCI_API_CALL_TIMEOUT,
        state.api_client.restore(&state.workspace, &tags, false),
    )
    .await
    .map_err(|_| {
        OciError::internal(format!(
            "Backend restore timed out after {}s",
            OCI_API_CALL_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| OciError::internal(format!("Backend restore failed: {e}")))?;

    let mut entries_by_tag: HashMap<String, _> = entries
        .into_iter()
        .map(|entry| (entry.tag.clone(), entry))
        .collect();
    let mut selected = None;
    for tag in &tags {
        if let Some(entry) = entries_by_tag.remove(tag)
            && entry.status == "hit"
        {
            selected = Some(entry);
            break;
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

    let pointer_response = tokio::time::timeout(
        OCI_POINTER_FETCH_TIMEOUT,
        state.api_client.transfer_client().get(manifest_url).send(),
    )
    .await
    .map_err(|_| {
        OciError::internal(format!(
            "Timed out downloading pointer after {}s",
            OCI_POINTER_FETCH_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| OciError::internal(format!("Failed to download pointer: {e}")))?
    .error_for_status()
    .map_err(|e| OciError::internal(format!("Pointer download returned error: {e}")))?;

    let pointer_bytes = tokio::time::timeout(OCI_POINTER_FETCH_TIMEOUT, pointer_response.bytes())
        .await
        .map_err(|_| {
            OciError::internal(format!(
                "Timed out reading pointer bytes after {}s",
                OCI_POINTER_FETCH_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| OciError::internal(format!("Failed to read pointer bytes: {e}")))?;

    let pointer = cas_oci::parse_pointer(&pointer_bytes)
        .map_err(|e| OciError::internal(format!("Failed to parse pointer: {e}")))?;

    let index_json = pointer
        .index_json_bytes()
        .map_err(|e| OciError::internal(format!("Failed to decode index_json: {e}")))?;
    let blob_descriptors: Vec<BlobDescriptor> = pointer
        .blobs
        .iter()
        .map(|blob| BlobDescriptor {
            digest: blob.digest.clone(),
            size_bytes: blob.size_bytes,
        })
        .collect();

    let prefetched_urls = if prefetch_blob_urls {
        prefetch_manifest_blob_download_urls(
            state,
            cache_entry_id,
            name,
            reference,
            &blob_descriptors,
        )
        .await
    } else {
        HashMap::new()
    };

    cache_blob_locator_entries(
        state,
        name,
        cache_entry_id,
        &blob_descriptors,
        &prefetched_urls,
    )
    .await;

    let content_type = detect_manifest_content_type(&index_json);
    let digest = cas_oci::prefixed_sha256_digest(&index_json);
    let resolved_entry_tag = entry.tag.clone();
    let cached = Arc::new(OciManifestCacheEntry {
        index_json: index_json.clone(),
        content_type: content_type.clone(),
        manifest_digest: digest.clone(),
        cache_entry_id: cache_entry_id.clone(),
        blobs: blob_descriptors.clone(),
        name: name.to_string(),
        inserted_at: Instant::now(),
    });
    let mut cache_keys = HashSet::new();
    for tag in &tags {
        cache_keys.insert(tag.clone());
    }
    cache_keys.insert(resolved_entry_tag);
    cache_keys.insert(digest_tag(&digest));
    for cache_key in cache_keys {
        state
            .oci_manifest_cache
            .insert(cache_key, Arc::clone(&cached));
    }

    Ok((index_json, content_type, digest))
}

async fn prefetch_manifest_blob_download_urls(
    state: &AppState,
    cache_entry_id: &str,
    name: &str,
    reference: &str,
    blob_descriptors: &[BlobDescriptor],
) -> HashMap<String, String> {
    if blob_descriptors.is_empty() {
        return HashMap::new();
    }

    match crate::serve::blob_download_urls::resolve_verified_blob_download_urls(
        state,
        cache_entry_id,
        blob_descriptors,
        OCI_API_CALL_TIMEOUT,
    )
    .await
    {
        Ok(resolved) => {
            if !resolved.missing.is_empty() {
                log::debug!(
                    "OCI manifest URL prefetch skipped {} missing blobs for {}:{}",
                    resolved.missing.len(),
                    name,
                    reference
                );
            }
            resolved.urls
        }
        Err(error) => {
            log::debug!(
                "OCI manifest URL prefetch failed for {}:{} ({})",
                name,
                reference,
                error
            );
            HashMap::new()
        }
    }
}

async fn cache_blob_locator_entries(
    state: &AppState,
    name: &str,
    cache_entry_id: &str,
    blob_descriptors: &[BlobDescriptor],
    prefetched_urls: &HashMap<String, String>,
) {
    let prefetched_at = if prefetched_urls.is_empty() {
        None
    } else {
        Some(std::time::Instant::now())
    };
    let mut locator = state.blob_locator.write().await;
    for blob in blob_descriptors {
        let existing = locator.get(name, &blob.digest).cloned();
        let (download_url, download_url_cached_at) =
            if let Some(download_url) = prefetched_urls.get(&blob.digest).cloned() {
                (Some(download_url), prefetched_at)
            } else if let Some(existing) = existing.as_ref() {
                if existing.cache_entry_id == cache_entry_id {
                    (
                        existing.download_url.clone(),
                        existing.download_url_cached_at,
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };
        let size_bytes = existing
            .as_ref()
            .map(|entry| entry.size_bytes.max(blob.size_bytes))
            .unwrap_or(blob.size_bytes);
        locator.insert(
            name,
            &blob.digest,
            BlobLocatorEntry {
                cache_entry_id: cache_entry_id.to_string(),
                size_bytes,
                download_url,
                download_url_cached_at,
            },
        );
    }
}

fn lookup_oci_manifest_cache(
    state: &AppState,
    tags: &[String],
) -> Option<Arc<OciManifestCacheEntry>> {
    for tag in tags {
        let cached_entry = state.oci_manifest_cache.get(tag);
        if let Some(entry) = cached_entry {
            if entry.inserted_at.elapsed() < OCI_MANIFEST_CACHE_TTL {
                return Some(Arc::clone(entry.value()));
            }
            drop(entry);
            state.oci_manifest_cache.remove(tag);
        }
    }
    None
}

fn detect_manifest_content_type(json_bytes: &[u8]) -> String {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(json_bytes)
        && val.get("manifests").is_some()
    {
        return "application/vnd.oci.image.index.v1+json".to_string();
    }
    "application/vnd.oci.image.manifest.v1+json".to_string()
}

fn adaptive_blob_upload_concurrency_impl(operation_count: usize) -> usize {
    if operation_count == 0 {
        return 1;
    }

    num_cpus::get()
        .max(1)
        .saturating_mul(2)
        .clamp(16, 64)
        .min(operation_count)
        .max(1)
}

fn extract_blob_descriptors_impl(
    manifest: &serde_json::Value,
) -> Result<Vec<BlobDescriptor>, OciError> {
    let mut blobs = Vec::new();

    if let Some(manifests) = manifest.get("manifests").and_then(|m| m.as_array()) {
        for child in manifests {
            if let (Some(digest), Some(size)) = (
                child.get("digest").and_then(|d| d.as_str()),
                child.get("size").and_then(|s| s.as_u64()),
            ) {
                if !cas_oci::is_valid_sha256_digest(digest) {
                    return Err(OciError::digest_invalid(format!(
                        "unsupported manifest digest format: {digest}"
                    )));
                }
                blobs.push(BlobDescriptor {
                    digest: digest.to_string(),
                    size_bytes: size,
                });
            }
        }
    }

    if let Some(config) = manifest.get("config")
        && let (Some(digest), Some(size)) = (
            config.get("digest").and_then(|d| d.as_str()),
            config.get("size").and_then(|s| s.as_u64()),
        )
    {
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

async fn stage_manifest_reference_uploads_impl(
    state: &AppState,
    name: &str,
    blob_descriptors: &[BlobDescriptor],
    manifest: &serde_json::Value,
) -> Result<(), OciError> {
    let Some(manifests) = manifest.get("manifests").and_then(|value| value.as_array()) else {
        return Ok(());
    };

    let manifest_digests: HashSet<&str> = manifests
        .iter()
        .filter_map(|child| child.get("digest").and_then(|value| value.as_str()))
        .collect();

    for descriptor in blob_descriptors {
        if !manifest_digests.contains(descriptor.digest.as_str()) {
            continue;
        }
        stage_manifest_reference_upload(state, name, descriptor).await?;
    }

    Ok(())
}

async fn stage_manifest_reference_upload(
    state: &AppState,
    name: &str,
    descriptor: &BlobDescriptor,
) -> Result<(), OciError> {
    if has_non_empty_local_blob(state, &descriptor.digest).await {
        return Ok(());
    }

    let digest_tag = digest_tag(&descriptor.digest);
    let manifest_bytes = match lookup_oci_manifest_cache(state, &[digest_tag]) {
        Some(cached) => cached.index_json.clone(),
        _ => {
            let (manifest_bytes, _content_type, resolved_digest) =
                resolve_manifest(state, name, &descriptor.digest, false).await?;
            if resolved_digest != descriptor.digest {
                return Err(OciError::internal(format!(
                    "resolved child manifest digest mismatch for {}: got {}",
                    descriptor.digest, resolved_digest
                )));
            }
            manifest_bytes
        }
    };

    let actual_digest = cas_oci::prefixed_sha256_digest(&manifest_bytes);
    if actual_digest != descriptor.digest {
        return Err(OciError::internal(format!(
            "child manifest digest mismatch for {}: got {}",
            descriptor.digest, actual_digest
        )));
    }

    let actual_size = manifest_bytes.len() as u64;
    if actual_size != descriptor.size_bytes {
        return Err(OciError::internal(format!(
            "child manifest size mismatch for {}: expected {} got {}",
            descriptor.digest, descriptor.size_bytes, actual_size
        )));
    }

    let temp_dir = state
        .runtime_temp_dir
        .join("oci-manifests")
        .join(uuid::Uuid::new_v4().to_string());
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| OciError::internal(format!("Failed to create temp dir: {e}")))?;
    let session_id = format!("oci-manifest-{}", uuid::Uuid::new_v4());
    let temp_path = temp_dir.join(&session_id);
    tokio::fs::write(&temp_path, &manifest_bytes)
        .await
        .map_err(|e| OciError::internal(format!("Failed to stage child manifest blob: {e}")))?;

    let mut sessions = state.upload_sessions.write().await;
    if sessions
        .find_by_name_and_digest(name, &descriptor.digest)
        .is_some()
        || sessions.find_by_digest(&descriptor.digest).is_some()
    {
        drop(sessions);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Ok(());
    }

    sessions.create(UploadSession {
        id: session_id,
        name: name.to_string(),
        temp_path,
        write_lock: Arc::new(tokio::sync::Mutex::new(())),
        bytes_received: actual_size,
        finalized_digest: Some(descriptor.digest.clone()),
        finalized_size: Some(actual_size),
        created_at: Instant::now(),
    });

    Ok(())
}

async fn cleanup_blob_sessions(state: &AppState, blob_descriptors: &[BlobDescriptor]) {
    let mut sessions = state.upload_sessions.write().await;
    for blob in blob_descriptors {
        if let Some(session) = sessions.find_by_digest(&blob.digest).map(|s| s.id.clone())
            && let Some(removed) = sessions.remove(&session)
        {
            let _ = tokio::fs::remove_file(&removed.temp_path).await;
        }
    }
}
