use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use crate::api::models::cache::{BlobDescriptor, ConfirmRequest, SaveRequest};
use crate::cas_oci;
use crate::cas_transport::upload_payload;
use crate::serve::engines::oci::manifests::{
    OCI_IMAGE_INDEX_CONTENT_TYPE, build_referrers_descriptor as engine_build_referrers_descriptor,
    dedupe_blob_descriptors as engine_dedupe_blob_descriptors,
    detect_manifest_content_type as engine_detect_manifest_content_type,
    extract_blob_descriptors as engine_extract_blob_descriptors,
    extract_subject_digest as engine_extract_subject_digest,
    manifest_child_descriptors as engine_manifest_child_descriptors,
    parse_referrers_descriptors as engine_parse_referrers_descriptors,
    referrers_reference_for_subject as engine_referrers_reference_for_subject,
    resolve_pushed_manifest_content_type as engine_resolve_pushed_manifest_content_type,
};
use crate::serve::engines::oci::{
    PresentBlob, ensure_manifest_blobs_present, uploads::has_non_empty_local_blob,
};
use crate::serve::http::error::OciError;
use crate::serve::http::flight::{Flight, await_flight, begin_flight, clear_flight_entry};
use crate::serve::http::oci_route::{insert_digest_etag, insert_header};
use crate::serve::http::oci_tags::{
    AliasBinding, AliasTagManifest, alias_tags_for_manifest, bind_alias_tag, scoped_restore_tags,
    scoped_save_tag, scoped_write_scope_tag,
};
use crate::serve::state::{
    AppState, BlobLocatorEntry, OCI_MANIFEST_CACHE_TTL, OciManifestCacheEntry, UploadSession,
    diagnostics_enabled, digest_tag,
};

use super::{
    OCI_API_CALL_TIMEOUT, OCI_DEGRADED_HEADER, OCI_POINTER_FETCH_TIMEOUT, OCI_TRANSFER_CALL_TIMEOUT,
};

const OCI_SUBJECT_HEADER: &str = "OCI-Subject";
const OCI_FILTERS_APPLIED_HEADER: &str = "OCI-Filters-Applied";

struct PersistManifestResult {
    manifest_digest: String,
}

struct PersistManifestEntryInput<'a> {
    state: &'a AppState,
    name: &'a str,
    primary_tag: String,
    write_scope_tag: String,
    manifest_body: Vec<u8>,
    content_type: String,
    blob_descriptors: Vec<BlobDescriptor>,
    present_blobs: Vec<PresentBlob>,
    configured_human_tags: &'a [String],
    additional_aliases: &'a [AliasBinding],
}

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
    insert_digest_etag(&mut headers, &digest)?;
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

pub(crate) async fn prefetch_manifest_reference(
    state: &AppState,
    name: &str,
    reference: &str,
    hydrate_bodies: bool,
) -> Result<(crate::serve::cache_registry::BlobPrefetchStats, usize), OciError> {
    let started_at = Instant::now();
    let tags = manifest_restore_tags(state, name, reference);
    let (_, _, digest) = resolve_manifest(state, name, reference, true).await?;
    let digest_tags = [digest_tag(&digest)];
    let cached = lookup_oci_manifest_cache(state, &tags)
        .or_else(|| lookup_oci_manifest_cache(state, &digest_tags))
        .ok_or_else(|| {
            OciError::internal(format!("Manifest cache missing for {name}:{reference}"))
        })?;

    let mut cached_urls = {
        let locator = state.blob_locator.read().await;
        cached
            .blobs
            .iter()
            .filter_map(|blob| {
                locator
                    .get(&cached.name, &blob.digest)
                    .and_then(|entry| entry.download_url.clone())
                    .map(|url| (blob.digest.clone(), url))
            })
            .collect::<HashMap<_, _>>()
    };
    if cached_urls.len() < cached.blobs.len() {
        let resolved_urls = prefetch_manifest_blob_download_urls(
            state,
            &cached.cache_entry_id,
            &cached.name,
            reference,
            &cached.blobs,
        )
        .await;
        if !resolved_urls.is_empty() {
            cache_blob_locator_entries(
                state,
                &cached.name,
                &cached.cache_entry_id,
                &cached.blobs,
                &resolved_urls,
            )
            .await;
            cached_urls.extend(resolved_urls);
        }
    }

    let local_blobs = count_local_oci_blobs(state, &cached.blobs).await;
    if !hydrate_bodies {
        let cold_blobs = cached.blobs.len().saturating_sub(local_blobs);
        eprintln!(
            "OCI prefetch {name}@{reference}: indexed {} blobs ({} locator URLs, {} already local); blob bodies remain on demand",
            cached.blobs.len(),
            cached_urls.len(),
            local_blobs,
        );

        return Ok((
            crate::serve::cache_registry::BlobPrefetchStats {
                total_unique_blobs: cached.blobs.len(),
                already_local: local_blobs,
                duration_ms: started_at.elapsed().as_millis() as u64,
                ..crate::serve::cache_registry::BlobPrefetchStats::default()
            },
            cold_blobs,
        ));
    }

    eprintln!(
        "OCI prefetch {name}@{reference}: indexed {} blobs ({} locator URLs, {} already local); hydrating blob bodies",
        cached.blobs.len(),
        cached_urls.len(),
        local_blobs,
    );
    let stats = crate::serve::cache_registry::prefetch_oci_blob_bodies(
        state,
        &cached.cache_entry_id,
        &cached.blobs,
        &cached_urls,
        &format!("OCI prefetch {name}@{reference}"),
    )
    .await;
    let cold_blobs =
        crate::serve::cache_registry::count_missing_local_blobs(state, &cached.blobs).await;

    Ok((stats, cold_blobs))
}

async fn count_local_oci_blobs(state: &AppState, blobs: &[BlobDescriptor]) -> usize {
    let mut local_blobs = 0usize;
    for blob in blobs {
        if state
            .blob_read_cache
            .get_handle(&blob.digest)
            .await
            .is_some()
        {
            local_blobs = local_blobs.saturating_add(1);
        }
    }
    local_blobs
}

pub(super) async fn get_referrers(
    method: Method,
    state: AppState,
    name: String,
    digest: String,
    params: HashMap<String, String>,
) -> Result<Response, OciError> {
    if !cas_oci::is_valid_sha256_digest(&digest) {
        return Err(OciError::digest_invalid(format!(
            "unsupported referrers digest format: {digest}"
        )));
    }

    let artifact_type = params
        .get("artifactType")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let mut manifests = load_referrers_descriptors(&state, &name, &digest).await?;
    if let Some(filter) = artifact_type.as_deref() {
        manifests.retain(|descriptor| {
            descriptor
                .get("artifactType")
                .and_then(|value| value.as_str())
                == Some(filter)
        });
    }

    referrers_response(
        method,
        manifests,
        artifact_type.as_ref().map(|_| "artifactType"),
    )
}

pub(super) fn empty_referrers_response(
    method: Method,
    filters_applied: Option<&str>,
) -> Result<Response, OciError> {
    referrers_response(method, Vec::new(), filters_applied)
}

pub(super) async fn put_manifest(
    state: AppState,
    name: String,
    reference: String,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, OciError> {
    let manifest_body = axum::body::to_bytes(body, 32 * 1024 * 1024)
        .await
        .map_err(|e| OciError::internal(format!("Failed to read manifest body: {e}")))?;
    let manifest_body: Vec<u8> = manifest_body.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);

    let parsed: serde_json::Value = serde_json::from_slice(&manifest_body)
        .map_err(|e| OciError::manifest_invalid(format!("Invalid manifest JSON: {e}")))?;
    let content_type = resolve_manifest_content_type_from_headers(&headers, &parsed)?;
    let subject_digest = engine_extract_subject_digest(&parsed)?;
    if reference.starts_with("sha256:") && !reference.eq_ignore_ascii_case(&manifest_digest) {
        return Err(OciError::digest_invalid(format!(
            "Manifest digest {manifest_digest} does not match requested reference {reference}"
        )));
    }

    let blob_descriptors = expand_manifest_blob_descriptors_impl(&state, &name, &parsed).await?;
    stage_manifest_reference_uploads_impl(&state, &name, &blob_descriptors, &parsed).await?;
    let present_blobs = ensure_manifest_blobs_present(&state, &name, &blob_descriptors).await?;
    log_manifest_blob_sources(&name, &reference, &present_blobs);

    let write_scope_tag = scoped_write_scope_tag(&state.tag_resolver, &name, &reference)?;
    let tag = if reference.starts_with("sha256:") {
        digest_tag(&reference)
    } else {
        scoped_save_tag(
            &state.tag_resolver,
            &state.registry_root_tag,
            &name,
            &reference,
        )?
    };
    let additional_aliases = if reference.starts_with("sha256:") {
        vec![AliasBinding {
            tag: scoped_save_tag(
                &state.tag_resolver,
                &state.registry_root_tag,
                &name,
                "latest",
            )?,
            write_scope_tag: Some(scoped_write_scope_tag(
                &state.tag_resolver,
                &name,
                "latest",
            )?),
        }]
    } else {
        Vec::new()
    };
    let persist_result: Result<bool, OciError> = async {
        persist_manifest_entry(PersistManifestEntryInput {
            state: &state,
            name: &name,
            primary_tag: tag,
            write_scope_tag,
            manifest_body: manifest_body.clone(),
            content_type: content_type.clone(),
            blob_descriptors: blob_descriptors.clone(),
            present_blobs: present_blobs.clone(),
            configured_human_tags: &state.configured_human_tags,
            additional_aliases: &additional_aliases,
        })
        .await?;

        if let Some(subject_digest) = subject_digest.as_deref() {
            persist_referrers_manifest(
                &state,
                &name,
                subject_digest,
                &parsed,
                &content_type,
                &manifest_digest,
                manifest_body.len() as u64,
            )
            .await?;
            return Ok(true);
        }

        Ok(false)
    }
    .await;

    cleanup_present_blob_sessions(&state, &present_blobs).await;
    let mut degraded_fallback = false;
    let mut subject_processed = false;

    match persist_result {
        Ok(processed) => {
            subject_processed = processed;
        }
        Err(error) => {
            if state.fail_on_cache_error || !error.status().is_server_error() {
                return Err(error);
            }
            let warning = format!(
                "Best-effort OCI manifest publish fallback on {}:{} ({}): {}",
                name,
                reference,
                error.status(),
                error.message()
            );
            eprintln!("{warning}");
            log::warn!("{warning}");
            degraded_fallback = true;
        }
    }

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Docker-Content-Digest", &manifest_digest)?;
    insert_digest_etag(&mut headers, &manifest_digest)?;
    insert_header(
        &mut headers,
        "Location",
        &format!("/v2/{name}/manifests/{manifest_digest}"),
    )?;
    insert_header(
        &mut headers,
        "Docker-Distribution-API-Version",
        "registry/2.0",
    )?;
    insert_header(&mut headers, "Content-Length", "0")?;
    if subject_processed && let Some(subject_digest) = subject_digest.as_deref() {
        insert_header(&mut headers, OCI_SUBJECT_HEADER, subject_digest)?;
    }
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
    engine_extract_blob_descriptors(manifest)
}

#[cfg(test)]
pub(super) async fn expand_manifest_blob_descriptors(
    state: &AppState,
    name: &str,
    manifest: &serde_json::Value,
) -> Result<Vec<BlobDescriptor>, OciError> {
    expand_manifest_blob_descriptors_impl(state, name, manifest).await
}

#[cfg(test)]
pub(super) fn detect_manifest_content_type_for_tests(json_bytes: &[u8]) -> String {
    engine_detect_manifest_content_type(json_bytes)
}

#[cfg(test)]
pub(super) fn resolve_pushed_manifest_content_type_for_tests(
    headers: &HeaderMap,
    manifest: &serde_json::Value,
) -> Result<String, OciError> {
    resolve_manifest_content_type_from_headers(headers, manifest)
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

fn resolve_manifest_content_type_from_headers(
    headers: &HeaderMap,
    manifest: &serde_json::Value,
) -> Result<String, OciError> {
    let header_content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .map(|value| {
            value.to_str().map_err(|e| {
                OciError::manifest_invalid(format!("Invalid manifest Content-Type header: {e}"))
            })
        })
        .transpose()?;

    engine_resolve_pushed_manifest_content_type(header_content_type, manifest)
}

async fn resolve_manifest(
    state: &AppState,
    name: &str,
    reference: &str,
    prefetch_blob_urls: bool,
) -> Result<(Vec<u8>, String, String), OciError> {
    let tags = manifest_restore_tags(state, name, reference);

    if let Some(cached) = lookup_oci_manifest_cache(state, &tags) {
        return cached_manifest_response(state, cached).await;
    }

    let flight_key = manifest_flight_key(&tags);
    loop {
        match begin_flight(&state.oci_lookup_inflight, flight_key.clone()) {
            Flight::Leader(_guard) => {
                if let Some(cached) = lookup_oci_manifest_cache(state, &tags) {
                    return cached_manifest_response(state, cached).await;
                }
                return resolve_manifest_remote(state, name, reference, &tags, prefetch_blob_urls)
                    .await;
            }
            Flight::Follower(notified) => {
                if !await_flight("oci-manifest", &flight_key, notified).await {
                    clear_flight_entry(&state.oci_lookup_inflight, &flight_key);
                }
                if let Some(cached) = lookup_oci_manifest_cache(state, &tags) {
                    return cached_manifest_response(state, cached).await;
                }
            }
        }
    }
}

fn manifest_restore_tags(state: &AppState, name: &str, reference: &str) -> Vec<String> {
    if reference.starts_with("sha256:") {
        vec![digest_tag(reference)]
    } else {
        scoped_restore_tags(
            &state.tag_resolver,
            &state.registry_root_tag,
            name,
            reference,
        )
    }
}

async fn resolve_manifest_remote(
    state: &AppState,
    name: &str,
    reference: &str,
    tags: &[String],
    prefetch_blob_urls: bool,
) -> Result<(Vec<u8>, String, String), OciError> {
    let entries = tokio::time::timeout(
        OCI_API_CALL_TIMEOUT,
        state.api_client.restore(&state.workspace, tags, false),
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
    for tag in tags {
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

    let content_type = pointer
        .manifest_content_type
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| engine_detect_manifest_content_type(&index_json));
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
    for tag in tags {
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

async fn cached_manifest_response(
    state: &AppState,
    cached: Arc<OciManifestCacheEntry>,
) -> Result<(Vec<u8>, String, String), OciError> {
    cache_blob_locator_entries(
        state,
        &cached.name,
        &cached.cache_entry_id,
        &cached.blobs,
        &HashMap::new(),
    )
    .await;
    let content_type = if cached.content_type.is_empty() {
        engine_detect_manifest_content_type(&cached.index_json)
    } else {
        cached.content_type.clone()
    };
    Ok((
        cached.index_json.clone(),
        content_type,
        cached.manifest_digest.clone(),
    ))
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

fn log_manifest_blob_sources(name: &str, reference: &str, present_blobs: &[PresentBlob]) {
    if present_blobs.is_empty() || !diagnostics_enabled() {
        return;
    }

    let mut sources: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut digest_sample = Vec::new();
    for blob in present_blobs {
        *sources.entry(blob.source.as_str()).or_insert(0) += 1;
        total_bytes = total_bytes.saturating_add(blob.size_bytes);
        if digest_sample.len() < 3 {
            digest_sample.push(blob.digest.as_str());
        }
    }

    log::debug!(
        "OCI manifest blob sources: name={} reference={} blobs={} bytes={} sources={:?} sample={:?}",
        name,
        reference,
        present_blobs.len(),
        total_bytes,
        sources,
        digest_sample
    );
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

fn manifest_flight_key(tags: &[String]) -> String {
    let mut sorted = tags.to_vec();
    sorted.sort();
    let digest = crate::cas_file::sha256_hex(sorted.join("\0").as_bytes());
    format!("manifest:{digest}")
}

async fn persist_manifest_entry(
    input: PersistManifestEntryInput<'_>,
) -> Result<PersistManifestResult, OciError> {
    let PersistManifestEntryInput {
        state,
        name,
        primary_tag,
        write_scope_tag,
        manifest_body,
        content_type,
        blob_descriptors,
        present_blobs,
        configured_human_tags,
        additional_aliases,
    } = input;
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let blob_count = blob_descriptors.len() as u64;
    let blob_total_size_bytes: u64 = blob_descriptors.iter().map(|blob| blob.size_bytes).sum();

    let pointer = cas_oci::OciPointer {
        format_version: 1,
        adapter: "oci-v1".to_string(),
        manifest_content_type: Some(content_type.clone()),
        index_json_base64: STANDARD.encode(&manifest_body),
        oci_layout_base64: STANDARD.encode(br#"{"imageLayoutVersion":"1.0.0"}"#),
        blobs: blob_descriptors
            .iter()
            .map(|blob| cas_oci::OciPointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
                sequence: None,
            })
            .collect(),
    };
    let pointer_bytes = serde_json::to_vec(&pointer)
        .map_err(|e| OciError::internal(format!("Failed to serialize pointer: {e}")))?;
    let manifest_root_digest = cas_oci::prefixed_sha256_digest(&pointer_bytes);
    let (request_blob_count, request_blob_total_size_bytes) = request_cas_blob_summary(
        blob_count,
        blob_total_size_bytes,
        pointer_bytes.len() as u64,
    );
    let total_size_bytes = blob_total_size_bytes + manifest_body.len() as u64;
    let alias_manifest = AliasTagManifest {
        manifest_root_digest: manifest_root_digest.clone(),
        manifest_size: pointer_bytes.len() as u64,
        blob_count: request_blob_count,
        blob_total_size_bytes: request_blob_total_size_bytes,
        total_size_bytes,
    };

    let save_request = SaveRequest {
        tag: primary_tag.clone(),
        write_scope_tag: Some(write_scope_tag.clone()),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(request_blob_count),
        blob_total_size_bytes: Some(request_blob_total_size_bytes),
        cas_layout: Some("oci-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(request_blob_count.min(u32::MAX as u64) as u32),
        expected_manifest_digest: Some(manifest_root_digest.clone()),
        expected_manifest_size: Some(alias_manifest.manifest_size),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

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
    let publish_present_blobs = present_blobs.clone();
    let publish_pointer_bytes = pointer_bytes.clone();
    let confirm_tag = primary_tag.clone();
    let confirm_write_scope_tag = write_scope_tag.clone();
    let confirm_cache_entry_id = save_response.cache_entry_id.clone();
    let confirm_manifest_digest = manifest_root_digest.clone();
    let confirm_manifest_size = pointer_bytes.len() as u64;
    let confirm_file_count = request_blob_count.min(u32::MAX as u64) as u32;
    let all_blob_digests: Vec<String> = present_blobs
        .iter()
        .map(|blob| blob.digest.clone())
        .collect();
    crate::serve::cas_publish::publish_after_save(
        &state.api_client,
        &state.workspace,
        &save_response,
        manifest_root_digest.clone(),
        pointer_bytes.len() as u64,
        Some(all_blob_digests),
        move |save_response| {
            let state = blob_state.clone();
            let present_blobs = publish_present_blobs.clone();
            let cache_entry_id = save_response.cache_entry_id.clone();
            async move {
                crate::serve::cas_publish::upload_tracked_blobs(
                    &state.api_client,
                    &state.workspace,
                    &cache_entry_id,
                    &present_blobs,
                    &state.upload_sessions,
                    adaptive_blob_upload_concurrency_impl(present_blobs.len()),
                    OCI_TRANSFER_CALL_TIMEOUT,
                )
                .await
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
                    blob_count: Some(request_blob_count),
                    blob_total_size_bytes: Some(request_blob_total_size_bytes),
                    file_count: Some(confirm_file_count),
                    uncompressed_size: None,
                    compressed_size: None,
                    storage_mode: Some("cas".to_string()),
                    tag: Some(tag.clone()),
                    write_scope_tag: Some(write_scope_tag),
                };

                match state
                    .api_client
                    .confirm_with_retry(&state.workspace, &cache_entry_id, &confirm_request)
                    .await
                {
                    Ok(_) => {}
                    Err(error) => {
                        return Err(OciError::internal(format!("confirm failed: {error}")));
                    }
                }

                Ok(())
            }
        },
    )
    .await?;

    let cached = Arc::new(OciManifestCacheEntry {
        index_json: manifest_body,
        content_type: content_type.clone(),
        manifest_digest: manifest_digest.clone(),
        cache_entry_id: save_response.cache_entry_id.clone(),
        blobs: blob_descriptors.clone(),
        name: name.to_string(),
        inserted_at: Instant::now(),
    });
    state
        .oci_manifest_cache
        .insert(primary_tag.clone(), Arc::clone(&cached));
    state
        .oci_manifest_cache
        .insert(digest_tag(&manifest_digest), Arc::clone(&cached));

    let alias_tags = alias_tags_for_manifest(
        &primary_tag,
        &manifest_digest,
        Some(write_scope_tag.as_str()),
        configured_human_tags,
        additional_aliases,
    );
    for alias in alias_tags {
        if let Err(error) = bind_alias_tag(
            state,
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

    Ok(PersistManifestResult { manifest_digest })
}

fn request_cas_blob_summary(
    manifest_blob_count: u64,
    manifest_blob_total_size_bytes: u64,
    pointer_size_bytes: u64,
) -> (u64, u64) {
    let request_blob_count = manifest_blob_count.max(1);
    let request_blob_total_size_bytes = if manifest_blob_total_size_bytes == 0 {
        pointer_size_bytes.max(1)
    } else {
        manifest_blob_total_size_bytes
    };
    (request_blob_count, request_blob_total_size_bytes)
}

async fn persist_referrers_manifest(
    state: &AppState,
    name: &str,
    subject_digest: &str,
    manifest: &serde_json::Value,
    content_type: &str,
    manifest_digest: &str,
    manifest_size: u64,
) -> Result<(), OciError> {
    let mut descriptors = load_referrers_descriptors(state, name, subject_digest).await?;
    descriptors.retain(|descriptor| {
        descriptor.get("digest").and_then(|value| value.as_str()) != Some(manifest_digest)
    });
    descriptors.push(engine_build_referrers_descriptor(
        manifest,
        content_type,
        manifest_digest,
        manifest_size,
    )?);

    let referrers_reference = engine_referrers_reference_for_subject(subject_digest)?;
    let referrers_tag = scoped_save_tag(
        &state.tag_resolver,
        &state.registry_root_tag,
        name,
        &referrers_reference,
    )?;
    let referrers_write_scope_tag =
        scoped_write_scope_tag(&state.tag_resolver, name, &referrers_reference)?;
    let referrers_body = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX_CONTENT_TYPE,
        "manifests": descriptors,
    }))
    .map_err(|e| OciError::internal(format!("Failed to serialize referrers index: {e}")))?;

    let persisted = persist_manifest_entry(PersistManifestEntryInput {
        state,
        name,
        primary_tag: referrers_tag,
        write_scope_tag: referrers_write_scope_tag,
        manifest_body: referrers_body,
        content_type: OCI_IMAGE_INDEX_CONTENT_TYPE.to_string(),
        blob_descriptors: Vec::new(),
        present_blobs: Vec::new(),
        configured_human_tags: &[],
        additional_aliases: &[],
    })
    .await?;
    if persisted.manifest_digest.is_empty() {
        return Err(OciError::internal(
            "Missing persisted referrers manifest digest",
        ));
    }
    Ok(())
}

async fn load_referrers_descriptors(
    state: &AppState,
    name: &str,
    subject_digest: &str,
) -> Result<Vec<serde_json::Value>, OciError> {
    let reference = engine_referrers_reference_for_subject(subject_digest)?;
    let manifest_bytes = match resolve_manifest(state, name, &reference, false).await {
        Ok((manifest_bytes, _, _)) => manifest_bytes,
        Err(error) if error.status() == StatusCode::NOT_FOUND => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    engine_parse_referrers_descriptors(&manifest_bytes)
}

fn referrers_response(
    method: Method,
    manifests: Vec<serde_json::Value>,
    filters_applied: Option<&str>,
) -> Result<Response, OciError> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX_CONTENT_TYPE,
        "manifests": manifests,
    }))
    .map_err(|e| OciError::internal(format!("Failed to serialize referrers response: {e}")))?;
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "Content-Type", OCI_IMAGE_INDEX_CONTENT_TYPE)?;
    insert_header(
        &mut headers,
        "Docker-Distribution-API-Version",
        "registry/2.0",
    )?;
    insert_header(&mut headers, "Content-Length", &payload.len().to_string())?;
    if let Some(filters_applied) = filters_applied {
        insert_header(&mut headers, OCI_FILTERS_APPLIED_HEADER, filters_applied)?;
    }
    if method == Method::HEAD {
        return Ok((StatusCode::OK, headers, Body::empty()).into_response());
    }
    Ok((StatusCode::OK, headers, Body::from(payload)).into_response())
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

async fn expand_manifest_blob_descriptors_impl(
    state: &AppState,
    name: &str,
    manifest: &serde_json::Value,
) -> Result<Vec<BlobDescriptor>, OciError> {
    let mut blobs = engine_extract_blob_descriptors(manifest)?;
    let mut pending = engine_manifest_child_descriptors(manifest);
    let mut visited = HashSet::new();

    while let Some(child_manifest) = pending.pop() {
        if !visited.insert(child_manifest.digest.clone()) {
            continue;
        }

        let child_manifest_bytes = load_manifest_bytes_by_digest(
            state,
            name,
            &child_manifest.digest,
            Some(child_manifest.size_bytes),
        )
        .await?;
        let child_manifest: serde_json::Value = serde_json::from_slice(&child_manifest_bytes)
            .map_err(|e| {
                OciError::internal(format!(
                    "Invalid child manifest JSON for {}: {}",
                    child_manifest.digest, e
                ))
            })?;
        blobs.extend(engine_extract_blob_descriptors(&child_manifest)?);
        pending.extend(engine_manifest_child_descriptors(&child_manifest));
    }

    engine_dedupe_blob_descriptors(blobs)
}

async fn load_manifest_bytes_by_digest(
    state: &AppState,
    name: &str,
    digest: &str,
    expected_size: Option<u64>,
) -> Result<Vec<u8>, OciError> {
    let digest_lookup_tag = digest_tag(digest);
    let manifest_bytes = match lookup_oci_manifest_cache(state, &[digest_lookup_tag]) {
        Some(cached) => cached.index_json.clone(),
        None => {
            let staged_path = {
                let sessions = state.upload_sessions.read().await;
                sessions
                    .find_by_name_and_digest(name, digest)
                    .map(|session| session.temp_path.clone())
            };

            if let Some(temp_path) = staged_path {
                tokio::fs::read(&temp_path).await.map_err(|e| {
                    OciError::internal(format!(
                        "Failed to read staged child manifest {}: {}",
                        digest, e
                    ))
                })?
            } else {
                let (manifest_bytes, _content_type, resolved_digest) =
                    match resolve_manifest(state, name, digest, false).await {
                        Ok(result) => result,
                        Err(error) if error.status() == StatusCode::NOT_FOUND => {
                            return Err(OciError::blob_unknown_upload(vec![digest.to_string()]));
                        }
                        Err(error) => return Err(error),
                    };
                if resolved_digest != digest {
                    return Err(OciError::internal(format!(
                        "resolved child manifest digest mismatch for {}: got {}",
                        digest, resolved_digest
                    )));
                }
                manifest_bytes
            }
        }
    };

    let actual_digest = cas_oci::prefixed_sha256_digest(&manifest_bytes);
    if actual_digest != digest {
        return Err(OciError::internal(format!(
            "child manifest digest mismatch for {}: got {}",
            digest, actual_digest
        )));
    }

    if let Some(expected_size) = expected_size {
        let actual_size = manifest_bytes.len() as u64;
        if actual_size != expected_size {
            return Err(OciError::internal(format!(
                "child manifest size mismatch for {}: expected {} got {}",
                digest, expected_size, actual_size
            )));
        }
    }

    Ok(manifest_bytes)
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
        .filter(|child| cas_oci::descriptor_is_manifest_reference(child))
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

    let manifest_bytes =
        load_manifest_bytes_by_digest(state, name, &descriptor.digest, Some(descriptor.size_bytes))
            .await?;
    let actual_size = manifest_bytes.len() as u64;

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

async fn cleanup_present_blob_sessions(state: &AppState, present_blobs: &[PresentBlob]) {
    let mut sessions = state.upload_sessions.write().await;
    for blob in present_blobs {
        if let Some(session_id) = blob.upload_session_id.as_deref()
            && let Some(removed) = sessions.remove(session_id)
        {
            let _ = tokio::fs::remove_file(&removed.temp_path).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::request_cas_blob_summary;

    #[test]
    fn request_cas_blob_summary_preserves_non_zero_values() {
        let (blob_count, blob_total_size_bytes) = request_cas_blob_summary(3, 456, 789);
        assert_eq!(blob_count, 3);
        assert_eq!(blob_total_size_bytes, 456);
    }

    #[test]
    fn request_cas_blob_summary_minimum_blob_count_is_one() {
        let (blob_count, blob_total_size_bytes) = request_cas_blob_summary(0, 456, 789);
        assert_eq!(blob_count, 1);
        assert_eq!(blob_total_size_bytes, 456);
    }

    #[test]
    fn request_cas_blob_summary_minimum_blob_size_uses_pointer_size() {
        let (blob_count, blob_total_size_bytes) = request_cas_blob_summary(0, 0, 789);
        assert_eq!(blob_count, 1);
        assert_eq!(blob_total_size_bytes, 789);
    }
}
