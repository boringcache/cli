use axum::http::StatusCode;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci;
use crate::serve::engines::oci::blobs::{self, BlobPrefetchStats};
use crate::serve::engines::oci::publish::{PersistManifestEntryInput, persist_manifest_entry};
use crate::serve::engines::oci::uploads::has_non_empty_local_blob;
use crate::serve::http::error::OciError;
use crate::serve::http::flight::{Flight, await_flight, begin_flight, clear_flight_entry};
use crate::serve::http::oci_tags::{scoped_restore_tags, scoped_save_tag, scoped_write_scope_tag};
use crate::serve::state::{
    AppState, BlobLocatorEntry, OCI_MANIFEST_CACHE_TTL, OciManifestCacheEntry, UploadSession,
    digest_tag,
};

const OCI_API_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const OCI_POINTER_FETCH_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) const OCI_IMAGE_INDEX_CONTENT_TYPE: &str = "application/vnd.oci.image.index.v1+json";

#[derive(Clone, Copy)]
pub(crate) enum ManifestBlobUrlPolicy {
    VerifyAndCache,
    VerifyOnly,
}

pub(crate) async fn resolve_manifest(
    state: &AppState,
    name: &str,
    reference: &str,
    blob_url_policy: ManifestBlobUrlPolicy,
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
                return resolve_manifest_remote(state, name, reference, &tags, blob_url_policy)
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

pub(crate) async fn prefetch_manifest_reference(
    state: &AppState,
    name: &str,
    reference: &str,
    hydrate_bodies: bool,
) -> Result<(BlobPrefetchStats, usize), OciError> {
    let started_at = Instant::now();
    let tags = manifest_restore_tags(state, name, reference);
    let (_, _, digest) = resolve_manifest(
        state,
        name,
        reference,
        ManifestBlobUrlPolicy::VerifyAndCache,
    )
    .await?;
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
        let resolved_urls = verified_manifest_blob_download_urls(
            state,
            &cached.cache_entry_id,
            &cached.name,
            reference,
            &cached.blobs,
        )
        .await?;
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
            BlobPrefetchStats {
                total_unique_blobs: cached.blobs.len(),
                already_local: local_blobs,
                duration_ms: started_at.elapsed().as_millis() as u64,
                ..BlobPrefetchStats::default()
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
    let stats = blobs::prefetch_blob_bodies(
        state,
        &cached.name,
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

pub(crate) async fn expand_manifest_blob_descriptors(
    state: &AppState,
    name: &str,
    manifest: &serde_json::Value,
) -> Result<Vec<BlobDescriptor>, OciError> {
    let mut blobs = extract_blob_descriptors(manifest)?;
    let mut pending = manifest_child_descriptors(manifest);
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
        blobs.extend(extract_blob_descriptors(&child_manifest)?);
        pending.extend(manifest_child_descriptors(&child_manifest));
    }

    let expanded_child_count = visited.len();
    let deduped = dedupe_blob_descriptors(blobs)?;
    state
        .oci_engine_diagnostics
        .record_graph_expansion(expanded_child_count, deduped.len());
    Ok(deduped)
}

pub(crate) async fn stage_manifest_reference_uploads(
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

pub(crate) async fn persist_referrers_manifest(
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
    descriptors.push(build_referrers_descriptor(
        manifest,
        content_type,
        manifest_digest,
        manifest_size,
    )?);

    let referrers_reference = referrers_reference_for_subject(subject_digest)?;
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

pub(crate) async fn load_referrers_descriptors(
    state: &AppState,
    name: &str,
    subject_digest: &str,
) -> Result<Vec<serde_json::Value>, OciError> {
    let reference = referrers_reference_for_subject(subject_digest)?;
    let manifest_bytes =
        match resolve_manifest(state, name, &reference, ManifestBlobUrlPolicy::VerifyOnly).await {
            Ok((manifest_bytes, _, _)) => manifest_bytes,
            Err(error) if error.status() == StatusCode::NOT_FOUND => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
    parse_referrers_descriptors(&manifest_bytes)
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
    blob_url_policy: ManifestBlobUrlPolicy,
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
    let entry = selected.ok_or_else(|| {
        state.oci_engine_diagnostics.record_miss("manifest");
        OciError::manifest_unknown(format!("{name}:{reference}"))
    })?;

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

    let prefetched_urls = match blob_url_policy {
        ManifestBlobUrlPolicy::VerifyAndCache => {
            verified_manifest_blob_download_urls(
                state,
                cache_entry_id,
                name,
                reference,
                &blob_descriptors,
            )
            .await?
        }
        ManifestBlobUrlPolicy::VerifyOnly => {
            verified_manifest_blob_download_urls(
                state,
                cache_entry_id,
                name,
                reference,
                &blob_descriptors,
            )
            .await?;
            HashMap::new()
        }
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
        .unwrap_or_else(|| detect_manifest_content_type(&index_json));
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
        detect_manifest_content_type(&cached.index_json)
    } else {
        cached.content_type.clone()
    };
    Ok((
        cached.index_json.clone(),
        content_type,
        cached.manifest_digest.clone(),
    ))
}

async fn verified_manifest_blob_download_urls(
    state: &AppState,
    cache_entry_id: &str,
    name: &str,
    reference: &str,
    blob_descriptors: &[BlobDescriptor],
) -> Result<HashMap<String, String>, OciError> {
    if blob_descriptors.is_empty() {
        return Ok(HashMap::new());
    }

    let resolved = crate::serve::blob_download_urls::resolve_verified_blob_download_urls(
        state,
        cache_entry_id,
        blob_descriptors,
        OCI_API_CALL_TIMEOUT,
    )
    .await
    .map_err(|error| {
        OciError::internal(format!(
            "OCI manifest blob verification failed for {name}:{reference}: {error}"
        ))
    })?;

    if !resolved.missing.is_empty() {
        state.oci_engine_diagnostics.record_miss("download-url");
        log::warn!(
            "OCI manifest {}:{} references {} missing blob(s): {}",
            name,
            reference,
            resolved.missing.len(),
            missing_blob_sample(&resolved.missing)
        );
        return Err(OciError::manifest_unknown(format!(
            "{name}:{reference} references missing blob(s)"
        )));
    }

    Ok(resolved.urls)
}

fn missing_blob_sample(missing: &[String]) -> String {
    let mut sample = missing.iter().take(3).cloned().collect::<Vec<_>>();
    if missing.len() > sample.len() {
        sample.push("...".to_string());
    }
    sample.join(", ")
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
        Some(Instant::now())
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

fn manifest_flight_key(tags: &[String]) -> String {
    let mut sorted = tags.to_vec();
    sorted.sort();
    let digest = crate::cas_file::sha256_hex(sorted.join("\0").as_bytes());
    format!("manifest:{digest}")
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
                    match resolve_manifest(state, name, digest, ManifestBlobUrlPolicy::VerifyOnly)
                        .await
                    {
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

pub(crate) fn detect_manifest_content_type(json_bytes: &[u8]) -> String {
    if let Some(media_type) = cas_oci::manifest_content_type_from_json_bytes(json_bytes) {
        return media_type;
    }
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(json_bytes)
        && val.get("manifests").is_some()
    {
        return OCI_IMAGE_INDEX_CONTENT_TYPE.to_string();
    }
    "application/vnd.oci.image.manifest.v1+json".to_string()
}

pub(crate) fn resolve_pushed_manifest_content_type(
    header_content_type: Option<&str>,
    manifest: &serde_json::Value,
) -> Result<String, OciError> {
    let header_content_type = header_content_type.and_then(normalize_manifest_content_type);
    let declared_media_type = cas_oci::manifest_declared_media_type(manifest);

    if let (Some(header_content_type), Some(declared_media_type)) =
        (header_content_type.as_deref(), declared_media_type)
        && !header_content_type.eq_ignore_ascii_case(declared_media_type)
    {
        return Err(OciError::manifest_invalid(format!(
            "Manifest Content-Type {header_content_type} does not match declared mediaType {declared_media_type}"
        )));
    }

    if let Some(header_content_type) = header_content_type {
        return Ok(header_content_type);
    }
    if let Some(declared_media_type) = declared_media_type {
        return Ok(declared_media_type.to_string());
    }
    let manifest_bytes = serde_json::to_vec(manifest)
        .map_err(|e| OciError::internal(format!("Failed to serialize manifest JSON: {e}")))?;
    Ok(detect_manifest_content_type(&manifest_bytes))
}

fn normalize_manifest_content_type(value: &str) -> Option<String> {
    let media_type = value.split(';').next()?.trim();
    if media_type.is_empty() {
        return None;
    }
    Some(media_type.to_string())
}

pub(crate) fn extract_subject_digest(
    manifest: &serde_json::Value,
) -> Result<Option<String>, OciError> {
    let Some(subject) = manifest.get("subject") else {
        return Ok(None);
    };
    let subject = subject
        .as_object()
        .ok_or_else(|| OciError::manifest_invalid("subject descriptor must be an object"))?;
    let digest = subject
        .get("digest")
        .and_then(|value| value.as_str())
        .ok_or_else(|| OciError::manifest_invalid("subject descriptor missing digest"))?;
    if !cas_oci::is_valid_sha256_digest(digest) {
        return Err(OciError::digest_invalid(format!(
            "unsupported subject digest format: {digest}"
        )));
    }
    Ok(Some(digest.to_string()))
}

pub(crate) fn referrers_reference_for_subject(subject_digest: &str) -> Result<String, OciError> {
    let (algorithm, hex) = subject_digest.split_once(':').ok_or_else(|| {
        OciError::digest_invalid(format!("invalid subject digest {subject_digest}"))
    })?;
    if !cas_oci::is_valid_sha256_digest(subject_digest) {
        return Err(OciError::digest_invalid(format!(
            "unsupported subject digest format: {subject_digest}"
        )));
    }
    Ok(format!("{algorithm}-{hex}"))
}

pub(crate) fn parse_referrers_descriptors(
    manifest_bytes: &[u8],
) -> Result<Vec<serde_json::Value>, OciError> {
    let manifest: serde_json::Value = serde_json::from_slice(manifest_bytes)
        .map_err(|e| OciError::internal(format!("Invalid referrers index JSON: {e}")))?;
    let manifests = manifest
        .get("manifests")
        .and_then(|value| value.as_array())
        .ok_or_else(|| OciError::internal("Referrers index missing manifests array"))?;
    Ok(manifests.clone())
}

pub(crate) fn build_referrers_descriptor(
    manifest: &serde_json::Value,
    content_type: &str,
    manifest_digest: &str,
    manifest_size: u64,
) -> Result<serde_json::Value, OciError> {
    let mut descriptor = serde_json::Map::new();
    descriptor.insert(
        "mediaType".to_string(),
        serde_json::Value::String(content_type.to_string()),
    );
    descriptor.insert(
        "digest".to_string(),
        serde_json::Value::String(manifest_digest.to_string()),
    );
    descriptor.insert(
        "size".to_string(),
        serde_json::Value::Number(serde_json::Number::from(manifest_size)),
    );
    if let Some(artifact_type) = manifest_artifact_type(manifest) {
        descriptor.insert(
            "artifactType".to_string(),
            serde_json::Value::String(artifact_type),
        );
    }
    if let Some(annotations) = manifest_annotations(manifest) {
        descriptor.insert(
            "annotations".to_string(),
            serde_json::Value::Object(annotations),
        );
    }
    Ok(serde_json::Value::Object(descriptor))
}

fn manifest_artifact_type(manifest: &serde_json::Value) -> Option<String> {
    manifest
        .get("artifactType")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            manifest
                .get("config")
                .and_then(|value| value.get("mediaType"))
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn manifest_annotations(
    manifest: &serde_json::Value,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    manifest
        .get("annotations")
        .and_then(|value| value.as_object())
        .cloned()
}

pub(crate) fn extract_blob_descriptors(
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

    if let Some(extra_blobs) = manifest.get("blobs").and_then(|value| value.as_array()) {
        for blob in extra_blobs {
            if let (Some(digest), Some(size)) = (
                blob.get("digest").and_then(|value| value.as_str()),
                blob.get("size").and_then(|value| value.as_u64()),
            ) {
                if !cas_oci::is_valid_sha256_digest(digest) {
                    return Err(OciError::digest_invalid(format!(
                        "unsupported blob digest format: {digest}"
                    )));
                }
                blobs.push(BlobDescriptor {
                    digest: digest.to_string(),
                    size_bytes: size,
                });
            }
        }
    }

    dedupe_blob_descriptors(blobs)
}

pub(crate) fn dedupe_blob_descriptors(
    blobs: Vec<BlobDescriptor>,
) -> Result<Vec<BlobDescriptor>, OciError> {
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

pub(crate) fn manifest_child_descriptors(manifest: &serde_json::Value) -> Vec<BlobDescriptor> {
    manifest
        .get("manifests")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter(|child| cas_oci::descriptor_is_manifest_reference(child))
        .filter_map(|child| {
            let digest = child.get("digest").and_then(|value| value.as_str())?;
            let size_bytes = child.get("size").and_then(|value| value.as_u64())?;
            Some(BlobDescriptor {
                digest: digest.to_string(),
                size_bytes,
            })
        })
        .collect()
}
