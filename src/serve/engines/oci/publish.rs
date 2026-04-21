use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::time::{Duration, Instant};

use crate::api::models::cache::{BlobDescriptor, ConfirmRequest, SaveRequest};
use crate::cas_oci;
use crate::cas_transport::upload_payload;
use crate::serve::engines::oci::PresentBlob;
use crate::serve::engines::oci::manifest_cache::OciManifestCacheEntry;
use crate::serve::http::error::OciError;
use crate::serve::http::oci_tags::{
    AliasBinding, AliasTagManifest, alias_tags_for_manifest, bind_alias_tag,
};
use crate::serve::state::{AppState, digest_tag};

const OCI_API_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const OCI_TRANSFER_CALL_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) struct PersistManifestResult {
    pub(crate) manifest_digest: String,
}

pub(crate) struct PersistManifestEntryInput<'a> {
    pub(crate) state: &'a AppState,
    pub(crate) name: &'a str,
    pub(crate) primary_tag: String,
    pub(crate) write_scope_tag: String,
    pub(crate) manifest_body: Vec<u8>,
    pub(crate) content_type: String,
    pub(crate) blob_descriptors: Vec<BlobDescriptor>,
    pub(crate) present_blobs: Vec<PresentBlob>,
    pub(crate) configured_human_tags: &'a [String],
    pub(crate) additional_aliases: &'a [AliasBinding],
}

pub(crate) async fn persist_manifest_entry(
    input: PersistManifestEntryInput<'_>,
) -> Result<PersistManifestResult, OciError> {
    let state = input.state;
    let started_at = Instant::now();
    let result = persist_manifest_entry_inner(input).await;
    state
        .oci_engine_diagnostics
        .record_publish_phase("total", started_at.elapsed().as_millis() as u64);
    result
}

async fn persist_manifest_entry_inner(
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

    let save_started_at = Instant::now();
    let save_result = tokio::time::timeout(
        OCI_API_CALL_TIMEOUT,
        state.api_client.save_entry(&state.workspace, &save_request),
    )
    .await;
    state
        .oci_engine_diagnostics
        .record_publish_phase("save", save_started_at.elapsed().as_millis() as u64);
    let save_response = match save_result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => return Err(OciError::internal(format!("save_entry failed: {error}"))),
        Err(_) => {
            return Err(OciError::internal(format!(
                "save_entry timed out after {}s",
                OCI_API_CALL_TIMEOUT.as_secs()
            )));
        }
    };

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
    crate::serve::cas_publish::publish_after_save_requiring_receipts(
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
                let started_at = Instant::now();
                let result = crate::serve::cas_publish::upload_tracked_blobs(
                    &state.api_client,
                    &state.workspace,
                    &cache_entry_id,
                    &present_blobs,
                    &state.upload_sessions,
                    adaptive_blob_upload_concurrency(present_blobs.len()),
                    OCI_TRANSFER_CALL_TIMEOUT,
                )
                .await;
                state
                    .oci_engine_diagnostics
                    .record_publish_phase("blobs", started_at.elapsed().as_millis() as u64);
                result
            }
        },
        move |save_response| {
            let state = manifest_state.clone();
            let pointer_bytes = publish_pointer_bytes.clone();
            let manifest_upload_url = save_response.manifest_upload_url.clone();
            let upload_headers = save_response.upload_headers.clone();
            async move {
                let started_at = Instant::now();
                let result = async {
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
                .await;
                state
                    .oci_engine_diagnostics
                    .record_publish_phase("pointer", started_at.elapsed().as_millis() as u64);
                result
            }
        },
        move |_manifest_etag| {
            let state = confirm_state.clone();
            let tag = confirm_tag.clone();
            let write_scope_tag = confirm_write_scope_tag.clone();
            let cache_entry_id = confirm_cache_entry_id.clone();
            let manifest_digest = confirm_manifest_digest.clone();
            async move {
                let started_at = Instant::now();
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

                let result = match state
                    .api_client
                    .confirm_with_retry(&state.workspace, &cache_entry_id, &confirm_request)
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(error) => Err(OciError::internal(format!("confirm failed: {error}"))),
                };
                state
                    .oci_engine_diagnostics
                    .record_publish_phase("confirm", started_at.elapsed().as_millis() as u64);
                result
            }
        },
        |message| OciError::internal(format!("receipt commit failed: {message}")),
    )
    .await?;

    let cached = std::sync::Arc::new(OciManifestCacheEntry {
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
        .insert(primary_tag.clone(), std::sync::Arc::clone(&cached));
    state
        .oci_manifest_cache
        .insert(digest_tag(&manifest_digest), std::sync::Arc::clone(&cached));

    let alias_started_at = Instant::now();
    let alias_result = async {
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
        Ok(())
    }
    .await;
    state
        .oci_engine_diagnostics
        .record_publish_phase("alias", alias_started_at.elapsed().as_millis() as u64);
    alias_result?;

    Ok(PersistManifestResult { manifest_digest })
}

pub(crate) fn request_cas_blob_summary(
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

pub(crate) fn adaptive_blob_upload_concurrency(operation_count: usize) -> usize {
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

pub(crate) async fn cleanup_present_blob_sessions(state: &AppState, present_blobs: &[PresentBlob]) {
    let mut owned_bodies = Vec::new();
    let mut sessions = state.upload_sessions.write().await;
    for blob in present_blobs {
        if let Some(session_id) = blob.upload_session_id.as_deref()
            && let Some(removed) = sessions.remove(session_id)
            && removed.owns_temp_file()
        {
            owned_bodies.push((
                blob.digest.clone(),
                removed.temp_path.clone(),
                removed.body_size(),
            ));
        }
    }
    drop(sessions);

    for (digest, path, size_bytes) in owned_bodies {
        let promote_started_at = Instant::now();
        match state
            .blob_read_cache
            .promote(&digest, &path, size_bytes)
            .await
        {
            Ok(_) => {
                state
                    .oci_engine_diagnostics
                    .record_cache_promotion(promote_started_at.elapsed().as_millis() as u64, true);
                let _ = tokio::fs::remove_file(&path).await;
            }
            Err(error) => {
                state
                    .oci_engine_diagnostics
                    .record_cache_promotion(promote_started_at.elapsed().as_millis() as u64, false);
                log::warn!("OCI published blob cache promote failed for {digest}: {error}");
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
    }
}
