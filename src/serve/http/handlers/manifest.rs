use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

#[cfg(test)]
use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci;
use crate::serve::engines::oci::manifests::{
    ManifestBlobUrlPolicy, OCI_IMAGE_INDEX_CONTENT_TYPE,
    expand_manifest_blob_descriptors as engine_expand_manifest_blob_descriptors,
    extract_subject_digest as engine_extract_subject_digest,
    load_referrers_descriptors as engine_load_referrers_descriptors,
    persist_referrers_manifest as engine_persist_referrers_manifest,
    resolve_manifest as engine_resolve_manifest,
    resolve_pushed_manifest_content_type as engine_resolve_pushed_manifest_content_type,
    stage_manifest_reference_uploads as engine_stage_manifest_reference_uploads,
};
#[cfg(test)]
use crate::serve::engines::oci::manifests::{
    detect_manifest_content_type as engine_detect_manifest_content_type,
    extract_blob_descriptors as engine_extract_blob_descriptors,
};
use crate::serve::engines::oci::publish::{
    PersistManifestEntryInput, cleanup_present_blob_sessions, persist_manifest_entry,
};
use crate::serve::engines::oci::{PresentBlob, ensure_manifest_blobs_present};
use crate::serve::http::error::OciError;
use crate::serve::http::oci_route::{insert_digest_etag, insert_header};
use crate::serve::http::oci_tags::{AliasBinding, scoped_save_tag, scoped_write_scope_tag};
use crate::serve::state::{AppState, diagnostics_enabled, digest_tag};

use super::OCI_DEGRADED_HEADER;

const OCI_SUBJECT_HEADER: &str = "OCI-Subject";
const OCI_FILTERS_APPLIED_HEADER: &str = "OCI-Filters-Applied";

pub(super) async fn get_manifest(
    method: Method,
    state: AppState,
    name: String,
    reference: String,
) -> Result<Response, OciError> {
    let blob_url_policy = if method == Method::GET {
        ManifestBlobUrlPolicy::VerifyAndCache
    } else {
        ManifestBlobUrlPolicy::VerifyOnly
    };
    let (manifest_bytes, content_type, digest) =
        engine_resolve_manifest(&state, &name, &reference, blob_url_policy).await?;

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
    let mut manifests = engine_load_referrers_descriptors(&state, &name, &digest).await?;
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

    let blob_descriptors = engine_expand_manifest_blob_descriptors(&state, &name, &parsed).await?;
    engine_stage_manifest_reference_uploads(&state, &name, &blob_descriptors, &parsed).await?;
    let present_blobs = ensure_manifest_blobs_present(&state, &name, &blob_descriptors).await?;
    log_manifest_blob_sources(&name, &reference, &present_blobs);
    for blob in &present_blobs {
        state
            .oci_engine_diagnostics
            .record_proof_source(blob.source.as_str(), blob.size_bytes);
    }

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
            let referrers_started_at = Instant::now();
            engine_persist_referrers_manifest(
                &state,
                &name,
                subject_digest,
                &parsed,
                &content_type,
                &manifest_digest,
                manifest_body.len() as u64,
            )
            .await?;
            state.oci_engine_diagnostics.record_publish_phase(
                "referrers",
                referrers_started_at.elapsed().as_millis() as u64,
            );
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
    crate::serve::engines::oci::publish::adaptive_blob_upload_concurrency(operation_count)
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
    engine_expand_manifest_blob_descriptors(state, name, manifest).await
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
    engine_stage_manifest_reference_uploads(state, name, blob_descriptors, manifest).await
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

#[cfg(test)]
fn request_cas_blob_summary(
    manifest_blob_count: u64,
    manifest_blob_total_size_bytes: u64,
    pointer_size_bytes: u64,
) -> (u64, u64) {
    crate::serve::engines::oci::publish::request_cas_blob_summary(
        manifest_blob_count,
        manifest_blob_total_size_bytes,
        pointer_size_bytes,
    )
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
