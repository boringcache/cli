use std::collections::HashMap;

use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci;
use crate::serve::http::error::OciError;

pub(crate) const OCI_IMAGE_INDEX_CONTENT_TYPE: &str = "application/vnd.oci.image.index.v1+json";

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
