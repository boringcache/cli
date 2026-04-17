use anyhow::{Context, Result};
use std::time::Duration;

use crate::api::ApiClient;
use crate::api::models::cache::CompleteMultipartRequest;
use crate::manifest::ManifestFile;
use crate::multipart_upload::{upload_via_part_urls, upload_via_single_url};
use crate::progress::{ProgressSession, Summary, TransferProgress};
use crate::telemetry::StorageMetrics;
use crate::ui;

pub(crate) fn complete_skipped_step(
    session: &mut ProgressSession,
    title: &str,
    detail: &str,
) -> Result<()> {
    let step = session.start_step(title.to_string(), Some(detail.to_string()))?;
    step.complete()?;
    Ok(())
}

pub(crate) fn save_summary(
    size_bytes: u64,
    file_count: u32,
    digest: String,
    path: String,
) -> Summary {
    Summary {
        size_bytes,
        file_count,
        digest: Some(digest),
        path: Some(path),
    }
}

pub(crate) fn progress_info(reporter: &crate::progress::Reporter, message: impl Into<String>) {
    let message = message.into();
    if reporter.info(message.clone()).is_err() {
        ui::info(&message);
    }
}

pub(crate) fn progress_warning(reporter: &crate::progress::Reporter, message: impl Into<String>) {
    let message = message.into();
    if reporter.warning(message.clone()).is_err() {
        ui::warn(&message);
    }
}

pub(crate) fn conflict_message_from_error(err: &anyhow::Error) -> Option<String> {
    err.downcast_ref::<crate::error::BoringCacheError>()
        .and_then(|bc_err| bc_err.conflict_message().map(|message| message.to_string()))
}

pub(crate) fn is_cache_pending_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<crate::error::BoringCacheError>()
        .is_some_and(|bc_err| matches!(bc_err, crate::error::BoringCacheError::CachePending))
}

pub(crate) fn manifest_files_from_draft(
    draft: &crate::manifest::ManifestDraft,
) -> Vec<ManifestFile> {
    draft
        .descriptors
        .iter()
        .map(|desc| ManifestFile {
            path: desc.path.clone(),
            entry_type: desc.entry_type,
            size: desc.size,
            executable: desc.executable,
            hash: desc.hash.clone(),
            target: desc.target.clone(),
            state: crate::manifest::EntryState::Present,
        })
        .collect()
}

pub(crate) fn build_manifest_bytes(
    tag: &str,
    manifest_root_digest: &str,
    manifest_files: &[ManifestFile],
    archive_content_hash: &str,
    encrypt: bool,
    recipient_str: Option<&str>,
    age_recipient: Option<&age::x25519::Recipient>,
) -> Result<(Vec<u8>, String, u64)> {
    let encryption_metadata = if encrypt {
        Some(crate::manifest::EncryptionMetadata {
            algorithm: crate::encryption::ENCRYPTION_ALGORITHM_AGE_X25519.to_string(),
            recipient_hint: recipient_str.map(crate::encryption::recipient_hint),
            encrypted_at: chrono::Utc::now(),
        })
    } else {
        None
    };
    let signature_metadata: Option<crate::manifest::SignatureMetadata> = None;

    let manifest_cbor = serialize_manifest(
        tag,
        manifest_root_digest,
        manifest_files,
        archive_content_hash,
        encryption_metadata,
        signature_metadata,
    )?;
    let mut manifest_bytes = crate::manifest::io::compress_manifest(&manifest_cbor)?;
    if let Some(recipient) = age_recipient {
        manifest_bytes = crate::encryption::encrypt_data(&manifest_bytes, recipient)?;
    }
    log::debug!(
        "Manifest compressed: {} -> {} bytes ({:.1}%)",
        manifest_cbor.len(),
        manifest_bytes.len(),
        (manifest_bytes.len() as f64 / manifest_cbor.len() as f64) * 100.0
    );
    let expected_manifest_digest = crate::manifest::io::compute_manifest_digest(&manifest_bytes);
    let expected_manifest_size = manifest_bytes.len() as u64;

    Ok((
        manifest_bytes,
        expected_manifest_digest,
        expected_manifest_size,
    ))
}

pub(crate) async fn upload_manifest(
    client: &reqwest::Client,
    url: &str,
    data: &[u8],
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<Option<String>> {
    upload_payload(client, url, data, "application/cbor", upload_headers).await
}

async fn upload_payload(
    client: &reqwest::Client,
    url: &str,
    data: &[u8],
    content_type: &str,
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<Option<String>> {
    let etag =
        crate::cas_transport::upload_payload(client, url, data, content_type, upload_headers)
            .await?;

    if etag.is_some() {
        log::debug!("Manifest uploaded with ETag: {:?}", etag);
    } else {
        log::warn!("Manifest upload response missing ETag header");
    }

    Ok(etag)
}

pub(crate) fn serialize_manifest(
    tag: &str,
    root_digest: &str,
    files: &[ManifestFile],
    archive_content_hash: &str,
    encryption: Option<crate::manifest::EncryptionMetadata>,
    signature: Option<crate::manifest::SignatureMetadata>,
) -> Result<Vec<u8>> {
    let manifest = crate::manifest::Manifest {
        format_version: 1,
        tag: tag.to_string(),
        root: crate::manifest::ManifestRoot {
            digest: root_digest.to_string(),
            algo: "sha256".to_string(),
        },
        summary: crate::manifest::ManifestSummary {
            file_count: files.len() as u64,
            raw_size: files.iter().map(|f| f.size).sum(),
            changed_count: files.len() as u64,
            removed_count: 0,
        },
        entry: None,
        archive: Some(crate::manifest::ManifestArchive {
            content_hash: Some(archive_content_hash.to_string()),
            compression: "zstd".to_string(),
            created_at: chrono::Utc::now(),
        }),
        files: files.to_vec(),
        encryption,
        signature,
    };

    let mut buffer = Vec::new();
    ciborium::into_writer(&manifest, &mut buffer).context("Failed to serialize manifest")?;
    Ok(buffer)
}

pub(crate) async fn upload_archive_file(
    archive_path: &std::path::Path,
    upload_url: &str,
    progress: &TransferProgress,
    transfer_client: &reqwest::Client,
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<(Option<String>, StorageMetrics)> {
    log::debug!(
        "Starting archive upload: path={} url={}",
        archive_path.display(),
        upload_url
    );

    upload_via_single_url(
        archive_path,
        upload_url,
        progress,
        transfer_client,
        upload_headers,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_archive_multipart(
    archive_path: &std::path::Path,
    part_urls: &[String],
    upload_id: &str,
    progress: &TransferProgress,
    transfer_client: &reqwest::Client,
    api_client: &ApiClient,
    workspace: &str,
    cache_entry_id: &str,
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<(Option<String>, StorageMetrics)> {
    log::info!(
        "Starting multipart archive upload: path={} parts={} upload_id={}",
        archive_path.display(),
        part_urls.len(),
        upload_id
    );

    let (uploaded_parts, storage_metrics) = upload_via_part_urls(
        archive_path,
        part_urls,
        progress,
        transfer_client,
        upload_headers,
    )
    .await?;

    let response = api_client
        .complete_multipart(
            workspace,
            cache_entry_id,
            &CompleteMultipartRequest {
                upload_id: upload_id.to_string(),
                parts: uploaded_parts,
            },
        )
        .await
        .context("Failed to finalize multipart upload")?;

    Ok((Some(response.archive_etag), storage_metrics))
}

pub(crate) fn format_phase_duration(duration: Duration) -> String {
    if duration.as_millis() >= 1_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

pub(crate) fn format_phase_duration_ms(ms: u64) -> String {
    if ms >= 1_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}ms", ms)
    }
}
