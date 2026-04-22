use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::api::ApiClient;
use crate::api::models::cache::{CompleteMultipartRequest, SaveRequest};
use crate::ci_detection::{CiRunContext, CiSourceRefType, detect_ci_context};
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

pub(crate) fn apply_detected_ci_context(request: &mut SaveRequest) {
    let context = detect_ci_context();
    request.ci_provider = Some(context.label());

    let Some(run_context) = context.run_context() else {
        return;
    };

    apply_ci_run_context(request, run_context);
}

fn apply_ci_run_context(request: &mut SaveRequest, run_context: &CiRunContext) {
    request.ci_provider = Some(run_context.provider.clone());
    request.ci_run_uid = Some(run_context.run_uid.clone());
    request.ci_run_attempt = run_context.run_attempt.clone();
    request.ci_ref_type = Some(ci_source_ref_type_name(run_context.source_ref_type).to_string());
    request.ci_ref_name = run_context.source_ref_name.clone();
    request.ci_default_branch = run_context.default_branch.clone();
    request.ci_pr_number = run_context.pull_request_number;
    request.ci_commit_sha = run_context.commit_sha.clone();
    request.ci_run_started_at = run_context.run_started_at.clone();
}

fn ci_source_ref_type_name(ref_type: CiSourceRefType) -> &'static str {
    match ref_type {
        CiSourceRefType::Branch => "branch",
        CiSourceRefType::Tag => "tag",
        CiSourceRefType::PullRequest => "pull-request",
        CiSourceRefType::Other => "other",
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

pub(crate) fn archive_cache_root_digest(
    content_root_digest: &str,
    recipient: Option<&str>,
) -> String {
    let Some(recipient) = recipient.filter(|value| !value.is_empty()) else {
        return content_root_digest.to_string();
    };

    // Archive object keys are rooted by this digest; encryption must include
    // the recipient so identical plaintext under different Age keys cannot alias.
    let mut hasher = Sha256::new();
    hasher.update(content_root_digest.as_bytes());
    hasher.update([0]);
    hasher.update(crate::encryption::ENCRYPTION_ALGORITHM_AGE_X25519.as_bytes());
    hasher.update([0]);
    hasher.update(recipient.as_bytes());

    let hex = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;

    const CI_ENV_KEYS: &[&str] = &[
        "CI",
        "GITHUB_ACTIONS",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_REF_NAME",
        "GITHUB_REF_TYPE",
        "GITHUB_HEAD_REF",
        "GITHUB_BASE_REF",
        "GITHUB_DEFAULT_BRANCH",
        "GITHUB_SHA",
        "GITHUB_EVENT_PATH",
        "BORINGCACHE_CI_PROVIDER",
        "BORINGCACHE_CI_RUN_ID",
        "BORINGCACHE_CI_RUN_ATTEMPT",
        "BORINGCACHE_CI_REPOSITORY",
        "BORINGCACHE_CI_REF",
        "BORINGCACHE_CI_REF_NAME",
        "BORINGCACHE_CI_REF_TYPE",
        "BORINGCACHE_CI_HEAD_REF",
        "BORINGCACHE_CI_BASE_REF",
        "BORINGCACHE_CI_DEFAULT_BRANCH",
        "BORINGCACHE_CI_PR_NUMBER",
        "BORINGCACHE_CI_SHA",
        "BORINGCACHE_CI_RUN_STARTED_AT",
    ];

    fn clear_ci_env() {
        for key in CI_ENV_KEYS {
            test_env::remove_var(key);
        }
    }

    fn base_save_request() -> SaveRequest {
        SaveRequest {
            tag: "example".to_string(),
            write_scope_tag: None,
            manifest_root_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            compression_algorithm: "zstd".to_string(),
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            manifest_format_version: Some(1),
            total_size_bytes: 1,
            uncompressed_size: Some(1),
            compressed_size: Some(1),
            file_count: Some(1),
            expected_manifest_digest: Some(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            ),
            expected_manifest_size: Some(1),
            force: None,
            use_multipart: Some(false),
            ci_provider: None,
            ci_run_uid: None,
            ci_run_attempt: None,
            ci_ref_type: None,
            ci_ref_name: None,
            ci_default_branch: None,
            ci_pr_number: None,
            ci_commit_sha: None,
            ci_run_started_at: None,
            encrypted: None,
            encryption_algorithm: None,
            encryption_recipient_hint: None,
        }
    }

    #[test]
    fn detected_ci_context_keeps_local_saves_out_of_run_ordering() {
        let _guard = test_env::lock();
        clear_ci_env();

        let mut request = base_save_request();
        apply_detected_ci_context(&mut request);

        assert_eq!(request.ci_provider.as_deref(), Some("local"));
        assert_eq!(request.ci_run_uid, None);
        assert_eq!(request.ci_run_started_at, None);

        clear_ci_env();
    }

    #[test]
    fn detected_ci_context_does_not_invent_ordering_for_generic_ci() {
        let _guard = test_env::lock();
        clear_ci_env();
        test_env::set_var("CI", "true");

        let mut request = base_save_request();
        apply_detected_ci_context(&mut request);

        assert_eq!(request.ci_provider.as_deref(), Some("generic-ci"));
        assert_eq!(request.ci_run_uid, None);
        assert_eq!(request.ci_run_started_at, None);

        clear_ci_env();
    }

    #[test]
    fn detected_ci_context_applies_provider_neutral_run_fields() {
        let _guard = test_env::lock();
        clear_ci_env();
        test_env::set_var("BORINGCACHE_CI_PROVIDER", "gitlab");
        test_env::set_var("BORINGCACHE_CI_RUN_ID", "pipeline-987");
        test_env::set_var("BORINGCACHE_CI_RUN_ATTEMPT", "2");
        test_env::set_var("BORINGCACHE_CI_REF_TYPE", "branch");
        test_env::set_var("BORINGCACHE_CI_REF_NAME", "main");
        test_env::set_var("BORINGCACHE_CI_DEFAULT_BRANCH", "main");
        test_env::set_var(
            "BORINGCACHE_CI_SHA",
            "1234567890abcdef1234567890abcdef12345678",
        );
        test_env::set_var("BORINGCACHE_CI_RUN_STARTED_AT", "2026-04-22T09:00:00Z");

        let mut request = base_save_request();
        apply_detected_ci_context(&mut request);

        assert_eq!(request.ci_provider.as_deref(), Some("gitlab"));
        assert_eq!(request.ci_run_uid.as_deref(), Some("pipeline-987"));
        assert_eq!(request.ci_run_attempt.as_deref(), Some("2"));
        assert_eq!(request.ci_ref_type.as_deref(), Some("branch"));
        assert_eq!(request.ci_ref_name.as_deref(), Some("main"));
        assert_eq!(request.ci_default_branch.as_deref(), Some("main"));
        assert_eq!(
            request.ci_commit_sha.as_deref(),
            Some("1234567890abcdef1234567890abcdef12345678")
        );
        assert_eq!(
            request.ci_run_started_at.as_deref(),
            Some("2026-04-22T09:00:00Z")
        );

        clear_ci_env();
    }
}
