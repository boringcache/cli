use super::{SaveStatus, shared_save_api_client};
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::OnceCell;
use tokio::task;

use crate::api::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cache::cas_publish::{self, BlobUploadSource};
use crate::cache::receipts::{maybe_commit_blob_receipts, maybe_commit_manifest_receipt};
use crate::command_support::save_support::{
    complete_skipped_step, conflict_message_from_error, is_cache_pending_error, progress_info,
    progress_warning, save_summary,
};
use crate::progress::{ProgressSession, System as ProgressSystem, TransferProgress};
use crate::telemetry::{SaveMetrics, StorageMetrics};

pub(super) struct CasSaveBundle {
    pub(super) expected_adapter: crate::adapters::CasAdapterKind,
    pub(super) cas_layout: Option<String>,
    pub(super) pointer_bytes: Vec<u8>,
    pub(super) manifest_root_digest: String,
    pub(super) total_size_bytes: u64,
    pub(super) blob_total_size_bytes: u64,
    pub(super) blobs: Vec<BlobDescriptor>,
    pub(super) blob_sources: HashMap<String, BlobUploadSource>,
    pub(super) confirm_spec: cas_publish::CasConfirmSpec,
    pub(super) empty_payload_error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_single_cas_entry<F>(
    shared_api_client: Arc<OnceCell<ApiClient>>,
    workspace: String,
    tag: String,
    path: String,
    force: bool,
    scan_step_title: &str,
    scan_panic_context: &'static str,
    scan_builder: F,
) -> Result<SaveStatus>
where
    F: FnOnce(PathBuf) -> Result<CasSaveBundle> + Send + 'static,
{
    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();
    let session_id = format!("save-{}", tag);
    let mut session = ProgressSession::new(
        reporter.clone(),
        session_id.clone(),
        format!("Saving {}", tag),
        6,
    )?;
    let overall_started = Instant::now();

    let scan_step = session.start_step(scan_step_title.to_string(), None)?;
    let scan_started = Instant::now();
    let scan_path = PathBuf::from(&path);
    let bundle = task::spawn_blocking(move || scan_builder(scan_path))
        .await
        .context(scan_panic_context)??;
    let scan_duration = scan_started.elapsed();
    scan_step.complete()?;

    if let Some(message) = bundle.empty_payload_error.as_ref() {
        session.error(message.clone())?;
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!(message.clone());
    }
    let api_client = shared_save_api_client(shared_api_client.as_ref()).await?;

    let create_step = session.start_step("Creating cache entry".to_string(), None)?;
    let request = cas_publish::build_save_request(
        tag.clone(),
        bundle.manifest_root_digest.clone(),
        bundle.total_size_bytes,
        bundle.cas_layout.clone(),
        &bundle.confirm_spec,
        force,
    );

    let save_response = match api_client.save_entry(&workspace, &request).await {
        Ok(response) => response,
        Err(err) => {
            create_step.complete()?;

            if let Some(message) = conflict_message_from_error(&err) {
                progress_warning(&reporter, format!("  Conflict: {}", message));
                progress_info(
                    &reporter,
                    "  Tag already exists with different content; skipping save",
                );
                complete_skipped_step(
                    &mut session,
                    "Checking remote blobs",
                    "skipped — tag conflict",
                )?;
                complete_skipped_step(&mut session, "Uploading blobs", "skipped — tag conflict")?;
                complete_skipped_step(
                    &mut session,
                    "Uploading CAS index",
                    "skipped — tag conflict",
                )?;
                complete_skipped_step(&mut session, "Confirming upload", "skipped — tag conflict")?;

                let summary = save_summary(
                    bundle.total_size_bytes,
                    bundle.confirm_spec.file_count,
                    bundle.manifest_root_digest.clone(),
                    path.clone(),
                );
                session.complete(summary)?;
                drop(reporter);
                progress_system.shutdown()?;
                return Ok(SaveStatus::Skipped);
            }

            if is_cache_pending_error(&err) {
                progress_info(
                    &reporter,
                    "  Another job is uploading this cache; skipping wait",
                );
                complete_skipped_step(
                    &mut session,
                    "Checking remote blobs",
                    "skipped — another job is uploading",
                )?;
                complete_skipped_step(
                    &mut session,
                    "Uploading blobs",
                    "skipped — another job is uploading",
                )?;
                complete_skipped_step(
                    &mut session,
                    "Uploading CAS index",
                    "skipped — another job is uploading",
                )?;
                complete_skipped_step(
                    &mut session,
                    "Confirming upload",
                    "skipped — another job is uploading",
                )?;

                let summary = save_summary(
                    bundle.total_size_bytes,
                    bundle.confirm_spec.file_count,
                    bundle.manifest_root_digest.clone(),
                    path.clone(),
                );
                session.complete(summary)?;
                drop(reporter);
                progress_system.shutdown()?;
                return Ok(SaveStatus::AlreadyExists);
            }

            session.error(err.to_string())?;
            drop(reporter);
            progress_system.shutdown()?;
            return Err(err.context(format!("Failed to create CAS entry for {}", tag)));
        }
    };
    create_step.complete()?;

    if let Err(err) =
        cas_publish::ensure_server_adapter(&tag, bundle.expected_adapter, &save_response)
    {
        let message = err.to_string();
        session.error(message.clone())?;
        drop(reporter);
        progress_system.shutdown()?;
        return Err(err);
    }

    if let Some(reason) = save_response.blocking_pending_cas_reason(&bundle.manifest_root_digest) {
        progress_warning(
            &reporter,
            format!("  Pending CAS entry is not resumable: {reason}"),
        );
        progress_info(
            &reporter,
            "  Another job is uploading this tag with a different or incomplete root; skipping save",
        );
        complete_skipped_step(
            &mut session,
            "Checking remote blobs",
            "skipped — another job is uploading",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading blobs",
            "skipped — another job is uploading",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading CAS index",
            "skipped — another job is uploading",
        )?;
        complete_skipped_step(
            &mut session,
            "Confirming upload",
            "skipped — another job is uploading",
        )?;

        let summary = save_summary(
            bundle.total_size_bytes,
            bundle.confirm_spec.file_count,
            bundle.manifest_root_digest.clone(),
            path,
        );
        session.complete(summary)?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(SaveStatus::Skipped);
    }

    let resumable_pending_existing =
        save_response.is_resumable_pending_cas_for(&bundle.manifest_root_digest);

    if resumable_pending_existing {
        progress_info(
            &reporter,
            "  Resuming pending CAS upload for this cache entry",
        );
    }

    if save_response.should_skip_existing_uploads_for(&bundle.manifest_root_digest) {
        complete_skipped_step(
            &mut session,
            "Checking remote blobs",
            "skipped — server reports entry exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading blobs",
            "skipped — server reports entry exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading CAS index",
            "skipped — server reports entry exists",
        )?;

        let save_status_pending = save_response.status.as_deref() == Some("pending");
        let same_tag = save_response.tag == tag;

        if save_status_pending && same_tag {
            complete_skipped_step(
                &mut session,
                "Confirming upload",
                "skipped — another job is uploading",
            )?;
        } else {
            let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
            cas_publish::confirm_upload(
                &api_client,
                &workspace,
                &save_response.cache_entry_id,
                &bundle.confirm_spec,
                None,
            )
            .await
            .with_context(|| format!("Failed to confirm existing CAS entry for {}", tag))?;
            confirm_step.complete()?;
        }

        let summary = save_summary(
            bundle.total_size_bytes,
            bundle.confirm_spec.file_count,
            bundle.manifest_root_digest.clone(),
            path,
        );
        session.complete(summary)?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(SaveStatus::AlreadyExists);
    }

    let check_step = session.start_step(
        "Checking remote blobs".to_string(),
        Some(format!("{} blobs", bundle.blobs.len())),
    )?;
    let missing_blobs =
        cas_publish::check_missing_blobs(&api_client, &workspace, &bundle.blobs).await?;
    check_step.complete()?;

    let mut upload_storage_metrics = StorageMetrics::default();
    let upload_step = session.start_step(
        "Uploading blobs".to_string(),
        Some(format!("{} missing", missing_blobs.len())),
    )?;
    let upload_started = Instant::now();
    if !missing_blobs.is_empty() {
        let total_upload_bytes = missing_blobs
            .iter()
            .map(|blob| blob.size_bytes)
            .sum::<u64>();
        let progress = TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            upload_step.step_number(),
            total_upload_bytes,
        );
        let upload_outcome = cas_publish::upload_missing_blobs(
            &api_client,
            &workspace,
            &save_response.cache_entry_id,
            &missing_blobs,
            &bundle.blob_sources,
            progress,
        )
        .await?;
        maybe_commit_blob_receipts(
            &api_client,
            &workspace,
            save_response.upload_session_id.as_deref(),
            upload_outcome.receipts,
        )
        .await;
        upload_storage_metrics = upload_outcome.storage_metrics;
    }
    let upload_duration = upload_started.elapsed();
    upload_step.complete()?;

    let index_step = session.start_step("Uploading CAS index".to_string(), None)?;
    let manifest_etag = cas_publish::upload_manifest(
        &api_client,
        save_response
            .manifest_upload_url
            .as_ref()
            .ok_or_else(|| anyhow!("Missing manifest_upload_url in response"))?,
        &bundle.pointer_bytes,
        &save_response.upload_headers,
    )
    .await?;
    index_step.complete()?;

    let all_blob_digests: Vec<String> = bundle.blobs.iter().map(|b| b.digest.clone()).collect();
    maybe_commit_manifest_receipt(
        &api_client,
        &workspace,
        save_response.upload_session_id.as_deref(),
        bundle.confirm_spec.manifest_digest.clone(),
        bundle.confirm_spec.manifest_size,
        manifest_etag.clone(),
        Some(all_blob_digests),
    )
    .await;

    let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
    if let Err(err) = cas_publish::confirm_upload(
        &api_client,
        &workspace,
        &save_response.cache_entry_id,
        &bundle.confirm_spec,
        manifest_etag,
    )
    .await
    {
        confirm_step.complete()?;

        if let Some(message) = conflict_message_from_error(&err) {
            progress_warning(&reporter, format!("  Conflict: {}", message));
            progress_info(
                &reporter,
                "  Another job finalized this tag first; skipping save",
            );
            let summary = save_summary(
                bundle.total_size_bytes,
                bundle.confirm_spec.file_count,
                bundle.manifest_root_digest.clone(),
                path.clone(),
            );
            session.complete(summary)?;
            drop(reporter);
            progress_system.shutdown()?;
            return Ok(SaveStatus::Skipped);
        }

        if is_cache_pending_error(&err) {
            progress_info(
                &reporter,
                "  Another job is uploading this cache; skipping wait",
            );
            let summary = save_summary(
                bundle.total_size_bytes,
                bundle.confirm_spec.file_count,
                bundle.manifest_root_digest.clone(),
                path.clone(),
            );
            session.complete(summary)?;
            drop(reporter);
            progress_system.shutdown()?;
            return Ok(SaveStatus::AlreadyExists);
        }

        session.error(err.to_string())?;
        drop(reporter);
        progress_system.shutdown()?;
        return Err(err.context(format!("Failed to confirm CAS upload for {}", tag)));
    }
    confirm_step.complete()?;

    let summary = save_summary(
        bundle.total_size_bytes,
        bundle.confirm_spec.file_count,
        bundle.manifest_root_digest.clone(),
        path.clone(),
    );
    session.complete(summary)?;
    drop(reporter);
    progress_system.shutdown()?;

    let total_elapsed = overall_started.elapsed();
    SaveMetrics {
        tag,
        manifest_root_digest: bundle.manifest_root_digest,
        total_duration_ms: total_elapsed.as_millis() as u64,
        archive_duration_ms: scan_duration.as_millis() as u64,
        upload_duration_ms: upload_duration.as_millis() as u64,
        uncompressed_size: bundle.total_size_bytes,
        compressed_size: bundle.blob_total_size_bytes,
        file_count: bundle.confirm_spec.file_count,
        part_count: if bundle.confirm_spec.blob_count > 0 {
            Some(bundle.confirm_spec.blob_count.min(u32::MAX as u64) as u32)
        } else {
            None
        },
        storage_metrics: upload_storage_metrics,
    }
    .send(&api_client, &workspace)
    .await;

    Ok(SaveStatus::Uploaded)
}
