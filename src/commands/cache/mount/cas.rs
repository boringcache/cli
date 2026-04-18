use anyhow::{Context, Result};
use std::collections::HashMap;

use crate::api::ApiClient;
use crate::api::models::cache::{BlobDescriptor, ManifestCheckRequest};
use crate::cache::cas_publish::{self, BlobUploadSource};
use crate::ui;

pub(super) struct MountCasSyncBundle {
    pub(super) expected_adapter: crate::adapters::CasAdapterKind,
    pub(super) cas_layout: Option<String>,
    pub(super) pointer_bytes: Vec<u8>,
    pub(super) manifest_root_digest: String,
    pub(super) total_size_bytes: u64,
    pub(super) blobs: Vec<BlobDescriptor>,
    pub(super) blob_sources: HashMap<String, BlobUploadSource>,
    pub(super) confirm_spec: cas_publish::CasConfirmSpec,
    pub(super) success_unit: &'static str,
    pub(super) success_size_bytes: u64,
    pub(super) empty_payload_error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn sync_to_remote_cas(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    verbose: bool,
    bundle: MountCasSyncBundle,
    require_server_signature: bool,
) -> Result<()> {
    if let Some(message) = bundle.empty_payload_error.as_ref() {
        anyhow::bail!(message.clone());
    }

    let check_response = api_client
        .check_manifests(
            workspace,
            &[ManifestCheckRequest {
                tag: resolved_tag.to_string(),
                manifest_root_digest: bundle.manifest_root_digest.clone(),
                lookup: None,
            }],
        )
        .await;

    if let Ok(response) = check_response
        && let Some(result) = response.results.first()
    {
        if super::manifest_check_is_ready(result) {
            if verbose {
                ui::info("  Cache already up to date");
            }
            return Ok(());
        }

        if super::manifest_check_is_pending(result) {
            if verbose {
                ui::info("  Remote cache publish pending; skipping duplicate publish");
            }
            return Ok(());
        }
    }

    let request = cas_publish::build_save_request(
        resolved_tag.to_string(),
        bundle.manifest_root_digest.clone(),
        bundle.total_size_bytes,
        bundle.cas_layout.clone(),
        &bundle.confirm_spec,
        true,
    );

    if verbose {
        ui::info("  Requesting CAS upload plan...");
    }

    let save_response = api_client
        .save_entry(workspace, &request)
        .await
        .with_context(|| format!("Failed to create CAS entry for {}", resolved_tag))?;
    cas_publish::ensure_server_adapter(resolved_tag, bundle.expected_adapter, &save_response)?;

    if save_response.exists {
        if verbose {
            ui::info("  Cache already exists on server");
        }
        return Ok(());
    }

    let missing_blobs =
        cas_publish::check_missing_blobs(api_client, workspace, &bundle.blobs).await?;
    if verbose {
        ui::info(&format!(
            "  Uploading {} missing blob(s)...",
            missing_blobs.len()
        ));
        ui::info("  Uploading CAS index...");
    }

    let all_blob_digests: Vec<String> = bundle.blobs.iter().map(|b| b.digest.clone()).collect();
    let publish_result = cas_publish::upload_missing_blobs_and_manifest(
        api_client,
        workspace,
        &save_response,
        &missing_blobs,
        &all_blob_digests,
        &bundle.blob_sources,
        &bundle.pointer_bytes,
        bundle.confirm_spec.manifest_digest.clone(),
        bundle.confirm_spec.manifest_size,
        crate::progress::TransferProgress::new_noop(),
    )
    .await?;

    if verbose {
        ui::info("  Confirming CAS upload...");
    }

    let confirm_request =
        cas_publish::build_confirm_request(&bundle.confirm_spec, publish_result.manifest_etag);
    let confirm_response = api_client
        .confirm(workspace, &save_response.cache_entry_id, &confirm_request)
        .await
        .with_context(|| format!("Failed to confirm CAS upload for {}", resolved_tag))?;
    let publication = super::MountSyncPublication {
        cache_entry_id: &save_response.cache_entry_id,
        manifest_root_digest: &bundle.manifest_root_digest,
    };
    super::ensure_mount_sync_won(publication, &confirm_response, resolved_tag)?;
    super::wait_for_mount_sync_visibility(
        api_client,
        workspace,
        resolved_tag,
        publication,
        require_server_signature,
    )
    .await?;

    if verbose {
        ui::info(&format!(
            "  Synced {} ({} {}, {})",
            base_tag,
            bundle.confirm_spec.file_count,
            bundle.success_unit,
            crate::progress::format_bytes(bundle.success_size_bytes)
        ));
    }

    Ok(())
}
