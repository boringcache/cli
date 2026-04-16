use std::collections::HashSet;

use super::error::OciError;
use crate::api::models::cache::SaveRequest;
use crate::serve::state::{AppState, digest_tag, ref_tag_for_input};
use crate::tag_utils::TagResolver;

pub(crate) fn scoped_restore_tags(
    tag_resolver: &TagResolver,
    name: &str,
    reference: &str,
) -> Vec<String> {
    let scoped_input = format!("{name}:{reference}");
    let scoped = tag_resolver
        .effective_save_tag(&scoped_input)
        .unwrap_or(scoped_input);
    vec![ref_tag_for_input(&scoped)]
}

pub(crate) fn scoped_save_tag(
    tag_resolver: &TagResolver,
    name: &str,
    reference: &str,
) -> Result<String, OciError> {
    let scoped_input = format!("{name}:{reference}");
    let scoped = tag_resolver
        .effective_save_tag(&scoped_input)
        .map_err(|e| OciError::internal(format!("Failed to resolve scoped tag: {e}")))?;
    Ok(ref_tag_for_input(&scoped))
}

pub(crate) fn scoped_write_scope_tag(
    tag_resolver: &TagResolver,
    name: &str,
    reference: &str,
) -> Result<String, OciError> {
    let scoped_input = format!("{name}:{reference}");
    tag_resolver
        .effective_save_tag(&scoped_input)
        .map_err(|e| OciError::internal(format!("Failed to resolve scoped tag: {e}")))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AliasBinding {
    pub tag: String,
    pub write_scope_tag: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct AliasTagManifest {
    pub manifest_root_digest: String,
    pub manifest_size: u64,
    pub blob_count: u64,
    pub blob_total_size_bytes: u64,
    pub total_size_bytes: u64,
}

pub(crate) fn alias_tags_for_manifest(
    primary_tag: &str,
    manifest_digest: &str,
    primary_write_scope_tag: Option<&str>,
    configured_human_tags: &[String],
    additional_aliases: &[AliasBinding],
) -> Vec<AliasBinding> {
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();

    let digest_alias = digest_tag(manifest_digest);
    if digest_alias != primary_tag && seen.insert(digest_alias.clone()) {
        aliases.push(AliasBinding {
            tag: digest_alias,
            write_scope_tag: primary_write_scope_tag.map(ToOwned::to_owned),
        });
    }

    for human_tag in configured_human_tags {
        if human_tag != primary_tag && seen.insert(human_tag.clone()) {
            aliases.push(AliasBinding {
                tag: human_tag.clone(),
                write_scope_tag: None,
            });
        }
    }

    for alias in additional_aliases {
        if alias.tag != primary_tag && seen.insert(alias.tag.clone()) {
            aliases.push(alias.clone());
        }
    }

    aliases
}

pub(crate) async fn bind_alias_tag(
    state: &AppState,
    alias_tag: &str,
    write_scope_tag: Option<&str>,
    manifest: &AliasTagManifest,
) -> Result<(), String> {
    let alias_request = SaveRequest {
        tag: alias_tag.to_string(),
        write_scope_tag: write_scope_tag.map(ToOwned::to_owned),
        manifest_root_digest: manifest.manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(manifest.blob_count),
        blob_total_size_bytes: Some(manifest.blob_total_size_bytes),
        cas_layout: Some("oci-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes: manifest.total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(manifest.blob_count.min(u32::MAX as u64) as u32),
        expected_manifest_digest: Some(manifest.manifest_root_digest.clone()),
        expected_manifest_size: Some(manifest.manifest_size),
        force: None,
        use_multipart: None,
        ci_provider: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let response = state
        .api_client
        .save_entry(&state.workspace, &alias_request)
        .await
        .map_err(|e| format!("save_entry failed: {e}"))?;

    let confirm_request = crate::api::models::cache::ConfirmRequest {
        manifest_digest: manifest.manifest_root_digest.clone(),
        manifest_size: manifest.manifest_size,
        manifest_etag: None,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(manifest.blob_count),
        blob_total_size_bytes: Some(manifest.blob_total_size_bytes),
        file_count: Some(manifest.blob_count.min(u32::MAX as u64) as u32),
        uncompressed_size: None,
        compressed_size: None,
        storage_mode: Some("cas".to_string()),
        tag: Some(alias_tag.to_string()),
        write_scope_tag: write_scope_tag.map(ToOwned::to_owned),
    };

    match state
        .api_client
        .confirm_wait_for_publish_or_pending_timeout(
            &state.workspace,
            &response.cache_entry_id,
            &confirm_request,
        )
        .await
    {
        Ok(crate::api::client::ConfirmPublishResult::Published(_)) => {}
        Ok(crate::api::client::ConfirmPublishResult::Pending(metadata)) => {
            return Err(format!("confirm deferred: ({:?})", metadata));
        }
        Err(error) => {
            return Err(format!("confirm failed: {error}"));
        }
    }

    Ok(())
}
