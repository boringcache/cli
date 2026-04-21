use std::collections::HashSet;

use super::error::OciError;
use crate::serve::state::{AppState, digest_tag, ref_tag_for_input};
use crate::tag_utils::TagResolver;

pub(crate) fn scoped_restore_tags(
    tag_resolver: &TagResolver,
    registry_root_tag: &str,
    name: &str,
    reference: &str,
) -> Vec<String> {
    let scoped = effective_ref_input(tag_resolver, name, reference);
    let primary = root_scoped_ref_tag(registry_root_tag, &scoped);
    let legacy = ref_tag_for_input(&scoped);
    if primary == legacy {
        vec![primary]
    } else {
        vec![primary, legacy]
    }
}

pub(crate) fn scoped_save_tag(
    tag_resolver: &TagResolver,
    registry_root_tag: &str,
    name: &str,
    reference: &str,
) -> Result<String, OciError> {
    let scoped = fallible_effective_ref_input(tag_resolver, name, reference)?;
    Ok(root_scoped_ref_tag(registry_root_tag, &scoped))
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

fn effective_ref_input(tag_resolver: &TagResolver, name: &str, reference: &str) -> String {
    let scoped_input = format!("{name}:{reference}");
    tag_resolver
        .effective_save_tag(&scoped_input)
        .unwrap_or(scoped_input)
}

fn fallible_effective_ref_input(
    tag_resolver: &TagResolver,
    name: &str,
    reference: &str,
) -> Result<String, OciError> {
    let scoped_input = format!("{name}:{reference}");
    tag_resolver
        .effective_save_tag(&scoped_input)
        .map_err(|e| OciError::internal(format!("Failed to resolve scoped tag: {e}")))
}

fn root_scoped_ref_tag(registry_root_tag: &str, scoped_ref: &str) -> String {
    let root = registry_root_tag.trim();
    if root.is_empty() {
        ref_tag_for_input(scoped_ref)
    } else {
        ref_tag_for_input(&format!("{root}:{scoped_ref}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AliasBinding {
    pub tag: String,
    pub write_scope_tag: Option<String>,
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
    cache_entry_id: &str,
) -> Result<(), String> {
    match state
        .api_client
        .publish_ready_tag(
            &state.workspace,
            alias_tag,
            cache_entry_id,
            write_scope_tag.map(ToOwned::to_owned),
            "cas",
        )
        .await
    {
        Ok(response) => {
            state
                .oci_engine_diagnostics
                .record_alias_promotion(response.promotion_status.as_deref());
        }
        Err(error) => {
            state.oci_engine_diagnostics.record_alias_promotion(None);
            return Err(format!("confirm failed: {error}"));
        }
    }

    Ok(())
}
