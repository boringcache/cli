use std::collections::HashSet;

use super::error::OciError;
use crate::serve::state::AppState;
use crate::tag_utils::{TagResolver, server_cache_tag_name};

// Human OCI references are cache heads. Non-human registry references are not
// converted into cache tags; callers should use digest restore or a valid human
// tag reference instead.
pub(crate) fn scoped_restore_tags(
    _tag_resolver: &TagResolver,
    _configured_human_tags: &[String],
    _primary_cache_tag: &str,
    _name: &str,
    reference: &str,
) -> Vec<String> {
    if server_cache_tag_name(reference) {
        vec![reference.to_string()]
    } else {
        Vec::new()
    }
}

pub(crate) fn scoped_save_tag(
    _tag_resolver: &TagResolver,
    _configured_human_tags: &[String],
    _primary_cache_tag: &str,
    name: &str,
    reference: &str,
) -> Result<String, OciError> {
    if server_cache_tag_name(reference) {
        Ok(reference.to_string())
    } else {
        Err(non_human_reference_error(name, reference))
    }
}

pub(crate) fn scoped_write_scope_tag(
    _tag_resolver: &TagResolver,
    name: &str,
    reference: &str,
) -> Result<String, OciError> {
    if server_cache_tag_name(reference) {
        Ok(reference.to_string())
    } else {
        Err(non_human_reference_error(name, reference))
    }
}

fn non_human_reference_error(name: &str, reference: &str) -> OciError {
    OciError::manifest_invalid(format!(
        "OCI registry reference {name}:{reference} is not a valid BoringCache human tag"
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AliasBinding {
    pub tag: String,
    pub write_scope_tag: Option<String>,
    pub required: bool,
}

pub(crate) fn alias_tags_for_manifest(
    primary_tag: &str,
    configured_human_tags: &[String],
    additional_aliases: &[AliasBinding],
) -> Vec<AliasBinding> {
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();

    for human_tag in configured_human_tags {
        if human_tag != primary_tag && seen.insert(human_tag.clone()) {
            aliases.push(AliasBinding {
                tag: human_tag.clone(),
                write_scope_tag: None,
                required: server_cache_tag_name(human_tag),
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
