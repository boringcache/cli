use anyhow::{ensure, Result};

use crate::api::client::ApiClient;
use crate::git::GitContext;
use crate::tag_utils::TagResolver;

pub async fn execute(
    workspace: String,
    tag: String,
    host: String,
    port: u16,
    no_platform: bool,
    no_git: bool,
) -> Result<()> {
    ensure!(
        workspace.contains('/'),
        "Workspace must be in org/project format"
    );

    let api_client = ApiClient::new()?;
    let platform = if no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };
    let git_enabled = !no_git && !crate::git::is_git_disabled_by_env();
    let git_context = if git_enabled {
        GitContext::detect()
    } else {
        GitContext::default()
    };
    let tag_resolver = TagResolver::new(platform, git_context, git_enabled);
    let (registry_root_tag, configured_human_tags) =
        resolve_registry_tag_config(&tag_resolver, &tag)?;

    crate::serve::run_server(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
    )
    .await
}

fn resolve_registry_tag_config(
    tag_resolver: &TagResolver,
    raw_tags: &str,
) -> Result<(String, Vec<String>)> {
    let mut resolved_tags = Vec::new();
    for raw in raw_tags
        .split(',')
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        resolved_tags.push(tag_resolver.effective_save_tag(raw)?);
    }
    ensure!(!resolved_tags.is_empty(), "Tag must not be empty");

    let registry_root_tag = resolved_tags[0].clone();
    let mut configured_human_tags = Vec::new();
    for resolved_tag in resolved_tags.into_iter().skip(1) {
        if resolved_tag != registry_root_tag && !configured_human_tags.contains(&resolved_tag) {
            configured_human_tags.push(resolved_tag);
        }
    }

    Ok((registry_root_tag, configured_human_tags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_tag_without_aliases() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let (root, aliases) = resolve_registry_tag_config(&resolver, "registry-root").unwrap();
        assert_eq!(root, "registry-root");
        assert!(aliases.is_empty());
    }

    #[test]
    fn aliases_skip_root_and_deduplicate() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let (root, aliases) = resolve_registry_tag_config(
            &resolver,
            "registry-root,oci-main,registry-root,oci-main,oci-stable",
        )
        .unwrap();

        assert_eq!(root, "registry-root");
        assert_eq!(
            aliases,
            vec!["oci-main".to_string(), "oci-stable".to_string()]
        );
    }

    #[test]
    fn empty_tag_string_is_rejected() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let error = resolve_registry_tag_config(&resolver, " , ").unwrap_err();
        assert!(error.to_string().contains("Tag must not be empty"));
    }
}
