use anyhow::{ensure, Result};

use crate::api::client::ApiClient;
use crate::cas_oci::sha256_hex;
use crate::git::GitContext;
use crate::tag_utils::TagResolver;

pub struct ProxyServerHandle {
    handle: crate::serve::ServeHandle,
    endpoint_host: String,
    port: u16,
    primary_human_tag: String,
}

impl ProxyServerHandle {
    pub fn endpoint_host(&self) -> &str {
        &self.endpoint_host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn cache_ref(&self) -> String {
        format!(
            "{}:{}/cache:{}",
            self.endpoint_host, self.port, self.primary_human_tag
        )
    }

    pub async fn shutdown_and_flush(self) -> Result<()> {
        self.handle.shutdown_and_flush().await
    }
}

pub async fn execute(
    workspace: String,
    tag: String,
    host: String,
    port: u16,
    no_platform: bool,
    no_git: bool,
    fail_on_cache_error: bool,
) -> Result<()> {
    ensure!(
        workspace.contains('/'),
        "Workspace must be in org/project format"
    );

    if std::env::var("BORINGCACHE_TEST_MODE").as_deref() == Ok("1") {
        return Ok(());
    }

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
        fail_on_cache_error,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn start_proxy_background(
    workspace: String,
    tag: String,
    host: String,
    port: u16,
    no_platform: bool,
    no_git: bool,
    fail_on_cache_error: bool,
) -> Result<ProxyServerHandle> {
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

    let primary_human_tag = configured_human_tags[0].clone();
    let endpoint_host = if host == "0.0.0.0" {
        "127.0.0.1".to_string()
    } else {
        host.clone()
    };

    let handle = crate::serve::start_server_background(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        fail_on_cache_error,
    )
    .await?;

    Ok(ProxyServerHandle {
        port: handle.port,
        handle,
        endpoint_host,
        primary_human_tag,
    })
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
        let resolved = tag_resolver.effective_save_tag(raw)?;
        if !resolved_tags.contains(&resolved) {
            resolved_tags.push(resolved);
        }
    }
    ensure!(!resolved_tags.is_empty(), "Tag must not be empty");

    let registry_root_tag = internal_registry_root_tag(&resolved_tags[0]);
    let configured_human_tags = resolved_tags;

    Ok((registry_root_tag, configured_human_tags))
}

fn internal_registry_root_tag(primary_human_tag: &str) -> String {
    format!(
        "bc_registry_root_v2_{}",
        sha256_hex(primary_human_tag.as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_tag_without_aliases() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let (root, aliases) = resolve_registry_tag_config(&resolver, "registry-root").unwrap();
        assert_eq!(root, internal_registry_root_tag("registry-root"));
        assert_eq!(aliases, vec!["registry-root".to_string()]);
    }

    #[test]
    fn aliases_include_first_tag_and_deduplicate() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let (root, aliases) = resolve_registry_tag_config(
            &resolver,
            "registry-root,oci-main,registry-root,oci-main,oci-stable",
        )
        .unwrap();

        assert_eq!(root, internal_registry_root_tag("registry-root"));
        assert_eq!(
            aliases,
            vec![
                "registry-root".to_string(),
                "oci-main".to_string(),
                "oci-stable".to_string()
            ]
        );
    }

    #[test]
    fn empty_tag_string_is_rejected() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let error = resolve_registry_tag_config(&resolver, " , ").unwrap_err();
        assert!(error.to_string().contains("Tag must not be empty"));
    }
}
