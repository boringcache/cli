use anyhow::{Result, ensure};
use std::collections::BTreeMap;

use crate::api::client::ApiClient;
use crate::cas_oci::sha256_hex;
use crate::git::GitContext;
use crate::tag_utils::TagResolver;

const PROXY_METADATA_HINTS_ENV: &str = "BORINGCACHE_PROXY_METADATA_HINTS";
const MAX_PROXY_METADATA_HINTS: usize = 8;
const MAX_PROXY_METADATA_HINT_KEY_BYTES: usize = 32;
const MAX_PROXY_METADATA_HINT_VALUE_BYTES: usize = 64;

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

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    workspace: String,
    tag: String,
    host: String,
    port: u16,
    no_platform: bool,
    no_git: bool,
    metadata_hints: Vec<String>,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<()> {
    ensure!(
        workspace.contains('/'),
        "Workspace must be in org/project format"
    );

    if std::env::var("BORINGCACHE_TEST_MODE").as_deref() == Ok("1") {
        return Ok(());
    }

    let api_client = if read_only {
        ApiClient::for_restore()?
    } else {
        ApiClient::for_save()?
    };
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
    let proxy_metadata_hints = resolve_proxy_metadata_hints(&metadata_hints)?;

    crate::serve::run_server(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        proxy_metadata_hints,
        fail_on_cache_error,
        read_only,
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
    proxy_metadata_hints: BTreeMap<String, String>,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<ProxyServerHandle> {
    ensure!(
        workspace.contains('/'),
        "Workspace must be in org/project format"
    );

    let api_client = if read_only {
        ApiClient::for_restore()?
    } else {
        ApiClient::for_save()?
    };
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
        proxy_metadata_hints,
        fail_on_cache_error,
        read_only,
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

pub(crate) fn internal_registry_root_tag(primary_human_tag: &str) -> String {
    format!(
        "bc_registry_root_v2_{}",
        sha256_hex(primary_human_tag.as_bytes())
    )
}

pub(crate) fn resolve_proxy_metadata_hints(
    raw_hints: &[String],
) -> Result<BTreeMap<String, String>> {
    let mut hints = BTreeMap::new();

    if let Some(env_hints) = crate::config::env_var(PROXY_METADATA_HINTS_ENV) {
        let parts = env_hints
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        merge_proxy_metadata_hints(&mut hints, &parts, PROXY_METADATA_HINTS_ENV)?;
    }

    merge_proxy_metadata_hints(&mut hints, raw_hints, "command line")?;
    Ok(hints)
}

fn merge_proxy_metadata_hints(
    hints: &mut BTreeMap<String, String>,
    raw_hints: &[String],
    source: &str,
) -> Result<()> {
    for raw_hint in raw_hints {
        let trimmed = raw_hint.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = parse_proxy_metadata_hint(trimmed, source)?;
        hints.insert(key, value);
        ensure!(
            hints.len() <= MAX_PROXY_METADATA_HINTS,
            "Proxy metadata hints support up to {MAX_PROXY_METADATA_HINTS} unique keys"
        );
    }

    Ok(())
}

fn parse_proxy_metadata_hint(raw_hint: &str, source: &str) -> Result<(String, String)> {
    let (raw_key, raw_value) = raw_hint
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("Invalid proxy metadata hint in {source}: {raw_hint}"))?;

    let key = normalize_proxy_metadata_hint_key(raw_key).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid proxy metadata hint key in {source}: {raw_key} (expected lowercase letters, digits, underscores, or hyphens)"
        )
    })?;
    let value = normalize_proxy_metadata_hint_value(raw_value).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid proxy metadata hint value in {source}: {raw_value} (use short ASCII labels like zed, grpc, warm, or changed-source)"
        )
    })?;

    Ok((key, value))
}

fn normalize_proxy_metadata_hint_key(raw_key: &str) -> Option<String> {
    let normalized = raw_key.trim().to_lowercase().replace('-', "_");
    if normalized.is_empty() || normalized.len() > MAX_PROXY_METADATA_HINT_KEY_BYTES {
        return None;
    }
    normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        .then_some(normalized)
}

fn normalize_proxy_metadata_hint_value(raw_value: &str) -> Option<String> {
    let normalized = raw_value
        .trim()
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_whitespace() { '-' } else { ch })
        .collect::<String>();
    if normalized.is_empty() || normalized.len() > MAX_PROXY_METADATA_HINT_VALUE_BYTES {
        return None;
    }
    normalized
        .chars()
        .all(|ch| {
            ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '_' | '-' | '.' | ':' | '/')
        })
        .then_some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;
    use std::collections::BTreeMap;

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

    #[test]
    fn proxy_metadata_hints_merge_env_and_flags() {
        let _guard = test_env::lock();
        test_env::set_var(PROXY_METADATA_HINTS_ENV, "project=zed,phase=seed");
        let hints =
            resolve_proxy_metadata_hints(&["phase=warm".to_string(), "tooling=main".to_string()])
                .unwrap();
        test_env::remove_var(PROXY_METADATA_HINTS_ENV);

        assert_eq!(
            hints,
            BTreeMap::from([
                ("phase".to_string(), "warm".to_string()),
                ("project".to_string(), "zed".to_string()),
                ("tooling".to_string(), "main".to_string()),
            ])
        );
    }

    #[test]
    fn proxy_metadata_hints_normalize_case_and_spacing() {
        let hints = resolve_proxy_metadata_hints(&[
            "Project=Zed".to_string(),
            "phase=Changed Source".to_string(),
        ])
        .unwrap();

        assert_eq!(hints.get("project"), Some(&"zed".to_string()));
        assert_eq!(hints.get("phase"), Some(&"changed-source".to_string()));
    }

    #[test]
    fn proxy_metadata_hints_reject_invalid_keys() {
        let error = resolve_proxy_metadata_hints(&["bad key=value".to_string()]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Invalid proxy metadata hint key")
        );
    }
}
