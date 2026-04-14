use crate::api::ApiClient;
use crate::config::Config;
use anyhow::{Result, anyhow};

pub fn get_workspace_name(workspace_option: Option<String>) -> Result<String> {
    get_workspace_name_with_fallback(workspace_option, None)
}

pub fn get_workspace_name_with_fallback(
    workspace_option: Option<String>,
    fallback_workspace: Option<String>,
) -> Result<String> {
    normalize_workspace(workspace_option)
        .or_else(|| normalize_workspace(fallback_workspace))
        .or_else(configured_workspace)
        .ok_or_else(|| {
            anyhow!(
                "No workspace specified. Set BORINGCACHE_DEFAULT_WORKSPACE or run `boringcache use`."
            )
        })
}

pub fn configured_workspace() -> Option<String> {
    normalize_workspace(crate::config::env_var("BORINGCACHE_DEFAULT_WORKSPACE")).or_else(|| {
        Config::load()
            .ok()
            .and_then(|config| normalize_workspace(config.default_workspace))
    })
}

fn normalize_workspace(workspace: Option<String>) -> Option<String> {
    workspace
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub async fn resolve_workspace(
    api_client: &ApiClient,
    workspace_option: Option<String>,
    explicit_example: &str,
) -> Result<String> {
    if let Some(workspace) = workspace_option
        .map(|workspace| workspace.trim().to_string())
        .filter(|workspace| !workspace.is_empty())
    {
        return Ok(workspace);
    }

    if let Some(workspace) = configured_workspace() {
        return Ok(workspace);
    }

    let mut workspaces = api_client.list_workspaces().await?;
    workspaces.sort_by(|a, b| a.name.cmp(&b.name));

    match workspaces.as_slice() {
        [] => Err(anyhow!(
            "No accessible workspaces found for this token. Pass a workspace explicitly or authenticate with a workspace-scoped token."
        )),
        [workspace] => Ok(workspace.slug.clone()),
        _ => {
            let names = workspaces
                .iter()
                .take(5)
                .map(|workspace| workspace.slug.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if workspaces.len() > 5 { ", ..." } else { "" };

            Err(anyhow!(
                "No workspace specified. Use `boringcache use` to choose a default workspace or run `{explicit_example}`.\nAvailable workspaces: {names}{suffix}"
            ))
        }
    }
}

pub fn resolve_encryption_config(
    workspace: &str,
    explicit_recipient: Option<String>,
) -> Result<(bool, Option<String>)> {
    if let Some(recipient) = explicit_recipient {
        return Ok((true, Some(recipient)));
    }

    if let Ok(config) = Config::load()
        && let Some(ws_encryption) = config.get_workspace_encryption(workspace)
        && ws_encryption.enabled
        && !ws_encryption.recipient.is_empty()
    {
        return Ok((true, Some(ws_encryption.recipient.clone())));
    }

    Ok((false, None))
}
