pub mod client;
pub mod models;

pub use client::ApiClient;
pub use models::*;

use anyhow::Result;

pub fn parse_workspace_slug(workspace: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = workspace.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid workspace format '{}'. Expected format: namespace/workspace (e.g., 'myorg/app')", workspace);
    }

    let namespace = parts[0];
    let workspace = parts[1];

    if namespace.is_empty() || workspace.is_empty() {
        anyhow::bail!("Namespace and workspace cannot be empty in '{}'", workspace);
    }

    let is_valid_name = |name: &str| {
        name.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.starts_with('.')
            && !name.ends_with('.')
    };

    if !is_valid_name(namespace) {
        anyhow::bail!("Invalid namespace '{}'. Must contain only alphanumeric characters, hyphens, underscores, and dots. Cannot start or end with hyphens or dots.", namespace);
    }

    if !is_valid_name(workspace) {
        anyhow::bail!("Invalid workspace '{}'. Must contain only alphanumeric characters, hyphens, underscores, and dots. Cannot start or end with hyphens or dots.", workspace);
    }

    Ok((namespace.to_string(), workspace.to_string()))
}
