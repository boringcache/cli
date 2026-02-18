use anyhow::{ensure, Result};

use crate::api::client::ApiClient;
use crate::git::GitContext;
use crate::tag_utils::TagResolver;

pub async fn execute(
    workspace: String,
    tag: Option<String>,
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
    let configured_human_tags = match tag {
        Some(value) => {
            let mut resolved = Vec::new();
            for raw in value
                .split(',')
                .map(str::trim)
                .filter(|raw| !raw.is_empty())
            {
                resolved.push(tag_resolver.effective_save_tag(raw)?);
            }
            resolved
        }
        None => Vec::new(),
    };

    crate::serve::run_server(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
    )
    .await
}
