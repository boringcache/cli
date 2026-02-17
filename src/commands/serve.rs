use anyhow::{ensure, Result};

use crate::api::client::ApiClient;
use crate::git::GitContext;
use crate::tag_utils::TagResolver;

pub async fn execute(
    workspace: String,
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

    crate::serve::run_server(api_client, workspace, host, port, tag_resolver).await
}
