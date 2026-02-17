use anyhow::{ensure, Result};

use crate::api::client::ApiClient;

pub async fn execute(workspace: String, host: String, port: u16) -> Result<()> {
    ensure!(
        workspace.contains('/'),
        "Workspace must be in org/project format"
    );

    let api_client = ApiClient::new()?;

    crate::serve::run_server(api_client, workspace, host, port).await
}
