use crate::api::ApiClient;
use anyhow::Result;

pub struct DeleteOperation {
    pub api_client: ApiClient,
    pub workspace: String,
    pub verbose: bool,
}

impl DeleteOperation {
    pub fn new(api_client: ApiClient, workspace: String, verbose: bool) -> Self {
        Self {
            api_client,
            workspace,
            verbose,
        }
    }

    pub async fn delete_by_key(&self, key: &str) -> Result<()> {
        // Delete progress is handled by command-level progress system

        self.api_client.delete_cache(&self.workspace, key).await?;

        // Delete completion handled by command-level progress system

        Ok(())
    }

    pub async fn delete_by_tag(&self, tag: &str) -> Result<()> {
        // Delete progress is handled by command-level progress system

        self.api_client.delete_cache(&self.workspace, tag).await?;

        // Delete completion handled by command-level progress system

        Ok(())
    }
}
