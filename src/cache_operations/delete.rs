use crate::api::ApiClient;
use crate::ui::CleanUI;
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
        if self.verbose {
            CleanUI::info(&format!("Deleting cache entry: {key}"));
        }

        CleanUI::step_start("Delete cache entry", Some(key));

        self.api_client.delete_cache(&self.workspace, key).await?;

        CleanUI::step_success(None);
        CleanUI::info(&format!("Deleted cache entry: {key}"));

        Ok(())
    }

    pub async fn delete_by_tag(&self, tag: &str) -> Result<()> {
        if self.verbose {
            CleanUI::info(&format!("Deleting cache entries with tag: {tag}"));
        }

        CleanUI::step_start("Delete by tag", Some(tag));

        self.api_client.delete_cache(&self.workspace, tag).await?;

        CleanUI::step_success(None);
        CleanUI::info(&format!("Deleted cache entries with tag: {tag}"));

        Ok(())
    }
}
