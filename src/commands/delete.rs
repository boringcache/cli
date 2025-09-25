use anyhow::Result;

use crate::api::ApiClient;
use crate::ui::CleanUI;

pub async fn execute(workspace_option: Option<String>, tag: String, verbose: bool) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let api_client = ApiClient::new(None)?;

    if verbose {
        CleanUI::info("Deleting cache entries");
        CleanUI::info(&format!("Workspace: {workspace}"));
        CleanUI::info(&format!("Tag: {tag}"));
    } else {
        CleanUI::info(&format!("Deleting cache entries with tag: {tag}"));
    }

    match api_client.delete_cache(&workspace, &tag).await {
        Ok(_) => {
            CleanUI::info("Cache entries deleted successfully");
            CleanUI::info(&format!("Tag: {tag}"));

            if verbose {
                CleanUI::info("Background cleanup will remove storage objects");
                CleanUI::info("This may take a few minutes to complete");
            } else {
                CleanUI::info("Storage cleanup enqueued for background processing");
            }
            Ok(())
        }
        Err(e) => {
            if e.to_string().contains("Cache miss") || e.to_string().contains("404") {
                CleanUI::info(&format!("Warning: No cache entries found with tag: {tag}"));
                if verbose {
                    CleanUI::info("This tag may have been previously deleted or never existed");
                }
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}
