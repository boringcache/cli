use crate::api::ApiClient;
use crate::progress::format_bytes;
use crate::ui::CleanUI;
use anyhow::Result;

pub async fn execute() -> Result<()> {
    let api_client = ApiClient::new(None)?;
    let workspaces = api_client.list_workspaces().await?;

    if workspaces.is_empty() {
        CleanUI::info("No workspaces found");
        return Ok(());
    }

    CleanUI::section_break();
    CleanUI::info(&format!(
        "{:<15} {:<20} {:<10} {:<15}",
        "ID", "NAME", "ENTRIES", "SIZE"
    ));
    CleanUI::info(&"-".repeat(60));

    let mut sorted_workspaces = workspaces;
    sorted_workspaces.sort_by(|a, b| a.name.cmp(&b.name));

    for workspace in &sorted_workspaces {
        let id = workspace.id.as_ref().unwrap_or(&workspace.slug);

        let id_display = if id.len() > 15 {
            format!("{}...", &id[..12.min(id.len())])
        } else {
            id.clone()
        };

        let name = if workspace.name.len() > 20 {
            format!("{}...", &workspace.name[..17.min(workspace.name.len())])
        } else {
            workspace.name.clone()
        };

        let entries = workspace.cache_entries_count.to_string();
        let size = format_bytes(workspace.total_cache_size);

        CleanUI::info(&format!(
            "{id_display:<15} {name:<20} {entries:<10} {size:<15}"
        ));
    }

    CleanUI::section_break();
    CleanUI::info(&format!("Total: {} workspaces", sorted_workspaces.len()));

    Ok(())
}
