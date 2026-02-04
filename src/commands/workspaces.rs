use crate::api::ApiClient;
use crate::progress::format_bytes;
use crate::ui;
use anyhow::Result;

pub async fn execute() -> Result<()> {
    let api_client = ApiClient::new()?;
    let workspaces = api_client.list_workspaces().await?;

    if workspaces.is_empty() {
        ui::info("No workspaces found");
        return Ok(());
    }

    ui::blank_line();
    ui::info(&format!(
        "{:<15} {:<20} {:<10} {:<15}",
        "ID", "NAME", "ENTRIES", "SIZE"
    ));
    ui::info(&"-".repeat(60));

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

        ui::info(&format!(
            "{id_display:<15} {name:<20} {entries:<10} {size:<15}"
        ));
    }

    ui::blank_line();
    ui::info(&format!("Total: {} workspaces", sorted_workspaces.len()));

    Ok(())
}
