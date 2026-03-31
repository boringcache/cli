use crate::api::ApiClient;
use crate::config::Config;
use crate::progress::format_bytes;
use crate::ui;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct WorkspaceSummary {
    id: Option<String>,
    slug: String,
    name: String,
    description: Option<String>,
    cache_entries_count: u32,
    total_cache_size: u64,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct WorkspacesSummary {
    total: usize,
    workspaces: Vec<WorkspaceSummary>,
}

pub async fn execute(json_output: bool) -> Result<()> {
    let api_client = ApiClient::for_restore()?;
    let mut sorted_workspaces = api_client.list_workspaces().await?;
    sorted_workspaces.sort_by(|a, b| a.name.cmp(&b.name));
    let current_workspace = Config::load()
        .ok()
        .and_then(|config| config.default_workspace)
        .filter(|workspace| !workspace.trim().is_empty());

    if json_output {
        let summary = WorkspacesSummary {
            total: sorted_workspaces.len(),
            workspaces: sorted_workspaces
                .into_iter()
                .map(|workspace| WorkspaceSummary {
                    id: workspace.id,
                    slug: workspace.slug,
                    name: workspace.name,
                    description: workspace.description,
                    cache_entries_count: workspace.cache_entries_count,
                    total_cache_size: workspace.total_cache_size,
                    created_at: workspace.created_at,
                    updated_at: workspace.updated_at,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    if sorted_workspaces.is_empty() {
        ui::info("No workspaces found");
        return Ok(());
    }

    ui::blank_line();
    ui::info(&format!(
        "{:<7} {:<32} {:<18} {:<10} {:<15}",
        "DEFAULT", "WORKSPACE", "NAME", "ENTRIES", "SIZE"
    ));
    ui::info(&"-".repeat(90));

    for workspace in &sorted_workspaces {
        let marker = if current_workspace.as_deref() == Some(workspace.slug.as_str()) {
            "*"
        } else {
            ""
        };

        let slug = if workspace.slug.len() > 32 {
            format!("{}...", &workspace.slug[..29.min(workspace.slug.len())])
        } else {
            workspace.slug.clone()
        };

        let name = if workspace.name.len() > 20 {
            format!("{}...", &workspace.name[..17.min(workspace.name.len())])
        } else {
            workspace.name.clone()
        };

        let entries = workspace.cache_entries_count.to_string();
        let size = format_bytes(workspace.total_cache_size);

        ui::info(&format!(
            "{marker:<7} {slug:<32} {name:<18} {entries:<10} {size:<15}"
        ));
    }

    ui::blank_line();
    ui::info(&format!("Total: {} workspaces", sorted_workspaces.len()));
    ui::info("Use `boringcache use <workspace>` to save a default workspace.");

    Ok(())
}
