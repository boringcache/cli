use crate::api::ApiClient;
use crate::config::{self, Config};
use crate::ui;
use anyhow::{Result, anyhow};
use serde::Serialize;
use std::io::{self, IsTerminal, Write};

#[derive(Debug, Serialize)]
struct UseWorkspaceOutput {
    workspace: String,
    saved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    env_override: Option<String>,
}

pub async fn execute(workspace: Option<String>, json_output: bool) -> Result<()> {
    let api_client = ApiClient::for_restore()?;
    let mut workspaces = api_client.list_workspaces().await?;
    workspaces.sort_by(|a, b| a.name.cmp(&b.name));

    if workspaces.is_empty() {
        return Err(anyhow!("No accessible workspaces found for this token."));
    }

    let selected_workspace = match workspace
        .map(|workspace| workspace.trim().to_string())
        .filter(|workspace| !workspace.is_empty())
    {
        Some(workspace) => {
            if workspaces
                .iter()
                .any(|candidate| candidate.slug == workspace)
            {
                workspace
            } else {
                return Err(anyhow!(
                    "Workspace '{workspace}' is not accessible with the current token."
                ));
            }
        }
        None if workspaces.len() == 1 => workspaces[0].slug.clone(),
        None if io::stdin().is_terminal() => prompt_for_workspace(&workspaces)?,
        None => {
            let names = workspaces
                .iter()
                .take(5)
                .map(|workspace| workspace.slug.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if workspaces.len() > 5 { ", ..." } else { "" };

            return Err(anyhow!(
                "No workspace specified. Run `boringcache use <workspace>`.\nAvailable workspaces: {names}{suffix}"
            ));
        }
    };

    let env_override = config::env_var("BORINGCACHE_DEFAULT_WORKSPACE");
    save_default_workspace(&selected_workspace)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&UseWorkspaceOutput {
                workspace: selected_workspace,
                saved: true,
                env_override,
            })?
        );
        return Ok(());
    }

    ui::info(&format!("Saved default workspace: {selected_workspace}"));
    if let Some(env_workspace) = env_override {
        ui::warn(&format!(
            "BORINGCACHE_DEFAULT_WORKSPACE is set to '{env_workspace}' and will override the saved default in this shell."
        ));
    }

    Ok(())
}

fn save_default_workspace(workspace: &str) -> Result<()> {
    let mut config = Config::load_for_write()?;
    config.default_workspace = Some(workspace.to_string());
    config.save_config()
}

fn prompt_for_workspace(workspaces: &[crate::api::models::Workspace]) -> Result<String> {
    ui::blank_line();
    ui::info("Available workspaces:");
    for (index, workspace) in workspaces.iter().enumerate() {
        ui::info(&format!(
            "  {}. {} ({})",
            index + 1,
            workspace.name,
            workspace.slug
        ));
    }

    loop {
        print!("Choose default workspace number: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        match input.parse::<usize>() {
            Ok(value) if value >= 1 && value <= workspaces.len() => {
                return Ok(workspaces[value - 1].slug.clone());
            }
            _ => ui::warn("Invalid selection. Enter one of the listed numbers."),
        }
    }
}
