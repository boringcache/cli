use anyhow::Result;
use serde::Serialize;

use crate::config::Config;
use crate::ui;

pub async fn execute(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Get { key, json } => get_config_value(key, json),
        ConfigAction::Set { key, value } => set_config_value(key, value),
        ConfigAction::List { json } => list_config(json),
    }
}

#[derive(Debug)]
pub enum ConfigAction {
    Get { key: String, json: bool },
    Set { key: String, value: String },
    List { json: bool },
}

#[derive(Debug, Serialize)]
struct ConfigGetOutput {
    key: String,
    value: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConfigListOutput {
    api_url: String,
    token_preview: String,
    default_workspace: Option<String>,
}

fn get_config_value(key: String, json_output: bool) -> Result<()> {
    let config = Config::load()?;

    match key.as_str() {
        "api_url" | "api-url" => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ConfigGetOutput {
                        key: "api_url".to_string(),
                        value: Some(config.api_url),
                    })?
                );
            } else {
                ui::info(&config.api_url);
            }
        }
        "token" => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ConfigGetOutput {
                        key: "token".to_string(),
                        value: Some(config.token),
                    })?
                );
            } else {
                ui::info(&config.token);
            }
        }
        "default_workspace" | "default-workspace" => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ConfigGetOutput {
                        key: "default_workspace".to_string(),
                        value: config.default_workspace,
                    })?
                );
            } else if let Some(workspace) = config.default_workspace {
                ui::info(&workspace);
            } else {
                ui::info("(not set)");
            }
        }
        _ => anyhow::bail!(
            "Unknown config key: {}. Valid keys: api_url, token, default_workspace",
            key
        ),
    }

    Ok(())
}

fn set_config_value(key: String, value: String) -> Result<()> {
    if std::env::var("BORINGCACHE_API_TOKEN").is_ok() {
        match key.as_str() {
            "default_workspace" | "default-workspace" => {
                ui::info("Warning: You are using environment variables for authentication.");
                ui::info(&format!("   To set default_workspace, use: export BORINGCACHE_DEFAULT_WORKSPACE=\"{value}\""));
                ui::info("   Or remove BORINGCACHE_API_TOKEN to use config file mode.");
                return Ok(());
            }
            _ => {}
        }
    }

    let mut config = Config::load()?;

    match key.as_str() {
        "api_url" | "api-url" => {
            config.api_url = value.clone();
            config.update(|_| {})?;
            ui::info(&format!("Set api_url to: {value}"));
        }
        "default_workspace" | "default-workspace" => {
            if value.is_empty() {
                config.default_workspace = None;
                config.update(|_| {})?;
                ui::info("Cleared default_workspace");
            } else {
                config.default_workspace = Some(value.clone());
                config.update(|_| {})?;
                ui::info(&format!("Set default_workspace to: {value}"));
            }
        }
        "token" => {
            anyhow::bail!("Token cannot be set via config command. Use 'boringcache auth --token <token>' instead.");
        }
        _ => anyhow::bail!(
            "Unknown config key: {}. Valid keys: api_url, default_workspace",
            key
        ),
    }

    Ok(())
}

fn list_config(json_output: bool) -> Result<()> {
    let config = Config::load()?;
    let token_preview = format!(
        "{}...{}",
        &config.token[..8.min(config.token.len())],
        &config.token[config.token.len().saturating_sub(4)..]
    );

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&ConfigListOutput {
                api_url: config.api_url,
                token_preview,
                default_workspace: config.default_workspace,
            })?
        );
        return Ok(());
    }

    ui::info("BoringCache Configuration:");
    ui::info(&format!("  api_url: {}", config.api_url));
    ui::info(&format!("  token: {token_preview}"));
    ui::info(&format!(
        "  default_workspace: {}",
        config.default_workspace.as_deref().unwrap_or("(not set)")
    ));

    Ok(())
}
