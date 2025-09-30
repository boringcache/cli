use anyhow::Result;

use crate::config::Config;
use crate::ui;

pub async fn execute(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Get { key } => get_config_value(key),
        ConfigAction::Set { key, value } => set_config_value(key, value),
        ConfigAction::List => list_config(),
    }
}

#[derive(Debug)]
pub enum ConfigAction {
    Get { key: String },
    Set { key: String, value: String },
    List,
}

fn get_config_value(key: String) -> Result<()> {
    let config = Config::load()?;

    match key.as_str() {
        "api_url" | "api-url" => println!("{}", config.api_url),
        "token" => println!("{}", config.token),
        "default_workspace" | "default-workspace" => {
            if let Some(workspace) = config.default_workspace {
                println!("{workspace}");
            } else {
                println!("(not set)");
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
            println!("SUCCESS: Set api_url to: {value}");
        }
        "default_workspace" | "default-workspace" => {
            if value.is_empty() {
                config.default_workspace = None;
                config.update(|_| {})?;
                println!("SUCCESS: Cleared default_workspace");
            } else {
                config.default_workspace = Some(value.clone());
                config.update(|_| {})?;
                println!("SUCCESS: Set default_workspace to: {value}");
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

fn list_config() -> Result<()> {
    let config = Config::load()?;

    println!("BoringCache Configuration:");
    println!("  api_url: {}", config.api_url);
    println!(
        "  token: {}...{}",
        &config.token[..8.min(config.token.len())],
        &config.token[config.token.len().saturating_sub(4)..]
    );
    println!(
        "  default_workspace: {}",
        config.default_workspace.as_deref().unwrap_or("(not set)")
    );

    Ok(())
}
