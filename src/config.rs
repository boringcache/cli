use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::error::BoringCacheError;

const CONFIG_DIR_NAME: &str = ".boringcache";
const CONFIG_FILE_NAME: &str = "config.json";
const DEFAULT_API_URL: &str = "https://api.boringcache.com/v1";

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_api_url")]
    pub api_url: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_workspace: Option<String>,
}

fn default_api_url() -> String {
    DEFAULT_API_URL.to_string()
}

impl Config {
    pub fn load() -> Result<Self> {
        if let Ok(env_token) = std::env::var("BORINGCACHE_API_TOKEN") {
            let api_url = std::env::var("BORINGCACHE_API_URL")
                .unwrap_or_else(|_| DEFAULT_API_URL.to_string());
            return Ok(Config {
                api_url,
                token: env_token,
                default_workspace: std::env::var("BORINGCACHE_DEFAULT_WORKSPACE").ok(),
            });
        }

        let config_path = Self::config_path()?;

        if !config_path.exists() {
            return Err(BoringCacheError::ConfigNotFound.into());
        }

        let contents = fs::read_to_string(&config_path).context("Failed to read config file")?;

        let mut config: Config =
            serde_json::from_str(&contents).context("Failed to parse config file")?;

        if let Ok(env_workspace) = std::env::var("BORINGCACHE_DEFAULT_WORKSPACE") {
            config.default_workspace = Some(env_workspace);
        }

        Ok(config)
    }

    pub fn save(token: String) -> Result<()> {
        let config_path = Self::config_path()?;
        let config_dir = config_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid config path"))?;

        fs::create_dir_all(config_dir).context("Failed to create config directory")?;

        let config = Config {
            api_url: DEFAULT_API_URL.to_string(),
            token,
            default_workspace: None,
        };

        let contents =
            serde_json::to_string_pretty(&config).context("Failed to serialize config")?;

        fs::write(&config_path, contents).context("Failed to write config file")?;

        Ok(())
    }

    pub fn update<F>(&mut self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut Self),
    {
        updater(self);

        let config_path = Self::config_path()?;
        let contents = serde_json::to_string_pretty(&self).context("Failed to serialize config")?;

        fs::write(&config_path, contents).context("Failed to write config file")?;

        Ok(())
    }

    pub fn get_api_url(override_url: Option<String>) -> Result<String> {
        if let Some(url) = override_url {
            return Ok(url);
        }

        if let Ok(url) = std::env::var("BORINGCACHE_API_URL") {
            return Ok(url);
        }

        match Config::load() {
            Ok(config) => Ok(config.api_url),
            Err(_) => Ok(DEFAULT_API_URL.to_string()),
        }
    }

    pub fn home_dir() -> Result<PathBuf> {
        dirs::home_dir().context(
            "Could not determine home directory. Please ensure HOME environment variable is set.",
        )
    }

    fn config_path() -> Result<PathBuf> {
        let home_dir = Self::home_dir()?;
        Ok(home_dir.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME))
    }

    pub fn get_default_workspace(&self) -> Result<String, BoringCacheError> {
        self.default_workspace
            .clone()
            .ok_or(BoringCacheError::ConfigNotFound)
    }
}
