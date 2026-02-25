use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::error::BoringCacheError;

const CONFIG_DIR_NAME: &str = ".boringcache";
const CONFIG_FILE_NAME: &str = "config.json";
pub const DEFAULT_API_URL: &str = "https://api.boringcache.com";

pub fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.trim().is_empty())
}

fn env_api_token() -> Option<String> {
    if let Some(token) = env_var("BORINGCACHE_API_TOKEN") {
        return Some(token);
    }

    let token_file = env_var("BORINGCACHE_TOKEN_FILE")?;
    let token = fs::read_to_string(token_file).ok()?;
    let token = token.trim().to_string();

    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceEncryption {
    pub enabled: bool,
    pub recipient: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_api_url")]
    pub api_url: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_age_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub workspace_encryption: Option<HashMap<String, WorkspaceEncryption>>,
}

fn default_api_url() -> String {
    DEFAULT_API_URL.to_string()
}

impl Config {
    pub fn default_api_url_value() -> &'static str {
        DEFAULT_API_URL
    }

    pub fn load() -> Result<Self> {
        if let Some(env_token) = env_api_token() {
            let api_url =
                env_var("BORINGCACHE_API_URL").unwrap_or_else(|| DEFAULT_API_URL.to_string());
            let mut config = Config {
                api_url,
                token: env_token,
                default_workspace: env_var("BORINGCACHE_DEFAULT_WORKSPACE"),
                default_age_identity: None,
                workspace_encryption: None,
            };
            if let Ok(file_config) = Self::load_from_file() {
                config.default_age_identity = file_config.default_age_identity;
                config.workspace_encryption = file_config.workspace_encryption;
            }
            return Ok(config);
        }

        Self::load_from_file()
    }

    fn load_from_file() -> Result<Self> {
        let config_path = Self::config_path()?;

        if !config_path.exists() {
            return Err(BoringCacheError::ConfigNotFound.into());
        }

        let contents = fs::read_to_string(&config_path).context("Failed to read config file")?;

        let mut config: Config =
            serde_json::from_str(&contents).context("Failed to parse config file")?;

        if let Some(env_workspace) = env_var("BORINGCACHE_DEFAULT_WORKSPACE") {
            config.default_workspace = Some(env_workspace);
        }

        Ok(config)
    }

    pub fn get_workspace_encryption(&self, workspace: &str) -> Option<&WorkspaceEncryption> {
        self.workspace_encryption
            .as_ref()
            .and_then(|map| map.get(workspace))
            .filter(|enc| enc.enabled)
    }

    pub fn set_workspace_encryption(&mut self, workspace: &str, recipient: &str) {
        let encryption = WorkspaceEncryption {
            enabled: true,
            recipient: recipient.to_string(),
        };
        self.workspace_encryption
            .get_or_insert_with(HashMap::new)
            .insert(workspace.to_string(), encryption);
    }

    pub fn save(token: String) -> Result<()> {
        let config_path = Self::config_path()?;
        let config_dir = config_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid config path"))?;

        fs::create_dir_all(config_dir).context("Failed to create config directory")?;

        let existing_config = Config::load_from_file().ok();
        let api_url = env_var("BORINGCACHE_API_URL")
            .or_else(|| existing_config.as_ref().map(|c| c.api_url.clone()))
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());
        let default_workspace = existing_config
            .as_ref()
            .and_then(|cfg| cfg.default_workspace.clone())
            .or_else(|| env_var("BORINGCACHE_DEFAULT_WORKSPACE"));

        let config = Config {
            api_url,
            token,
            default_workspace,
            default_age_identity: existing_config
                .as_ref()
                .and_then(|c| c.default_age_identity.clone()),
            workspace_encryption: existing_config
                .as_ref()
                .and_then(|c| c.workspace_encryption.clone()),
        };

        let contents =
            serde_json::to_string_pretty(&config).context("Failed to serialize config")?;

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&config_path)
                .context("Failed to open config file for writing")?;

            file.write_all(contents.as_bytes())
                .context("Failed to write config file")?;
        }

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&config_path)
                .context("Failed to read config file metadata")?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config_path, perms)
                .context("Failed to set secure permissions on config file")?;
        }

        Ok(())
    }

    pub fn save_config(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        let config_dir = config_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid config path"))?;

        fs::create_dir_all(config_dir).context("Failed to create config directory")?;

        let contents = serde_json::to_string_pretty(&self).context("Failed to serialize config")?;

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&config_path)
                .context("Failed to open config file for writing")?;

            file.write_all(contents.as_bytes())
                .context("Failed to write config file")?;
        }

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&config_path)
                .context("Failed to read config file metadata")?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config_path, perms)
                .context("Failed to set secure permissions on config file")?;
        }

        Ok(())
    }

    pub fn update<F>(&mut self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut Self),
    {
        updater(self);

        let config_path = Self::config_path()?;
        let contents = serde_json::to_string_pretty(&self).context("Failed to serialize config")?;

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&config_path)
                .context("Failed to open config file for writing")?;

            file.write_all(contents.as_bytes())
                .context("Failed to write config file")?;
        }

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&config_path)
                .context("Failed to read config file metadata")?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config_path, perms)
                .context("Failed to set secure permissions on config file")?;
        }

        Ok(())
    }

    pub fn get_api_url(override_url: Option<String>) -> Result<String> {
        if let Some(url) = override_url {
            return Ok(url);
        }

        if let Some(url) = env_var("BORINGCACHE_API_URL") {
            return Ok(url);
        }

        match Config::load() {
            Ok(config) => Ok(config.api_url),
            Err(_) => Ok(DEFAULT_API_URL.to_string()),
        }
    }

    pub fn home_dir() -> Result<PathBuf> {
        if let Ok(home) = std::env::var("HOME") {
            return Ok(PathBuf::from(home));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn new(key: &'static str) -> Self {
            Self {
                key,
                original: std::env::var(key).ok(),
            }
        }

        fn set(&self, value: Option<&str>) {
            if let Some(value) = value {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(ref value) = self.original {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn test_default_api_url() {
        assert_eq!(Config::default_api_url_value(), DEFAULT_API_URL);
        assert!(DEFAULT_API_URL.starts_with("https://"));
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            api_url: "https://example.com".to_string(),
            token: "test_token".to_string(),
            default_workspace: Some("org/workspace".to_string()),
            default_age_identity: None,
            workspace_encryption: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.api_url, config.api_url);
        assert_eq!(deserialized.token, config.token);
        assert_eq!(deserialized.default_workspace, config.default_workspace);
    }

    #[test]
    fn test_config_deserialization_with_defaults() {
        let json = r#"{"token": "test_token"}"#;
        let config: Config = serde_json::from_str(json).unwrap();

        assert_eq!(config.api_url, DEFAULT_API_URL);
        assert_eq!(config.token, "test_token");
        assert!(config.default_workspace.is_none());
    }

    #[test]
    fn test_get_default_workspace() {
        let config_with_workspace = Config {
            api_url: DEFAULT_API_URL.to_string(),
            token: "token".to_string(),
            default_workspace: Some("org/ws".to_string()),
            default_age_identity: None,
            workspace_encryption: None,
        };
        assert_eq!(
            config_with_workspace.get_default_workspace().unwrap(),
            "org/ws"
        );

        let config_without_workspace = Config {
            api_url: DEFAULT_API_URL.to_string(),
            token: "token".to_string(),
            default_workspace: None,
            default_age_identity: None,
            workspace_encryption: None,
        };
        assert!(config_without_workspace.get_default_workspace().is_err());
    }

    #[test]
    fn test_workspace_encryption() {
        let mut config = Config {
            api_url: DEFAULT_API_URL.to_string(),
            token: "token".to_string(),
            default_workspace: None,
            default_age_identity: None,
            workspace_encryption: None,
        };

        assert!(config.get_workspace_encryption("org/ws").is_none());

        config.set_workspace_encryption("org/ws", "age1xxx...");
        let enc = config.get_workspace_encryption("org/ws").unwrap();
        assert!(enc.enabled);
        assert_eq!(enc.recipient, "age1xxx...");
    }

    #[test]
    fn test_get_api_url_with_override() {
        let result = Config::get_api_url(Some("https://custom.api.com".to_string()));
        assert_eq!(result.unwrap(), "https://custom.api.com");
    }

    #[test]
    fn test_env_api_token_uses_token_file_when_api_token_missing() {
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.txt");
        fs::write(&token_path, "token-from-file\n").unwrap();

        api_token_guard.set(None);
        token_file_guard.set(Some(token_path.to_str().unwrap()));

        assert_eq!(env_api_token().as_deref(), Some("token-from-file"));
    }

    #[test]
    fn test_env_api_token_prefers_api_token_env() {
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.txt");
        fs::write(&token_path, "token-from-file").unwrap();

        api_token_guard.set(Some("token-from-env"));
        token_file_guard.set(Some(token_path.to_str().unwrap()));

        assert_eq!(env_api_token().as_deref(), Some("token-from-env"));
    }
}
