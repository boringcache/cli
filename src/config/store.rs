use anyhow::{Context, Result, anyhow};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::BoringCacheError;

use super::env::{env_api_token_for, purpose_missing_token_message, token_from_file};
use super::{AuthPurpose, Config, DEFAULT_API_URL, env_var};

const CONFIG_DIR_NAME: &str = ".boringcache";
const CONFIG_FILE_NAME: &str = "config.json";

impl Config {
    pub fn load() -> Result<Self> {
        Self::load_for_auth_purpose(AuthPurpose::Default)
    }

    pub fn load_for_auth_purpose(purpose: AuthPurpose) -> Result<Self> {
        if let Some(env_token) = env_api_token_for(purpose).or_else(token_from_file) {
            return load_with_env_token(env_token);
        }

        let config_path = Self::config_path()?;
        if !config_path.exists() {
            return Err(anyhow!(purpose_missing_token_message(purpose)));
        }

        Self::load_from_file()
    }

    pub(super) fn load_from_file() -> Result<Self> {
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

    pub fn save(token: String) -> Result<()> {
        let existing_config = Config::load_from_file().ok();
        let api_url = env_var("BORINGCACHE_API_URL")
            .or_else(|| {
                existing_config
                    .as_ref()
                    .map(|config| config.api_url.clone())
            })
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());
        let default_workspace = existing_config
            .as_ref()
            .and_then(|config| config.default_workspace.clone())
            .or_else(|| env_var("BORINGCACHE_DEFAULT_WORKSPACE"));

        let config = Config {
            api_url,
            token,
            default_workspace,
            default_age_identity: existing_config
                .as_ref()
                .and_then(|config| config.default_age_identity.clone()),
            workspace_encryption: existing_config
                .as_ref()
                .and_then(|config| config.workspace_encryption.clone()),
        };

        config.persist()
    }

    pub fn save_config(&self) -> Result<()> {
        self.persist()
    }

    pub fn load_for_write() -> Result<Self> {
        match Self::load_from_file() {
            Ok(config) => Ok(config),
            Err(err) => {
                if is_config_not_found(&err) {
                    let mut config = Self::empty_for_write();
                    if let Some(api_url) = env_var("BORINGCACHE_API_URL") {
                        config.api_url = api_url;
                    }
                    Ok(config)
                } else {
                    Err(err)
                }
            }
        }
    }

    pub fn update<F>(&mut self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut Self),
    {
        updater(self);
        self.persist()
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

    pub(super) fn config_path() -> Result<PathBuf> {
        let home_dir = Self::home_dir()?;
        Ok(home_dir.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME))
    }

    fn persist(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        write_config_file(&config_path, self)
    }
}

fn load_with_env_token(env_token: String) -> Result<Config> {
    let api_url = env_var("BORINGCACHE_API_URL").unwrap_or_else(|| DEFAULT_API_URL.to_string());
    let mut config = Config {
        api_url,
        token: env_token,
        default_workspace: env_var("BORINGCACHE_DEFAULT_WORKSPACE"),
        default_age_identity: None,
        workspace_encryption: None,
    };

    if let Ok(file_config) = Config::load_from_file() {
        if config.default_workspace.is_none() {
            config.default_workspace = file_config.default_workspace;
        }
        config.default_age_identity = file_config.default_age_identity;
        config.workspace_encryption = file_config.workspace_encryption;
    }

    Ok(config)
}

fn write_config_file(config_path: &Path, config: &Config) -> Result<()> {
    ensure_config_dir(config_path)?;
    let contents = serde_json::to_string_pretty(config).context("Failed to serialize config")?;

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(config_path)
            .context("Failed to open config file for writing")?;

        file.write_all(contents.as_bytes())
            .context("Failed to write config file")?;
    }

    secure_config_permissions(config_path)
}

fn ensure_config_dir(config_path: &Path) -> Result<()> {
    let config_dir = config_path
        .parent()
        .ok_or_else(|| anyhow!("Invalid config path"))?;

    fs::create_dir_all(config_dir).context("Failed to create config directory")?;
    Ok(())
}

#[cfg(unix)]
fn secure_config_permissions(config_path: &Path) -> Result<()> {
    let mut perms = fs::metadata(config_path)
        .context("Failed to read config file metadata")?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(config_path, perms)
        .context("Failed to set secure permissions on config file")?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_config_permissions(_config_path: &Path) -> Result<()> {
    Ok(())
}

fn is_config_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<BoringCacheError>()
        .is_some_and(|error| matches!(error, BoringCacheError::ConfigNotFound))
}
