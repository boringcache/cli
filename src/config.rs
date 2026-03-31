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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPurpose {
    Default,
    Restore,
    Save,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValueSource {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ValueSource {
    fn env(key: &str) -> Self {
        Self {
            kind: "env".to_string(),
            detail: Some(key.to_string()),
        }
    }

    fn token_file(path: impl Into<String>) -> Self {
        Self {
            kind: "token_file".to_string(),
            detail: Some(path.into()),
        }
    }

    fn config_file(path: impl Into<String>) -> Self {
        Self {
            kind: "config_file".to_string(),
            detail: Some(path.into()),
        }
    }

    fn default() -> Self {
        Self {
            kind: "default".to_string(),
            detail: None,
        }
    }

    fn missing() -> Self {
        Self {
            kind: "missing".to_string(),
            detail: None,
        }
    }

    pub fn is_missing(&self) -> bool {
        self.kind == "missing"
    }
}

pub fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub fn env_bool(key: &str) -> bool {
    env_var(key)
        .map(|raw| {
            let value = raw.trim();
            value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

const DOCKER_SECRET_PATH: &str = "/run/secrets/bc_token";

fn token_from_file() -> Option<String> {
    let token_file = env_var("BORINGCACHE_TOKEN_FILE").or_else(|| {
        let path = std::path::Path::new(DOCKER_SECRET_PATH);
        path.exists().then(|| DOCKER_SECRET_PATH.to_string())
    })?;
    let token = fs::read_to_string(token_file).ok()?;
    let token = token.trim().to_string();

    if token.is_empty() { None } else { Some(token) }
}

fn token_file_source_path() -> Option<String> {
    let token_file = env_var("BORINGCACHE_TOKEN_FILE").or_else(|| {
        let path = std::path::Path::new(DOCKER_SECRET_PATH);
        path.exists().then(|| DOCKER_SECRET_PATH.to_string())
    })?;
    let token = fs::read_to_string(&token_file).ok()?;
    (!token.trim().is_empty()).then_some(token_file)
}

fn env_api_token_for(purpose: AuthPurpose) -> Option<String> {
    match purpose {
        AuthPurpose::Default | AuthPurpose::Admin => {
            env_var("BORINGCACHE_ADMIN_TOKEN").or_else(|| env_var("BORINGCACHE_API_TOKEN"))
        }
        AuthPurpose::Restore => env_var("BORINGCACHE_RESTORE_TOKEN")
            .or_else(|| env_var("BORINGCACHE_SAVE_TOKEN"))
            .or_else(|| env_var("BORINGCACHE_ADMIN_TOKEN"))
            .or_else(|| env_var("BORINGCACHE_API_TOKEN")),
        AuthPurpose::Save => env_var("BORINGCACHE_SAVE_TOKEN")
            .or_else(|| env_var("BORINGCACHE_ADMIN_TOKEN"))
            .or_else(|| env_var("BORINGCACHE_API_TOKEN")),
    }
}

fn purpose_missing_token_message(purpose: AuthPurpose) -> String {
    match purpose {
        AuthPurpose::Default | AuthPurpose::Restore => {
            "No authentication token configured. Set BORINGCACHE_RESTORE_TOKEN, \
             BORINGCACHE_SAVE_TOKEN, BORINGCACHE_ADMIN_TOKEN, BORINGCACHE_API_TOKEN, \
             BORINGCACHE_TOKEN_FILE, \
             or run 'boringcache auth --token <token>'."
                .to_string()
        }
        AuthPurpose::Save => {
            if env_var("BORINGCACHE_RESTORE_TOKEN").is_some() {
                "This command needs a save-capable token. BORINGCACHE_RESTORE_TOKEN is configured, \
                 but save requires BORINGCACHE_SAVE_TOKEN, BORINGCACHE_ADMIN_TOKEN, \
                 BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or a token saved with \
                 'boringcache auth --token <token>'."
                    .to_string()
            } else {
                "No save-capable token configured. Set BORINGCACHE_SAVE_TOKEN, \
                 BORINGCACHE_ADMIN_TOKEN, BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or run \
                 'boringcache auth --token <token>'."
                    .to_string()
            }
        }
        AuthPurpose::Admin => {
            if env_var("BORINGCACHE_SAVE_TOKEN").is_some()
                || env_var("BORINGCACHE_RESTORE_TOKEN").is_some()
            {
                "This command needs an admin-capable token. BORINGCACHE_RESTORE_TOKEN and \
                 BORINGCACHE_SAVE_TOKEN are not enough for admin operations. Use \
                 BORINGCACHE_ADMIN_TOKEN, BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or \
                 a token saved with 'boringcache auth --token <token>'."
                    .to_string()
            } else {
                "No admin-capable token configured. Use BORINGCACHE_ADMIN_TOKEN, \
                 BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or run \
                 'boringcache auth --token <token>'."
                    .to_string()
            }
        }
    }
}

fn env_token_source_for(purpose: AuthPurpose) -> Option<ValueSource> {
    let keys = match purpose {
        AuthPurpose::Default | AuthPurpose::Admin => {
            &["BORINGCACHE_ADMIN_TOKEN", "BORINGCACHE_API_TOKEN"][..]
        }
        AuthPurpose::Restore => &[
            "BORINGCACHE_RESTORE_TOKEN",
            "BORINGCACHE_SAVE_TOKEN",
            "BORINGCACHE_ADMIN_TOKEN",
            "BORINGCACHE_API_TOKEN",
        ][..],
        AuthPurpose::Save => &[
            "BORINGCACHE_SAVE_TOKEN",
            "BORINGCACHE_ADMIN_TOKEN",
            "BORINGCACHE_API_TOKEN",
        ][..],
    };

    keys.iter()
        .find(|key| env_var(key).is_some())
        .map(|key| ValueSource::env(key))
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
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
        Self::load_for_auth_purpose(AuthPurpose::Default)
    }

    pub fn load_for_auth_purpose(purpose: AuthPurpose) -> Result<Self> {
        if let Some(env_token) = env_api_token_for(purpose).or_else(token_from_file) {
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
                if config.default_workspace.is_none() {
                    config.default_workspace = file_config.default_workspace;
                }
                config.default_age_identity = file_config.default_age_identity;
                config.workspace_encryption = file_config.workspace_encryption;
            }
            return Ok(config);
        }

        let config_path = Self::config_path()?;
        if !config_path.exists() {
            return Err(anyhow::anyhow!(purpose_missing_token_message(purpose)));
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

    pub fn load_for_write() -> Result<Self> {
        match Self::load_from_file() {
            Ok(config) => Ok(config),
            Err(err) => {
                if err
                    .downcast_ref::<BoringCacheError>()
                    .is_some_and(|error| matches!(error, BoringCacheError::ConfigNotFound))
                {
                    Ok(Self {
                        api_url: env_var("BORINGCACHE_API_URL")
                            .unwrap_or_else(|| DEFAULT_API_URL.to_string()),
                        token: String::new(),
                        default_workspace: None,
                        default_age_identity: None,
                        workspace_encryption: None,
                    })
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

pub fn token_source_for(purpose: AuthPurpose) -> ValueSource {
    if let Some(source) = env_token_source_for(purpose) {
        return source;
    }

    if let Some(path) = token_file_source_path() {
        return ValueSource::token_file(path);
    }

    if let (Ok(config), Ok(path)) = (Config::load_from_file(), Config::config_path())
        && !config.token.trim().is_empty()
    {
        return ValueSource::config_file(path.display().to_string());
    }

    ValueSource::missing()
}

pub fn api_url_source() -> ValueSource {
    if env_var("BORINGCACHE_API_URL").is_some() {
        return ValueSource::env("BORINGCACHE_API_URL");
    }

    if let Ok(path) = Config::config_path()
        && path.exists()
    {
        return ValueSource::config_file(path.display().to_string());
    }

    ValueSource::default()
}

pub fn default_workspace_source() -> ValueSource {
    if env_var("BORINGCACHE_DEFAULT_WORKSPACE").is_some() {
        return ValueSource::env("BORINGCACHE_DEFAULT_WORKSPACE");
    }

    if let (Ok(config), Ok(path)) = (Config::load_from_file(), Config::config_path())
        && config
            .default_workspace
            .as_deref()
            .is_some_and(|workspace| !workspace.trim().is_empty())
    {
        return ValueSource::config_file(path.display().to_string());
    }

    ValueSource::missing()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;
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
                test_env::set_var(self.key, value);
            } else {
                test_env::remove_var(self.key);
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(ref value) = self.original {
                test_env::set_var(self.key, value);
            } else {
                test_env::remove_var(self.key);
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
    fn test_config_deserialization_without_token() {
        let json = r#"{"default_workspace":"org/ws"}"#;
        let config: Config = serde_json::from_str(json).unwrap();

        assert_eq!(config.token, "");
        assert_eq!(config.default_workspace.as_deref(), Some("org/ws"));
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
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let restore_token_guard = EnvVarGuard::new("BORINGCACHE_RESTORE_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.txt");
        fs::write(&token_path, "token-from-file\n").unwrap();

        admin_token_guard.set(None);
        api_token_guard.set(None);
        restore_token_guard.set(None);
        save_token_guard.set(None);
        token_file_guard.set(Some(token_path.to_str().unwrap()));

        assert_eq!(
            env_api_token_for(AuthPurpose::Restore)
                .or_else(token_from_file)
                .as_deref(),
            Some("token-from-file")
        );
    }

    #[test]
    fn test_env_api_token_prefers_api_token_env() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let restore_token_guard = EnvVarGuard::new("BORINGCACHE_RESTORE_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.txt");
        fs::write(&token_path, "token-from-file").unwrap();

        admin_token_guard.set(None);
        api_token_guard.set(Some("token-from-env"));
        restore_token_guard.set(None);
        save_token_guard.set(None);
        token_file_guard.set(Some(token_path.to_str().unwrap()));

        assert_eq!(
            env_api_token_for(AuthPurpose::Restore).as_deref(),
            Some("token-from-env")
        );
    }

    #[test]
    fn test_env_var_trims_whitespace_and_drops_empty_values() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let workspace_guard = EnvVarGuard::new("BORINGCACHE_DEFAULT_WORKSPACE");

        admin_token_guard.set(None);
        api_token_guard.set(Some("  token-from-env\n"));
        workspace_guard.set(Some("   \n\t"));

        assert_eq!(
            env_var("BORINGCACHE_API_TOKEN").as_deref(),
            Some("token-from-env")
        );
        assert_eq!(env_var("BORINGCACHE_DEFAULT_WORKSPACE"), None);
    }

    #[test]
    fn test_load_for_auth_purpose_trims_env_token() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let restore_token_guard = EnvVarGuard::new("BORINGCACHE_RESTORE_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        let api_url_guard = EnvVarGuard::new("BORINGCACHE_API_URL");

        admin_token_guard.set(None);
        api_token_guard.set(None);
        restore_token_guard.set(Some("  restore-token\n"));
        save_token_guard.set(None);
        token_file_guard.set(None);
        api_url_guard.set(Some("  https://api.example.test/v2 \n"));

        let config = Config::load_for_auth_purpose(AuthPurpose::Restore).unwrap();
        assert_eq!(config.token, "restore-token");
        assert_eq!(config.api_url, "https://api.example.test/v2");
    }

    #[test]
    fn test_load_for_auth_purpose_merges_file_default_workspace_with_env_token() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let home_guard = EnvVarGuard::new("HOME");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let restore_token_guard = EnvVarGuard::new("BORINGCACHE_RESTORE_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        let workspace_guard = EnvVarGuard::new("BORINGCACHE_DEFAULT_WORKSPACE");
        let temp_dir = TempDir::new().unwrap();

        admin_token_guard.set(None);
        home_guard.set(Some(temp_dir.path().to_str().unwrap()));
        api_token_guard.set(Some("env-token"));
        restore_token_guard.set(None);
        save_token_guard.set(None);
        token_file_guard.set(None);
        workspace_guard.set(None);

        let mut file_config = Config::load_for_write().unwrap();
        file_config.default_workspace = Some("org/from-file".to_string());
        file_config.save_config().unwrap();

        let config = Config::load_for_auth_purpose(AuthPurpose::Restore).unwrap();
        assert_eq!(config.token, "env-token");
        assert_eq!(config.default_workspace.as_deref(), Some("org/from-file"));
    }

    #[test]
    fn test_load_for_write_does_not_copy_env_token() {
        let _guard = test_env::lock();
        let home_guard = EnvVarGuard::new("HOME");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let temp_dir = TempDir::new().unwrap();

        home_guard.set(Some(temp_dir.path().to_str().unwrap()));
        api_token_guard.set(Some("env-token"));

        let config = Config::load_for_write().unwrap();
        assert!(config.token.is_empty());
    }

    #[test]
    fn test_restore_prefers_restore_token_over_save_and_api() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let restore_token_guard = EnvVarGuard::new("BORINGCACHE_RESTORE_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");

        admin_token_guard.set(Some("admin-token"));
        api_token_guard.set(Some("api-token"));
        restore_token_guard.set(Some("restore-token"));
        save_token_guard.set(Some("save-token"));

        assert_eq!(
            env_api_token_for(AuthPurpose::Restore).as_deref(),
            Some("restore-token")
        );
    }

    #[test]
    fn test_restore_falls_back_to_save_token() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let restore_token_guard = EnvVarGuard::new("BORINGCACHE_RESTORE_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");

        admin_token_guard.set(Some("admin-token"));
        api_token_guard.set(Some("api-token"));
        restore_token_guard.set(None);
        save_token_guard.set(Some("save-token"));

        assert_eq!(
            env_api_token_for(AuthPurpose::Restore).as_deref(),
            Some("save-token")
        );
    }

    #[test]
    fn test_save_prefers_save_token_over_api_token() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");

        admin_token_guard.set(Some("admin-token"));
        api_token_guard.set(Some("api-token"));
        save_token_guard.set(Some("save-token"));

        assert_eq!(
            env_api_token_for(AuthPurpose::Save).as_deref(),
            Some("save-token")
        );
    }

    #[test]
    fn test_missing_save_token_message_mentions_restore_only_token() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");
        let restore_token_guard = EnvVarGuard::new("BORINGCACHE_RESTORE_TOKEN");
        let save_token_guard = EnvVarGuard::new("BORINGCACHE_SAVE_TOKEN");
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");

        admin_token_guard.set(None);
        api_token_guard.set(None);
        restore_token_guard.set(Some("restore-token"));
        save_token_guard.set(None);
        token_file_guard.set(None);

        let message = purpose_missing_token_message(AuthPurpose::Save);
        assert!(message.contains("BORINGCACHE_RESTORE_TOKEN"));
        assert!(message.contains("BORINGCACHE_SAVE_TOKEN"));
    }

    #[test]
    fn test_admin_prefers_admin_token_over_api_token() {
        let _guard = test_env::lock();
        let admin_token_guard = EnvVarGuard::new("BORINGCACHE_ADMIN_TOKEN");
        let api_token_guard = EnvVarGuard::new("BORINGCACHE_API_TOKEN");

        admin_token_guard.set(Some("admin-token"));
        api_token_guard.set(Some("api-token"));

        assert_eq!(
            env_api_token_for(AuthPurpose::Admin).as_deref(),
            Some("admin-token")
        );
    }

    #[test]
    fn test_token_from_file_reads_docker_secret_when_env_unset() {
        let _guard = test_env::lock();
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        token_file_guard.set(None);

        let result = token_from_file();
        if std::path::Path::new(DOCKER_SECRET_PATH).exists() {
            assert!(result.is_some());
        } else {
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_token_from_file_prefers_env_over_docker_secret() {
        let _guard = test_env::lock();
        let token_file_guard = EnvVarGuard::new("BORINGCACHE_TOKEN_FILE");
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("explicit-token.txt");
        fs::write(&token_path, "explicit-token").unwrap();

        token_file_guard.set(Some(token_path.to_str().unwrap()));

        let result = token_from_file();
        assert_eq!(result.as_deref(), Some("explicit-token"));
    }

    #[test]
    fn test_docker_secret_constant_is_conventional_path() {
        assert_eq!(DOCKER_SECRET_PATH, "/run/secrets/bc_token");
    }
}
