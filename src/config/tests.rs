use std::fs;

use super::env::{
    DOCKER_SECRET_PATH, env_api_token_for, purpose_missing_token_message, token_from_file,
};
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
