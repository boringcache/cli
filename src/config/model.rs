use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::BoringCacheError;

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
    pub(super) fn env(key: &str) -> Self {
        Self {
            kind: "env".to_string(),
            detail: Some(key.to_string()),
        }
    }

    pub(super) fn token_file(path: impl Into<String>) -> Self {
        Self {
            kind: "token_file".to_string(),
            detail: Some(path.into()),
        }
    }

    pub(super) fn config_file(path: impl Into<String>) -> Self {
        Self {
            kind: "config_file".to_string(),
            detail: Some(path.into()),
        }
    }

    pub(super) fn default() -> Self {
        Self {
            kind: "default".to_string(),
            detail: None,
        }
    }

    pub(super) fn missing() -> Self {
        Self {
            kind: "missing".to_string(),
            detail: None,
        }
    }

    pub fn is_missing(&self) -> bool {
        self.kind == "missing"
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

    pub fn get_default_workspace(&self) -> Result<String, BoringCacheError> {
        self.default_workspace
            .clone()
            .ok_or(BoringCacheError::ConfigNotFound)
    }

    pub(super) fn empty_for_write() -> Self {
        Self {
            api_url: DEFAULT_API_URL.to_string(),
            token: String::new(),
            default_workspace: None,
            default_age_identity: None,
            workspace_encryption: None,
        }
    }
}
