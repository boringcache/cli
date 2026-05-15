use super::*;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct CliConnectEmailAuthRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliConnectTokenScope {
    User,
    Workspace,
}

#[derive(Debug, Serialize)]
pub struct CliConnectSessionCreateRequest {
    pub token_scope: CliConnectTokenScope,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CliConnectSessionCreateResponse {
    pub session_id: String,
    pub poll_token: String,
    #[serde(default)]
    pub token_scope: Option<CliConnectTokenScope>,
    pub user_code: String,
    pub verification_url: String,
    pub authorize_url: String,
    pub expires_at: String,
    pub poll_interval_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CliConnectWorkspace {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CliConnectSessionPollResponse {
    pub session_id: String,
    #[serde(default)]
    pub token_scope: Option<CliConnectTokenScope>,
    pub status: String,
    pub expires_at: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub workspace: Option<CliConnectWorkspace>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CliConnectEmailAuthResponse {
    pub session_id: String,
    pub status: String,
    #[serde(default)]
    pub next_step: Option<String>,
    #[serde(default)]
    pub field_errors: HashMap<String, Vec<String>>,
}
