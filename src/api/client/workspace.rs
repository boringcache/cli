use super::*;

impl ApiClient {
    pub async fn optimize(
        &self,
        request: &crate::api::models::optimize::OptimizeRequest,
    ) -> Result<crate::api::models::optimize::OptimizeResponse> {
        self.post_v2("optimize", request).await
    }

    pub async fn list_workspaces(&self) -> Result<Vec<crate::api::models::Workspace>> {
        self.get_v2("workspaces").await
    }

    pub async fn workspace_status(
        &self,
        workspace: &str,
        period: &str,
        limit: u32,
    ) -> Result<crate::api::models::workspace::WorkspaceStatusResponse> {
        let endpoint = self.workspace_endpoint(workspace, "status")?;
        let url = format!("{endpoint}?period={period}&limit={limit}");
        self.get_v2(&url).await
    }

    pub async fn workspace_tags(
        &self,
        workspace: &str,
        filter: Option<&str>,
        include_system: bool,
        limit: u32,
        offset: u32,
    ) -> Result<crate::api::models::workspace::WorkspaceTagsResponse> {
        let endpoint = self.workspace_endpoint(workspace, "tags")?;
        let mut params = vec![format!("limit={limit}"), format!("offset={offset}")];
        if let Some(filter) = filter.filter(|value| !value.trim().is_empty()) {
            params.push(format!("filter={}", urlencoding::encode(filter.trim())));
        }
        if include_system {
            params.push("include_system=true".to_string());
        }
        let url = format!("{endpoint}?{}", params.join("&"));
        self.get_v2(&url).await
    }

    pub async fn workspace_tokens(
        &self,
        workspace: &str,
        include_inactive: bool,
        limit: u32,
        offset: u32,
    ) -> Result<crate::api::models::workspace::WorkspaceTokensResponse> {
        let endpoint = self.workspace_endpoint(workspace, "tokens")?;
        let mut params = vec![format!("limit={limit}"), format!("offset={offset}")];
        if include_inactive {
            params.push("include_inactive=true".to_string());
        }
        let url = format!("{endpoint}?{}", params.join("&"));
        self.get_v2(&url).await
    }

    pub async fn workspace_token(
        &self,
        workspace: &str,
        token_id: &str,
    ) -> Result<crate::api::models::workspace::WorkspaceTokenResponse> {
        let endpoint = self.workspace_endpoint(
            workspace,
            &format!("tokens/{}", urlencoding::encode(token_id)),
        )?;
        self.get_v2(&endpoint).await
    }

    pub async fn create_workspace_token(
        &self,
        workspace: &str,
        body: &crate::api::models::workspace::WorkspaceTokenCreateRequest,
    ) -> Result<crate::api::models::workspace::WorkspaceTokenResponse> {
        let endpoint = self.workspace_endpoint(workspace, "tokens")?;
        self.post_v2(&endpoint, body).await
    }

    pub async fn create_workspace_token_pair(
        &self,
        workspace: &str,
        body: &crate::api::models::workspace::WorkspaceTokenPairCreateRequest,
    ) -> Result<crate::api::models::workspace::WorkspaceTokenPairResponse> {
        let endpoint = self.workspace_endpoint(workspace, "tokens/ci-pair")?;
        self.post_v2(&endpoint, body).await
    }

    pub async fn revoke_workspace_token(
        &self,
        workspace: &str,
        token_id: &str,
    ) -> Result<crate::api::models::workspace::WorkspaceTokenResponse> {
        let endpoint = self.workspace_endpoint(
            workspace,
            &format!("tokens/{}/revoke", urlencoding::encode(token_id)),
        )?;
        self.post_v2(&endpoint, &serde_json::json!({})).await
    }

    pub async fn rotate_workspace_token(
        &self,
        workspace: &str,
        token_id: &str,
        body: &crate::api::models::workspace::WorkspaceTokenRotateRequest,
    ) -> Result<crate::api::models::workspace::WorkspaceTokenResponse> {
        let endpoint = self.workspace_endpoint(
            workspace,
            &format!("tokens/{}/rotate", urlencoding::encode(token_id)),
        )?;
        self.post_v2(&endpoint, body).await
    }

    pub async fn workspace_sessions(
        &self,
        workspace: &str,
        period: &str,
        limit: u32,
        offset: u32,
    ) -> Result<crate::api::models::workspace::WorkspaceSessionsResponse> {
        let endpoint = self.workspace_endpoint(workspace, "sessions")?;
        let url = format!("{endpoint}?period={period}&limit={limit}&offset={offset}");
        self.get_v2(&url).await
    }

    pub async fn workspace_misses(
        &self,
        workspace: &str,
        period: &str,
        limit: u32,
        offset: u32,
    ) -> Result<crate::api::models::workspace::WorkspaceMissesResponse> {
        let endpoint = self.workspace_endpoint(workspace, "misses")?;
        let url = format!("{endpoint}?period={period}&limit={limit}&offset={offset}");
        self.get_v2(&url).await
    }
}
