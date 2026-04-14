use super::*;

impl ApiClient {
    pub async fn create_cli_connect_session(
        &self,
    ) -> Result<crate::api::models::cli_connect::CliConnectSessionCreateResponse> {
        let url = self.build_v2_url("cli-connect/sessions");
        debug!("POST {}", url);

        let response = self
            .send_public_request(self.client.post(&url).json(&serde_json::json!({})))
            .await?;

        self.parse_json_response(response).await
    }

    pub async fn poll_cli_connect_session(
        &self,
        session_id: &str,
        poll_token: &str,
    ) -> Result<crate::api::models::cli_connect::CliConnectSessionPollResponse> {
        let url = self.build_v2_url(&format!("cli-connect/sessions/{session_id}"));
        debug!("GET {}", url);

        let response = self
            .send_public_request(
                self.client
                    .get(&url)
                    .header("X-BoringCache-Connect-Token", poll_token),
            )
            .await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            anyhow::bail!(
                "CLI connect poll rejected. Restart onboarding and approve the new session."
            );
        }

        self.parse_json_response(response).await
    }

    pub async fn start_cli_connect_email_auth(
        &self,
        session_id: &str,
        request: &crate::api::models::cli_connect::CliConnectEmailAuthRequest,
    ) -> Result<crate::api::models::cli_connect::CliConnectEmailAuthResponse> {
        let url = self.build_v2_url(&format!("cli-connect/sessions/{session_id}/email-auth"));
        debug!("POST {}", url);

        let response = self
            .send_public_request(self.client.post(&url).json(request))
            .await?;

        self.parse_json_response(response).await
    }

    pub async fn get_session_info(&self) -> Result<crate::api::models::SessionInfo> {
        self.get_v2("session").await
    }

    pub async fn validate_token(&self, _token: &str) -> Result<crate::api::models::SessionInfo> {
        match self.get_session_info().await {
            Ok(session_info) => Ok(session_info),
            Err(e) => {
                if e.to_string().contains("ERROR: Cannot connect") {
                    Err(anyhow::anyhow!(
                        "Token validation failed: Invalid or expired token"
                    ))
                } else {
                    Err(e)
                }
            }
        }
    }
}
