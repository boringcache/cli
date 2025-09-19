use crate::api::ApiClient;
use crate::config::Config;
use crate::ui::CleanUI;
use anyhow::Result;

pub async fn execute(token: String) -> Result<()> {
    CleanUI::info("Validating token with server...");

    let api_client = ApiClient::new(None)?;
    let session_info = api_client.validate_token(&token).await?;

    Config::save(token)?;

    CleanUI::info("Token validated successfully!");

    match session_info.token.scope_type.as_str() {
        "user" => CleanUI::info(&format!("Scope: Personal ({})", session_info.user.name)),
        "organization" => {
            if let Some(org) = &session_info.organization {
                CleanUI::info(&format!("Scope: Organization ({})", org.name));
            } else {
                CleanUI::info("Scope: Organization");
            }
        }
        "workspace" => {
            if let Some(ws) = &session_info.workspace {
                CleanUI::info(&format!("Scope: Workspace ({})", ws.name));
            } else {
                CleanUI::info("Scope: Workspace");
            }
        }
        _ => CleanUI::info(&format!(
            "Scope: {} ({})",
            session_info.token.scope_type, session_info.user.name
        )),
    }

    CleanUI::info(&format!(
        "Token: {} ({})",
        session_info.token.name, session_info.token.id
    ));

    if let Some(expires_at) = session_info.token.expires_at {
        CleanUI::info(&format!("Expires: {expires_at}"));
    } else if let Some(expires_in_days) = session_info.token.expires_in_days {
        if expires_in_days < 30 {
            CleanUI::info(&format!(
                "⚠️  Token expires in {expires_in_days} days - consider refreshing"
            ));
        } else {
            CleanUI::info(&format!("Token expires in {expires_in_days} days"));
        }
    } else {
        CleanUI::info("Token never expires");
    }

    if let Some(last_used) = session_info.token.last_used_at {
        CleanUI::info(&format!("Last used: {last_used}"));
    }

    CleanUI::info("Token saved to ~/.boringcache/config.json");
    Ok(())
}
